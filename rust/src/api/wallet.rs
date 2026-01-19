use std::{collections::HashMap, str::FromStr, sync::Arc, time::Duration, vec};

use bip39::Mnemonic;
use cdk::{
    amount::{Amount, SplitTarget},
    mint_url::MintUrl,
    nuts::{
        nut00::ProofsMethods, AuthProof as CdkAuthProof, CurrencyUnit,
        MintQuoteState as CdkMintQuoteState, PublicKey, SecretKey, SpendingConditions,
        State as ProofState, Token as CdkToken,
    },
    wallet::{
        MeltQuote as CdkMeltQuote, MintQuote as CdkMintQuote, PreparedSend as CdkPreparedSend,
        ReceiveOptions as CdkReceiveOptions, SendMemo, SendOptions as CdkSendOptions,
        Wallet as CdkWallet,
    },
};
use cdk_common::{
    nut23::Amountless,
    util::unix_time,
    wallet::{
        Transaction as CdkTransaction, TransactionDirection as CdkTransactionDirection,
        TransactionId,
    },
    MeltOptions as CdkMeltOptions, Mpp, PaymentRequestPayload,
};
use cdk_sqlite::WalletSqliteDatabase;
use cdk_supabase::SupabaseWalletDatabase;
use flutter_rust_bridge::frb;
use log::info;
use nostr::{
    key::Keys,
    nips::nip19::{FromBech32, Nip19Profile},
};
use tokio::{
    sync::{broadcast, mpsc, Mutex},
    time::sleep,
};
use url::Url;

use crate::frb_generated::StreamSink;

use super::{
    bitcoin::BitcoinAddress,
    bolt11::Bolt11Invoice,
    error::Error,
    mint::Mint,
    payment_request::{PaymentRequest, TransportType},
    token::Token,
};

/// Database backend type - exposed to Dart for runtime type checking
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DatabaseType {
    /// Local SQLite database
    Sqlite,
    /// Remote Supabase database
    Supabase,
}

/// Authentication proof for protected mint endpoints
#[derive(Clone, Debug)]
pub struct AuthProof {
    /// Keyset ID
    pub keyset_id: String,
    /// Secret message
    pub secret: String,
    /// Unblinded signature (C)
    pub c: String,
    /// Y value (hash_to_curve of secret)
    pub y: String,
}

impl From<CdkAuthProof> for AuthProof {
    fn from(auth_proof: CdkAuthProof) -> Self {
        Self {
            keyset_id: auth_proof.keyset_id.to_string(),
            secret: auth_proof.secret.to_string(),
            c: auth_proof.c.to_string(),
            y: auth_proof.y().map(|y| y.to_string()).unwrap_or_default(),
        }
    }
}

#[derive(Clone)]
pub struct Wallet {
    pub mint_url: String,
    pub unit: String,

    balance_broadcast: broadcast::Sender<u64>,
    inner: CdkWallet,
    seed: [u8; 64],
}

impl Wallet {
    /// Create a new wallet from a BIP39 mnemonic
    #[frb(sync)]
    pub fn new(
        mint_url: String,
        unit: String,
        mnemonic: String,
        target_proof_count: Option<usize>,
        db: &WalletDatabase,
    ) -> Result<Self, Error> {
        let mnemonic = Mnemonic::parse(&mnemonic).map_err(|_| Error::InvalidInput)?;
        let seed: [u8; 64] = mnemonic.to_seed("").into();
        let unit = CurrencyUnit::from_str(&unit).unwrap_or(CurrencyUnit::Custom(unit.to_string()));
        Ok(Self {
            mint_url: mint_url.clone(),
            unit: unit.to_string(),
            balance_broadcast: broadcast::channel(1).0,
            inner: CdkWallet::new(&mint_url, unit, db.inner.clone(), seed, target_proof_count)?,
            seed,
        })
    }

    #[tracing::instrument(skip(self))]
    pub async fn balance(&self) -> Result<u64, Error> {
        Ok(self.inner.total_balance().await?.into())
    }

    #[tracing::instrument(skip(self, sink))]
    pub async fn stream_balance(&self, sink: StreamSink<u64>) -> Result<(), Error> {
        let mut receiver = self.balance_broadcast.subscribe();
        let _ = sink.add(self.balance().await?);
        flutter_rust_bridge::spawn(async move {
            loop {
                match receiver.recv().await {
                    Ok(balance) => {
                        if sink.add(balance).is_err() {
                            break;
                        }
                    }
                    Err(_) => break,
                }
            }
        });
        Ok(())
    }

    #[tracing::instrument(skip(self))]
    pub async fn get_mint(&self) -> Result<Mint, Error> {
        let info = self.inner.fetch_mint_info().await?;
        Ok(Mint {
            url: self.mint_url.clone(),
            balance: self.balance().await.ok(),
            info: info.map(|info| info.into()),
        })
    }

    #[tracing::instrument(skip(self))]
    pub async fn check_all_mint_quotes(&self) -> Result<(), Error> {
        let amount = self.inner.check_all_mint_quotes().await?;
        if amount > Amount::ZERO {
            self.update_balance_streams().await;
        }
        Ok(())
    }

    #[tracing::instrument(skip(self))]
    pub async fn check_pending_melt_quotes(&self) -> Result<(), Error> {
        self.inner.check_pending_melt_quotes().await?;
        Ok(())
    }

    #[tracing::instrument(skip(self))]
    pub async fn check_pending_transactions(&self) -> Result<(), Error> {
        self.inner.check_all_pending_proofs().await?;
        self.update_balance_streams().await;
        Ok(())
    }

    #[tracing::instrument(skip(self))]
    pub async fn get_active_mint_quotes(&self) -> Result<Vec<MintQuote>, Error> {
        let quotes = self.inner.get_active_mint_quotes().await?;
        Ok(quotes.into_iter().map(MintQuote::from).collect())
    }

    #[tracing::instrument(skip(self, token))]
    pub async fn is_token_spent(&self, token: Token) -> Result<bool, Error> {
        let token: CdkToken = token.try_into()?;
        let mint_keysets = self.inner.get_mint_keysets().await?;
        let proof_states = self
            .inner
            .check_proofs_spent(token.proofs(&mint_keysets)?)
            .await?;
        Ok(proof_states
            .iter()
            .any(|state| state.state == ProofState::Spent))
    }

    #[tracing::instrument(skip(self))]
    pub async fn list_transactions(
        &self,
        direction: Option<TransactionDirection>,
    ) -> Result<Vec<Transaction>, Error> {
        let pending_ys = self
            .inner
            .get_pending_spent_proofs()
            .await?
            .into_iter()
            .map(|p| p.y())
            .collect::<Result<Vec<_>, _>>()?;
        let cdk_txs = self
            .inner
            .list_transactions(direction.map(|d| d.into()))
            .await?;
        let mut txs = Vec::new();
        for tx in cdk_txs {
            let status = if pending_ys.iter().any(|y| tx.ys.contains(y)) {
                TransactionStatus::Pending
            } else {
                TransactionStatus::Settled
            };
            let mut transaction: Transaction = tx.into();
            transaction.status = status;
            txs.push(transaction);
        }
        Ok(txs)
    }

    #[tracing::instrument(skip(self))]
    pub async fn melt_quote(
        &self,
        request: String,
        opts: Option<MeltOptions>,
    ) -> Result<MeltQuote, Error> {
        Ok(self
            .inner
            .melt_quote(request, opts.map(|o| o.try_into()).transpose()?)
            .await?
            .into())
    }

    #[tracing::instrument(skip(self, request))]
    pub async fn melt_bolt12_quote(
        &self,
        request: String,
        opts: Option<MeltOptions>,
    ) -> Result<MeltQuote, Error> {
        Ok(self
            .inner
            .melt_bolt12_quote(request, opts.map(|o| o.try_into()).transpose()?)
            .await?
            .into())
    }

    #[tracing::instrument(skip(self, quote))]
    pub async fn melt(&self, quote: MeltQuote) -> Result<u64, Error> {
        let melted = self.inner.melt(&quote.id).await?;
        self.update_balance_streams().await;
        Ok(melted.total_amount().into())
    }

    #[tracing::instrument(skip(self, sink))]
    pub async fn mint(
        &self,
        amount: u64,
        description: Option<String>,
        sink: StreamSink<MintQuote>,
    ) -> Result<(), Error> {
        let mint_url = self.mint_url()?;
        let unit = self.unit();
        let quote = self.inner.mint_quote(amount.into(), description).await?;
        let _ = sink.add(MintQuote::from(quote.clone()));
        let _self = self.clone();
        flutter_rust_bridge::spawn(async move {
            loop {
                sleep(Duration::from_secs(3)).await;
                info!("Checking mint quote state for {}", quote.id);
                match _self.inner.mint_quote_state(&quote.id).await {
                    Ok(state_res) => match state_res.state {
                        CdkMintQuoteState::Unpaid => {
                            if let Some(expiry) = state_res.expiry {
                                if expiry < unix_time() {
                                    let _ = sink.add(MintQuote {
                                        id: quote.id,
                                        request: quote.request,
                                        amount: quote.amount.map(|a| a.into()),
                                        expiry: Some(expiry),
                                        state: MintQuoteState::Error,
                                        token: None,
                                        error: Some("Quote expired".to_string()),
                                    });
                                    break;
                                }
                            }
                            continue;
                        }
                        CdkMintQuoteState::Issued => {
                            break;
                        }
                        CdkMintQuoteState::Paid => {
                            let _ = sink.add(MintQuote {
                                id: quote.id.clone(),
                                request: quote.request.clone(),
                                amount: quote.amount.map(|a| a.into()),
                                expiry: Some(quote.expiry),
                                state: CdkMintQuoteState::Paid.into(),
                                token: None,
                                error: None,
                            });
                            match _self.inner.mint(&quote.id, SplitTarget::None, None).await {
                                Ok(mint_proofs) => {
                                    let mint_amount =
                                        mint_proofs.total_amount().unwrap_or_default();
                                    let _ = sink.add(MintQuote {
                                        id: quote.id,
                                        request: quote.request,
                                        amount: Some(mint_amount.into()),
                                        expiry: Some(quote.expiry),
                                        state: CdkMintQuoteState::Issued.into(),
                                        token: Token::try_from(CdkToken::new(
                                            mint_url,
                                            mint_proofs,
                                            None,
                                            unit,
                                        ))
                                        .ok(),
                                        error: None,
                                    });
                                    _self.update_balance_streams().await;
                                    break;
                                }
                                Err(e) => {
                                    let _ = sink.add(MintQuote {
                                        id: quote.id,
                                        request: quote.request,
                                        amount: quote.amount.map(|a| a.into()),
                                        expiry: Some(quote.expiry),
                                        state: MintQuoteState::Error,
                                        token: None,
                                        error: Some(e.to_string()),
                                    });
                                    break;
                                }
                            }
                        }
                    },
                    Err(e) => {
                        let _ = sink.add(MintQuote {
                            id: quote.id,
                            request: quote.request,
                            amount: quote.amount.map(|a| a.into()),
                            expiry: Some(quote.expiry),
                            state: MintQuoteState::Error,
                            token: None,
                            error: Some(e.to_string()),
                        });
                        break;
                    }
                }
            }
        });
        Ok(())
    }

    #[tracing::instrument(skip(self, request))]
    pub async fn prepare_pay_request(
        &self,
        request: PaymentRequest,
    ) -> Result<PreparedSend, Error> {
        if !request.validate(self.mint_url()?, self.unit()) {
            return Err(Error::InvalidInput);
        }
        self.prepare_send(request.amount.ok_or(Error::InvalidInput)?, None)
            .await
    }

    #[tracing::instrument(skip(self, send, memo))]
    pub async fn pay_request(
        &self,
        send: PreparedSend,
        memo: Option<String>,
        include_memo: Option<bool>,
    ) -> Result<(), Error> {
        let pay_request = send.pay_request.clone().ok_or(Error::InvalidInput)?;
        if !pay_request.validate(self.mint_url()?, self.unit()) {
            return Err(Error::InvalidInput);
        }
        let token = self.send(send, memo.clone(), include_memo).await?;

        let transports = pay_request.transports.ok_or(Error::InvalidInput)?;
        let transport = transports.first().ok_or(Error::InvalidInput)?;

        let mint_keysets = self.inner.get_mint_keysets().await?;
        let payload = PaymentRequestPayload {
            id: pay_request.payment_id,
            memo,
            mint: self.mint_url()?,
            unit: self.unit(),
            proofs: token.proofs(&mint_keysets)?,
        };

        match transport._type {
            TransportType::Nostr => {
                let profile = Nip19Profile::from_bech32(&transport.target)
                    .map_err(|_| Error::InvalidInput)?;
                // Use first 32 bytes of seed for Nostr secret key
                let client = nostr_sdk::Client::new(Keys::new(nostr::SecretKey::from_slice(
                    &self.seed[..32],
                )?));
                for relay in profile.relays {
                    client.add_relay(relay).await?;
                }
                client
                    .send_private_msg(profile.public_key, serde_json::to_string(&payload)?, vec![])
                    .await?;
                Ok(())
            }
            TransportType::HttpPost => {
                let client = reqwest::Client::new();
                let res = client.post(&transport.target).json(&payload).send().await?;

                let status = res.status();
                if status.is_success() {
                    Ok(())
                } else {
                    Err(Error::Reqwest(format!("HTTP error: {}", status)))
                }
            }
            TransportType::InBand => {
                // InBand transport means the payment is handled in-band (directly)
                // and doesn't require external transport
                Ok(())
            }
        }
    }

    #[tracing::instrument(skip(self, token, opts))]
    pub async fn receive(&self, token: Token, opts: Option<ReceiveOptions>) -> Result<u64, Error> {
        let amount = self
            .inner
            .receive(&token.encoded, opts.unwrap_or_default().try_into()?)
            .await?
            .into();
        self.update_balance_streams().await;
        Ok(amount)
    }

    #[tracing::instrument(skip(self))]
    pub async fn restore(&self) -> Result<(), Error> {
        self.inner.restore().await?;
        self.update_balance_streams().await;
        Ok(())
    }

    #[tracing::instrument(skip(self, opts))]
    pub async fn prepare_send(
        &self,
        amount: u64,
        opts: Option<SendOptions>,
    ) -> Result<PreparedSend, Error> {
        let prepared_send = self
            .inner
            .prepare_send(amount.into(), opts.unwrap_or_default().try_into()?)
            .await?;
        Ok(prepared_send.into())
    }

    #[tracing::instrument(skip(self, send, memo))]
    pub async fn send(
        &self,
        send: PreparedSend,
        memo: Option<String>,
        include_memo: Option<bool>,
    ) -> Result<Token, Error> {
        let send_memo = memo.map(|m| SendMemo {
            memo: m,
            include_memo: include_memo.unwrap_or_default(),
        });
        let token = send.inner.confirm(send_memo).await?.to_string();
        self.update_balance_streams().await;
        Ok(Token::from_str(&token)?)
    }

    #[tracing::instrument(skip(self, send))]
    pub async fn cancel_send(&self, send: PreparedSend) -> Result<(), Error> {
        send.inner.cancel().await?;
        Ok(())
    }

    #[tracing::instrument(skip(self))]
    pub async fn reclaim_reserved(&self) -> Result<(), Error> {
        let proofs = self.inner.get_reserved_proofs().await?;
        if proofs.is_empty() {
            return Ok(());
        }
        self.inner.reclaim_unspent(proofs).await?;
        self.inner.check_all_pending_proofs().await?;
        self.update_balance_streams().await;
        Ok(())
    }

    #[tracing::instrument(skip(self, token))]
    pub async fn reclaim_send(&self, token: Token) -> Result<(), Error> {
        let mint_keysets = self.inner.get_mint_keysets().await?;
        self.inner
            .reclaim_unspent(token.proofs(&mint_keysets)?)
            .await?;
        self.inner.check_all_pending_proofs().await?;
        self.update_balance_streams().await;
        Ok(())
    }

    #[tracing::instrument(skip(self))]
    pub async fn revert_transaction(&self, transaction_id: String) -> Result<(), Error> {
        let id = TransactionId::from_str(&transaction_id)?;
        self.inner.revert_transaction(id).await?;
        self.update_balance_streams().await;
        Ok(())
    }

    fn mint_url(&self) -> Result<MintUrl, Error> {
        Ok(MintUrl::from_str(&self.mint_url)?)
    }

    fn unit(&self) -> CurrencyUnit {
        CurrencyUnit::from_str(&self.unit).unwrap_or(CurrencyUnit::Custom(self.unit.clone()))
    }

    async fn update_balance_streams(&self) {
        let balance = self
            .inner
            .total_balance()
            .await
            .unwrap_or(Amount::ZERO)
            .into();
        let _ = self.balance_broadcast.send(balance);
    }

    /// Get unspent authentication proofs for protected mint endpoints
    #[tracing::instrument(skip(self))]
    pub async fn get_unspent_auth_proofs(&self) -> Result<Vec<AuthProof>, Error> {
        let auth_proofs = self.inner.get_unspent_auth_proofs().await?;
        Ok(auth_proofs.into_iter().map(Into::into).collect())
    }

    /// Fetch mint info from the mint server
    ///
    /// This always makes a network call to fetch fresh mint info.
    #[tracing::instrument(skip(self))]
    pub async fn fetch_mint_info(&self) -> Result<Option<Mint>, Error> {
        let mint_info = self.inner.fetch_mint_info().await?;
        Ok(Some(Mint {
            url: self.mint_url.clone(),
            balance: None,
            info: mint_info.map(|info| info.into()),
        }))
    }
}

#[derive(Debug)]
pub struct MeltOptions {
    pub mpp: Option<u64>,
    pub amountless_msat: Option<u64>,
}

impl TryInto<CdkMeltOptions> for MeltOptions {
    type Error = Error;

    fn try_into(self) -> Result<CdkMeltOptions, Self::Error> {
        if let Some(mpp) = self.mpp {
            return Ok(CdkMeltOptions::Mpp {
                mpp: Mpp { amount: mpp.into() },
            });
        }
        if let Some(amountless_msat) = self.amountless_msat {
            return Ok(CdkMeltOptions::Amountless {
                amountless: Amountless {
                    amount_msat: amountless_msat.into(),
                },
            });
        }
        Err(Error::InvalidInput)
    }
}

pub struct MeltQuote {
    pub id: String,
    pub request: String,
    pub amount: u64,
    pub fee_reserve: u64,
    pub expiry: u64,
}

impl From<CdkMeltQuote> for MeltQuote {
    fn from(quote: CdkMeltQuote) -> Self {
        Self {
            id: quote.id,
            request: quote.request,
            amount: quote.amount.into(),
            fee_reserve: quote.fee_reserve.into(),
            expiry: quote.expiry,
        }
    }
}

pub struct MintQuote {
    pub id: String,
    pub request: String,
    pub amount: Option<u64>,
    pub expiry: Option<u64>,
    pub state: MintQuoteState,
    pub token: Option<Token>,
    pub error: Option<String>,
}

impl From<CdkMintQuote> for MintQuote {
    fn from(quote: CdkMintQuote) -> Self {
        Self {
            id: quote.id,
            request: quote.request,
            amount: quote.amount.map(|a| a.into()),
            expiry: Some(quote.expiry),
            state: quote.state.into(),
            token: None,
            error: None,
        }
    }
}

pub enum MintQuoteState {
    Unpaid,
    Paid,
    Issued,
    Error,
}

impl From<CdkMintQuoteState> for MintQuoteState {
    fn from(state: CdkMintQuoteState) -> Self {
        match state {
            CdkMintQuoteState::Unpaid => Self::Unpaid,
            CdkMintQuoteState::Paid => Self::Paid,
            CdkMintQuoteState::Issued => Self::Issued,
        }
    }
}

pub struct PreparedSend {
    pub amount: u64,
    pub swap_fee: u64,
    pub send_fee: u64,
    pub fee: u64,

    inner: CdkPreparedSend,
    pay_request: Option<PaymentRequest>,
}

impl From<CdkPreparedSend> for PreparedSend {
    fn from(prepared_send: CdkPreparedSend) -> Self {
        Self {
            amount: prepared_send.amount().into(),
            swap_fee: prepared_send.swap_fee().into(),
            send_fee: prepared_send.send_fee().into(),
            fee: prepared_send.fee().into(),
            inner: prepared_send,
            pay_request: None,
        }
    }
}

#[derive(Default)]
pub struct ReceiveOptions {
    pub signing_keys: Option<Vec<String>>,
    pub preimages: Option<Vec<String>>,
    pub metdata: Option<HashMap<String, String>>,
}

impl TryInto<CdkReceiveOptions> for ReceiveOptions {
    type Error = Error;

    fn try_into(self) -> Result<CdkReceiveOptions, Self::Error> {
        let p2pk_signing_keys = self
            .signing_keys
            .unwrap_or_default()
            .into_iter()
            .map(|s| SecretKey::from_str(&s))
            .collect::<Result<Vec<_>, _>>()?;
        Ok(CdkReceiveOptions {
            p2pk_signing_keys,
            preimages: self.preimages.unwrap_or_default(),
            metadata: self.metdata.unwrap_or_default(),
            ..Default::default()
        })
    }
}

#[derive(Default)]
pub struct SendOptions {
    pub memo: Option<String>,
    pub include_memo: Option<bool>,
    pub pubkey: Option<String>,
    pub metadata: Option<HashMap<String, String>>,
}

impl TryInto<CdkSendOptions> for SendOptions {
    type Error = Error;

    fn try_into(self) -> Result<CdkSendOptions, Self::Error> {
        let pubkey = self.pubkey.map(|s| PublicKey::from_str(&s)).transpose()?;
        let send_memo = self.memo.map(|m| SendMemo {
            memo: m,
            include_memo: self.include_memo.unwrap_or_default(),
        });
        Ok(CdkSendOptions {
            memo: send_memo,
            conditions: pubkey.map(|pubkey| SpendingConditions::new_p2pk(pubkey, None)),
            metadata: self.metadata.unwrap_or_default(),
            ..Default::default()
        })
    }
}

#[derive(PartialEq, Eq)]
pub struct Transaction {
    pub id: String,
    pub mint_url: String,
    pub direction: TransactionDirection,
    pub amount: u64,
    pub fee: u64,
    pub unit: String,
    pub ys: Vec<String>,
    pub timestamp: u64,
    pub memo: Option<String>,
    pub metadata: HashMap<String, String>,
    pub status: TransactionStatus,
}

impl From<CdkTransaction> for Transaction {
    fn from(tx: CdkTransaction) -> Self {
        Self {
            id: tx.id().to_string(),
            mint_url: tx.mint_url.to_string(),
            direction: tx.direction.into(),
            amount: tx.amount.into(),
            fee: tx.fee.into(),
            unit: tx.unit.to_string(),
            ys: tx.ys.iter().map(|y| y.to_string()).collect(),
            timestamp: tx.timestamp,
            memo: tx.memo,
            metadata: tx.metadata,
            status: TransactionStatus::Settled,
        }
    }
}

impl PartialOrd for Transaction {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for Transaction {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.timestamp.cmp(&other.timestamp).reverse()
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TransactionDirection {
    Incoming,
    Outgoing,
}

impl From<CdkTransactionDirection> for TransactionDirection {
    fn from(direction: CdkTransactionDirection) -> Self {
        match direction {
            CdkTransactionDirection::Incoming => Self::Incoming,
            CdkTransactionDirection::Outgoing => Self::Outgoing,
        }
    }
}

impl Into<CdkTransactionDirection> for TransactionDirection {
    fn into(self) -> CdkTransactionDirection {
        match self {
            Self::Incoming => CdkTransactionDirection::Incoming,
            Self::Outgoing => CdkTransactionDirection::Outgoing,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransactionStatus {
    Pending,
    Settled,
}

#[derive(Clone)]
pub struct MultiMintWallet {
    pub unit: String,

    mnemonic: String,
    target_proof_count: Option<usize>,
    db: WalletDatabase,

    wallets: Arc<Mutex<HashMap<MintUrl, Wallet>>>,
    added_wallets: Arc<Mutex<Vec<mpsc::Sender<MintUrl>>>>,
}

impl MultiMintWallet {
    /// Create a new multi-mint wallet from a BIP39 mnemonic
    pub async fn new(
        unit: String,
        mnemonic: String,
        target_proof_count: Option<usize>,
        db: &WalletDatabase,
    ) -> Result<Self, Error> {
        println!("MultiMintWallet::new called");
        // Validate mnemonic
        Mnemonic::parse(&mnemonic).map_err(|_| Error::InvalidInput)?;
        println!("Mnemonic parsed successfully");

        let mints = db.inner.get_mints().await?;
        println!("Retrieved {} mints from DB", mints.len());

        let mut wallets = HashMap::new();
        for (mint_url, _) in &mints {
            println!("Initializing wallet for mint: {}", mint_url);
            wallets.insert(
                mint_url.clone(),
                Wallet::new(
                    mint_url.to_string(),
                    unit.clone(),
                    mnemonic.clone(),
                    target_proof_count,
                    db,
                )?,
            );
        }
        println!("All wallets initialized");
        Ok(Self {
            unit: unit.to_string(),
            mnemonic,
            target_proof_count,
            db: db.clone(),
            wallets: Arc::new(Mutex::new(wallets)),
            added_wallets: Arc::new(Mutex::new(Vec::new())),
        })
    }

    #[tracing::instrument(skip(self))]
    pub async fn add_mint(&self, mint_url: String) -> Result<(), Error> {
        let mint_url = MintUrl::from_str(&mint_url)?;
        let mut wallets = self.wallets.lock().await;
        if wallets.contains_key(&mint_url) {
            return Ok(());
        }

        let wallet = Wallet::new(
            mint_url.to_string(),
            self.unit.clone(),
            self.mnemonic.clone(),
            self.target_proof_count,
            &self.db,
        )?;
        wallets.insert(mint_url.clone(), wallet);
        let mut added_wallets = self.added_wallets.lock().await;
        let mut failed_senders = Vec::new();
        for (idx, sender) in added_wallets.iter().enumerate() {
            if sender.send(mint_url.clone()).await.is_err() {
                failed_senders.push(idx);
            }
        }
        for sender in failed_senders {
            added_wallets.remove(sender);
        }
        Ok(())
    }

    #[tracing::instrument(skip(self, wallet))]
    pub async fn add_wallet(&self, wallet: Wallet) -> Result<(), Error> {
        self.wallets
            .lock()
            .await
            .insert(MintUrl::from_str(&wallet.mint_url)?, wallet);
        Ok(())
    }

    #[tracing::instrument(skip(self))]
    pub async fn available_mints(
        &self,
        amount: Option<u64>,
        mint_urls: Option<Vec<String>>,
    ) -> Result<Vec<Mint>, Error> {
        let all_mint_urls = self
            .list_mints()
            .await?
            .into_iter()
            .map(|m| m.url)
            .collect();
        let mint_urls = mint_urls.unwrap_or(all_mint_urls);
        let wallets = self.wallets.lock().await;
        let mut mints = Vec::new();
        for mint_url in mint_urls {
            let mint_url = MintUrl::from_str(&mint_url)?;
            if let Some(wallet) = wallets.get(&mint_url) {
                let mint = wallet.get_mint().await?;
                if mint.balance.unwrap_or_default() >= amount.unwrap_or_default() {
                    mints.push(mint);
                }
            }
        }
        mints.sort();
        Ok(mints)
    }

    #[tracing::instrument(skip(self))]
    pub async fn create_or_get_wallet(&self, mint_url: String) -> Result<Wallet, Error> {
        let mint_url = MintUrl::from_str(&mint_url)?;
        let mut wallets = self.wallets.lock().await;
        if let Some(wallet) = wallets.get(&mint_url) {
            return Ok(wallet.clone());
        }
        let wallet = Wallet::new(
            mint_url.to_string(),
            self.unit.clone(),
            self.mnemonic.clone(),
            self.target_proof_count,
            &self.db,
        )?;
        wallets.insert(mint_url, wallet.clone());
        Ok(wallet)
    }

    #[tracing::instrument(skip(self))]
    pub async fn get_active_mint_quotes(
        &self,
        mint_url: Option<String>,
    ) -> Result<Vec<MintQuote>, Error> {
        let mint_url = mint_url.map(|s| MintUrl::from_str(&s)).transpose()?;
        let wallets = self.wallets.lock().await;
        match mint_url {
            Some(mint_url) => {
                if let Some(wallet) = wallets.get(&mint_url) {
                    return Ok(wallet.get_active_mint_quotes().await?);
                }
                Err(Error::WalletNotFound(mint_url.to_string()))
            }
            None => {
                let mut all_quotes = Vec::new();
                for wallet in wallets.values() {
                    let quotes = wallet.get_active_mint_quotes().await?;
                    all_quotes.extend(quotes);
                }
                Ok(all_quotes)
            }
        }
    }

    #[tracing::instrument(skip(self))]
    pub async fn get_wallet(&self, mint_url: &str) -> Result<Option<Wallet>, Error> {
        let mint_url = MintUrl::from_str(mint_url)?;
        let wallets = self.wallets.lock().await;
        if let Some(wallet) = wallets.get(&mint_url) {
            return Ok(Some(wallet.clone()));
        }
        Ok(None)
    }

    #[tracing::instrument(skip(self))]
    pub async fn list_mints(&self) -> Result<Vec<Mint>, Error> {
        let wallets_guard = self.wallets.lock().await;
        let wallets = wallets_guard.values();
        let mut mints = Vec::new();
        for wallet in wallets {
            let mint = wallet.get_mint().await?;
            mints.push(mint);
        }
        mints.sort();
        Ok(mints)
    }

    #[tracing::instrument(skip(self))]
    pub async fn list_transactions(
        &self,
        direction: Option<TransactionDirection>,
        mint_url: Option<String>,
    ) -> Result<Vec<Transaction>, Error> {
        let wallets = self.wallets.lock().await;
        let mut transactions = Vec::new();

        if let Some(mint_url) = mint_url {
            let mint_url = MintUrl::from_str(&mint_url)?;
            if let Some(wallet) = wallets.get(&mint_url) {
                let wallet_transactions = wallet.list_transactions(direction).await?;
                transactions.extend(wallet_transactions);
            }
            transactions.sort();
            return Ok(transactions);
        }

        for wallet in wallets.values() {
            let wallet_transactions = wallet.list_transactions(direction).await?;
            transactions.extend(wallet_transactions);
        }
        transactions.sort();
        Ok(transactions)
    }

    #[tracing::instrument(skip(self))]
    pub async fn list_wallets(&self) -> Vec<Wallet> {
        self.wallets.lock().await.values().cloned().collect()
    }

    #[tracing::instrument(skip(self))]
    pub async fn reclaim_reserved(&self) -> Result<(), Error> {
        let wallets = self.wallets.lock().await;
        for wallet in wallets.values() {
            wallet.reclaim_reserved().await?;
        }
        Ok(())
    }

    #[tracing::instrument(skip(self))]
    pub async fn remove_mint(&self, mint_url: String) -> Result<(), Error> {
        let mint_url = MintUrl::from_str(&mint_url)?;
        let mut wallets = self.wallets.lock().await;
        if let Some(wallet) = wallets.get(&mint_url) {
            if wallet.balance().await? > 0 {
                return Err(Error::WalletNotEmpty);
            }
        }
        wallets.remove(&mint_url);
        Ok(())
    }

    #[tracing::instrument(skip(self))]
    pub async fn select_wallet(
        &self,
        amount: Option<u64>,
        mint_urls: Option<Vec<String>>,
    ) -> Result<Option<Wallet>, Error> {
        let mints = self.available_mints(amount, mint_urls).await?;
        if let Some(mint) = mints.first() {
            return self.get_wallet(&mint.url).await;
        }
        Ok(None)
    }

    #[tracing::instrument(skip(self))]
    pub async fn total_balance(&self) -> Result<u64, Error> {
        let wallets = self.wallets.lock().await;
        let mut total = 0;
        for wallet in wallets.values() {
            total += wallet.balance().await?;
        }
        Ok(total)
    }

    #[tracing::instrument(skip(self, sink))]
    pub async fn stream_balance(&self, sink: StreamSink<u64>) -> Result<(), Error> {
        let _ = sink.add(self.total_balance().await?);
        let wallets = self.wallets.lock().await;
        for wallet in wallets.values() {
            let wallet = wallet.clone();
            let sink = sink.clone();
            let _self = self.clone();
            flutter_rust_bridge::spawn(async move {
                let mut rx = wallet.balance_broadcast.subscribe();
                loop {
                    match rx.recv().await {
                        Ok(_) => {
                            let total = _self.total_balance().await.unwrap_or_default();
                            if sink.add(total).is_err() {
                                break;
                            }
                        }
                        Err(_) => break,
                    }
                }
            });
        }
        let (tx, mut rx) = mpsc::channel(1);
        self.added_wallets.lock().await.push(tx);
        let _self = self.clone();
        flutter_rust_bridge::spawn(async move {
            loop {
                match rx.recv().await {
                    Some(mint_url) => {
                        let wallet = match _self.create_or_get_wallet(mint_url.to_string()).await {
                            Ok(wallet) => wallet,
                            Err(_) => continue,
                        };
                        let sink = sink.clone();
                        let _self = _self.clone();
                        flutter_rust_bridge::spawn(async move {
                            let mut rx = wallet.balance_broadcast.subscribe();
                            loop {
                                match rx.recv().await {
                                    Ok(_) => {
                                        let total = _self.total_balance().await.unwrap_or_default();
                                        if sink.add(total).is_err() {
                                            break;
                                        }
                                    }
                                    Err(_) => break,
                                }
                            }
                        });
                    }
                    None => break,
                }
            }
        });
        Ok(())
    }

    /// Set the Clear Auth Token (CAT) for a specific mint
    ///
    /// The CAT is an OIDC/JWT token from the authentication provider (e.g., Keycloak)
    /// that is required for minting blind auth tokens.
    #[tracing::instrument(skip(self, cat))]
    pub async fn set_cat(&self, mint_url: String, cat: String) -> Result<(), Error> {
        let mint_url = MintUrl::from_str(&mint_url)?;
        let wallets = self.wallets.lock().await;
        let wallet = wallets.get(&mint_url).ok_or(Error::WalletNotFound(mint_url.to_string()))?;
        wallet.inner.set_cat(cat).await?;
        Ok(())
    }

    /// Set the refresh token for a specific mint
    ///
    /// The refresh token is used to obtain new CATs when they expire.
    #[tracing::instrument(skip(self, refresh_token))]
    pub async fn set_refresh_token(&self, mint_url: String, refresh_token: String) -> Result<(), Error> {
        let mint_url = MintUrl::from_str(&mint_url)?;
        let wallets = self.wallets.lock().await;
        let wallet = wallets.get(&mint_url).ok_or(Error::WalletNotFound(mint_url.to_string()))?;
        wallet.inner.set_refresh_token(refresh_token).await?;
        Ok(())
    }

    /// Refresh the access token using the stored refresh token
    #[tracing::instrument(skip(self))]
    pub async fn refresh_access_token(&self, mint_url: String) -> Result<(), Error> {
        let mint_url = MintUrl::from_str(&mint_url)?;
        let wallets = self.wallets.lock().await;
        let wallet = wallets.get(&mint_url).ok_or(Error::WalletNotFound(mint_url.to_string()))?;
        wallet.inner.refresh_access_token().await?;
        Ok(())
    }

    /// Mint blind auth tokens for a specific mint
    ///
    /// Blind auth tokens are required for protected mint operations.
    /// A Clear Auth Token (CAT) must be set before calling this method.
    ///
    /// # Arguments
    /// * `mint_url` - The mint URL to mint blind auth tokens from
    /// * `amount` - The number of blind auth tokens to mint
    ///
    /// # Returns
    /// A vector of AuthProof that can be used for authenticated operations
    #[tracing::instrument(skip(self))]
    pub async fn mint_blind_auth(&self, mint_url: String, amount: u64) -> Result<Vec<AuthProof>, Error> {
        let mint_url = MintUrl::from_str(&mint_url)?;
        let wallets = self.wallets.lock().await;
        let wallet = wallets.get(&mint_url).ok_or(Error::WalletNotFound(mint_url.to_string()))?;
        let proofs = wallet.inner.mint_blind_auth(Amount::from(amount)).await?;
        
        // Convert the proofs to AuthProof structs
        let auth_proofs: Vec<AuthProof> = proofs
            .iter()
            .filter_map(|p| {
                // Create AuthProof from Proof
                Some(AuthProof {
                    keyset_id: p.keyset_id.to_string(),
                    secret: p.secret.to_string(),
                    c: p.c.to_string(),
                    y: p.y().map(|y| y.to_string()).unwrap_or_default(),
                })
            })
            .collect();
        
        Ok(auth_proofs)
    }

    /// Get unspent authentication proofs for a specific mint
    #[tracing::instrument(skip(self))]
    pub async fn get_unspent_auth_proofs(&self, mint_url: String) -> Result<Vec<AuthProof>, Error> {
        let mint_url = MintUrl::from_str(&mint_url)?;
        let wallets = self.wallets.lock().await;
        let wallet = wallets.get(&mint_url).ok_or(Error::WalletNotFound(mint_url.to_string()))?;
        let auth_proofs = wallet.inner.get_unspent_auth_proofs().await?;
        Ok(auth_proofs.into_iter().map(Into::into).collect())
    }
}

/// Unified wallet database supporting both SQLite and Supabase backends
#[derive(Clone)]
pub struct WalletDatabase {
    /// Path for SQLite database (None for Supabase)
    pub path: Option<String>,
    /// URL for Supabase database (None for SQLite)
    pub url: Option<String>,
    /// The type of database backend being used
    pub backend_type: DatabaseType,

    inner: Arc<dyn cdk::cdk_database::WalletDatabase<cdk::cdk_database::Error> + Send + Sync>,
}

impl WalletDatabase {
    /// Create a new SQLite database (backwards compatible)
    pub async fn new(path: &str) -> Result<Self, Error> {
        let sqlite_db = WalletSqliteDatabase::new(path).await?;
        Ok(Self {
            path: Some(path.to_string()),
            url: None,
            backend_type: DatabaseType::Sqlite,
            inner: Arc::new(sqlite_db),
        })
    }

    /// Create a new Supabase database
    pub async fn new_supabase(url: String, api_key: String) -> Result<Self, Error> {
        let parsed_url = Url::parse(&url).map_err(|e| Error::Url(e.to_string()))?;
        let supabase_db = SupabaseWalletDatabase::new(parsed_url, api_key);
        Ok(Self {
            path: None,
            url: Some(url),
            backend_type: DatabaseType::Supabase,
            inner: Arc::new(supabase_db),
        })
    }

    /// Create a new Supabase database with separate API key and JWT token
    ///
    /// - `api_key`: The Supabase project API key (used in `apikey` header)
    /// - `jwt_token`: Optional JWT token for user authentication (used in `Authorization: Bearer` header)
    ///
    /// Use this method when you need to authenticate with Keycloak or another OIDC provider
    /// while still using Supabase for data storage.
    pub async fn new_supabase_with_jwt(
        url: String,
        api_key: String,
        jwt_token: Option<String>,
    ) -> Result<Self, Error> {
        let parsed_url = Url::parse(&url).map_err(|e| Error::Url(e.to_string()))?;
        let supabase_db = SupabaseWalletDatabase::with_jwt(parsed_url, api_key, jwt_token);
        Ok(Self {
            path: None,
            url: Some(url),
            backend_type: DatabaseType::Supabase,
            inner: Arc::new(supabase_db),
        })
    }

    /// Check if this is a SQLite database
    #[frb(sync)]
    pub fn is_sqlite(&self) -> bool {
        matches!(self.backend_type, DatabaseType::Sqlite)
    }

    /// Check if this is a Supabase database
    #[frb(sync)]
    pub fn is_supabase(&self) -> bool {
        matches!(self.backend_type, DatabaseType::Supabase)
    }

    #[tracing::instrument(skip(self, mnemonic))]
    pub async fn list_mints(
        &self,
        unit: Option<String>,
        mnemonic: Option<String>,
    ) -> Result<Vec<Mint>, Error> {
        let mut mints = Vec::new();
        let mint_infos = self.inner.get_mints().await?;
        for (mint_url, mint_info) in mint_infos {
            let mut balance = None;
            if let Some(unit) = &unit {
                if let Some(mnemonic) = &mnemonic {
                    let wallet = Wallet::new(
                        mint_url.to_string(),
                        unit.clone(),
                        mnemonic.clone(),
                        None,
                        self,
                    )?;
                    balance = wallet.balance().await.ok();
                }
            }
            let mint = Mint {
                url: mint_url.to_string(),
                balance,
                info: mint_info.map(|info| info.into()),
            };
            mints.push(mint);
        }
        mints.sort();
        Ok(mints)
    }

    #[tracing::instrument(skip(self))]
    pub async fn remove_mint(&self, mint_url: &str) -> Result<(), Error> {
        let mint_url = MintUrl::from_str(mint_url)?;
        self.inner.remove_mint(mint_url).await?;
        Ok(())
    }
}

#[frb(sync)]
pub fn parse_input(input: String) -> Result<ParseInputResult, Error> {
    let input = input.trim();
    if let Ok(req) = PaymentRequest::from_str(input) {
        return Ok(ParseInputResult::PaymentRequest(req));
    }
    if let Ok(token) = Token::from_str(input) {
        return Ok(ParseInputResult::Token(token));
    }
    if let Ok(invoice) = Bolt11Invoice::from_str(input) {
        return Ok(ParseInputResult::Bolt11Invoice(invoice));
    }
    if let Ok(addr) = BitcoinAddress::from_str(input) {
        return Ok(ParseInputResult::BitcoinAddress(addr));
    }
    Err(Error::InvalidInput)
}

pub enum ParseInputResult {
    BitcoinAddress(BitcoinAddress),
    Bolt11Invoice(Bolt11Invoice),
    PaymentRequest(PaymentRequest),
    Token(Token),
}
