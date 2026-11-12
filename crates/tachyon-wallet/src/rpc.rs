//! Direct, bounded Zakura JSON-RPC. This wallet does not use lightwalletd.

use anyhow::{Context, Result, bail, ensure};
use oss_core::{
    BlockParams, ErrorCode, InfoParams, InfoResult, MAX_TACHYGRAM_VALUES, NotReadyData, SpentData,
    TachygramsParams, TachygramsResult,
};
use reqwest::{Client, Url};
use serde::{Serialize, de::DeserializeOwned};
use serde_json::{Value, json};
use std::{
    path::PathBuf,
    time::{Duration, Instant},
};

use crate::{chain::Block, control::Control};

#[derive(Debug)]
pub(crate) struct RpcError {
    pub code: Option<i64>,
    method: String,
    error: Value,
}
impl std::fmt::Display for RpcError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}: RPC error {}", self.method, self.error)
    }
}
impl std::error::Error for RpcError {}

pub struct Rpc {
    client: Client,
    url: Url,
    cookie: Option<PathBuf>,
    max_body: usize,
    timeout: Duration,
    runtime: Option<tokio::runtime::Runtime>,
    pub(crate) control: Control,
}

impl Drop for Rpc {
    fn drop(&mut self) {
        if let Some(runtime) = self.runtime.take() {
            // An OS DNS lookup can outlive a cancelled request. It owns no wallet
            // state, and must not make runtime teardown block cancellation.
            runtime.shutdown_background();
        }
    }
}

impl Rpc {
    pub fn new(url: &str, cookie: Option<PathBuf>, control: &Control) -> Result<Self> {
        Self::with_limits(url, cookie, control, 16 << 20, Duration::from_secs(30))
    }

    fn with_limits(
        url: &str,
        cookie: Option<PathBuf>,
        control: &Control,
        max_body: usize,
        timeout: Duration,
    ) -> Result<Self> {
        control.check()?;
        let url = Url::parse(url)?;
        ensure!(
            matches!(url.scheme(), "http" | "https")
                && url.username().is_empty()
                && url.password().is_none(),
            "use an HTTP(S) RPC URL without embedded credentials; use --cookie-file for authentication"
        );
        Ok(Self {
            client: Client::builder()
                .connect_timeout(Duration::from_secs(10))
                .timeout(timeout)
                .redirect(reqwest::redirect::Policy::none())
                .build()?,
            url,
            cookie,
            max_body,
            timeout,
            // The wallet/proof code stays synchronous on its blocking worker,
            // but HTTP waits are futures that can actually be cancelled.
            runtime: Some(
                tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()?,
            ),
            control: control.clone(),
        })
    }

    pub fn call<T: DeserializeOwned>(&self, method: &str, params: Value) -> Result<T> {
        let started = std::time::Instant::now();
        let mut bytes_read = 0u64;
        let result = self.call_inner(method, params, &mut bytes_read);
        self.control
            .record_rpc(method, started.elapsed(), bytes_read);
        result
    }

    fn call_inner<T: DeserializeOwned>(
        &self,
        method: &str,
        params: Value,
        bytes_read: &mut u64,
    ) -> Result<T> {
        // Never log params: they can include addresses, raw payments or secrets.
        self.control.stage(format!("Requesting {method}…"))?;
        let mut request = self
            .client
            .post(self.url.clone())
            .json(&json!({"jsonrpc":"2.0","id":1,"method":method,"params":params}));
        if let Some(path) = &self.cookie {
            let cookie = std::fs::read_to_string(path).context("cannot read RPC cookie")?;
            let (user, password) = cookie
                .trim()
                .split_once(':')
                .context("invalid RPC cookie")?;
            request = request.basic_auth(user, Some(password));
        }
        let (status, bytes) = self.runtime.as_ref().expect("runtime exists until the RPC client drops").block_on(async {
            tokio::select! {
                biased;
                _ = self.control.cancellation.cancelled() => {
                    self.control.check()?;
                    unreachable!("the cancellation token was triggered")
                }
                result = async {
                    let mut response = request.send().await.map_err(reqwest::Error::without_url)
                        .with_context(|| format!("{method}: transport failed (10s connection / {}s request timeout)", self.timeout.as_secs()))?;
                    let status = response.status();
                    let mut bytes = Vec::new();
                    while let Some(chunk) = response.chunk().await.map_err(reqwest::Error::without_url)
                        .with_context(|| format!("{method}: reading response failed"))? {
                        ensure!(chunk.len() <= self.max_body.saturating_sub(bytes.len()),
                            "{method}: RPC response exceeds {} MiB", self.max_body >> 20);
                        bytes.extend_from_slice(&chunk);
                    }
                    Ok::<_, anyhow::Error>((status, bytes))
                } => result,
            }
        })?;
        self.control.check()?;
        *bytes_read = u64::try_from(bytes.len()).unwrap_or(u64::MAX);
        let envelope: Value = serde_json::from_slice(&bytes).context("invalid RPC JSON")?;
        if !envelope["error"].is_null() {
            return Err(RpcError {
                code: envelope["error"]["code"].as_i64(),
                method: method.into(),
                error: envelope["error"].clone(),
            }
            .into());
        }
        ensure!(status.is_success(), "{method}: HTTP {status}");
        ensure!(envelope["id"] == 1, "RPC response ID mismatch");
        Ok(serde_json::from_value(
            envelope
                .get("result")
                .context("missing RPC result")?
                .clone(),
        )?)
    }

    pub fn hash(&self, height: u32) -> Result<String> {
        self.call("getblockhash", json!([height]))
    }
    pub fn height(&self) -> Result<u32> {
        self.call("getblockcount", json!([]))
    }
    /// Sleeps, unless the command is cancelled first.
    fn sleep(&self, duration: Duration) -> Result<()> {
        self.runtime
            .as_ref()
            .expect("runtime exists until the RPC client drops")
            .block_on(async {
                tokio::select! {
                    _ = self.control.cancellation.cancelled() => {}
                    _ = tokio::time::sleep(duration) => {}
                }
            });
        self.control.check()
    }

    pub fn block(&self, height: u32) -> Result<Block> {
        let block: Block = self.call("gettachyonblock", json!([height.to_string()]))?;
        ensure!(block.height == height, "gettachyonblock height mismatch");
        self.with_transactions(block, false)
    }

    /// Fills in the block's transaction list from `getblock`. Zakura has none
    /// for a pruned body, so an `archived` (OSS) block then keeps only the
    /// txids of its stamps.
    // shortcut: transparent-only transactions in pruned blocks never show as
    // mined; have `oss_block` carry every txid if that starts to matter.
    pub fn with_transactions(&self, mut block: Block, archived: bool) -> Result<Block> {
        let ordinary: Value = match self.call("getblock", json!([block.hash, 1])) {
            Err(error) if archived && error.is::<RpcError>() => {
                block.transactions = block.stamps.iter().map(|s| s.txid.clone()).collect();
                return Ok(block);
            }
            result => result?,
        };
        ensure!(ordinary["hash"] == block.hash, "getblock identity mismatch");
        block.transactions = serde_json::from_value(ordinary["tx"].clone())?;
        for stamp in &block.stamps {
            ensure!(
                block.transactions.get(stamp.transaction_index) == Some(&stamp.txid),
                "stamp transaction position mismatch"
            );
        }
        Ok(block)
    }

    pub fn submit(&self, txid: &str, raw: &str) -> Result<()> {
        let accepted: String = self.call("sendrawtransaction", json!([raw])).context(
            "broadcast outcome may be ambiguous; input remains reserved; retry with submit",
        )?;
        ensure!(
            accepted == txid,
            "node returned a different transaction ID; input remains reserved"
        );
        Ok(())
    }
}

/// Whether `error` is an OSS `Unavailable` answer: outside its archive, or no
/// longer canonical.
pub(crate) fn unavailable(error: &anyhow::Error) -> bool {
    error.downcast_ref::<RpcError>().and_then(|e| e.code) == Some(ErrorCode::Unavailable.code())
}

/// The OSS client (design §4.1): an [`Rpc`] with a 64 MiB body cap, which
/// waits out `NotReady` and turns the other OSS errors into clear ones.
pub struct Oss {
    rpc: Rpc,
    /// How long one call waits out `NotReady` in all. Sealing a full epoch
    /// holds the OSS for about 16 s.
    pub(crate) patience: Duration,
    /// Log every request and how long it took (`-v`).
    pub(crate) verbose: bool,
}

impl Oss {
    pub fn new(url: &str, cookie: Option<PathBuf>, control: &Control) -> Result<Self> {
        Ok(Self {
            // An `oss_unspent` call is up to 64 proof steps, maybe queued.
            rpc: Rpc::with_limits(url, cookie, control, 64 << 20, Duration::from_secs(300))?,
            patience: Duration::from_secs(90),
            verbose: false,
        })
    }

    pub fn call<T: DeserializeOwned>(&self, method: &str, params: impl Serialize) -> Result<T> {
        let params = serde_json::to_value(params)?;
        let deadline = Instant::now() + self.patience;
        loop {
            let error = match self.timed(method, params.clone()) {
                Ok(result) => return Ok(result),
                Err(error) => error,
            };
            let Some(RpcError {
                code: Some(code),
                error: body,
                ..
            }) = error.downcast_ref::<RpcError>()
            else {
                return Err(error);
            };
            let data = body["data"].clone();
            match ErrorCode::from_code(*code) {
                Some(ErrorCode::NotReady) => {
                    let NotReadyData {
                        retry_after_ms,
                        reason,
                    } = serde_json::from_value(data)?;
                    let wait = Duration::from_millis(retry_after_ms.clamp(100, 10_000));
                    ensure!(
                        Instant::now() + wait <= deadline,
                        "OSS not ready after {}s ({method}: {reason}); retry later",
                        self.patience.as_secs()
                    );
                    self.rpc.sleep(wait)?;
                }
                Some(ErrorCode::Spent) => {
                    let SpentData {
                        epoch,
                        height,
                        txid,
                    } = serde_json::from_value(data)?;
                    bail!(
                        "note is spent: the OSS has one of its nullifiers in epoch {epoch}, block {height}, transaction {txid}"
                    );
                }
                Some(ErrorCode::Unavailable) => {
                    return Err(error.context(
                        "the OSS cannot serve this: it is outside its archive or no longer canonical",
                    ));
                }
                Some(ErrorCode::InvalidParams) => {
                    return Err(error.context("the OSS rejected the request"));
                }
                None => return Err(error.context("OSS request failed")),
            }
        }
    }

    /// One request, logged with its duration when verbose.
    fn timed<T: DeserializeOwned>(&self, method: &str, params: Value) -> Result<T> {
        let log = |line: String| self.verbose.then(|| self.rpc.control.notice(&line));
        log(format!("contacting OSS ({method})…"));
        let started = Instant::now();
        let result = self.rpc.call(method, params);
        let secs = started.elapsed().as_secs_f64();
        log(match &result {
            Ok(_) => format!("got OSS response ({method}, {secs:.1}s)"),
            Err(_) => format!("OSS request failed ({method}, {secs:.1}s)"),
        });
        result
    }

    /// Waits up to 10 s for the OSS tip to reach the node's (design §4.3).
    /// Returns the first height of its archive and its tip.
    pub fn archive(&self, node_tip: u32, genesis: &str) -> Result<(u32, u32)> {
        let deadline = Instant::now() + Duration::from_secs(10);
        loop {
            let info: InfoResult = self.call("oss_info", InfoParams {})?;
            ensure!(
                info.genesis_hash.eq_ignore_ascii_case(genesis),
                "the OSS follows another chain (genesis {})",
                info.genesis_hash
            );
            if info.tip.height >= node_tip || Instant::now() >= deadline {
                return Ok((info.archive_from_height, info.tip.height));
            }
            self.rpc.sleep(Duration::from_millis(250))?;
        }
    }

    /// The archived `gettachyonblock` JSON, kept after the node prunes it.
    /// `thin` leaves out the tachygrams (thin sync).
    pub fn block(&self, height: u32, thin: bool) -> Result<Block> {
        let block: Block = self.call("oss_block", BlockParams { height, thin })?;
        ensure!(block.height == height, "oss_block height mismatch");
        Ok(block)
    }

    /// Where each value is published in the OSS archive, if anywhere.
    // privacy: the OSS learns every value asked (see the callers' warnings).
    pub fn tachygrams(&self, values: &[String]) -> Result<Vec<Option<u32>>> {
        let mut heights = Vec::with_capacity(values.len());
        for chunk in values.chunks(MAX_TACHYGRAM_VALUES) {
            let TachygramsResult { heights: answer } = self.call(
                "oss_tachygrams",
                TachygramsParams {
                    values: chunk.to_vec(),
                },
            )?;
            ensure!(
                answer.len() == chunk.len(),
                "the OSS answered {} of {} tachygram lookups",
                answer.len(),
                chunk.len()
            );
            heights.extend(answer);
        }
        Ok(heights)
    }
}

#[cfg(test)]
mod tests;
