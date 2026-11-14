//! Direct, bounded Zakura JSON-RPC. This wallet does not use lightwalletd.

use anyhow::{Context, Result, bail, ensure};
use oss_core::{
    BlockParams, BlocksParams, BlocksResult, ErrorCode, InfoParams, InfoResult,
    MAX_TACHYGRAM_VALUES, MAX_TRANSACTION_IDS, NotReadyData, SpentData, TachygramsParams,
    TachygramsResult, TransactionsParams, TransactionsResult,
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
        let request = json!({"jsonrpc":"2.0","id":1,"method":method,"params":params});
        let (status, envelope) = self.post(method, &request, bytes_read)?;
        Ok(serde_json::from_value(answer(
            method, status, envelope, 1,
        )?)?)
    }

    /// `method` once per entry of `params`, in one JSON-RPC batch request.
    /// Each answer is its own result, in order.
    pub fn batch(&self, method: &str, params: Vec<Value>) -> Result<Vec<Result<Value>>> {
        let started = Instant::now();
        let mut bytes_read = 0u64;
        let count = params.len();
        let requests = params
            .into_iter()
            .enumerate()
            .map(|(id, params)| json!({"jsonrpc":"2.0","id":id,"method":method,"params":params}))
            .collect();
        let result = self
            .post(method, &Value::Array(requests), &mut bytes_read)
            .and_then(|(status, answers)| {
                let Value::Array(answers) = answers else {
                    answer(method, status, answers, 0)?; // A rejected batch is one error.
                    bail!("{method}: expected a batch answer");
                };
                ensure!(
                    answers.len() == count,
                    "{method}: {} answers to a batch of {count}",
                    answers.len()
                );
                let mut results: Vec<Option<Result<Value>>> = (0..count).map(|_| None).collect();
                for envelope in answers {
                    let id = envelope["id"]
                        .as_u64()
                        .and_then(|id| usize::try_from(id).ok());
                    let slot = id
                        .and_then(|id| results.get_mut(id))
                        .filter(|slot| slot.is_none())
                        .context("RPC batch answer ID mismatch")?;
                    *slot = Some(answer(
                        method,
                        status,
                        envelope,
                        id.expect("matched a slot"),
                    ));
                }
                Ok(results
                    .into_iter()
                    .map(|r| r.expect("each ID answered once"))
                    .collect())
            });
        self.control
            .record_rpc(method, started.elapsed(), bytes_read);
        result
    }

    /// Sends `body` and parses the JSON answer: cancellable, within the body cap.
    fn post(
        &self,
        method: &str,
        body: &Value,
        bytes_read: &mut u64,
    ) -> Result<(reqwest::StatusCode, Value)> {
        // Never log params: they can include addresses, raw payments or secrets.
        self.control.stage(format!("Requesting {method}…"))?;
        let mut request = self.client.post(self.url.clone()).json(body);
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
        // A proxy in front of the node or OSS answers errors (401, 502) with HTML.
        let answer = serde_json::from_slice(&bytes)
            .with_context(|| format!("{method}: invalid RPC JSON (HTTP {status})"))?;
        Ok((status, answer))
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

    /// The Tachyon block at `height`. Callers check its hash with [`Rpc::hash`].
    pub fn block(&self, height: u32) -> Result<Block> {
        let block: Block = self.call("gettachyonblock", json!([height.to_string()]))?;
        ensure!(block.height == height, "gettachyonblock height mismatch");
        Ok(block)
    }

    /// The node's block hashes at `from..=to`, in one batch.
    pub fn hashes(&self, from: u32, to: u32) -> Result<Vec<String>> {
        let answers = self.batch("getblockhash", (from..=to).map(|h| json!([h])).collect())?;
        answers
            .into_iter()
            .map(|answer| Ok(serde_json::from_value(answer?)?))
            .collect()
    }

    /// The lowest height whose transactions the node still serves, if it
    /// prunes: below it, `getrawtransaction` answers "not found" for mined
    /// transactions too.
    pub fn pruned_below(&self) -> Result<Option<u32>> {
        let info: Value = self.call("getblockchaininfo", json!([]))?;
        Ok((info["pruned"] == true).then(|| {
            info["pruneheight"]
                .as_u64()
                .and_then(|height| u32::try_from(height).ok())
                .unwrap_or(u32::MAX)
        }))
    }

    /// Warns what a request reveals to the node, unless it runs on this machine.
    pub(crate) fn privacy(&self, what: &str) {
        let host = self.url.host_str().unwrap_or_default();
        let local = host == "localhost"
            || host
                .trim_matches(['[', ']'])
                .parse::<std::net::IpAddr>()
                .is_ok_and(|ip| ip.is_loopback());
        if !local {
            self.control.privacy(what);
        }
    }

    /// A client for the same server, for use on another thread.
    pub(crate) fn fork(&self, control: &Control) -> Result<Self> {
        Self::with_limits(
            self.url.as_str(),
            self.cookie.clone(),
            control,
            self.max_body,
            self.timeout,
        )
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

/// One JSON-RPC answer's result, or its error.
fn answer(
    method: &str,
    status: reqwest::StatusCode,
    mut envelope: Value,
    id: usize,
) -> Result<Value> {
    if !envelope["error"].is_null() {
        return Err(RpcError {
            code: envelope["error"]["code"].as_i64(),
            method: method.into(),
            error: envelope["error"].clone(),
        }
        .into());
    }
    ensure!(status.is_success(), "{method}: HTTP {status}");
    ensure!(envelope["id"] == id, "RPC response ID mismatch");
    envelope
        .get_mut("result")
        .map(Value::take)
        .context("missing RPC result")
}

/// Whether `error` is the node's "No such mempool or main chain transaction".
pub(crate) fn not_found(error: &anyhow::Error) -> bool {
    error
        .downcast_ref::<RpcError>()
        .and_then(|error| error.code)
        == Some(-5)
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

    /// Blocks `from..from + count` as [`Oss::block`] serves them, in one
    /// request. The OSS may answer fewer, never none.
    pub fn blocks(&self, from: u32, count: u32, thin: bool) -> Result<Vec<Block>> {
        let BlocksResult { blocks } =
            self.call("oss_blocks", BlocksParams { from, count, thin })?;
        ensure!(
            !blocks.is_empty()
                && blocks.len() <= count as usize
                && blocks
                    .iter()
                    .zip(from..)
                    .all(|(block, h)| block.height == h),
            "oss_blocks answered other heights than {count} from {from}"
        );
        Ok(blocks)
    }

    /// A client for the same OSS, for use on another thread.
    pub(crate) fn fork(&self, control: &Control) -> Result<Self> {
        Ok(Self {
            rpc: self.rpc.fork(control)?,
            patience: self.patience,
            verbose: self.verbose,
        })
    }

    /// The archived height that mined each transaction, if any.
    // privacy: the OSS learns every ID asked (see the callers' warnings).
    pub fn transactions(&self, txids: &[String]) -> Result<Vec<Option<u32>>> {
        let mut heights = Vec::with_capacity(txids.len());
        for chunk in txids.chunks(MAX_TRANSACTION_IDS) {
            let TransactionsResult { heights: answer } = self.call(
                "oss_transactions",
                TransactionsParams {
                    txids: chunk.to_vec(),
                },
            )?;
            ensure!(
                answer.len() == chunk.len(),
                "the OSS answered {} of {} transaction lookups",
                answer.len(),
                chunk.len()
            );
            heights.extend(answer);
        }
        Ok(heights)
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
