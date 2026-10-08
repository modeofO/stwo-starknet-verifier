//! C ABI over `starknet_transaction_prover`: run the SNIP-36 virtual OS and the Stwo recursive
//! prover in-process, so a phone can produce the `proof` / `proof_facts` of an invoke without a
//! proving service.
//!
//! One call: `snip36_prove(request_json) -> response_json`. The request is
//! `{"rpc_url", "chain_id", "block_id": {"block_number": N}, "transaction": <RPC INVOKE v3>,
//!   "log_path"?}`; the response is the `starknet_proveTransaction` result plus timings, or
//! `{"error": "..."}`. Large allocations spill to `$ZKMSG_SPILL_DIR` when it is set.

mod spill_alloc;

#[global_allocator]
static GLOBAL: spill_alloc::SpillAlloc = spill_alloc::SpillAlloc;

use std::ffi::{c_char, CStr, CString};
use std::sync::Once;
use std::time::Instant;

use blockifier_reexecution::state_reader::rpc_objects::BlockId;
use serde_json::{json, Value};
use starknet_api::core::ChainId;
use starknet_api::rpc_transaction::RpcTransaction;
use starknet_transaction_prover::config::ProverConfig;
use starknet_transaction_prover::proving::virtual_snos_prover::RpcVirtualSnosProver;
use starknet_transaction_prover::running::runner::RunnerConfig;

static LOG_INIT: Once = Once::new();

fn init_logging(log_path: Option<&str>) {
    LOG_INIT.call_once(|| {
        let filter = tracing_subscriber::EnvFilter::new(
            "warn,starknet_transaction_prover=info,privacy_prove=info",
        );
        let builder = tracing_subscriber::fmt().with_env_filter(filter).with_ansi(false);
        match log_path.and_then(|p| std::fs::File::create(p).ok()) {
            Some(file) => builder.with_writer(std::sync::Mutex::new(file)).init(),
            None => builder.init(),
        }
    });
}

/// The prover configuration for one request.
///
/// State prefetch is off. With it on (the library default), the executor first sends the whole
/// virtual transaction to the RPC as `starknet_simulateTransactions` to learn its initial reads,
/// and that transaction's calldata is the send's witness (member secret, leaf, Merkle path). Off,
/// the executor reads state key by key (`getStorageAt`, `getNonce`, `getClassHashAt`,
/// `getClass`), so the RPC sees which storage slots the send touches but never the calldata.
///
/// `prefetch_state` is `pub(crate)` in `starknet_transaction_prover`, so it is set through the
/// runner config's serde form: serialize the defaults, flip the one flag, deserialize. Every other
/// field keeps its library default.
pub fn prover_config(chain_id: ChainId, rpc_url: String) -> Result<ProverConfig, String> {
    let mut runner = serde_json::to_value(RunnerConfig::default())
        .map_err(|e| format!("runner config: {e}"))?;
    let flag = runner
        .pointer_mut("/virtual_block_executor_config/prefetch_state")
        .ok_or("runner config: no virtual_block_executor_config.prefetch_state")?;
    *flag = json!(false);
    let runner_config: RunnerConfig =
        serde_json::from_value(runner).map_err(|e| format!("runner config: {e}"))?;
    Ok(ProverConfig {
        chain_id,
        rpc_node_url: rpc_url,
        runner_config,
        // Matches `snip36 prove virtual-os` (--skip-fee-field-validation).
        validate_zero_fee_fields: false,
        ..ProverConfig::default()
    })
}

/// Proves one request end to end. Blocking; run it off the main thread.
pub fn prove_request(request: &Value) -> Result<Value, String> {
    init_logging(request.get("log_path").and_then(Value::as_str));

    let rpc_url = request["rpc_url"].as_str().ok_or("missing rpc_url")?.to_string();
    let chain_id = ChainId::from(request["chain_id"].as_str().unwrap_or("SN_SEPOLIA").to_string());
    let block_id: BlockId =
        serde_json::from_value(request["block_id"].clone()).map_err(|e| format!("block_id: {e}"))?;
    let transaction: RpcTransaction = serde_json::from_value(request["transaction"].clone())
        .map_err(|e| format!("transaction: {e}"))?;

    let config = prover_config(chain_id, rpc_url)?;

    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .map_err(|e| format!("tokio runtime: {e}"))?;

    // Development only (`--features profiling`): samples live spilled MiB every 100 ms into
    // this file, which is how the per-stage memory profile in the README was taken.
    #[cfg(feature = "profiling")]
    if let Ok(path) = std::env::var("SNIP36_LIVE_PROFILE") {
        std::thread::spawn(move || {
            use std::io::Write;
            let mut f = std::fs::File::create(path).unwrap();
            let t0 = Instant::now();
            loop {
                let _ = writeln!(f, "{} {}", t0.elapsed().as_millis(), spill_alloc::live_spill_bytes() >> 20);
                std::thread::sleep(std::time::Duration::from_millis(100));
            }
        });
    }

    let precompute_start = Instant::now();
    // `new` prepares the recursive prover precomputes (twiddles, preprocessed trees).
    let prover = runtime.block_on(async { RpcVirtualSnosProver::new(&config) });
    let precompute_ms = precompute_start.elapsed().as_millis() as u64;

    let prove_start = Instant::now();
    let result = runtime
        .block_on(prover.prove_transaction(block_id, transaction))
        .map_err(|e| format!("prove_transaction: {e}"))?;
    let prove_ms = prove_start.elapsed().as_millis() as u64;

    let mut out = serde_json::to_value(&result).map_err(|e| format!("serialize: {e}"))?;
    out["timings_ms"] = json!({ "precompute": precompute_ms, "run_and_prove": prove_ms });
    out["peak_spill_bytes"] = json!(spill_alloc::snip36_peak_spill_bytes());
    tracing::info!(
        precompute_ms,
        prove_ms,
        peak_spill_mib = spill_alloc::snip36_peak_spill_bytes() >> 20,
        "snip36 prove finished"
    );
    Ok(out)
}

fn to_c(value: Value) -> *mut c_char {
    CString::new(value.to_string()).map(CString::into_raw).unwrap_or(std::ptr::null_mut())
}

/// # Safety
/// `request` must be a valid NUL-terminated UTF-8 JSON string. Free the result with
/// `snip36_free_string`.
#[no_mangle]
pub unsafe extern "C" fn snip36_prove(request: *const c_char) -> *mut c_char {
    let outcome = std::panic::catch_unwind(|| {
        let text = unsafe { CStr::from_ptr(request) }.to_str().map_err(|e| e.to_string())?;
        let value: Value = serde_json::from_str(text).map_err(|e| format!("request: {e}"))?;
        prove_request(&value)
    });
    match outcome {
        Ok(Ok(value)) => to_c(value),
        Ok(Err(error)) => to_c(json!({ "error": error })),
        Err(_) => to_c(json!({ "error": "prover panicked" })),
    }
}

/// # Safety
/// `ptr` must come from `snip36_prove` and be freed once.
#[no_mangle]
pub unsafe extern "C" fn snip36_free_string(ptr: *mut c_char) {
    if !ptr.is_null() {
        drop(unsafe { CString::from_raw(ptr) });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The send's witness is the virtual transaction's calldata; with prefetch on it would go to
    /// the RPC in `starknet_simulateTransactions`.
    #[test]
    fn prover_config_does_not_prefetch_state() {
        let config =
            prover_config(ChainId::Sepolia, "http://127.0.0.1:1".to_string()).unwrap();
        let value = serde_json::to_value(&config).unwrap();
        assert_eq!(
            value.pointer("/runner_config/virtual_block_executor_config/prefetch_state"),
            Some(&json!(false))
        );
        assert_eq!(value["validate_zero_fee_fields"], json!(false));
        assert_eq!(value["blocking_check_url"], Value::Null);

        // Everything else is the library default.
        let mut expected = serde_json::to_value(ProverConfig {
            chain_id: ChainId::Sepolia,
            rpc_node_url: "http://127.0.0.1:1".to_string(),
            validate_zero_fee_fields: false,
            ..ProverConfig::default()
        })
        .unwrap();
        assert_eq!(
            expected.pointer("/runner_config/virtual_block_executor_config/prefetch_state"),
            Some(&json!(true)),
            "library default changed; revisit prover_config"
        );
        *expected
            .pointer_mut("/runner_config/virtual_block_executor_config/prefetch_state")
            .unwrap() = json!(false);
        assert_eq!(value, expected);
    }
}
