//! Desktop prover: `snip36-prove <out.json>` reads one request from stdin and
//! writes the `starknet_proveTransaction` result (`proof`, `proof_facts`,
//! timings) to `<out.json>`. The same code path the phone runs.
//!
//! The request travels on stdin because the virtual transaction's calldata is
//! the send's witness (membership secret, leaf, Merkle path): it must never
//! be written to disk, and the prover never sends it to the RPC (`prover_config`). The result is public and goes to a file. Logs go to
//! stderr unless the request names a `log_path`. Exit status is non-zero, and
//! stderr carries the reason, when proving fails.

use std::io::Read;

fn main() {
    let Some(out_path) = std::env::args().nth(1) else {
        eprintln!("usage: snip36-prove <out.json>   (request JSON on stdin)");
        std::process::exit(2);
    };
    let mut raw = String::new();
    if let Err(e) = std::io::stdin().read_to_string(&mut raw) {
        eprintln!("snip36-prove: reading stdin: {e}");
        std::process::exit(2);
    }
    let mut request: serde_json::Value = match serde_json::from_str(&raw) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("snip36-prove: request: {e}");
            std::process::exit(2);
        }
    };
    drop(raw);
    if request.get("log_path").is_none() {
        request["log_path"] = serde_json::json!("/dev/stderr");
    }
    let result = snip36_phone_ffi::prove_request(&request);
    drop(request);
    match result {
        Ok(out) => {
            if let Err(e) = std::fs::write(&out_path, out.to_string()) {
                eprintln!("snip36-prove: writing {out_path}: {e}");
                std::process::exit(1);
            }
        }
        Err(e) => {
            eprintln!("snip36-prove: {e}");
            std::process::exit(1);
        }
    }
}
