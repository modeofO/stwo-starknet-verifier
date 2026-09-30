//! Host check of the exact code path the phone runs:
//! `prove_cli <request.json> <out_prefix>` writes `<out_prefix>.proof` (base64) and
//! `<out_prefix>.proof_facts` in the layout `snip36 submit` reads.

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let request: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&args[1]).unwrap()).unwrap();
    let out = snip36_phone_ffi::prove_request(&request).unwrap_or_else(|e| panic!("{e}"));
    std::fs::write(format!("{}.proof", args[2]), out["proof"].as_str().unwrap()).unwrap();
    std::fs::write(format!("{}.proof_facts", args[2]), out["proof_facts"].to_string()).unwrap();
    eprintln!("timings {} spill {}", out["timings_ms"], out["peak_spill_bytes"]);
}
