//! C ABI over the one part of zkmsg the iOS app still links: the v1 SNIP-36
//! send builder (`zkmsg_prepare_send`), which must agree with the prover
//! contract felt-for-felt. The phone's lane-1 exports (proof packing, the
//! RPC-free registry sync, Merkle paths) were removed 2026-10-01 with that
//! route; this export goes too once the Swift v2 send builder replaces it.
//!
//! Deliberately *not* here: keys, signing, transactions, or storage. The app
//! owns those natively — `ZkmsgCore` has Stark ECDSA, SNIP-8 v3 hashing and
//! Keychain custody — and they are the parts a user's security depends on
//! being auditable in the app's own language.
//!
//! ABI shape: every entry point takes and returns JSON as a NUL-terminated
//! UTF-8 string. Returned strings are heap-allocated here and MUST be freed
//! with `zkmsg_string_free`. Results are wrapped as `{"ok": …}` or
//! `{"error": "…"}` so a caller never has to interpret a null pointer, and
//! panics are caught rather than unwinding across the boundary (undefined
//! behaviour).

use std::ffi::{c_char, CStr, CString};

use anyhow::{anyhow, Context, Result};
use serde::{Deserialize, Serialize};
use starknet_types_core::felt::Felt;

use zkmsg_core::send::{build_send, SendInputs};

/// Frees a string returned by any function in this library.
///
/// # Safety
/// `s` must be a pointer this library returned and not yet freed.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn zkmsg_string_free(s: *mut c_char) {
    if !s.is_null() {
        drop(unsafe { CString::from_raw(s) });
    }
}

fn respond<T: Serialize>(result: Result<T>) -> *mut c_char {
    let json = match result {
        Ok(value) => serde_json::json!({ "ok": value }),
        Err(e) => serde_json::json!({ "error": format!("{e:#}") }),
    };
    // A CString allocation cannot fail for JSON (no interior NULs), but if
    // serialization ever did, report it in the same shape rather than crashing.
    let text = serde_json::to_string(&json)
        .unwrap_or_else(|e| format!("{{\"error\":\"serialize: {e}\"}}"));
    CString::new(text).unwrap_or_default().into_raw()
}

/// Runs `f` over a JSON request string, catching panics so none unwind into
/// Swift. A panic here means a bug in this library, and the caller gets an
/// error string instead of a crashed process.
fn entry<Req, Res, F>(request: *const c_char, f: F) -> *mut c_char
where
    Req: for<'de> Deserialize<'de> + std::panic::UnwindSafe,
    Res: Serialize,
    F: FnOnce(Req) -> Result<Res> + std::panic::UnwindSafe,
{
    let parsed = (|| -> Result<Req> {
        if request.is_null() {
            return Err(anyhow!("null request"));
        }
        let text = unsafe { CStr::from_ptr(request) }.to_str().context("request is not utf-8")?;
        serde_json::from_str(text).context("request is not valid json for this call")
    })();

    match parsed {
        Err(e) => respond::<Res>(Err(e)),
        Ok(req) => match std::panic::catch_unwind(move || f(req)) {
            Ok(result) => respond(result),
            Err(_) => respond::<Res>(Err(anyhow!("panicked"))),
        },
    }
}

fn felt(s: &str) -> Result<Felt> {
    Felt::from_hex(s).map_err(|e| anyhow!("bad felt {s}: {e}"))
}

fn felts(v: &[String]) -> Result<Vec<Felt>> {
    v.iter().map(|s| felt(s)).collect()
}

// ---------------------------------------------------------------------------
// Send preparation

#[derive(Deserialize)]
struct PrepareRequest {
    merkle_root: String,
    sender_scan_priv: String,
    recipient_scan_pub: String,
    sender_leaf_index: u32,
    recipient_leaf_index: u32,
    sender_path: Vec<String>,
    recipient_path: Vec<String>,
    text: String,
    /// Test-only: pin the ephemeral key to reproduce a known send. Omitted in
    /// production, where a fresh key is minted and dropped per send.
    #[serde(default)]
    ephemeral_priv: Option<String>,
}

/// Builds the circuit witness and the encrypted envelope for one message.
///
/// Membership verification happens inside, so a stale root or wrong path fails
/// here — before the caller spends minutes proving something that cannot
/// verify.
///
/// # Safety
/// `request` must be a NUL-terminated UTF-8 JSON string.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn zkmsg_prepare_send(request: *const c_char) -> *mut c_char {
    entry(request, |req: PrepareRequest| {
        let sender_path = felts(&req.sender_path)?;
        let recipient_path = felts(&req.recipient_path)?;
        let ephemeral_priv = req.ephemeral_priv.as_deref().map(felt).transpose()?;
        build_send(&SendInputs {
            merkle_root: felt(&req.merkle_root)?,
            sender_scan_priv: felt(&req.sender_scan_priv)?,
            recipient_scan_pub: felt(&req.recipient_scan_pub)?,
            sender_leaf_index: req.sender_leaf_index,
            recipient_leaf_index: req.recipient_leaf_index,
            sender_path: &sender_path,
            recipient_path: &recipient_path,
            text: &req.text,
            ephemeral_priv,
        })
    })
}
