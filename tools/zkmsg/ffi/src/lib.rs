//! C ABI over the parts of zkmsg an iOS app cannot reasonably reimplement:
//! the send builder (which must agree with the circuit felt-for-felt), proof
//! packing (which must agree with the contract's unpacker), and RPC-free chain
//! sync (which must agree with the store's own tree).
//!
//! Deliberately *not* here: keys, signing, transactions, or storage. The app
//! already owns those natively — `ZkmsgCore` has Stark ECDSA, SNIP-8 v3
//! hashing and Keychain custody — and they are the parts a user's security
//! depends on being auditable in the app's own language. What crosses this
//! boundary is only the logic whose definition of "correct" lives in a Cairo
//! contract or a proving circuit.
//!
//! ABI shape: every entry point takes and returns JSON as a NUL-terminated
//! UTF-8 string. Returned strings are heap-allocated here and MUST be freed
//! with `zkmsg_string_free`. Results are wrapped as `{"ok": …}` or
//! `{"error": "…"}` so a caller never has to interpret a null pointer, and
//! panics are caught rather than unwinding across the boundary (undefined
//! behaviour).
//!
//! Sibling library: the prover bridge exports `zkmsg_prove`/`zkmsg_wrap` from
//! a separate workspace (`.prover/proving-utils`) and is linked alongside this
//! one. They are split because the prover pins StarkWare's proving stack at a
//! specific revision, which the app crates must not be forced to share.
//!
//! Swift side: `App/Sources/ZkmsgBridge.swift` in the zkmsg-ios repo conforms
//! to its `ProofBridging` protocol by forwarding to these symbols.

use std::ffi::{c_char, CStr, CString};

use anyhow::{anyhow, Context, Result};
use serde::{Deserialize, Serialize};
use starknet_types_core::felt::Felt;

use zkmsg_core::pack::pack_v1;
use zkmsg_core::send::{build_send, SendInputs};
use zkmsg_gateway::{feeder::Feeder, Index, Registry};

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
/// here — before the caller spends ten minutes proving and ~37 STRK publishing
/// something that cannot verify.
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

// ---------------------------------------------------------------------------
// Proof packing

#[derive(Deserialize)]
struct PackRequest {
    /// The wrapped proof's felt stream, as written by `zkmsg_wrap`.
    values: Vec<String>,
}

#[derive(Serialize)]
struct PackResponse {
    /// 7 u32 limbs per felt252 slot — the transport the contract unpacks.
    slots: Vec<String>,
    n_values: usize,
}

/// Packs a wrapped proof for calldata/storage. Mirrors the contract's
/// `unpack_proof`; a mismatch here is rejected on-chain after paying.
///
/// # Safety
/// `request` must be a NUL-terminated UTF-8 JSON string.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn zkmsg_pack_proof(request: *const c_char) -> *mut c_char {
    entry(request, |req: PackRequest| {
        let values = felts(&req.values)?;
        let slots = pack_v1(&values)?;
        Ok(PackResponse {
            slots: slots.iter().map(|f| format!("{f:#x}")).collect(),
            n_values: values.len(),
        })
    })
}

// ---------------------------------------------------------------------------
// Chain sync without an RPC provider

#[derive(Deserialize)]
struct SyncRequest {
    /// Feeder base URL; defaults to sepolia-integration.
    #[serde(default)]
    feeder: Option<String>,
    store: String,
    from_block: u64,
    /// Defaults to the chain head.
    #[serde(default)]
    to_block: Option<u64>,
    /// The feeder rate-limits per IP; 2 is the measured sustainable value.
    #[serde(default = "default_workers")]
    workers: usize,
}

fn default_workers() -> usize {
    2
}

#[derive(Serialize)]
struct Member {
    handle: String,
    leaf_index: u32,
    scan_pubkey: String,
}

#[derive(Serialize)]
struct SyncResponse {
    /// Resume point: pass as `from_block` next time rather than re-syncing.
    next_block: u64,
    root: String,
    members: Vec<Member>,
    events_seen: usize,
}

/// Syncs blocks and rebuilds the membership tree locally, replacing the
/// `get_merkle_root` / `get_merkle_path` / `get_user` view calls on networks
/// that serve no RPC. Returns every member so the caller can resolve a handle
/// and read its own leaf without a second pass.
///
/// # Safety
/// `request` must be a NUL-terminated UTF-8 JSON string.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn zkmsg_sync_registry(request: *const c_char) -> *mut c_char {
    entry(request, |req: SyncRequest| {
        let feeder = match req.feeder.as_deref() {
            Some(base) => Feeder::new(base),
            None => Feeder::integration(),
        };
        let to = match req.to_block {
            Some(n) => n,
            None => feeder.latest()?.block_number + 1,
        };
        let mut index = Index::new(&req.store, req.from_block);
        for block in feeder.blocks(req.from_block, to, req.workers)? {
            index.absorb(&block);
        }
        let registry = Registry::rebuild(&index)?;
        let mut members: Vec<Member> = registry
            .handles
            .iter()
            .map(|(handle, leaf)| Member {
                handle: handle.clone(),
                leaf_index: *leaf,
                scan_pubkey: registry
                    .scan_keys
                    .get(leaf)
                    .map(|k| format!("{k:#x}"))
                    .unwrap_or_default(),
            })
            .collect();
        members.sort_by_key(|m| m.leaf_index);

        Ok(SyncResponse {
            next_block: index.next_block,
            root: format!("{:#x}", registry.root()),
            members,
            events_seen: index.events.len(),
        })
    })
}

#[derive(Deserialize)]
struct PathRequest {
    #[serde(default)]
    feeder: Option<String>,
    store: String,
    from_block: u64,
    #[serde(default)]
    to_block: Option<u64>,
    #[serde(default = "default_workers")]
    workers: usize,
    leaf_index: u32,
}

#[derive(Serialize)]
struct PathResponse {
    root: String,
    path: Vec<String>,
    next_block: u64,
}

/// The Merkle path for one leaf, derived locally — the other half of what
/// `zkmsg_prepare_send` needs.
///
/// # Safety
/// `request` must be a NUL-terminated UTF-8 JSON string.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn zkmsg_merkle_path(request: *const c_char) -> *mut c_char {
    entry(request, |req: PathRequest| {
        let feeder = match req.feeder.as_deref() {
            Some(base) => Feeder::new(base),
            None => Feeder::integration(),
        };
        let to = match req.to_block {
            Some(n) => n,
            None => feeder.latest()?.block_number + 1,
        };
        let mut index = Index::new(&req.store, req.from_block);
        for block in feeder.blocks(req.from_block, to, req.workers)? {
            index.absorb(&block);
        }
        let registry = Registry::rebuild(&index)?;
        Ok(PathResponse {
            root: format!("{:#x}", registry.root()),
            path: registry.path(req.leaf_index).iter().map(|f| format!("{f:#x}")).collect(),
            next_block: index.next_block,
        })
    })
}
