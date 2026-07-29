// Swift wrapper over libzkmsg_ffi (send builder, proof packing, RPC-free
// chain sync) and libprivacy_prove_cairo_bridge (prove, wrap).
//
// Drop this into the app target and link both staticlibs. Keys, signing and
// transaction submission stay in Swift — only logic whose definition of
// "correct" lives in a Cairo contract or a proving circuit crosses the FFI.
//
// Reference copy: tools/zkmsg/ffi/ZkmsgBridge.swift in stwo-starknet-verifier.

import Foundation

// MARK: - C symbols

@_silgen_name("zkmsg_prepare_send")
private func c_prepare_send(_ req: UnsafePointer<CChar>?) -> UnsafeMutablePointer<CChar>?

@_silgen_name("zkmsg_pack_proof")
private func c_pack_proof(_ req: UnsafePointer<CChar>?) -> UnsafeMutablePointer<CChar>?

@_silgen_name("zkmsg_sync_registry")
private func c_sync_registry(_ req: UnsafePointer<CChar>?) -> UnsafeMutablePointer<CChar>?

@_silgen_name("zkmsg_merkle_path")
private func c_merkle_path(_ req: UnsafePointer<CChar>?) -> UnsafeMutablePointer<CChar>?

@_silgen_name("zkmsg_string_free")
private func c_string_free(_ s: UnsafeMutablePointer<CChar>?)

// The prover lives in a sibling staticlib; 0 = ok, 1 = error, 2 = panic,
// 3 = bad arguments.
@_silgen_name("zkmsg_prove")
private func c_prove(
    _ task: UnsafePointer<CChar>?, _ args: UnsafePointer<CChar>?,
    _ proofOut: UnsafePointer<CChar>?, _ preimageOut: UnsafePointer<CChar>?
) -> Int32

@_silgen_name("zkmsg_wrap")
private func c_wrap(
    _ proofIn: UnsafePointer<CChar>?, _ preimageIn: UnsafePointer<CChar>?,
    _ out: UnsafePointer<CChar>?
) -> Int32

// MARK: - Types

public struct SendMaterial: Decodable {
    /// Short id derived from the commitment; names the send's working directory.
    public let id: String
    /// The 46-felt circuit witness, in the order the circuit consumes it.
    public let args: [String]
    /// AES-256-GCM envelope (nonce ‖ ciphertext ‖ tag), hex.
    public let ciphertext: String
    /// The public tuple the store checks against the proof.
    public let commitment: String
    public let ephemeralPubkey: String
    public let merkleRoot: String
    /// Storage key for staging the proof.
    public let proofId: String

    enum CodingKeys: String, CodingKey {
        case id, args, ciphertext, commitment
        case ephemeralPubkey = "ephemeral_pubkey"
        case merkleRoot = "merkle_root"
        case proofId = "proof_id"
    }
}

public struct RegistryMember: Decodable {
    public let handle: String
    public let leafIndex: UInt32
    public let scanPubkey: String

    enum CodingKeys: String, CodingKey {
        case handle
        case leafIndex = "leaf_index"
        case scanPubkey = "scan_pubkey"
    }
}

public struct RegistrySnapshot: Decodable {
    /// Resume point — persist it and pass as `fromBlock` next time. Full sync
    /// is ~4 minutes per day of chain history, so never rescan from scratch.
    public let nextBlock: UInt64
    public let root: String
    public let members: [RegistryMember]
    public let eventsSeen: Int

    enum CodingKeys: String, CodingKey {
        case nextBlock = "next_block"
        case root, members
        case eventsSeen = "events_seen"
    }
}

public struct MerklePath: Decodable {
    public let root: String
    public let path: [String]
    public let nextBlock: UInt64

    enum CodingKeys: String, CodingKey {
        case root, path
        case nextBlock = "next_block"
    }
}

public struct PackedProof: Decodable {
    public let slots: [String]
    public let nValues: Int

    enum CodingKeys: String, CodingKey {
        case slots
        case nValues = "n_values"
    }
}

public enum ZkmsgBridgeError: Error, LocalizedError {
    /// The Rust side reported a problem — e.g. membership that does not fold
    /// to the root, which must stop a send before it is proved and paid for.
    case rust(String)
    case malformedResponse
    case prover(leg: String, code: Int32)

    public var errorDescription: String? {
        switch self {
        case .rust(let message): return message
        case .malformedResponse: return "bridge returned an unreadable response"
        case .prover(let leg, let code): return "\(leg) failed (code \(code))"
        }
    }
}

// MARK: - Bridge

public enum ZkmsgBridge {
    /// Calls a JSON-in/JSON-out entry point, always freeing the returned string.
    private static func call<T: Decodable>(
        _ fn: (UnsafePointer<CChar>?) -> UnsafeMutablePointer<CChar>?,
        _ request: [String: Any]
    ) throws -> T {
        let data = try JSONSerialization.data(withJSONObject: request)
        guard let json = String(data: data, encoding: .utf8) else {
            throw ZkmsgBridgeError.malformedResponse
        }
        let raw: UnsafeMutablePointer<CChar>? = json.withCString { fn($0) }
        guard let raw else { throw ZkmsgBridgeError.malformedResponse }
        defer { c_string_free(raw) }

        let responseText = String(cString: raw)
        guard let responseData = responseText.data(using: .utf8),
              let object = try JSONSerialization.jsonObject(with: responseData) as? [String: Any]
        else { throw ZkmsgBridgeError.malformedResponse }

        if let message = object["error"] as? String {
            throw ZkmsgBridgeError.rust(message)
        }
        guard let payload = object["ok"] else { throw ZkmsgBridgeError.malformedResponse }
        let payloadData = try JSONSerialization.data(withJSONObject: payload)
        return try JSONDecoder().decode(T.self, from: payloadData)
    }

    /// Builds the circuit witness and encrypted envelope for one message.
    ///
    /// Membership is verified inside, so a stale root or wrong path throws here
    /// rather than after ~10 minutes of proving and a paid transaction.
    public static func prepareSend(
        merkleRoot: String,
        senderScanPriv: String,
        recipientScanPub: String,
        senderLeafIndex: UInt32,
        recipientLeafIndex: UInt32,
        senderPath: [String],
        recipientPath: [String],
        text: String
    ) throws -> SendMaterial {
        try call(c_prepare_send, [
            "merkle_root": merkleRoot,
            "sender_scan_priv": senderScanPriv,
            "recipient_scan_pub": recipientScanPub,
            "sender_leaf_index": senderLeafIndex,
            "recipient_leaf_index": recipientLeafIndex,
            "sender_path": senderPath,
            "recipient_path": recipientPath,
            "text": text,
        ])
    }

    /// Packs a wrapped proof into the transport the contract unpacks.
    public static func packProof(values: [String]) throws -> PackedProof {
        try call(c_pack_proof, ["values": values])
    }

    /// Rebuilds the membership tree from chain events — the substitute for the
    /// view calls on networks that serve no RPC.
    public static func syncRegistry(
        store: String, fromBlock: UInt64, toBlock: UInt64? = nil,
        feeder: String? = nil, workers: Int = 2
    ) throws -> RegistrySnapshot {
        var request: [String: Any] = [
            "store": store, "from_block": fromBlock, "workers": workers,
        ]
        if let toBlock { request["to_block"] = toBlock }
        if let feeder { request["feeder"] = feeder }
        return try call(c_sync_registry, request)
    }

    /// The Merkle path for one leaf, derived locally.
    public static func merklePath(
        store: String, leafIndex: UInt32, fromBlock: UInt64, toBlock: UInt64? = nil,
        feeder: String? = nil, workers: Int = 2
    ) throws -> MerklePath {
        var request: [String: Any] = [
            "store": store, "leaf_index": leafIndex,
            "from_block": fromBlock, "workers": workers,
        ]
        if let toBlock { request["to_block"] = toBlock }
        if let feeder { request["feeder"] = feeder }
        return try call(c_merkle_path, request)
    }

    // MARK: Prover

    /// Set before proving so large allocations become file-backed and stay out
    /// of `phys_footprint` — the ledger jetsam enforces. Without this the wrap
    /// leg is unrunnable on a phone. Also requires the
    /// `com.apple.developer.kernel.extended-virtual-addressing` entitlement,
    /// since iOS otherwise caps the process near ~7 GB of mappings.
    public static func enableSpill(directory: String = NSTemporaryDirectory()) {
        setenv("ZKMSG_SPILL_DIR", directory, 1)
    }

    /// Proves the send. The witness never leaves the device.
    public static func prove(
        taskPath: String, argsPath: String, proofOut: String, preimageOut: String
    ) throws {
        let code = taskPath.withCString { task in
            argsPath.withCString { args in
                proofOut.withCString { proof in
                    preimageOut.withCString { preimage in
                        c_prove(task, args, proof, preimage)
                    }
                }
            }
        }
        if code != 0 { throw ZkmsgBridgeError.prover(leg: "prove", code: code) }
    }

    /// Wraps a proof into the felt stream the on-chain verifier consumes.
    /// Inputs are entirely public, so this leg may also be delegated to an
    /// untrusted relay — verify the result before spending gas on it.
    public static func wrap(proofPath: String, preimagePath: String, out: String) throws {
        let code = proofPath.withCString { proof in
            preimagePath.withCString { preimage in
                out.withCString { output in
                    c_wrap(proof, preimage, output)
                }
            }
        }
        if code != 0 { throw ZkmsgBridgeError.prover(leg: "wrap", code: code) }
    }
}
