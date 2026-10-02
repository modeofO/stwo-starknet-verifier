// zkmsg prover bench: runs the real Stwo prove + wrap pipeline on-device via
// the privacy_prove_cairo_bridge staticlib, with the spill allocator enabled
// (ZKMSG_SPILL_DIR -> app tmp), and reports the phys_footprint peak — the
// ledger jetsam enforces. Workload is the public poseidon_chain(100) fixture;
// no key material ships in this bundle.

import SwiftUI

@_silgen_name("zkmsg_prove")
func zkmsg_prove(
    _ task: UnsafePointer<CChar>?, _ args: UnsafePointer<CChar>?,
    _ proofOut: UnsafePointer<CChar>?, _ preimageOut: UnsafePointer<CChar>?
) -> Int32

@_silgen_name("zkmsg_peak_spill_bytes")
func zkmsg_peak_spill_bytes() -> UInt64

@_silgen_name("zkmsg_wrap")
func zkmsg_wrap(
    _ proofIn: UnsafePointer<CChar>?, _ preimageIn: UnsafePointer<CChar>?,
    _ out: UnsafePointer<CChar>?
) -> Int32

func physFootprintMB() -> Double {
    var info = task_vm_info_data_t()
    var count = mach_msg_type_number_t(
        MemoryLayout<task_vm_info_data_t>.size / MemoryLayout<Int32>.size)
    let kr = withUnsafeMutablePointer(to: &info) {
        $0.withMemoryRebound(to: integer_t.self, capacity: Int(count)) {
            task_info(mach_task_self_, task_flavor_t(TASK_VM_INFO), $0, &count)
        }
    }
    guard kr == KERN_SUCCESS else { return -1 }
    return Double(info.phys_footprint) / 1_048_576
}

struct LegResult: Identifiable {
    let id = UUID()
    let name: String
    let seconds: Double
    let peakFootprintMB: Double
    let exitCode: Int32
}

@MainActor
final class BenchModel: ObservableObject {
    @Published var status = "idle"
    @Published var liveFootprintMB = physFootprintMB()
    @Published var results: [LegResult] = []
    @Published var running = false

    private var peak: Double = 0
    private var timer: Timer?

    func start() {
        guard !running else { return }
        running = true
        results = []
        status = "starting"

        let tmp = NSTemporaryDirectory()
        setenv("ZKMSG_SPILL_DIR", tmp, 1)

        timer = Timer.scheduledTimer(withTimeInterval: 0.05, repeats: true) { _ in
            let f = physFootprintMB()
            Task { @MainActor in
                self.liveFootprintMB = f
                self.peak = max(self.peak, f)
            }
        }

        let bundle = Bundle.main
        guard
            let task = bundle.path(forResource: "task.executable", ofType: "json"),
            let args = bundle.path(forResource: "task_args", ofType: "json"),
            let wrapProof = bundle.path(forResource: "wrap_input_proof", ofType: "json"),
            let wrapPreimage = bundle.path(forResource: "wrap_input_preimage", ofType: "json")
        else {
            status = "missing bundled fixtures"
            running = false
            return
        }
        let proofOut = tmp + "bench_cairo_proof.json"
        let preimageOut = tmp + "bench_preimage.json"
        let feltsOut = tmp + "bench_felts.json"

        // A spill failure aborts the process by design, so refuse the wrap leg
        // rather than crash when the device cannot back ~25 GB of mappings.
        let freeGB = Self.freeDiskGB()
        let ramGB = Double(ProcessInfo.processInfo.physicalMemory) / 1_073_741_824
        print(String(
            format: "[bench] device: %.1f GB RAM, %.1f GB free disk, spill=%@",
            ramGB, freeGB, tmp))
        let wrapAffordable = freeGB > 30

        Task.detached(priority: .userInitiated) {
            await self.runLeg(name: "prove") {
                zkmsg_prove(task, args, proofOut, preimageOut)
            }
            if wrapAffordable {
                await self.runLeg(name: "wrap (bundled input)") {
                    zkmsg_wrap(wrapProof, wrapPreimage, feltsOut)
                }
                await self.runLeg(name: "wrap (on-device proof)") {
                    zkmsg_wrap(proofOut, preimageOut, feltsOut)
                }
            } else {
                await MainActor.run {
                    print("[bench] skipping wrap: needs >30 GB free, have \(freeGB)")
                }
            }
            await MainActor.run {
                self.timer?.invalidate()
                self.status = "done"
                self.running = false
                print("[bench] ALL LEGS COMPLETE")
            }
        }
    }

    static func freeDiskGB() -> Double {
        let url = URL(fileURLWithPath: NSTemporaryDirectory())
        let values = try? url.resourceValues(
            forKeys: [.volumeAvailableCapacityForImportantUsageKey])
        let bytes = values?.volumeAvailableCapacityForImportantUsage ?? 0
        return Double(bytes) / 1_073_741_824
    }

    private func runLeg(name: String, _ body: @escaping () -> Int32) async {
        await MainActor.run {
            self.status = "running \(name)"
            self.peak = physFootprintMB()
        }
        let started = Date()
        let code = body()
        let seconds = Date().timeIntervalSince(started)
        await MainActor.run {
            let result = LegResult(
                name: name, seconds: seconds, peakFootprintMB: self.peak, exitCode: code)
            self.results.append(result)
            let spillGB = Double(zkmsg_peak_spill_bytes()) / 1_073_741_824
            print(
                "[bench] \(name): exit=\(code) wall=\(String(format: "%.1f", seconds))s "
                    + "peak_footprint=\(String(format: "%.0f", self.peakFootprintMB(result)))MB "
                    + "peak_spill=\(String(format: "%.1f", spillGB))GB")
        }
    }

    private func peakFootprintMB(_ r: LegResult) -> Double { r.peakFootprintMB }
}

struct ContentView: View {
    @StateObject var model = BenchModel()

    var body: some View {
        NavigationStack {
            List {
                Section("Live") {
                    LabeledContent(
                        "phys_footprint",
                        value: String(format: "%.0f MB", model.liveFootprintMB))
                    LabeledContent("status", value: model.status)
                }
                Section("Results") {
                    ForEach(model.results) { r in
                        VStack(alignment: .leading, spacing: 2) {
                            Text(r.name).font(.headline)
                            Text(String(
                                format: "%.1f s · peak %.0f MB · exit %d",
                                r.seconds, r.peakFootprintMB, r.exitCode))
                                .font(.caption.monospaced())
                                .foregroundStyle(r.exitCode == 0 ? .secondary : Color.red)
                        }
                    }
                }
                Section {
                    Button(model.running ? "Running…" : "Run bench") { model.start() }
                        .disabled(model.running)
                }
            }
            .navigationTitle("zkmsg prover bench")
            .onAppear { model.start() }
        }
    }
}
