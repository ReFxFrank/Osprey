import Charts
import SwiftUI

/// One machine's live view: M-01 metrics, session state, and unpair.
///
/// Charts comes from the system (iOS 17 deployment target), so nothing here
/// adds a dependency.
struct DeviceDashboardView: View {
    let model: AppModel
    let device: DeviceModel
    @State private var confirmingUnpair = false

    var body: some View {
        List {
            if let banner = device.banner {
                Section {
                    BannerView(text: banner) { device.banner = nil }
                        .listRowInsets(EdgeInsets())
                        .listRowBackground(Color.clear)
                }
            }

            connectionSection
            if device.isConnected || !device.samples.isEmpty {
                metricsSections
            }
            identitySection
            unpairSection
        }
        .navigationTitle(device.host.listLabel)
        .navigationBarTitleDisplayMode(.inline)
        .task {
            // Opening a machine is the request to connect to it; the list stays
            // deliberately passive so browsing does not dial every machine.
            await device.connect()
        }
    }

    // MARK: - Sections

    @ViewBuilder
    private var connectionSection: some View {
        Section("Connection") {
            switch device.connection {
            case .idle:
                Button("Connect") { Task { await device.connect() } }
            case .connecting:
                HStack {
                    ProgressView()
                    Text("Connecting…").foregroundStyle(.secondary)
                }
            case .connected(let session):
                LabeledContent("Host build", value: session.hostSoftwareVersion)
                LabeledContent("Round trip") {
                    Text(
                        session.lastRoundTripMilliseconds.map { "\($0) ms" }
                            ?? "—")
                }
                Button("Send encrypted ping") { Task { await device.sendPing() } }
                Button("Disconnect", role: .destructive) {
                    Task { await device.disconnect() }
                }
            case .failed(let reason):
                Text(reason).foregroundStyle(.red)
                Button("Try again") { Task { await device.connect() } }
            }
        }
    }

    @ViewBuilder
    private var metricsSections: some View {
        if device.isStale {
            Section {
                Label(
                    "Showing the last readings from before this app was in the background.",
                    systemImage: "clock.arrow.circlepath")
                    .font(.footnote)
                    .foregroundStyle(.secondary)
            }
        }

        if !device.hostServesMetrics && device.isConnected {
            Section("Metrics") {
                Text("This host does not report metrics.")
                    .foregroundStyle(.secondary)
            }
        } else if device.samples.isEmpty {
            Section("Metrics") {
                Text("Waiting for the first sample…")
                    .foregroundStyle(.secondary)
            }
        } else {
            Section("Processor") {
                MetricChart(
                    samples: device.samples,
                    value: { $0.cpuPercent },
                    domain: 0...100,
                    tint: .blue)
                if let latest = device.latest {
                    LabeledContent("Now", value: "\(Int(latest.cpuPercent.rounded()))%")
                }
            }

            Section("Memory") {
                MetricChart(
                    samples: device.samples,
                    value: { Double($0.memUsedBytes) },
                    domain: nil,
                    tint: .purple)
                if let latest = device.latest {
                    LabeledContent("In use", value: ByteFormat.string(latest.memUsedBytes))
                }
                if let installed = device.installedMemoryBytes {
                    LabeledContent("Installed", value: ByteFormat.string(installed))
                } else {
                    // The wire says absent, not zero, so the UI says unknown
                    // rather than drawing a bar against a fabricated total.
                    LabeledContent("Installed", value: "Not reported")
                }
            }

            Section("Network") {
                if let latest = device.latest {
                    LabeledContent("Down", value: ByteFormat.rate(latest.netRxBytesPerSec))
                    LabeledContent("Up", value: ByteFormat.rate(latest.netTxBytesPerSec))
                    if latest.netRxBytesPerSec == nil {
                        Text(
                            "Throughput is unknown for this interval — an adapter changed or "
                                + "its counters reset.")
                            .font(.caption)
                            .foregroundStyle(.secondary)
                    }
                }
            }

            if !device.volumes.isEmpty {
                Section("Storage") {
                    ForEach(device.volumes) { volume in
                        VStack(alignment: .leading, spacing: 4) {
                            HStack {
                                Text(volume.label)
                                Spacer()
                                Text(
                                    "\(ByteFormat.string(volume.usedBytes)) of "
                                        + ByteFormat.string(volume.totalBytes))
                                    .font(.caption)
                                    .foregroundStyle(.secondary)
                            }
                            ProgressView(value: volume.usedFraction)
                        }
                    }
                }
            }
        }
    }

    @ViewBuilder
    private var identitySection: some View {
        Section {
            LabeledContent("Fingerprint") {
                Text(device.host.fingerprint.short)
                    .font(.body.monospaced())
            }
            LabeledContent("Paired", value: device.host.pairedAt.formatted(date: .abbreviated, time: .shortened))
        } header: {
            Text("Pinned host")
        } footer: {
            Text(
                "This fingerprint is what `osprey-svc pair` printed on the host. If it ever "
                    + "changes, this phone is talking to a different machine.")
        }
    }

    @ViewBuilder
    private var unpairSection: some View {
        Section {
            Button("Unpair", role: .destructive) { confirmingUnpair = true }
        }
        .confirmationDialog(
            "Unpair \(device.host.listLabel)?",
            isPresented: $confirmingUnpair,
            titleVisibility: .visible
        ) {
            Button("Unpair", role: .destructive) {
                Task { await model.forget(device) }
            }
            Button("Cancel", role: .cancel) {}
        } message: {
            Text(
                "Reconnecting later needs physical access to that machine to scan a new "
                    + "pairing code.")
        }
    }
}

/// A line chart over the sample series.
private struct MetricChart: View {
    let samples: [MetricSample]
    let value: (MetricSample) -> Double
    let domain: ClosedRange<Double>?
    let tint: Color

    var body: some View {
        Chart(samples) { sample in
            LineMark(
                x: .value("Time", sample.timestamp),
                y: .value("Value", value(sample)))
                .interpolationMethod(.monotone)
                .foregroundStyle(tint)
        }
        .chartYScale(domain: domain ?? autoDomain)
        .chartXAxis {
            AxisMarks(values: .automatic(desiredCount: 3))
        }
        .frame(height: 140)
        .accessibilityLabel("Chart of the last \(samples.count) samples")
    }

    /// Zero-based so a flat line near the top does not read as "almost full"
    /// when the axis silently starts at the minimum.
    private var autoDomain: ClosedRange<Double> {
        let peak = samples.map(value).max() ?? 1
        return 0...max(peak, 1)
    }
}
