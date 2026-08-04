import SwiftUI

/// The app's root once at least one machine is paired (amendment A23).
struct DeviceListView: View {
    let model: AppModel

    var body: some View {
        List {
            if let banner = model.banner {
                Section {
                    BannerView(text: banner) { model.banner = nil }
                        .listRowInsets(EdgeInsets())
                        .listRowBackground(Color.clear)
                }
            }

            Section("Machines") {
                ForEach(model.devices) { device in
                    NavigationLink(value: device) {
                        DeviceRow(device: device)
                    }
                }
            }

            Section {
                Button {
                    model.beginScanning()
                } label: {
                    Label("Pair another machine", systemImage: "qrcode.viewfinder")
                }
            } footer: {
                Text(
                    "Pairing needs physical access to the machine: run `osprey-svc pair` there "
                        + "and scan the code it shows.")
            }
        }
        .sheet(isPresented: scannerBinding) {
            ScannerSheet(model: model)
        }
    }

    /// The scanner is presented from a state enum rather than a `@State` flag,
    /// so the sheet cannot disagree with the model about whether a scan is in
    /// progress.
    private var scannerBinding: Binding<Bool> {
        Binding(
            get: { model.pairingState == .scanning },
            set: { presented in
                if !presented { model.cancelScanning() }
            })
    }
}

private struct DeviceRow: View {
    let device: DeviceModel

    var body: some View {
        HStack(spacing: 12) {
            StatusDot(state: device.connection)
            VStack(alignment: .leading, spacing: 2) {
                Text(device.host.listLabel)
                    .font(.body)
                Text(subtitle)
                    .font(.caption)
                    .foregroundStyle(.secondary)
            }
            Spacer()
            if let latest = device.latest, device.isConnected {
                Text("\(Int(latest.cpuPercent.rounded()))%")
                    .font(.caption.monospacedDigit())
                    .foregroundStyle(.secondary)
            }
        }
        .padding(.vertical, 2)
    }

    private var subtitle: String {
        switch device.connection {
        case .idle:
            // The fingerprint, not the name: this is the value an operator
            // compares against the host, and a name is attacker-supplied text.
            return device.host.fingerprint.short
        case .connecting:
            return "Connecting…"
        case .connected(let session):
            if let rtt = session.lastRoundTripMilliseconds {
                return "Connected · \(rtt) ms"
            }
            return "Connected"
        case .failed(let reason):
            return reason
        }
    }
}

private struct StatusDot: View {
    let state: ConnectionState

    var body: some View {
        Circle()
            .fill(colour)
            .frame(width: 10, height: 10)
            .accessibilityLabel(label)
    }

    private var colour: Color {
        switch state {
        case .idle: return .secondary
        case .connecting: return .orange
        case .connected: return .green
        case .failed: return .red
        }
    }

    private var label: String {
        switch state {
        case .idle: return "Not connected"
        case .connecting: return "Connecting"
        case .connected: return "Connected"
        case .failed: return "Failed"
        }
    }
}
