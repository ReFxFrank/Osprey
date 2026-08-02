import SwiftUI

/// The unpaired state: explain what pairing does, then scan.
struct PairView: View {
    let model: AppModel

    var body: some View {
        List {
            if let banner = model.banner {
                Section {
                    BannerView(text: banner) { model.banner = nil }
                }
            }

            Section {
                Text(
                    "Run `osprey-svc pair` on the Windows machine and scan the code it prints. "
                        + "The code can only be scanned in front of the machine, and it is the "
                        + "only way to enrol this phone."
                )
                .font(.callout)
                Button {
                    model.beginScanning()
                } label: {
                    Label("Scan pairing code", systemImage: "qrcode.viewfinder")
                }
            } header: {
                Text("Pair with a host")
            }

            if case .failed(let reason) = model.pairingState {
                Section {
                    Text(reason)
                        .font(.callout)
                        .foregroundStyle(.red)
                } header: {
                    Text("Pairing failed")
                }
            }

            if case .pairing = model.pairingState {
                Section {
                    HStack(spacing: 12) {
                        ProgressView()
                        Text("Connecting to the host and running the handshake…")
                            .font(.callout)
                    }
                }
            }

            if let identity = model.identity {
                Section {
                    FingerprintRow(
                        label: "This phone",
                        fingerprint: identity.fingerprint)
                    LabeledContent("Device id", value: identity.deviceID.uuidString)
                        .font(.footnote.monospaced())
                } header: {
                    Text("This device")
                } footer: {
                    Text(
                        "The host shows this fingerprint after pairing. If it does not match, "
                            + "unpair at the host immediately."
                    )
                }
            }
        }
        .sheet(isPresented: scannerPresented) {
            ScannerSheet(model: model)
        }
    }

    private var scannerPresented: Binding<Bool> {
        Binding(
            get: { model.pairingState == .scanning },
            set: { presented in
                if !presented { model.cancelScanning() }
            })
    }
}

/// A fingerprint shown the way the host console prints it, so the two can be
/// compared character by character.
struct FingerprintRow: View {
    let label: String
    let fingerprint: Fingerprint

    var body: some View {
        VStack(alignment: .leading, spacing: 4) {
            Text(label)
                .font(.footnote)
                .foregroundStyle(.secondary)
            Text(fingerprint.short)
                .font(.title3.monospaced())
                .textSelection(.enabled)
            Text(fingerprint.grouped)
                .font(.caption.monospaced())
                .foregroundStyle(.secondary)
                .textSelection(.enabled)
        }
        .padding(.vertical, 2)
    }
}
