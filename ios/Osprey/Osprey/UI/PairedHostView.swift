import SwiftUI

/// The paired state: what is pinned, whether it is reachable, and how to undo it.
struct PairedHostView: View {
    let model: AppModel

    @State private var confirmingUnpair = false

    var body: some View {
        List {
            if let banner = model.banner {
                Section {
                    BannerView(text: banner) { model.banner = nil }
                }
            }

            if let host = model.pairedHost {
                Section {
                    FingerprintRow(
                        label: "Host identity",
                        fingerprint: Fingerprint.of(host.pinnedIdentity))
                    LabeledContent("Algorithm", value: host.pinnedIdentity.identityAlgorithm.wireValue)
                    LabeledContent("Device id", value: host.agentDeviceID)
                    LabeledContent("Paired", value: host.pairedAt.formatted(date: .abbreviated, time: .shortened))
                } header: {
                    Text("Pinned host")
                } footer: {
                    Text(
                        "This fingerprint is what `osprey-svc pair` printed on the host. "
                            + "If it ever changes, this phone is talking to a different machine."
                    )
                }

                Section {
                    ForEach(host.lanHints, id: \.self) { hint in
                        Text(hint.description)
                            .font(.footnote.monospaced())
                    }
                } header: {
                    Text("Addresses from the pairing code")
                } footer: {
                    Text(
                        "Recorded when the code was shown. A new DHCP lease or a move between "
                            + "wifi and ethernet invalidates them."
                    )
                }
            }

            connectionSection

            Section {
                Button(role: .destructive) {
                    confirmingUnpair = true
                } label: {
                    Label("Unpair", systemImage: "trash")
                }
            }
        }
        .confirmationDialog(
            "Unpair from this host?",
            isPresented: $confirmingUnpair,
            titleVisibility: .visible
        ) {
            Button("Unpair", role: .destructive) {
                Task { await model.unpair() }
            }
            Button("Cancel", role: .cancel) {}
        } message: {
            Text(
                "This phone will stop connecting immediately. Osprey will also ask the host to "
                    + "drop its pin, and will tell you if it could not."
            )
        }
    }

    @ViewBuilder
    private var connectionSection: some View {
        Section {
            switch model.connectionState {
            case .idle:
                Button {
                    Task { await model.connect() }
                } label: {
                    Label("Connect", systemImage: "bolt.horizontal")
                }
                Text("The host must be running `osprey-svc run`.")
                    .font(.footnote)
                    .foregroundStyle(.secondary)

            case .connecting:
                HStack(spacing: 12) {
                    ProgressView()
                    Text("Opening an encrypted session…")
                }

            case .connected(let session):
                LabeledContent("Session", value: session.sessionID.uuidString)
                    .font(.footnote.monospaced())
                LabeledContent("Host build", value: session.hostSoftwareVersion)
                if let roundTrip = session.lastRoundTripMilliseconds {
                    LabeledContent("Last round trip", value: "\(roundTrip) ms")
                } else {
                    Text("No ping sent yet.")
                        .font(.footnote)
                        .foregroundStyle(.secondary)
                }
                LabeledContent("Pings sent", value: "\(session.pingsSent)")
                Button {
                    Task { await model.sendPing() }
                } label: {
                    Label("Send encrypted ping", systemImage: "arrow.up.arrow.down")
                }
                Button(role: .cancel) {
                    Task { await model.disconnect() }
                } label: {
                    Label("Disconnect", systemImage: "xmark.circle")
                }

            case .failed(let reason):
                Text(reason)
                    .font(.callout)
                    .foregroundStyle(.red)
                Button {
                    Task { await model.connect() }
                } label: {
                    Label("Try again", systemImage: "arrow.clockwise")
                }
            }
        } header: {
            Text("Connection")
        }
    }
}
