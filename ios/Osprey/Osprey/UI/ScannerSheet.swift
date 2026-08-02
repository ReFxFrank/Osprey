import SwiftUI

/// The camera sheet. One decoded code is enough; the result is reported on the
/// screen underneath.
struct ScannerSheet: View {
    let model: AppModel

    @Environment(\.dismiss) private var dismiss
    @State private var source = CameraPairingPayloadSource()
    @State private var startFailure: String?

    var body: some View {
        NavigationStack {
            ZStack {
                if let startFailure {
                    BlockedView(title: "Cannot scan", detail: startFailure)
                } else {
                    CameraPreviewView(session: source.session)
                        .ignoresSafeArea()
                    VStack {
                        Spacer()
                        Text("Point the camera at the code on the host's screen.")
                            .font(.callout)
                            .padding(12)
                            .background(.thinMaterial, in: RoundedRectangle(cornerRadius: 10))
                            .padding(.bottom, 32)
                    }
                }
            }
            .navigationTitle("Scan pairing code")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .cancellationAction) {
                    Button("Cancel") { dismiss() }
                }
            }
        }
        .task {
            // Subscribe before starting: a code decoded between `start()` and the
            // first `for await` would otherwise be dropped, and the operator
            // would be holding a steady camera at a code nothing reacts to.
            let stream = source.payloads()
            do {
                try await source.start()
            } catch {
                startFailure = error.localizedMessage
                return
            }
            for await text in stream {
                await model.pair(withScannedText: text)
                break
            }
            await source.stop()
            dismiss()
        }
    }
}
