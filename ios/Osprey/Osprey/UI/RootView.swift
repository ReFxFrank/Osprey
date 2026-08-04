import SwiftUI

struct RootView: View {
    let model: AppModel
    @Environment(\.scenePhase) private var scenePhase

    var body: some View {
        NavigationStack {
            content
                .navigationTitle("Osprey")
                .navigationBarTitleDisplayMode(.inline)
                // Declared here rather than inside the dashboard so a push does
                // not tear down and rebuild the destination's state.
                .navigationDestination(for: DeviceModel.self) { device in
                    DeviceDashboardView(model: model, device: device)
                }
        }
        .task { model.load() }
        .onChange(of: scenePhase) { _, phase in
            // iOS suspends the process in the background, so a session that was
            // healthy at suspend is usually dead on return — and nothing tells
            // the app, it only finds out by trying (§9.3).
            guard phase == .active else { return }
            Task { await model.refreshAfterForeground() }
        }
    }

    @ViewBuilder
    private var content: some View {
        switch model.identityState {
        case .loading:
            ProgressView("Preparing this device's identity…")
        case .unsupported(let reason):
            BlockedView(title: "This device cannot run Osprey", detail: reason)
        case .failed(let reason):
            BlockedView(title: "Identity unavailable", detail: reason)
        case .ready:
            if model.devices.isEmpty {
                PairView(model: model)
            } else {
                DeviceListView(model: model)
            }
        }
    }
}

/// A dead end the operator cannot work around, stated plainly.
struct BlockedView: View {
    let title: String
    let detail: String

    var body: some View {
        VStack(spacing: 16) {
            Image(systemName: "exclamationmark.triangle")
                .font(.system(size: 44))
                .foregroundStyle(.secondary)
            Text(title)
                .font(.headline)
                .multilineTextAlignment(.center)
            Text(detail)
                .font(.callout)
                .foregroundStyle(.secondary)
                .multilineTextAlignment(.center)
        }
        .padding(32)
    }
}

/// The single line of feedback for the operator's last action.
struct BannerView: View {
    let text: String
    let dismiss: () -> Void

    var body: some View {
        HStack(alignment: .top, spacing: 12) {
            Text(text)
                .font(.footnote)
                .frame(maxWidth: .infinity, alignment: .leading)
            Button {
                dismiss()
            } label: {
                Image(systemName: "xmark.circle.fill")
            }
            .buttonStyle(.plain)
            .foregroundStyle(.secondary)
            .accessibilityLabel("Dismiss message")
        }
        .padding(12)
        .background(Color.secondary.opacity(0.12), in: RoundedRectangle(cornerRadius: 10))
    }
}
