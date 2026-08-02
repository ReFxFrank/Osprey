import SwiftUI

struct RootView: View {
    let model: AppModel

    var body: some View {
        NavigationStack {
            content
                .navigationTitle("Osprey")
                .navigationBarTitleDisplayMode(.inline)
        }
        .task { model.load() }
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
            if model.pairedHost == nil {
                PairView(model: model)
            } else {
                PairedHostView(model: model)
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
