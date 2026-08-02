import AVFoundation
import SwiftUI
import UIKit

/// Live camera preview for the QR scanner.
///
/// The layer is the view's backing layer rather than a sublayer, so it resizes
/// with the view without any manual frame bookkeeping.
struct CameraPreviewView: UIViewRepresentable {
    let session: AVCaptureSession

    func makeUIView(context: Context) -> CameraPreviewUIView {
        let view = CameraPreviewUIView()
        view.backgroundColor = .black
        view.attach(session: session)
        return view
    }

    func updateUIView(_ uiView: CameraPreviewUIView, context: Context) {
        uiView.attach(session: session)
    }
}

final class CameraPreviewUIView: UIView {
    override class var layerClass: AnyClass { AVCaptureVideoPreviewLayer.self }

    private var previewLayer: AVCaptureVideoPreviewLayer? {
        layer as? AVCaptureVideoPreviewLayer
    }

    func attach(session: AVCaptureSession) {
        guard let previewLayer else { return }
        if previewLayer.session !== session {
            previewLayer.session = session
        }
        previewLayer.videoGravity = .resizeAspectFill
    }
}
