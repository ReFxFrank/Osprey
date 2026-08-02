import SwiftUI

@main
struct OspreyApp: App {
    @State private var model = AppModel(engine: FFINoiseEngine())

    var body: some Scene {
        WindowGroup {
            RootView(model: model)
        }
    }
}
