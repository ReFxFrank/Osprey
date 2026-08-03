//! Stamps the Windows executable with Osprey's icon and version metadata.
//!
//! This is what makes the agent identifiable in Task Manager, in the services
//! list, and in the UAC prompt the installer raises — a remote-access agent
//! that shows up as a nameless generic binary is exactly the thing a user
//! should be suspicious of, and brief §6.6 forbids obscuring what this process
//! is.

fn main() {
    // Rerun only when the inputs actually change, rather than on every build.
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-changed=../../branding/osprey.ico");

    #[cfg(windows)]
    stamp_resources();
}

#[cfg(windows)]
fn stamp_resources() {
    use std::path::Path;

    // Resolved from the manifest directory so the build does not depend on the
    // working directory cargo happens to be invoked from.
    let manifest = std::env::var("CARGO_MANIFEST_DIR").unwrap_or_default();
    let icon = Path::new(&manifest).join("../../branding/osprey.ico");
    if !icon.exists() {
        // Not fatal: the icon is regenerable from the source logo with
        // scripts/make-icons.ps1, and a missing one should not stop anyone from
        // building and testing the agent.
        println!(
            "cargo:warning=branding icon not found at {}; building without it (run scripts/make-icons.ps1)",
            icon.display()
        );
        return;
    }

    let mut resources = winresource::WindowsResource::new();
    resources
        .set_icon(&icon.to_string_lossy())
        .set("ProductName", "Osprey")
        .set("FileDescription", "Osprey Agent")
        .set("CompanyName", "Osprey")
        .set(
            "LegalCopyright",
            "Distributed under the MIT licence. See LICENSE.",
        );

    if let Err(err) = resources.compile() {
        // A warning rather than a hard failure: resource compilation needs
        // rc.exe from the Windows SDK, and a contributor without it should
        // still get a working binary — just an unbranded one.
        println!("cargo:warning=could not embed the Windows resources: {err}");
    }
}
