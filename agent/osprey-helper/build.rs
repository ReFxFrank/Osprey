//! Embeds the helper's DPI manifest, icon and version metadata.
//!
//! The manifest is the load-bearing part. Brief §9.5 requires `PerMonitorV2`
//! from P1 rather than P6, because without it Windows reports scaled
//! coordinates in the wrong units and every captured frame and injected click
//! lands in the wrong place — silently, and only on scaled displays, which is
//! the worst way to find out.

fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-changed=osprey-helper.manifest");
    println!("cargo:rerun-if-changed=../../branding/osprey.ico");

    #[cfg(windows)]
    stamp_resources();
}

#[cfg(windows)]
fn stamp_resources() {
    use std::path::Path;

    let manifest_dir = std::env::var("CARGO_MANIFEST_DIR").unwrap_or_default();
    let manifest = Path::new(&manifest_dir).join("osprey-helper.manifest");
    if !manifest.exists() {
        // A hard failure: an unmanifested helper builds and runs and is wrong
        // in a way nothing downstream can detect.
        panic!("{} is missing; the helper must be DPI-manifested", manifest.display());
    }

    let mut resources = winresource::WindowsResource::new();
    resources
        .set_manifest_file(&manifest.to_string_lossy())
        .set("ProductName", "Osprey")
        .set("FileDescription", "Osprey Session Helper")
        .set("CompanyName", "Osprey")
        .set(
            "LegalCopyright",
            "Distributed under the MIT licence. See LICENSE.",
        );

    let icon = Path::new(&manifest_dir).join("../../branding/osprey.ico");
    if icon.exists() {
        resources.set_icon(&icon.to_string_lossy());
    } else {
        println!(
            "cargo:warning=branding icon not found at {}; run scripts/make-icons.ps1",
            icon.display()
        );
    }

    if let Err(err) = resources.compile() {
        // Unlike the missing manifest above this is only a warning: resource
        // compilation needs rc.exe from the Windows SDK, and a contributor
        // without it should still get a working binary.
        println!("cargo:warning=could not embed the helper resources: {err}");
    }
}
