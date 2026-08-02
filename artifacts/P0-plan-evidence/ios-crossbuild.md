# Evidence: the iOS Rust core cross-compiles from Linux (no Mac, no Apple SDK)

Run on the P0 Linux container, rustc 1.94.1, 2026-08-02. Reproducible.

## Finding

The Noise/crypto core builds for **real iOS device and simulator targets from
Linux**, producing valid `Mach-O 64-bit arm64` objects. A `staticlib` needs no
linker, so no Apple SDK and no `xcrun` are involved. Only the final
`xcodebuild -create-xcframework` packaging step and the Swift app build
require macOS.

## The trap: snow's default features pull in `ring` (a C dependency)

`snow`'s `default = ["default-resolver", "default-resolver-crypto", "std"]`, and
its `std` feature is declared as:

    std = ["getrandom/std", "subtle/std", "ring/std", "blake2/std", "sha2/std"]

`ring/std` is written WITHOUT the weak-dependency `?` syntax (`ring?/std`), so it
force-enables the optional `ring` dependency even though the default resolver is
pure Rust. `ring` has a C build script that shells out to `xcrun`, which does not
exist off macOS:

    error occurred in cc-rs: failed to find tool "xcrun": No such file or directory

## The working configuration

    snow = { version = "0.10", default-features = false,
             features = ["default-resolver", "default-resolver-crypto"] }

This drops `std` (snow 0.10 supports no_std + alloc) and yields zero `ring` in
the dependency tree.

## Commands and observed output

    $ rustup target add aarch64-apple-ios aarch64-apple-ios-sim
    $ cargo build --release --target aarch64-apple-ios
    Finished `release` profile [optimized] target(s) in 2.61s
    $ cargo build --release --target aarch64-apple-ios-sim
    Finished `release` profile [optimized] target(s) in 3.93s

    $ cargo tree --target aarch64-apple-ios | grep -c ring
    0

    $ ar x libiosspike.a && file *.o
    Mach-O 64-bit arm64 object, flags:<|SUBSECTIONS_VIA_SYMBOLS>

    $ strings libiosspike.a | grep osprey_noise_selftest
    _osprey_noise_selftest

## Consequence for the plan

The cloud-Mac session shortens substantially: the Rust static libraries for
device and simulator can be built and committed as CI artifacts from Linux or
Windows, leaving only XCFramework packaging, the Swift build, signing, and
TestFlight upload to macOS.

Caveat carried forward: the AGENT build (Windows/Linux) may keep snow's default
features; only the iOS target needs the no-`std` configuration. Verify the two
builds agree on protocol behaviour, since they differ in feature flags.
