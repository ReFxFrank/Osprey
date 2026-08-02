#!/usr/bin/env bash
#
# Build Osprey.xcframework — the packaged form of `agent/osprey-ffi`, so the
# iOS client runs the same `snow` implementation as the Windows agent.
#
# ---------------------------------------------------------------------------
# WHICH STEPS NEED A MAC
#
#   1. cargo build --target aarch64-apple-ios          LINUX OK  (no Mac needed)
#   2. cargo build --target aarch64-apple-ios-sim      LINUX OK
#   2b. cargo build --target x86_64-apple-ios          LINUX OK  (Intel sim)
#   3. uniffi-bindgen generate --language swift        LINUX OK
#   ------------------------------------------------------------------------
#   4. lipo -create  (fuse the simulator slices)       macOS ONLY
#   5. xcodebuild -create-xcframework                  macOS ONLY
#
# Steps 1–3 need no Apple SDK and no `xcrun`. A Rust `staticlib` is produced by
# `ar`, not by a linker, so rustc emits real Mach-O arm64 objects on Linux; and
# uniffi's library mode reads the metadata straight out of the `.a`. Only the
# packaging tools in steps 4–5 are Apple binaries with no non-Apple equivalent.
#
# On Linux this script therefore runs 1–3, prints exactly what it produced, and
# then FAILS with a clear message naming the two remaining steps — rather than
# writing a directory called `Osprey.xcframework` that no Xcode would accept.
# Pass --partial (or set OSPREY_XCFRAMEWORK_PARTIAL=1) to make the Linux half
# exit 0, which is what a Linux CI job that only publishes the `.a` files wants.
#
# ---------------------------------------------------------------------------
# USAGE
#
#   scripts/build-xcframework.sh [--partial] [--debug]
#
# Output lands in agent/target/xcframework/:
#   bindings/     osprey_ffi.swift            → add to the Xcode target
#   headers/      osprey_ffiFFI.h + module.modulemap
#   ios-arm64/    libosprey_ffi.a             → device slice
#   ios-arm64-simulator/ libosprey_ffi.a      → simulator slice(s), lipo'd
#   Osprey.xcframework                        → step 5's output (macOS only)

set -euo pipefail

PROFILE=release
PARTIAL=${OSPREY_XCFRAMEWORK_PARTIAL:-0}
for arg in "$@"; do
    case "$arg" in
        --partial) PARTIAL=1 ;;
        --debug) PROFILE=debug ;;
        -h|--help) sed -n '2,45p' "$0"; exit 0 ;;
        *) echo "unknown argument: $arg" >&2; exit 64 ;;
    esac
done

SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
REPO_ROOT=$(cd -- "$SCRIPT_DIR/.." && pwd)
AGENT_DIR="$REPO_ROOT/agent"
CRATE=osprey-ffi
LIB=libosprey_ffi.a
OUT="$AGENT_DIR/target/xcframework"

DEVICE_TARGET=aarch64-apple-ios
# aarch64 first: it is the only simulator slice an Apple Silicon Mac can run,
# so it must exist even when the x86_64 toolchain target is not installed.
SIM_TARGETS=(aarch64-apple-ios-sim x86_64-apple-ios)

say() { printf '\n\033[1m==> %s\033[0m\n' "$*"; }
die() { printf '\n\033[1;31merror:\033[0m %s\n' "$*" >&2; exit 1; }

HOST=$(uname -s)
case "$HOST" in
    Darwin) IS_MAC=1 ;;
    *) IS_MAC=0 ;;
esac

command -v cargo >/dev/null || die "cargo is not on PATH"

profile_flag=()
[ "$PROFILE" = release ] && profile_flag=(--release)
target_dir() { echo "$AGENT_DIR/target/$1/$PROFILE"; }

installed_targets=$(rustup target list --installed 2>/dev/null || true)
have_target() { grep -qx "$1" <<<"$installed_targets"; }

# ---------------------------------------------------------------- steps 1 & 2
say "[1/5] building the device slice ($DEVICE_TARGET)"
have_target "$DEVICE_TARGET" ||
    die "rust target $DEVICE_TARGET is not installed. Run: rustup target add $DEVICE_TARGET"
(cd "$AGENT_DIR" && cargo build -p "$CRATE" "${profile_flag[@]}" --target "$DEVICE_TARGET")

say "[2/5] building the simulator slices"
built_sim=()
skipped_sim=()
for target in "${SIM_TARGETS[@]}"; do
    if have_target "$target"; then
        (cd "$AGENT_DIR" && cargo build -p "$CRATE" "${profile_flag[@]}" --target "$target")
        built_sim+=("$target")
    else
        skipped_sim+=("$target")
    fi
done
[ ${#built_sim[@]} -gt 0 ] ||
    die "no simulator target is installed. Run: rustup target add ${SIM_TARGETS[*]}"
if [ ${#skipped_sim[@]} -gt 0 ]; then
    # Named rather than silently dropped: an XCFramework missing the x86_64
    # slice builds fine and then fails to run on an Intel Mac's simulator, which
    # is a confusing failure to debug months later.
    printf '\033[1;33mwarning:\033[0m simulator target(s) not installed, slice omitted: %s\n' \
        "${skipped_sim[*]}"
    printf '         install with: rustup target add %s\n' "${skipped_sim[*]}"
fi

# -------------------------------------------------------------------- step 3
say "[3/5] generating the Swift bindings"
(cd "$AGENT_DIR" && cargo build -p "$CRATE" --release --features bindgen-cli --bin uniffi-bindgen)
BINDGEN="$AGENT_DIR/target/release/uniffi-bindgen"
[ -x "$BINDGEN" ] || die "uniffi-bindgen was not produced at $BINDGEN"

rm -rf "$OUT/bindings" "$OUT/headers"
mkdir -p "$OUT/bindings" "$OUT/headers"
# Library mode reads the UniFFI metadata out of the archive itself, so the
# bindings are generated from the exact artifact that ships rather than from a
# separately compiled host build that could drift from it.
"$BINDGEN" generate \
    --library "$(target_dir "$DEVICE_TARGET")/$LIB" \
    --language swift \
    --out-dir "$OUT/bindings"

mv "$OUT/bindings/osprey_ffiFFI.h" "$OUT/headers/"
# xcodebuild requires the map to be named `module.modulemap`; uniffi emits it
# under the module's own name.
mv "$OUT/bindings/osprey_ffiFFI.modulemap" "$OUT/headers/module.modulemap"

mkdir -p "$OUT/ios-arm64"
cp "$(target_dir "$DEVICE_TARGET")/$LIB" "$OUT/ios-arm64/$LIB"

if [ "$IS_MAC" -eq 0 ]; then
    say "Linux half complete"
    cat <<EOF
Produced:
  $OUT/bindings/osprey_ffi.swift
  $OUT/headers/osprey_ffiFFI.h
  $OUT/headers/module.modulemap
  $OUT/ios-arm64/$LIB
$(for t in "${built_sim[@]}"; do echo "  $(target_dir "$t")/$LIB"; done)

Still to do, on macOS with Xcode installed:
  [4/5] lipo -create <simulator slices> -output ios-arm64-simulator/$LIB
  [5/5] xcodebuild -create-xcframework ...
Re-run this same script there; it will redo 1-3 and then finish 4-5.
EOF
    if [ "$PARTIAL" -eq 1 ]; then
        echo "(--partial given: treating the Linux half as success)"
        exit 0
    fi
    die "steps 4 and 5 need macOS: lipo and xcodebuild are Apple-only tools with no Linux equivalent. Pass --partial if the .a files alone are the wanted output."
fi

# --------------------------------------------------------------- steps 4 & 5
command -v lipo >/dev/null || die "lipo is not on PATH (install the Xcode command line tools)"
command -v xcodebuild >/dev/null || die "xcodebuild is not on PATH (install Xcode)"

say "[4/5] fusing the simulator slices"
mkdir -p "$OUT/ios-arm64-simulator"
sim_libs=()
for target in "${built_sim[@]}"; do
    sim_libs+=("$(target_dir "$target")/$LIB")
done
lipo -create "${sim_libs[@]}" -output "$OUT/ios-arm64-simulator/$LIB"
lipo -info "$OUT/ios-arm64-simulator/$LIB"

say "[5/5] creating the XCFramework"
rm -rf "$OUT/Osprey.xcframework"
xcodebuild -create-xcframework \
    -library "$OUT/ios-arm64/$LIB" -headers "$OUT/headers" \
    -library "$OUT/ios-arm64-simulator/$LIB" -headers "$OUT/headers" \
    -output "$OUT/Osprey.xcframework"

say "done"
echo "  $OUT/Osprey.xcframework"
echo "  $OUT/bindings/osprey_ffi.swift  (add this file to the Xcode target)"
