# P0 crypto feasibility — reproducible evidence
# Generated on the P0 planning session's Linux container (rustc 1.94.1).
# Reproduce: copy the two files into a cargo project and run 'cargo test'.

## Windows agent code type-checks from Linux (no MSVC linker needed):
$ cargo check --target x86_64-pc-windows-msvc   # on the wincheck DPAPI project
Finished dev profile in 0.03s  (CryptProtectData / CryptUnprotectData / CRYPTPROTECT_LOCAL_MACHINE resolve)

## Noise IKpsk2 + Ed25519 cross-sign both pass:
test ik_psk2_handshake_roundtrip ... ok
test ed25519_cross_signs_x25519_static ... ok
test result: ok. 2 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.01s
test result: ok. 0 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s
