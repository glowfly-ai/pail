// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Glowfly Identity Systems Co.,Ltd

//! Generate clients from the selected repository's canonical RPC and Core ABI schemas.

mod build_paths;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    let repo = root.join("../..").canonicalize()?;
    println!("cargo:rerun-if-env-changed=PAIL_PROTO_DIR");
    let explicit = std::env::var_os("PAIL_PROTO_DIR").map(std::path::PathBuf::from);
    let proto_dir = build_paths::resolve(&repo, explicit.as_deref())
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidInput, e))?;
    println!("cargo:warning=PAIL proto input: {}", proto_dir.display());
    // AD-5 (2026-09-06): the library is its own top-level directory; nothing under pail_ws/ is
    // needed to build this adapter.
    let abi_dir = root.join("../../libpail_gate/abi");
    let token = proto_dir.join("token_service.proto");
    let abi = abi_dir.join("pail_gate_abi.proto");
    println!("cargo:rerun-if-changed={}", token.display());
    println!("cargo:rerun-if-changed={}", proto_dir.join("pail.proto").display());
    println!("cargo:rerun-if-changed={}", abi.display());
    // The libpail_gate ABI schema is generated from the library's own .proto (MD-2b): the
    // Rust side has no hand-written mirror of it.
    tonic_prost_build::configure()
        .build_server(false)
        .build_client(true)
        .compile_protos(&[token, abi], &[proto_dir, abi_dir])?;
    // `--features libgate`: link libpail_gate.so from PAIL_GATE_LIB_DIR (libpail_gate's own
    // `cmake --install` lib/ — no ROS needed — or, on the dev bench, the colcon install
    // tree's lib/). Without the feature nothing is linked and only NoGate exists.
    println!("cargo:rerun-if-env-changed=PAIL_GATE_LIB_DIR");
    if std::env::var("CARGO_FEATURE_LIBGATE").is_ok() {
        if let Ok(dir) = std::env::var("PAIL_GATE_LIB_DIR") {
            println!("cargo:rustc-link-search=native={dir}");
        }
    }
    Ok(())
}
