// SPDX-License-Identifier: Apache-2.0 OR MIT

extern crate cbindgen;

use std::path::PathBuf;
use std::{env, fs};

fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-changed=cbindgen.toml");
    println!("cargo:rerun-if-changed=src/lib.rs");

    let crate_dir = PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap());
    let cbindgen_file = crate_dir.join("cbindgen.toml");
    let config =
        cbindgen::Config::from_file(&cbindgen_file).expect("Failed to parse {cbindgen_file}");
    let output_dir = PathBuf::from(env::var("OUT_DIR").unwrap());
    let header_file = "landlockconfig.h";
    let header_path = output_dir.join(header_file);

    cbindgen::Builder::new()
        .with_crate(&crate_dir)
        .with_config(config)
        .generate()
        .expect("Unable to generate bindings")
        .write_to_file(&header_path);

    let target_dir = PathBuf::from(&crate_dir).join("assets");
    fs::copy(&header_path, target_dir.join(header_file)).expect("Failed to copy header file");
}
