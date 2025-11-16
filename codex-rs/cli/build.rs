// build.rs - Embed GravityCode INS extensions into Codex binary

use std::env;
use std::path::PathBuf;

fn main() {
    // Declare custom cfg for Rust's check-cfg lint
    println!("cargo::rustc-check-cfg=cfg(gravitycode_extensions)");

    // Check if GravityCode extensions exist
    // Path: codex-rs/cli/../../../extensions/
    let manifest_dir = env::var("CARGO_MANIFEST_DIR")
        .expect("CARGO_MANIFEST_DIR not set");

    println!("cargo:warning=🔍 Searching for extensions from: {}", manifest_dir);

    let extensions_path = PathBuf::from(&manifest_dir)
        .parent()  // cli -> codex-rs
        .and_then(|p| p.parent())  // codex-rs -> codex
        .and_then(|p| p.parent())  // codex -> GravityCode
        .map(|p| p.join("extensions"));

    if let Some(ext_path) = extensions_path {
        println!("cargo:warning=📂 Checking path: {}", ext_path.display());

        if ext_path.exists() {
            println!("cargo:rerun-if-changed={}", ext_path.display());
            println!("cargo:rustc-env=GRAVITYCODE_EXTENSIONS_DIR={}", ext_path.display());
            println!("cargo:rustc-cfg=gravitycode_extensions");

            // Calculate size
            let size = calculate_dir_size(&ext_path);
            let size_mb = size as f64 / 1024.0 / 1024.0;
            println!("cargo:warning=🌍 GravityCode: Embedding INS extensions ({:.2} MB)", size_mb);

            if size_mb > 10.0 {
                println!("cargo:warning=⚠️  Extensions size > 10MB");
            }
        } else {
            println!("cargo:warning=❌ Extensions directory not found at: {}", ext_path.display());
            println!("cargo:warning=ℹ️  GravityCode extensions will not be embedded");
        }
    } else {
        println!("cargo:warning=❌ Failed to compute extensions path");
    }
}

fn calculate_dir_size(dir: &PathBuf) -> u64 {
    use std::fs;

    let mut total = 0u64;
    if let Ok(entries) = fs::read_dir(dir) {
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                total += calculate_dir_size(&path);
            } else if path.is_file() {
                total += fs::metadata(&path)
                    .map(|m| m.len())
                    .unwrap_or(0);
            }
        }
    }
    total
}
