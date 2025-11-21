// build.rs - Embed GravityCode encrypted INS extensions into Codex binary.
// If the encrypted bundle is missing or stale, it will be generated from the
// plaintext `extensions/` directory using the embedded extension license key.

use std::env;
use std::fs;
use std::path::Path;
use std::path::PathBuf;
use std::time::SystemTime;

use aes::Aes256;
use anyhow::Context;
use anyhow::Result;
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as BASE64;
use cbc::Encryptor;
use cipher::BlockEncryptMut;
use cipher::KeyIvInit;
use cipher::block_padding::Pkcs7;
use rand::RngCore;
use scrypt::Params as ScryptParams;
use scrypt::scrypt;
use sha2::Digest;
use sha2::Sha256;

const EXT_LICENSE_KEY: &str = "dclRbAXPtB0_CcG-SNmG3xC2Pl0aioTKpqN3Wgu5OCYVExrbGUK3i_Wcoy5FpPpwWABT3rDdzvpcYNFFFH6T7I8S8TTf4accCXHrI3SlTZysTrF5fP3gi28L6Id8Ky9ENAGpH8IRqfAivzf1_2aSUnwFO8e4w1jkXfa8Z8VrCAwqa-z1IALM5jfEC8iGy_EQH1yr1jI3xRyBcsHZWl-GeN61zkG89rEdH3tSk2Qe9zyT6tVbu4s2EkQVYk52DdfpuNCDheGWQu3EwWy2Y6AcpG-HZOdt9i3gs8htiAYcrIHrNLBFy0agdBlBTGN5hywTzvcb_xEtutBKPrf_lHWI2A==";
const WRAP_KDF_SALT: &str = "gravitycode-ext-wrap-v1";

fn main() {
    println!("cargo::rustc-check-cfg=cfg(gravitycode_ext_encrypted)");

    let manifest_dir = env::var("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR not set");
    let manifest_dir_path = PathBuf::from(manifest_dir);
    let root = manifest_dir_path
        .parent()
        .and_then(|p| p.parent())
        .and_then(|p| p.parent())
        .expect("Cannot compute GravityCode root")
        .to_path_buf();

    let bundle_path = root.join("extensions.bundle.encrypted");
    let wrap_path = root.join("extensions.wrap.json");
    let plain_dir = root.join("extensions");

    if !plain_dir.exists() {
        panic!(
            "❌ 未找到明文 extensions 目录: {}。无法生成加密扩展。",
            plain_dir.display()
        );
    }

    let bundle_len = fs::metadata(&bundle_path).map(|m| m.len()).unwrap_or(0);
    let wrap_len = fs::metadata(&wrap_path).map(|m| m.len()).unwrap_or(0);

    let need_encrypt = bundle_len == 0
        || wrap_len == 0
        || !bundle_path.exists()
        || !wrap_path.exists()
        || newer_than(&plain_dir, &bundle_path).unwrap_or(false)
        || newer_than(&plain_dir, &wrap_path).unwrap_or(false);

    if need_encrypt {
        println!(
            "cargo:warning=🔐 重新加密 extensions 并嵌入: {}",
            plain_dir.display()
        );
        if let Err(err) = encrypt_and_write(&plain_dir, &bundle_path, &wrap_path, EXT_LICENSE_KEY) {
            panic!("❌ 加密 extensions 失败: {err}");
        }
    }

    emit_embed(&bundle_path, &wrap_path);
}

fn emit_embed(bundle_path: &PathBuf, wrap_path: &PathBuf) {
    println!("cargo:warning=📦 Using encrypted GravityCode extensions");
    println!("cargo:rerun-if-changed={}", bundle_path.display());
    println!("cargo:rerun-if-changed={}", wrap_path.display());
    println!("cargo:rerun-if-changed=../../extensions");
    println!(
        "cargo:rustc-env=GRAVITYCODE_EXT_BUNDLE_PATH={}",
        bundle_path.display()
    );
    println!(
        "cargo:rustc-env=GRAVITYCODE_EXT_WRAP_PATH={}",
        wrap_path.display()
    );
    println!("cargo:rustc-cfg=gravitycode_ext_encrypted");
}

fn encrypt_and_write(
    extensions_dir: &PathBuf,
    bundle_out: &PathBuf,
    wrap_out: &PathBuf,
    license_key: &str,
) -> Result<()> {
    let packed = pack_extensions(extensions_dir)?;
    let sha256 = Sha256::digest(&packed);

    let mut rng = rand::thread_rng();

    let mut content_key = [0u8; 32];
    rng.fill_bytes(&mut content_key);
    let mut bundle_iv = [0u8; 16];
    rng.fill_bytes(&mut bundle_iv);
    let bundle_ct = encrypt_aes_cbc(&content_key, &bundle_iv, &packed)?;

    let bundle = serde_json::json!({
        "version": 1,
        "iv_b64": BASE64.encode(bundle_iv),
        "ciphertext_b64": BASE64.encode(bundle_ct),
        "sha256_plain_b64": BASE64.encode(sha256),
    });

    let wrap_key = derive_wrap_key(license_key)?;
    let mut wrap_iv = [0u8; 16];
    rng.fill_bytes(&mut wrap_iv);
    let wrap_ct = encrypt_aes_cbc(&wrap_key, &wrap_iv, &content_key)?;
    let _ = content_key; // avoid drop(copy) warning

    let wrap = serde_json::json!({
        "version": 1,
        "iv_b64": BASE64.encode(wrap_iv),
        "ciphertext_b64": BASE64.encode(wrap_ct),
    });

    fs::write(bundle_out, serde_json::to_vec_pretty(&bundle)?)
        .with_context(|| format!("写入 bundle 失败: {}", bundle_out.display()))?;
    fs::write(wrap_out, serde_json::to_vec_pretty(&wrap)?)
        .with_context(|| format!("写入 wrap 失败: {}", wrap_out.display()))?;

    let size_mb = (fs::metadata(bundle_out)?.len() as f64) / 1024.0 / 1024.0;
    println!(
        "cargo:warning=🌍 GravityCode: 生成并嵌入加密扩展 ({:.2} MB)",
        size_mb
    );

    Ok(())
}

fn newer_than(src_dir: &Path, target: &Path) -> Result<bool> {
    let target_meta = match fs::metadata(target) {
        Ok(meta) => meta,
        Err(_) => return Ok(true),
    };
    let target_time = target_meta.modified().unwrap_or(SystemTime::UNIX_EPOCH);
    let mut stack = vec![src_dir.to_path_buf()];
    while let Some(dir) = stack.pop() {
        for entry in fs::read_dir(dir)? {
            let entry = entry?;
            let path = entry.path();
            if path.is_dir() {
                stack.push(path);
                continue;
            }
            let meta = entry.metadata()?;
            if meta.modified().unwrap_or(SystemTime::UNIX_EPOCH) > target_time {
                return Ok(true);
            }
        }
    }
    Ok(false)
}

fn pack_extensions(root: &PathBuf) -> Result<Vec<u8>> {
    let mut out = Vec::new();
    let mut dirs = vec![root.clone()];
    while let Some(dir) = dirs.pop() {
        for entry in fs::read_dir(&dir)? {
            let entry = entry?;
            let path = entry.path();
            if path.is_dir() {
                dirs.push(path);
                continue;
            }
            let rel = path.strip_prefix(root).context("计算相对路径失败")?;
            let rel_str = rel
                .to_str()
                .ok_or_else(|| anyhow::anyhow!("路径非 UTF-8: {}", rel.display()))?;
            let data = fs::read(&path)?;
            let path_len = rel_str.len() as u32;
            let data_len = data.len() as u32;
            out.extend_from_slice(&path_len.to_le_bytes());
            out.extend_from_slice(&data_len.to_le_bytes());
            out.extend_from_slice(rel_str.as_bytes());
            out.extend_from_slice(&data);
        }
    }
    Ok(out)
}

fn encrypt_aes_cbc(key: &[u8; 32], iv: &[u8; 16], plaintext: &[u8]) -> Result<Vec<u8>> {
    let cipher = Encryptor::<Aes256>::new_from_slices(key, iv).context("创建加密器失败")?;
    Ok(cipher.encrypt_padded_vec_mut::<Pkcs7>(plaintext))
}

fn derive_wrap_key(license_key: &str) -> Result<[u8; 32]> {
    let params = ScryptParams::recommended();
    let mut key = [0u8; 32];
    scrypt(
        license_key.as_bytes(),
        WRAP_KDF_SALT.as_bytes(),
        &params,
        &mut key,
    )
    .context("派生 wrap 密钥失败")?;
    Ok(key)
}
