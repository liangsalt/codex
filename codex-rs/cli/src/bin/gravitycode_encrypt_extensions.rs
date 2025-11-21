//! GravityCode extensions encryption tool
//!
//! Usage:
//!   cargo run -p codex-cli --bin gravitycode_encrypt_extensions -- \
//!       --extensions ../../extensions \
//!       --bundle-out ../../extensions.bundle.encrypted \
//!       --wrap-out ../../extensions.wrap.json
//!
//! Required environment:
//!   GRAVITYCODE_EXT_LICENSE_KEY   (extension license key, base64/url-safe string)

use aes::Aes256;
use anyhow::Context;
use anyhow::Result;
use anyhow::anyhow;
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as BASE64;
use cbc::Encryptor;
use cipher::BlockEncryptMut;
use cipher::KeyIvInit;
use cipher::block_padding::Pkcs7;
use rand::RngCore;
use scrypt::Params as ScryptParams;
use scrypt::scrypt;
use serde::Serialize;
use sha2::Digest;
use sha2::Sha256;
use std::env;
use std::fs;
use std::io;
use std::path::Path;
use std::path::PathBuf;

const WRAP_KDF_SALT: &str = "gravitycode-ext-wrap-v1";

#[derive(Debug, Serialize)]
struct BundleFile {
    version: i32,
    iv_b64: String,
    ciphertext_b64: String,
    sha256_plain_b64: String,
}

#[derive(Debug, Serialize)]
struct WrapFile {
    version: i32,
    iv_b64: String,
    ciphertext_b64: String,
}

fn main() -> Result<()> {
    let args: Vec<String> = std::env::args().collect();
    let mut extensions_dir = PathBuf::from("../../extensions");
    let mut bundle_out = PathBuf::from("../../extensions.bundle.encrypted");
    let mut wrap_out = PathBuf::from("../../extensions.wrap.json");

    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--extensions" => {
                i += 1;
                extensions_dir = PathBuf::from(args.get(i).context("缺少 --extensions 参数")?);
            }
            "--bundle-out" => {
                i += 1;
                bundle_out = PathBuf::from(args.get(i).context("缺少 --bundle-out 参数")?);
            }
            "--wrap-out" => {
                i += 1;
                wrap_out = PathBuf::from(args.get(i).context("缺少 --wrap-out 参数")?);
            }
            "--help" | "-h" => {
                print_help();
                return Ok(());
            }
            _ => {}
        }
        i += 1;
    }

    let license_key = env::var("GRAVITYCODE_EXT_LICENSE_KEY")
        .context("缺少环境变量 GRAVITYCODE_EXT_LICENSE_KEY")?;

    if !extensions_dir.exists() {
        return Err(anyhow!(
            "extensions 目录不存在: {}",
            extensions_dir.display()
        ));
    }

    println!("🔒 加密 extensions: {}", extensions_dir.display());

    let packed = pack_extensions(&extensions_dir)?;
    let sha256 = Sha256::digest(&packed);

    let mut rng = rand::thread_rng();
    let mut content_key = [0u8; 32];
    rng.fill_bytes(&mut content_key);
    let mut bundle_iv = [0u8; 16];
    rng.fill_bytes(&mut bundle_iv);
    let bundle_ct = encrypt_aes_cbc(&content_key, &bundle_iv, &packed)?;

    let bundle = BundleFile {
        version: 1,
        iv_b64: BASE64.encode(bundle_iv),
        ciphertext_b64: BASE64.encode(bundle_ct),
        sha256_plain_b64: BASE64.encode(sha256),
    };

    let wrap_key = derive_wrap_key(&license_key)?;
    let mut wrap_iv = [0u8; 16];
    rng.fill_bytes(&mut wrap_iv);
    let wrap_ct = encrypt_aes_cbc(&wrap_key, &wrap_iv, &content_key)?;
    drop(content_key);

    let wrap = WrapFile {
        version: 1,
        iv_b64: BASE64.encode(wrap_iv),
        ciphertext_b64: BASE64.encode(wrap_ct),
    };

    let bundle_json = serde_json::to_vec_pretty(&bundle)?;
    let wrap_json = serde_json::to_vec_pretty(&wrap)?;

    fs::write(&bundle_out, bundle_json)
        .with_context(|| format!("写入 bundle 失败: {}", bundle_out.display()))?;
    fs::write(&wrap_out, wrap_json)
        .with_context(|| format!("写入 wrap 失败: {}", wrap_out.display()))?;

    println!("✅ 加密完成");
    println!("   bundle: {}", bundle_out.display());
    println!("   wrap:   {}", wrap_out.display());
    Ok(())
}

fn print_help() {
    eprintln!("GravityCode extensions encryption tool");
    eprintln!("Params:");
    eprintln!("  --extensions <path>   默认 ../../extensions");
    eprintln!("  --bundle-out <path>   默认 ../../extensions.bundle.encrypted");
    eprintln!("  --wrap-out <path>     默认 ../../extensions.wrap.json");
    eprintln!("Env:");
    eprintln!("  GRAVITYCODE_EXT_LICENSE_KEY (必填)");
}

fn pack_extensions(root: &Path) -> Result<Vec<u8>> {
    let mut out = Vec::new();
    let mut stack = vec![root.to_path_buf()];
    while let Some(dir) = stack.pop() {
        for entry in fs::read_dir(&dir)? {
            let entry = entry?;
            let path = entry.path();
            if path.is_dir() {
                stack.push(path);
                continue;
            }
            let rel = path
                .strip_prefix(root)
                .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;
            let rel_str = rel
                .to_str()
                .ok_or_else(|| anyhow!("文件路径不是 UTF-8: {}", rel.display()))?;
            let data = fs::read(&path)?;

            let path_bytes = rel_str.as_bytes();
            let path_len = path_bytes.len() as u32;
            let data_len = data.len() as u32;

            out.extend_from_slice(&path_len.to_le_bytes());
            out.extend_from_slice(&data_len.to_le_bytes());
            out.extend_from_slice(path_bytes);
            out.extend_from_slice(&data);
        }
    }
    Ok(out)
}

fn encrypt_aes_cbc(key: &[u8; 32], iv: &[u8; 16], plaintext: impl AsRef<[u8]>) -> Result<Vec<u8>> {
    let cipher = Encryptor::<Aes256>::new_from_slices(key, iv).context("创建加密器失败")?;
    Ok(cipher.encrypt_padded_vec_mut::<Pkcs7>(plaintext.as_ref()))
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
