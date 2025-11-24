// GravityCode INS Extensions Initialization (encrypted bundle)
//
// - Encrypted bundle is embedded at build time (extensions.bundle.encrypted + extensions.wrap.json).
// - Decryption requires a valid extension license key (GRAVITYCODE_EXT_LICENSE_KEY) and online Keygen validation.
// - Decrypted contents are written per-run to `~/.codex/.gravitycode-extensions/` and deleted on drop.

use std::env;
use std::fs;
use std::io::Read;
use std::path::Path;
use std::path::PathBuf;

use aes::Aes256;
use anyhow::Context;
use anyhow::Result;
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as BASE64;
use cbc::Decryptor;
use cipher::BlockDecryptMut;
use cipher::KeyIvInit;
use cipher::block_padding::Pkcs7;
use flate2::read::GzDecoder;
use scrypt::Params as ScryptParams;
use scrypt::scrypt;
use serde::Deserialize;
use sha2::Digest;
use sha2::Sha256;

use crate::gravitycode_license::LicenseManager;

#[cfg(gravitycode_ext_encrypted)]
static EXT_BUNDLE: &[u8] = include_bytes!(env!("GRAVITYCODE_EXT_BUNDLE_PATH"));
#[cfg(gravitycode_ext_encrypted)]
static EXT_WRAP: &[u8] = include_bytes!(env!("GRAVITYCODE_EXT_WRAP_PATH"));

const VERSION: &str = env!("CARGO_PKG_VERSION");
// Embedded extension license key (not read from environment).
const EXT_LICENSE_KEY: &str = "dclRbAXPtB0_CcG-SNmG3xC2Pl0aioTKpqN3Wgu5OCYVExrbGUK3i_Wcoy5FpPpwWABT3rDdzvpcYNFFFH6T7I8S8TTf4accCXHrI3SlTZysTrF5fP3gi28L6Id8Ky9ENAGpH8IRqfAivzf1_2aSUnwFO8e4w1jkXfa8Z8VrCAwqa-z1IALM5jfEC8iGy_EQH1yr1jI3xRyBcsHZWl-GeN61zkG89rEdH3tSk2Qe9zyT6tVbu4s2EkQVYk52DdfpuNCDheGWQu3EwWy2Y6AcpG-HZOdt9i3gs8htiAYcrIHrNLBFy0agdBlBTGN5hywTzvcb_xEtutBKPrf_lHWI2A==";
const WRAP_KDF_SALT: &str = "gravitycode-ext-wrap-v1";

#[derive(Debug, Deserialize)]
struct WrapBlob {
    version: i32,
    iv_b64: String,
    ciphertext_b64: String,
}

#[derive(Debug, Deserialize)]
struct EncryptedBundle {
    version: i32,
    iv_b64: String,
    ciphertext_b64: String,
    sha256_plain_b64: String,
    compression: Option<String>,
}

/// Removes decrypted extensions when dropped (normal exit).
pub struct GravitycodeCleanupGuard {
    path: PathBuf,
}

impl Drop for GravitycodeCleanupGuard {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.path);
    }
}

/// Initialize GravityCode INS extensions (decrypt when needed).
/// Returns a cleanup guard that will delete the decrypted directory on drop.
pub async fn initialize_gravitycode()
-> Result<Option<GravitycodeCleanupGuard>, Box<dyn std::error::Error>> {
    #[cfg(not(gravitycode_ext_encrypted))]
    {
        return Err("GravityCode 加密扩展未嵌入，无法继续".into());
    }

    #[cfg(gravitycode_ext_encrypted)]
    {
        let codex_home = get_codex_home()?;
        let ext_dir = codex_home.join(".gravitycode-extensions");

        if ext_dir.exists() {
            fs::remove_dir_all(&ext_dir)?;
        }
        fs::create_dir_all(&ext_dir)?;

        // Validate extension license (separate from application license).
        let ext_manager = LicenseManager::new_for_extension()?;
        ext_manager
            .ensure_active_with_key_async(EXT_LICENSE_KEY)
            .await?;

        decrypt_extensions(&ext_dir, EXT_LICENSE_KEY)?;
        fs::write(codex_home.join(".gravitycode-version"), VERSION)?;

        unsafe {
            env::set_var("INS_KNOWLEDGE_BASE", &ext_dir);
        }

        Ok(Some(GravitycodeCleanupGuard { path: ext_dir }))
    }
}

#[cfg(gravitycode_ext_encrypted)]
fn decrypt_extensions(target_dir: &Path, ext_license_key: &str) -> Result<()> {
    let wrap: WrapBlob = serde_json::from_slice(EXT_WRAP).context("解析 wrap blob 失败")?;
    let bundle: EncryptedBundle =
        serde_json::from_slice(EXT_BUNDLE).context("解析加密扩展包失败")?;

    if wrap.version != 1 {
        return Err(anyhow::anyhow!("扩展包 wrap 版本不匹配"));
    }
    if bundle.version != 1 && bundle.version != 2 {
        return Err(anyhow::anyhow!("扩展包版本不匹配"));
    }

    let wrap_iv = BASE64
        .decode(wrap.iv_b64.as_bytes())
        .context("解码 wrap IV 失败")?;
    let wrap_ct = BASE64
        .decode(wrap.ciphertext_b64.as_bytes())
        .context("解码 wrap 密文失败")?;

    let content_key = unwrap_content_key(ext_license_key, &wrap_iv, &wrap_ct)?;

    let bundle_iv = BASE64
        .decode(bundle.iv_b64.as_bytes())
        .context("解码 bundle IV 失败")?;
    let bundle_ct = BASE64
        .decode(bundle.ciphertext_b64.as_bytes())
        .context("解码 bundle 密文失败")?;

    let decrypted = decrypt_aes256_cbc(&content_key, &bundle_iv, &bundle_ct)?;
    let plaintext = match bundle.compression.as_deref() {
        None | Some("") => decrypted,
        Some("gzip") => decompress_gzip(&decrypted).context("解压 bundle 失败")?,
        Some(other) => return Err(anyhow::anyhow!("扩展包 compression 不支持: {other}")),
    };

    if !bundle.sha256_plain_b64.is_empty() {
        let expected = BASE64
            .decode(bundle.sha256_plain_b64.as_bytes())
            .context("解码 bundle sha256 失败")?;
        let actual = Sha256::digest(&plaintext);
        if expected.as_slice() != actual.as_slice() {
            return Err(anyhow::anyhow!("扩展包校验失败: sha256 不匹配"));
        }
    }

    // Plaintext format: repeated blocks => path_len:u32 | content_len:u32 | path bytes | content bytes.
    let mut cursor: &[u8] = &plaintext;
    while cursor.len() >= 8 {
        let path_len_bytes: [u8; 4] = cursor
            .get(0..4)
            .ok_or_else(|| anyhow::anyhow!("扩展包格式错误: path_len 缺失"))?
            .try_into()
            .map_err(|_| anyhow::anyhow!("扩展包格式错误: path_len 长度"))?;
        let content_len_bytes: [u8; 4] = cursor
            .get(4..8)
            .ok_or_else(|| anyhow::anyhow!("扩展包格式错误: content_len 缺失"))?
            .try_into()
            .map_err(|_| anyhow::anyhow!("扩展包格式错误: content_len 长度"))?;
        let path_len = u32::from_le_bytes(path_len_bytes) as usize;
        let content_len = u32::from_le_bytes(content_len_bytes) as usize;
        if cursor.len() < 8 + path_len + content_len {
            break;
        }
        let path_bytes = &cursor[8..8 + path_len];
        let content_bytes = &cursor[8 + path_len..8 + path_len + content_len];
        let rel = std::str::from_utf8(path_bytes).context("扩展路径非 UTF-8")?;
        let dest = target_dir.join(rel);
        if let Some(parent) = dest.parent() {
            fs::create_dir_all(parent)?;
        }
        fs::write(&dest, content_bytes)?;
        cursor = &cursor[8 + path_len + content_len..];
    }

    Ok(())
}

fn unwrap_content_key(ext_license_key: &str, iv: &[u8], ct: &[u8]) -> Result<[u8; 32]> {
    let kdf_key = derive_wrap_key(ext_license_key)?;
    let decrypted = decrypt_aes256_cbc(&kdf_key, iv, ct)?;
    if decrypted.len() < 32 {
        return Err(anyhow::anyhow!("content key 长度不正确"));
    }
    let mut key = [0u8; 32];
    key.copy_from_slice(&decrypted[..32]);
    Ok(key)
}

fn derive_wrap_key(ext_license_key: &str) -> Result<[u8; 32]> {
    let params = ScryptParams::recommended();
    let mut key = [0u8; 32];
    scrypt(
        ext_license_key.as_bytes(),
        WRAP_KDF_SALT.as_bytes(),
        &params,
        &mut key,
    )
    .context("派生 wrap 密钥失败")?;
    Ok(key)
}

fn decrypt_aes256_cbc(key: &[u8; 32], iv: &[u8], ct: &[u8]) -> Result<Vec<u8>> {
    let cipher = Decryptor::<Aes256>::new_from_slices(key, iv).context("创建解密器失败")?;
    cipher
        .decrypt_padded_vec_mut::<Pkcs7>(ct)
        .map_err(|_| anyhow::anyhow!("解密失败"))
}

#[cfg(gravitycode_ext_encrypted)]
fn decompress_gzip(data: &[u8]) -> Result<Vec<u8>> {
    let mut decoder = GzDecoder::new(data);
    let mut out = Vec::new();
    decoder
        .read_to_end(&mut out)
        .map_err(|e| anyhow::anyhow!("gzip 解压失败: {e}"))?;
    Ok(out)
}

fn get_codex_home() -> Result<PathBuf> {
    if let Ok(home) = env::var("CODEX_HOME") {
        Ok(PathBuf::from(home))
    } else {
        dirs::home_dir()
            .map(|h| h.join(".codex"))
            .ok_or_else(|| anyhow::anyhow!("Cannot find home directory"))
    }
}
