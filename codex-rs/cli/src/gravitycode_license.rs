//! Product license gating for GravityCode (Keygen-based, prompt for key).

use aes::Aes256;
use anyhow::Context;
use anyhow::Result;
use anyhow::anyhow;
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as BASE64;
use cbc::Decryptor;
use cbc::Encryptor;
use cipher::BlockDecryptMut;
use cipher::BlockEncryptMut;
use cipher::KeyIvInit;
use cipher::block_padding::Pkcs7;
use rand::RngCore;
use reqwest::StatusCode;
use scrypt::Params as ScryptParams;
use scrypt::scrypt;
use serde::Deserialize;
use serde::Serialize;
use std::env;
use std::fs;
use std::io::Write;
use std::io::{self};
use std::path::Path;
use std::path::PathBuf;
use std::time::Duration;
use std::time::SystemTime;
use std::time::UNIX_EPOCH;
use thiserror::Error;
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;
use tokio::runtime::Runtime;

const ACCOUNT_ID: &str = "e0c011c3-8b88-496c-ab5a-06d0d2a01ccf";
const PRODUCT_ID: &str = "555cf493-b2a9-4219-a6ba-7f7b0e9854b9";

const GRACE_PERIOD_MS: i64 = 3 * 24 * 60 * 60 * 1000;
const REQUEST_TIMEOUT_MS: i64 = 10_000;

const ACTIVATION_VERSION: i32 = 1;
const ACTIVATION_FILE: &str = "activation.dat";
const ACTIVATION_DIR: &str = "gravitycode-license";
const KDF_SALT: &str = "gravitycode-license-kdf-v1";

pub struct LicenseManager {
    http: reqwest::Client,
    home: PathBuf,
}

#[derive(Debug, Clone)]
pub struct ActiveLicense {
    pub license_id: String,
    pub machine_id: Option<String>,
    pub expires_at: Option<OffsetDateTime>,
    pub last_validated_ms: i64,
    pub fingerprint: String,
}

#[derive(Debug, Error)]
pub enum LicenseError {
    #[error("license key无效或不匹配")]
    InvalidKey,
    #[error("license已过期")]
    Expired,
    #[error("license已被暂停或封禁")]
    Suspended,
    #[error("设备数量已达上限")]
    MaxMachinesExceeded,
    #[error("设备指纹不匹配")]
    FingerprintMismatch,
    #[error("超过离线宽限期，请联网重试")]
    GracePeriodExpired,
    #[error("网络请求失败: {0}")]
    Network(String),
    #[error("Keygen服务异常: {0}")]
    Api(String),
    #[error("缺少产品 License Key")]
    MissingKey,
}

#[derive(Debug, Serialize, Deserialize)]
struct ActivationPayload {
    license_key: String,
    license_id: String,
    machine_id: Option<String>,
    fingerprint: String,
    expires_at: Option<String>,
    last_validated_ms: i64,
    activation_version: i32,
}

#[derive(Debug, Serialize, Deserialize)]
struct EncryptedActivation {
    version: i32,
    iv_b64: String,
    ciphertext_b64: String,
}

#[derive(Debug, Deserialize)]
struct KeygenValidateResponse {
    meta: ValidateMeta,
    data: Option<KeygenLicenseData>,
    errors: Option<Vec<KeygenError>>,
}

#[derive(Debug, Deserialize)]
struct ValidateMeta {
    valid: bool,
    detail: Option<String>,
    timestamp: Option<String>,
}

#[derive(Debug, Deserialize)]
struct KeygenLicenseData {
    id: String,
    attributes: KeygenLicenseAttributes,
}

#[derive(Debug, Deserialize)]
struct KeygenLicenseAttributes {
    status: String,
    expiry: Option<String>,
    max_machines: Option<i64>,
}

#[derive(Debug, Deserialize)]
struct KeygenError {
    detail: Option<String>,
}

#[derive(Debug, Serialize)]
struct ValidateRequest {
    meta: ValidateRequestMeta,
}

#[derive(Debug, Serialize)]
struct ValidateRequestMeta {
    key: String,
    scope: ValidateScope,
}

#[derive(Debug, Serialize)]
struct ValidateScope {
    fingerprint: String,
    product: String,
}

#[derive(Debug, Serialize)]
struct CreateMachineRequest {
    data: MachineData,
}

#[derive(Debug, Serialize)]
struct MachineData {
    #[serde(rename = "type")]
    resource_type: String,
    attributes: MachineAttributes,
    relationships: MachineRelationships,
}

#[derive(Debug, Serialize)]
struct MachineAttributes {
    fingerprint: String,
    name: String,
    platform: String,
}

#[derive(Debug, Serialize)]
struct MachineRelationships {
    license: MachineRelationshipLicense,
}

#[derive(Debug, Serialize)]
struct MachineRelationshipLicense {
    data: MachineRelationshipLicenseData,
}

#[derive(Debug, Serialize)]
struct MachineRelationshipLicenseData {
    #[serde(rename = "type")]
    resource_type: String,
    id: String,
}

impl LicenseManager {
    pub fn new() -> Result<Self> {
        let timeout = Duration::from_millis(REQUEST_TIMEOUT_MS as u64);
        let http = reqwest::Client::builder()
            .timeout(timeout)
            .build()
            .context("构建 HTTP 客户端失败")?;

        let home = get_codex_home()?;

        Ok(Self { http, home })
    }

    pub async fn ensure_active(&self) -> Result<ActiveLicense> {
        let fingerprint = compute_fingerprint()?;
        let storage_dir = self.home.join(ACTIVATION_DIR);
        fs::create_dir_all(&storage_dir).context("创建 license 存储目录失败")?;
        let activation_path = storage_dir.join(ACTIVATION_FILE);

        if let Some(payload) = self.load_activation(&activation_path, &fingerprint)? {
            let now_ms = now_ms();
            let elapsed = now_ms.saturating_sub(payload.last_validated_ms);
            if elapsed <= GRACE_PERIOD_MS {
                return Ok(to_active(&payload, &fingerprint));
            }

            let refreshed = self
                .validate_online(&payload.license_key, &fingerprint)
                .await?;
            self.save_activation(&activation_path, &fingerprint, &refreshed)?;
            return Ok(to_active(&refreshed, &fingerprint));
        }

        let license_key = prompt_license_key()?;
        let activated = self
            .validate_online(&license_key, &fingerprint)
            .await
            .context("在线验证 license 失败")?;

        self.save_activation(&activation_path, &fingerprint, &activated)?;

        Ok(to_active(&activated, &fingerprint))
    }

    pub fn ensure_active_with_key(&self, license_key: &str) -> Result<ActiveLicense> {
        let fingerprint = compute_fingerprint()?;
        let storage_dir = self.home.join(ACTIVATION_DIR);
        fs::create_dir_all(&storage_dir).context("创建 license 存储目录失败")?;
        let activation_path = storage_dir.join(ACTIVATION_FILE);

        if let Some(payload) = self.load_activation(&activation_path, &fingerprint)? {
            let now_ms = now_ms();
            let elapsed = now_ms.saturating_sub(payload.last_validated_ms);
            if elapsed <= GRACE_PERIOD_MS {
                return Ok(to_active(&payload, &fingerprint));
            }
        }

        let rt = Runtime::new().context("无法创建 tokio runtime")?;
        let activated = rt
            .block_on(self.validate_online(license_key, &fingerprint))
            .context("在线验证 license 失败")?;

        self.save_activation(&activation_path, &fingerprint, &activated)?;

        Ok(to_active(&activated, &fingerprint))
    }

    async fn validate_online(
        &self,
        license_key: &str,
        fingerprint: &str,
    ) -> Result<ActivationPayload> {
        let validate_url = format!(
            "https://api.keygen.sh/v1/accounts/{}/licenses/actions/validate-key",
            ACCOUNT_ID
        );

        let request_body = ValidateRequest {
            meta: ValidateRequestMeta {
                key: license_key.to_owned(),
                scope: ValidateScope {
                    fingerprint: fingerprint.to_owned(),
                    product: PRODUCT_ID.to_owned(),
                },
            },
        };

        let response = self
            .http
            .post(validate_url)
            .header("Accept", "application/vnd.api+json")
            .header("Content-Type", "application/vnd.api+json")
            .json(&request_body)
            .send()
            .await
            .map_err(map_network_error)?;

        let status = response.status();
        let raw_body = response
            .text()
            .await
            .map_err(map_network_error)
            .context("读取 Keygen 响应失败")?;
        let parsed: KeygenValidateResponse =
            serde_json::from_str(&raw_body).context("解析 Keygen 验证响应失败")?;

        if !status.is_success() || !parsed.meta.valid {
            return Err(map_keygen_error(parsed.errors, parsed.meta.detail));
        }

        let data = parsed.data.context("Keygen 响应缺少 license 数据")?;

        let attributes = data.attributes;
        let status_str = attributes.status.to_uppercase();
        if status_str == "SUSPENDED" || status_str == "BANNED" {
            return Err(anyhow!(LicenseError::Suspended));
        }

        if let Some(expiry) = attributes.expiry.as_deref() {
            let expiry_time = parse_rfc3339(expiry)?;
            let expiry_ms = (expiry_time.unix_timestamp_nanos() / 1_000_000) as i64;
            if expiry_ms < now_ms() {
                return Err(anyhow!(LicenseError::Expired));
            }
        }

        let machine_id = self
            .create_machine(license_key, &data.id, fingerprint)
            .await?;

        let payload = ActivationPayload {
            license_key: license_key.to_owned(),
            license_id: data.id,
            machine_id,
            fingerprint: fingerprint.to_owned(),
            expires_at: attributes.expiry,
            last_validated_ms: now_ms(),
            activation_version: ACTIVATION_VERSION,
        };

        Ok(payload)
    }

    async fn create_machine(
        &self,
        license_key: &str,
        license_id: &str,
        fingerprint: &str,
    ) -> Result<Option<String>> {
        let url = format!("https://api.keygen.sh/v1/accounts/{}/machines", ACCOUNT_ID);

        let host = hostname::get()
            .ok()
            .and_then(|h| h.into_string().ok())
            .unwrap_or_else(|| "GravityCode".to_string());

        let payload = CreateMachineRequest {
            data: MachineData {
                resource_type: "machines".to_string(),
                attributes: MachineAttributes {
                    fingerprint: fingerprint.to_owned(),
                    name: format!("GravityCode-{host}"),
                    platform: std::env::consts::OS.to_string(),
                },
                relationships: MachineRelationships {
                    license: MachineRelationshipLicense {
                        data: MachineRelationshipLicenseData {
                            resource_type: "licenses".to_string(),
                            id: license_id.to_owned(),
                        },
                    },
                },
            },
        };

        let response = self
            .http
            .post(url)
            .header("Accept", "application/vnd.api+json")
            .header("Content-Type", "application/vnd.api+json")
            .header("Authorization", format!("License {license_key}"))
            .json(&payload)
            .send()
            .await
            .map_err(map_network_error)?;

        let status = response.status();
        let raw_body = response
            .text()
            .await
            .map_err(map_network_error)
            .context("读取 machine 响应失败")?;

        if status.is_success() {
            let data: serde_json::Value =
                serde_json::from_str(&raw_body).context("解析 machine 创建响应失败")?;
            let id = data["data"]["id"].as_str().map(|s| s.to_string());
            return Ok(id);
        }

        if status == StatusCode::UNPROCESSABLE_ENTITY {
            if raw_body.contains("fingerprint has already been taken")
                || raw_body.contains("fingerprint is already in use")
            {
                return Ok(None);
            }
            if raw_body.contains("maximum number of machines") {
                return Err(anyhow!(LicenseError::MaxMachinesExceeded));
            }
        }

        Err(anyhow!(LicenseError::Api(format!(
            "machine 绑定失败: {raw_body}"
        ))))
    }

    fn load_activation(&self, path: &Path, fingerprint: &str) -> Result<Option<ActivationPayload>> {
        if !path.exists() {
            return Ok(None);
        }

        let raw = fs::read(path).context("读取本地激活文件失败")?;
        let encrypted: EncryptedActivation =
            serde_json::from_slice(&raw).context("解析本地激活文件失败")?;

        if encrypted.version != ACTIVATION_VERSION {
            return Ok(None);
        }

        let iv = BASE64
            .decode(encrypted.iv_b64.as_bytes())
            .context("IV 解码失败")?;
        let ciphertext = BASE64
            .decode(encrypted.ciphertext_b64.as_bytes())
            .context("密文解码失败")?;

        let key = derive_key(fingerprint)?;
        let decrypted = decrypt_payload(&key, &iv, &ciphertext)?;
        let payload: ActivationPayload =
            serde_json::from_slice(&decrypted).context("解密本地激活数据失败")?;

        if payload.fingerprint != fingerprint {
            return Ok(None);
        }

        Ok(Some(payload))
    }

    fn save_activation(
        &self,
        path: &Path,
        fingerprint: &str,
        payload: &ActivationPayload,
    ) -> Result<()> {
        let key = derive_key(fingerprint)?;
        let mut rng = rand::thread_rng();
        let mut iv = [0u8; 16];
        rng.fill_bytes(&mut iv);

        let plaintext = serde_json::to_vec(payload).context("序列化激活数据失败")?;
        let ciphertext = encrypt_payload(&key, &iv, &plaintext)?;

        let encrypted = EncryptedActivation {
            version: ACTIVATION_VERSION,
            iv_b64: BASE64.encode(iv),
            ciphertext_b64: BASE64.encode(ciphertext),
        };

        let encoded = serde_json::to_vec_pretty(&encrypted).context("编码激活文件失败")?;
        fs::write(path, encoded).context("写入激活文件失败")?;
        Ok(())
    }
}

fn prompt_license_key() -> Result<String> {
    print!("请输入产品 License Key: ");
    io::stdout().flush().ok();
    let mut buf = String::new();
    io::stdin()
        .read_line(&mut buf)
        .map_err(|e| anyhow!("读取输入失败: {e}"))?;
    let key = buf.trim().to_owned();
    if key.is_empty() {
        return Err(anyhow!(LicenseError::MissingKey));
    }
    Ok(key)
}

fn to_active(payload: &ActivationPayload, fingerprint: &str) -> ActiveLicense {
    let expires_at = payload
        .expires_at
        .as_deref()
        .and_then(|ts| parse_rfc3339(ts).ok());
    ActiveLicense {
        license_id: payload.license_id.clone(),
        machine_id: payload.machine_id.clone(),
        expires_at,
        last_validated_ms: payload.last_validated_ms,
        fingerprint: fingerprint.to_owned(),
    }
}

fn encrypt_payload(key: &[u8; 32], iv: &[u8], plaintext: &[u8]) -> Result<Vec<u8>> {
    let cipher = Encryptor::<Aes256>::new_from_slices(key, iv).context("创建加密器失败")?;
    Ok(cipher.encrypt_padded_vec_mut::<Pkcs7>(plaintext))
}

fn decrypt_payload(key: &[u8; 32], iv: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>> {
    let cipher = Decryptor::<Aes256>::new_from_slices(key, iv).context("创建解密器失败")?;
    cipher
        .decrypt_padded_vec_mut::<Pkcs7>(ciphertext)
        .map_err(|_| anyhow!("解密失败"))
}

fn derive_key(fingerprint: &str) -> Result<[u8; 32]> {
    let params = ScryptParams::recommended();
    let mut key = [0u8; 32];
    scrypt(
        fingerprint.as_bytes(),
        KDF_SALT.as_bytes(),
        &params,
        &mut key,
    )
    .context("派生密钥失败")?;
    Ok(key)
}

fn compute_fingerprint() -> Result<String> {
    use sha2::Digest;
    use sha2::Sha256;
    let hostname = hostname::get()
        .ok()
        .and_then(|h| h.into_string().ok())
        .unwrap_or_else(|| "unknown-host".to_string());
    let platform = std::env::consts::OS;
    let arch = std::env::consts::ARCH;
    let username = whoami::username();
    let home = dirs::home_dir()
        .map(|p| p.display().to_string())
        .unwrap_or_else(|| "unknown-home".to_string());
    let cpus = num_cpus::get();
    let mut hasher = Sha256::new();
    hasher.update(hostname.as_bytes());
    hasher.update(platform.as_bytes());
    hasher.update(arch.as_bytes());
    hasher.update(username.as_bytes());
    hasher.update(home.as_bytes());
    hasher.update(cpus.to_string().as_bytes());
    hasher.update(b"gravitycode-keygen-fp-v1");
    let digest = hasher.finalize();
    Ok(hex::encode(digest))
}

fn get_codex_home() -> Result<PathBuf> {
    if let Ok(home) = env::var("CODEX_HOME") {
        Ok(PathBuf::from(home))
    } else {
        dirs::home_dir()
            .map(|h| h.join(".codex"))
            .ok_or_else(|| anyhow!("无法确定用户主目录"))
    }
}

fn now_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

fn parse_rfc3339(input: &str) -> Result<OffsetDateTime> {
    OffsetDateTime::parse(input, &Rfc3339).map_err(|e| anyhow!("时间解析失败: {e}"))
}

fn map_network_error(err: reqwest::Error) -> anyhow::Error {
    anyhow!(LicenseError::Network(err.to_string()))
}

fn map_keygen_error(errors: Option<Vec<KeygenError>>, detail: Option<String>) -> anyhow::Error {
    if let Some(items) = errors {
        for item in items {
            if let Some(text) = item.detail {
                if text.contains("fingerprint") && text.contains("activated") {
                    return anyhow!(LicenseError::FingerprintMismatch);
                }
                if text.contains("expired") {
                    return anyhow!(LicenseError::Expired);
                }
                if text.contains("SUSPENDED") || text.contains("suspended") {
                    return anyhow!(LicenseError::Suspended);
                }
                if text.contains("maximum number of machines") {
                    return anyhow!(LicenseError::MaxMachinesExceeded);
                }
            }
        }
    }

    if let Some(text) = detail {
        return anyhow!(LicenseError::Api(text));
    }

    anyhow!(LicenseError::Api("未知 Keygen 错误".to_string()))
}
