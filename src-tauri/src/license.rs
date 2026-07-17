use serde::{Deserialize, Serialize};
use std::{
    fs,
    path::PathBuf,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

const LICENSE_FILE: &str = "license.json";
const REQUEST_TIMEOUT: Duration = Duration::from_secs(20);
const PRODUCT_CONFIG: &str = include_str!("../../config/product.json");
const DEFAULT_LICENSE_VALIDATE_URL: &str = "https://dustonic.com/api/license/validate";

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
struct ProductConfig {
    license_validate_url: String,
}

fn validation_url() -> String {
    serde_json::from_str::<ProductConfig>(PRODUCT_CONFIG)
        .map(|config| config.license_validate_url)
        .unwrap_or_else(|_| DEFAULT_LICENSE_VALIDATE_URL.to_string())
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Entitlements {
    pub id: String,
    pub name: String,
    pub safe_cleaning: bool,
    pub manual_clean: bool,
    pub pro_rules: bool,
    pub scheduled_clean: bool,
    pub auto_clean: bool,
    pub duplicate_finder: bool,
    pub large_file_finder: bool,
}

impl Entitlements {
    pub fn free() -> Self {
        Self {
            id: "free".into(),
            name: "Free".into(),
            safe_cleaning: true,
            manual_clean: true,
            pro_rules: false,
            scheduled_clean: false,
            auto_clean: false,
            duplicate_finder: false,
            large_file_finder: false,
        }
    }

    pub fn pro() -> Self {
        Self {
            id: "pro".into(),
            name: "Pro".into(),
            safe_cleaning: true,
            manual_clean: true,
            pro_rules: true,
            scheduled_clean: true,
            auto_clean: true,
            duplicate_finder: true,
            large_file_finder: true,
        }
    }

    pub fn for_tier(tier: &str) -> Option<Self> {
        match tier.to_ascii_lowercase().as_str() {
            "free" => Some(Self::free()),
            "pro" => Some(Self::pro()),
            _ => None,
        }
    }

    pub fn is_pro(&self) -> bool {
        self.id == "pro"
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct StoredLicense {
    key: Option<String>,
    tier: Option<String>,
    email: Option<String>,
    entitlements: Option<Entitlements>,
    activated_at: Option<u64>,
    last_validated_at: Option<u64>,
}

#[derive(Debug, Deserialize)]
struct ValidateResponse {
    valid: bool,
    #[serde(default)]
    tier: Option<String>,
    #[serde(default)]
    email: Option<String>,
    #[serde(default)]
    entitlements: Option<Entitlements>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct LicenseStatus {
    pub activated: bool,
    pub tier: String,
    pub name: String,
    pub key_masked: Option<String>,
    pub email: Option<String>,
    pub entitlements: Entitlements,
}

#[derive(Debug, Clone)]
pub struct LicenseManager {
    app_data: PathBuf,
}

impl LicenseManager {
    pub fn new(app_data: PathBuf) -> Self {
        Self { app_data }
    }

    fn license_file(&self) -> PathBuf {
        self.app_data.join(LICENSE_FILE)
    }

    fn load(&self) -> StoredLicense {
        fs::read_to_string(self.license_file())
            .ok()
            .and_then(|contents| serde_json::from_str(&contents).ok())
            .unwrap_or_default()
    }

    fn save(&self, license: &StoredLicense) -> Result<(), String> {
        fs::create_dir_all(&self.app_data).map_err(|error| error.to_string())?;
        let contents = serde_json::to_string_pretty(license).map_err(|error| error.to_string())?;
        fs::write(self.license_file(), contents).map_err(|error| error.to_string())
    }

    pub fn current_entitlements(&self) -> Entitlements {
        let stored = self.load();
        stored
            .tier
            .as_deref()
            .and_then(Entitlements::for_tier)
            .filter(|_| stored.key.is_some())
            .unwrap_or_else(Entitlements::free)
    }

    pub fn status(&self) -> LicenseStatus {
        let stored = self.load();
        let entitlements = self.current_entitlements();
        let activated = stored.key.is_some() && entitlements.is_pro();
        LicenseStatus {
            activated,
            tier: entitlements.id.clone(),
            name: entitlements.name.clone(),
            key_masked: stored.key.as_deref().map(mask_key),
            email: if activated { stored.email } else { None },
            entitlements,
        }
    }

    pub async fn activate(&self, raw_key: &str) -> Result<LicenseStatus, String> {
        let key = raw_key.trim().to_ascii_uppercase();
        if key.is_empty() {
            return Err(error_code("LICENSE_KEY_REQUIRED", None));
        }
        let response = reqwest::Client::builder()
            .timeout(REQUEST_TIMEOUT)
            .build()
            .map_err(|error| error_code("LICENSE_VALIDATION_FAILED", Some(&error.to_string())))?
            .post(validation_url())
            .json(&serde_json::json!({ "key": key }))
            .send()
            .await
            .map_err(|error| error_code("LICENSE_VALIDATION_FAILED", Some(&error.to_string())))?;
        if !response.status().is_success() {
            return Err(error_code(
                "LICENSE_VALIDATION_FAILED",
                Some(&format!("HTTP {}", response.status())),
            ));
        }
        let body: ValidateResponse = response
            .json()
            .await
            .map_err(|error| error_code("LICENSE_VALIDATION_FAILED", Some(&error.to_string())))?;
        if !body.valid {
            return Err(error_code("LICENSE_INVALID", None));
        }
        let tier = body
            .tier
            .or_else(|| {
                body.entitlements
                    .as_ref()
                    .map(|entitlements| entitlements.id.clone())
            })
            .ok_or_else(|| error_code("LICENSE_VALIDATION_FAILED", Some("missing tier")))?;
        let entitlements = Entitlements::for_tier(&tier)
            .ok_or_else(|| error_code("LICENSE_VALIDATION_FAILED", Some("unsupported tier")))?;
        let now = timestamp();
        self.save(&StoredLicense {
            key: Some(key),
            tier: Some(entitlements.id.clone()),
            email: body.email,
            entitlements: Some(entitlements),
            activated_at: Some(now),
            last_validated_at: Some(now),
        })?;
        Ok(self.status())
    }

    pub fn deactivate(&self) -> Result<LicenseStatus, String> {
        let path = self.license_file();
        if path.exists() {
            fs::remove_file(path).map_err(|error| error.to_string())?;
        }
        Ok(self.status())
    }

    pub async fn refresh(&self) {
        let stored = self.load();
        let Some(key) = stored.key.clone() else {
            return;
        };
        let Ok(client) = reqwest::Client::builder().timeout(REQUEST_TIMEOUT).build() else {
            return;
        };
        let Ok(response) = client
            .post(validation_url())
            .json(&serde_json::json!({ "key": key }))
            .send()
            .await
        else {
            return;
        };
        if !response.status().is_success() {
            return;
        }
        let Ok(body) = response.json::<ValidateResponse>().await else {
            return;
        };
        if !body.valid {
            let _ = self.deactivate();
            return;
        }
        let Some(tier) = body.tier.or_else(|| {
            body.entitlements
                .as_ref()
                .map(|entitlements| entitlements.id.clone())
        }) else {
            return;
        };
        let Some(entitlements) = Entitlements::for_tier(&tier) else {
            return;
        };
        let _ = self.save(&StoredLicense {
            key: stored.key,
            tier: Some(entitlements.id.clone()),
            email: body.email.or(stored.email),
            entitlements: Some(entitlements),
            activated_at: stored.activated_at,
            last_validated_at: Some(timestamp()),
        });
    }
}

pub fn error_code(code: &str, detail: Option<&str>) -> String {
    let params = detail
        .map(|value| serde_json::json!({ "detail": value }))
        .unwrap_or_else(|| serde_json::json!({}));
    serde_json::json!({ "code": code, "params": params }).to_string()
}

fn mask_key(key: &str) -> String {
    let parts: Vec<_> = key.split('-').collect();
    if parts.len() >= 2 {
        format!("{}-•••••-•••••-•••••-{}", parts[0], parts[parts.len() - 1])
    } else {
        "•••••".into()
    }
}

fn timestamp() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn free_entitlements_block_pro_features() {
        let free = Entitlements::free();
        assert!(free.safe_cleaning);
        assert!(free.manual_clean);
        assert!(!free.pro_rules);
        assert!(!free.scheduled_clean);
        assert!(!free.auto_clean);
        assert!(!free.duplicate_finder);
        assert!(!free.large_file_finder);
    }

    #[test]
    fn pro_entitlements_unlock_pro_features() {
        let pro = Entitlements::for_tier("pro").unwrap();
        assert!(pro.is_pro());
        assert!(pro.pro_rules);
        assert!(pro.scheduled_clean);
        assert!(pro.auto_clean);
        assert!(pro.duplicate_finder);
        assert!(pro.large_file_finder);
    }

    #[test]
    fn key_masking_preserves_prefix_and_suffix() {
        assert_eq!(
            mask_key("DUST-ABCDE-FGHIJ-KLMNO-PQRST"),
            "DUST-•••••-•••••-•••••-PQRST"
        );
    }

    #[test]
    fn product_config_provides_license_validation_url() {
        assert_eq!(
            validation_url(),
            "https://dustonic.com/api/license/validate"
        );
    }
}
