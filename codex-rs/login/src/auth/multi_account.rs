use std::collections::HashSet;
use std::fs;
use std::fs::File;
use std::io::Write;
use std::path::Path;
use std::path::PathBuf;
use std::time::Duration;

use chrono::DateTime;
use chrono::Utc;
use codex_app_server_protocol::AuthMode as ApiAuthMode;
use codex_config::types::AuthCredentialsStoreMode;
use serde::Deserialize;
use serde::Serialize;

use super::manager::CodexAuth;
use super::manager::RefreshTokenError;
use super::manager::request_chatgpt_token_refresh;
use crate::auth::AuthDotJson;
use crate::default_client::create_client;
use crate::token_data::TokenData;
use crate::token_data::parse_chatgpt_jwt_claims;
use crate::token_data::parse_jwt_expiration;

const DEFAULT_ACCOUNTS_FILE: &str = ".config/opencode/codex-accounts.json";
const DEFAULT_STATE_FILE: &str = ".codex-accounts.state.json";
const BB_CODEX_ACCOUNTS_FILE_ENV: &str = "BB_CODEX_ACCOUNTS_FILE";
const BB_CODEX_DEV_ACCOUNTS_FILE_ENV: &str = "BB_CODEX_DEV_ACCOUNTS_FILE";
const BB_CODEX_ACCOUNT_ENV: &str = "BB_CODEX_ACCOUNT";
const BB_CODEX_DEV_ACCOUNT_ENV: &str = "BB_CODEX_DEV_ACCOUNT";
const RATE_LIMIT_COOLDOWN: Duration = Duration::from_secs(15 * 60);
const REFRESH_SKEW: Duration = Duration::from_secs(60);

#[derive(Debug, Clone)]
pub struct MultiAccountAuth {
    pub account_id: String,
    pub auth: CodexAuth,
}

#[derive(Debug, Clone)]
pub(crate) struct MultiAccountStore {
    accounts_path: PathBuf,
    state_path: PathBuf,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
struct AccountRegistry {
    #[serde(default = "registry_version")]
    version: u64,
    #[serde(default)]
    selection: AccountSelection,
    #[serde(default)]
    accounts: Vec<AccountRecord>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
struct AccountSelection {
    #[serde(default)]
    strategy: SelectionStrategy,
    default_account_id: Option<String>,
}

impl Default for AccountSelection {
    fn default() -> Self {
        Self {
            strategy: SelectionStrategy::RoundRobin,
            default_account_id: None,
        }
    }
}

#[derive(Debug, Clone, Copy, Default, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
enum SelectionStrategy {
    Default,
    #[default]
    RoundRobin,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
struct AccountRecord {
    id: String,
    #[serde(rename = "type")]
    account_type: String,
    access_token: Option<String>,
    refresh_token: Option<String>,
    id_token: Option<String>,
    account_id: Option<String>,
    email: Option<String>,
    expires_at: Option<u64>,
    last_refresh: Option<String>,
    last_used: Option<u64>,
    #[serde(default)]
    usage_count: u64,
    #[serde(default = "default_enabled")]
    enabled: bool,
    #[serde(default)]
    auth_invalid: bool,
    auth_invalidated_at: Option<u64>,
    rate_limited_until: Option<u64>,
    limit_error: Option<String>,
    #[serde(default)]
    include_models: Vec<String>,
    #[serde(default)]
    exclude_models: Vec<String>,
    #[serde(default)]
    available_models: Vec<String>,
    available_models_fetched_at: Option<u64>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
struct AccountState {
    version: u64,
    cursor: usize,
}

impl Default for AccountState {
    fn default() -> Self {
        Self {
            version: 1,
            cursor: 0,
        }
    }
}

#[derive(Debug, Clone)]
struct SelectedAccount {
    account: AccountRecord,
    next_state: AccountState,
    advance_state: bool,
}

impl MultiAccountStore {
    pub(crate) fn new(codex_home: &Path) -> Self {
        let accounts_path = accounts_path(codex_home);
        let state_path = accounts_path
            .parent()
            .map(|parent| parent.join(DEFAULT_STATE_FILE))
            .unwrap_or_else(|| codex_home.join(DEFAULT_STATE_FILE));
        Self {
            accounts_path,
            state_path,
        }
    }

    pub(crate) fn is_available(&self) -> bool {
        self.load_registry().is_ok_and(|registry| {
            registry
                .accounts
                .iter()
                .any(AccountRecord::has_oauth_credentials)
        })
    }

    pub(crate) async fn select_auth_for_model(
        &self,
        model_id: &str,
        excluded_account_ids: &[String],
        auth_credentials_store_mode: AuthCredentialsStoreMode,
        chatgpt_base_url: Option<&str>,
    ) -> std::io::Result<Option<MultiAccountAuth>> {
        let mut excluded = excluded_account_ids.iter().cloned().collect::<HashSet<_>>();
        loop {
            let Some(selected) = self.select_account(model_id, &excluded)? else {
                return Ok(None);
            };
            let account_id = selected.account.id.clone();
            if selected.advance_state {
                self.save_state(&selected.next_state)?;
            }

            match self.ensure_fresh_account(selected.account).await {
                Ok(account) => {
                    self.mark_used(&account.id)?;
                    let auth = account
                        .to_codex_auth(
                            &self.accounts_path,
                            auth_credentials_store_mode,
                            chatgpt_base_url,
                        )
                        .await?;
                    return Ok(Some(MultiAccountAuth { account_id, auth }));
                }
                Err(RefreshTokenError::Permanent(err)) => {
                    self.mark_auth_invalid(&account_id, Some(&err.to_string()))?;
                    excluded.insert(account_id);
                }
                Err(RefreshTokenError::Transient(err)) => return Err(err),
            }
        }
    }

    pub(crate) fn mark_rate_limited(
        &self,
        account_id: &str,
        message: Option<&str>,
        retry_after: Option<Duration>,
    ) -> std::io::Result<()> {
        let until =
            unix_timestamp_millis() + duration_millis(retry_after.unwrap_or(RATE_LIMIT_COOLDOWN));
        self.update_account(account_id, |account| {
            account.rate_limited_until = Some(until);
            account.limit_error = message.map(str::to_string);
        })
    }

    pub(crate) fn mark_auth_invalid(
        &self,
        account_id: &str,
        message: Option<&str>,
    ) -> std::io::Result<()> {
        self.update_account(account_id, |account| {
            account.auth_invalid = true;
            account.auth_invalidated_at = Some(unix_timestamp_millis());
            account.limit_error = message.map(str::to_string);
        })
    }

    fn select_account(
        &self,
        model_id: &str,
        excluded_account_ids: &HashSet<String>,
    ) -> std::io::Result<Option<SelectedAccount>> {
        let registry = match self.load_registry() {
            Ok(registry) => registry,
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(err) => return Err(err),
        };
        if registry.accounts.is_empty() {
            return Ok(None);
        }
        let forced_account_id = forced_account_id();
        let eligible = registry
            .accounts
            .iter()
            .filter(|account| !excluded_account_ids.contains(&account.id))
            .filter(|account| account.supports_model(model_id, unix_timestamp_millis()))
            .collect::<Vec<_>>();

        if let Some(forced_account_id) = forced_account_id {
            let Some(account) = registry
                .accounts
                .iter()
                .find(|account| account.id == forced_account_id)
            else {
                return Err(std::io::Error::other(format!(
                    "Forced account \"{forced_account_id}\" was not found in the account registry."
                )));
            };
            if !account.supports_model(model_id, unix_timestamp_millis()) {
                return Err(std::io::Error::other(format!(
                    "Forced account \"{forced_account_id}\" is not enabled for model \"{model_id}\"."
                )));
            }
            return Ok(Some(SelectedAccount {
                account: account.clone(),
                next_state: self.load_state()?,
                advance_state: false,
            }));
        }

        if eligible.is_empty() {
            return Err(std::io::Error::other(format!(
                "No enabled Codex OAuth account is configured for model \"{model_id}\"."
            )));
        }

        let state = self.load_state()?;
        if registry.selection.strategy == SelectionStrategy::Default {
            let Some(account) = registry
                .selection
                .default_account_id
                .as_ref()
                .and_then(|id| eligible.iter().find(|account| &account.id == id))
                .or_else(|| eligible.first())
            else {
                return Ok(None);
            };
            return Ok(Some(SelectedAccount {
                account: (*account).clone(),
                next_state: state,
                advance_state: false,
            }));
        }

        let index = state.cursor % eligible.len();
        Ok(Some(SelectedAccount {
            account: (*eligible[index]).clone(),
            next_state: AccountState {
                version: 1,
                cursor: (state.cursor + 1) % eligible.len(),
            },
            advance_state: true,
        }))
    }

    async fn ensure_fresh_account(
        &self,
        mut account: AccountRecord,
    ) -> Result<AccountRecord, RefreshTokenError> {
        if !account.needs_refresh() {
            return Ok(account);
        }
        let Some(refresh_token) = account
            .refresh_token
            .clone()
            .filter(|token| !token.is_empty())
        else {
            return Err(RefreshTokenError::Permanent(
                codex_protocol::auth::RefreshTokenFailedError::new(
                    codex_protocol::auth::RefreshTokenFailedReason::Other,
                    "Codex OAuth account is missing a refresh token.".to_string(),
                ),
            ));
        };
        let refresh_response =
            request_chatgpt_token_refresh(refresh_token, &create_client()).await?;
        if let Some(id_token) = refresh_response.id_token {
            account.id_token = Some(id_token);
        }
        if let Some(access_token) = refresh_response.access_token {
            account.expires_at = token_expiration_millis(&access_token);
            account.access_token = Some(access_token);
        }
        if let Some(refresh_token) = refresh_response.refresh_token {
            account.refresh_token = Some(refresh_token);
        }
        account.last_refresh = Some(Utc::now().to_rfc3339());
        let updated = account.clone();
        self.update_account(&account.id, |account| *account = updated.clone())?;
        Ok(account)
    }

    fn mark_used(&self, account_id: &str) -> std::io::Result<()> {
        self.update_account(account_id, |account| {
            account.last_used = Some(unix_timestamp_millis());
            account.usage_count = account.usage_count.saturating_add(1);
            account.rate_limited_until = None;
            account.limit_error = None;
        })
    }

    fn update_account(
        &self,
        account_id: &str,
        update: impl FnOnce(&mut AccountRecord),
    ) -> std::io::Result<()> {
        let mut registry = self.load_registry()?;
        let Some(account) = registry
            .accounts
            .iter_mut()
            .find(|account| account.id == account_id)
        else {
            return Err(std::io::Error::new(
                std::io::ErrorKind::NotFound,
                format!("OpenCode account not found: {account_id}"),
            ));
        };
        update(account);
        self.save_registry(&registry)
    }

    fn load_registry(&self) -> std::io::Result<AccountRegistry> {
        let raw = fs::read_to_string(&self.accounts_path)?;
        serde_json::from_str(&raw).map_err(std::io::Error::other)
    }

    fn save_registry(&self, registry: &AccountRegistry) -> std::io::Result<()> {
        write_json_secure(&self.accounts_path, registry)
    }

    fn load_state(&self) -> std::io::Result<AccountState> {
        match fs::read_to_string(&self.state_path) {
            Ok(raw) => serde_json::from_str(&raw).map_err(std::io::Error::other),
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(AccountState::default()),
            Err(err) => Err(err),
        }
    }

    fn save_state(&self, state: &AccountState) -> std::io::Result<()> {
        write_json_secure(&self.state_path, state)
    }
}

impl AccountRecord {
    fn has_oauth_credentials(&self) -> bool {
        self.account_type == "oauth"
            && self
                .access_token
                .as_deref()
                .is_some_and(|token| !token.is_empty())
            && self
                .refresh_token
                .as_deref()
                .is_some_and(|token| !token.is_empty())
            && self
                .id_token
                .as_deref()
                .is_some_and(|token| !token.is_empty())
            && self.account_id.as_deref().is_some_and(|id| !id.is_empty())
    }

    fn supports_model(&self, model_id: &str, now_millis: u64) -> bool {
        self.account_type == "oauth"
            && self.enabled
            && self.has_oauth_credentials()
            && !self.auth_invalid
            && self
                .rate_limited_until
                .is_none_or(|until| until <= now_millis)
            && self.model_allowed(model_id)
    }

    fn model_allowed(&self, model_id: &str) -> bool {
        if !self.include_models.is_empty()
            && !self
                .include_models
                .iter()
                .any(|pattern| model_matches_pattern(model_id, pattern))
        {
            return false;
        }
        if self
            .exclude_models
            .iter()
            .any(|pattern| model_matches_pattern(model_id, pattern))
        {
            return false;
        }
        if self.include_models.is_empty()
            && !self.available_models.is_empty()
            && !selectable_model_ids(model_id)
                .iter()
                .any(|candidate| self.available_models.iter().any(|model| model == candidate))
        {
            return false;
        }
        true
    }

    fn needs_refresh(&self) -> bool {
        let Some(access_token) = self.access_token.as_deref() else {
            return true;
        };
        match parse_jwt_expiration(access_token) {
            Ok(Some(expires_at)) => expires_at <= Utc::now() + REFRESH_SKEW,
            Ok(None) | Err(_) => false,
        }
    }

    async fn to_codex_auth(
        &self,
        codex_home: &Path,
        auth_credentials_store_mode: AuthCredentialsStoreMode,
        chatgpt_base_url: Option<&str>,
    ) -> std::io::Result<CodexAuth> {
        let id_token = required_field(self.id_token.as_deref(), "idToken")?;
        let access_token = required_field(self.access_token.as_deref(), "accessToken")?;
        let refresh_token = required_field(self.refresh_token.as_deref(), "refreshToken")?;
        let account_id = required_field(self.account_id.as_deref(), "accountId")?;
        let mut token_info = parse_chatgpt_jwt_claims(id_token).map_err(std::io::Error::other)?;
        token_info.chatgpt_account_id = Some(account_id.to_string());
        if token_info.email.is_none() {
            token_info.email.clone_from(&self.email);
        }
        let last_refresh = self
            .last_refresh
            .as_deref()
            .and_then(|value| DateTime::parse_from_rfc3339(value).ok())
            .map(|value| value.with_timezone(&Utc))
            .unwrap_or_else(Utc::now);
        let auth_dot_json = AuthDotJson {
            auth_mode: Some(ApiAuthMode::ChatgptAuthTokens),
            openai_api_key: None,
            tokens: Some(TokenData {
                id_token: token_info,
                access_token: access_token.to_string(),
                refresh_token: refresh_token.to_string(),
                account_id: Some(account_id.to_string()),
            }),
            last_refresh: Some(last_refresh),
            agent_identity: None,
        };
        CodexAuth::from_auth_dot_json(
            codex_home,
            auth_dot_json,
            auth_credentials_store_mode,
            chatgpt_base_url,
        )
        .await
    }
}

fn accounts_path(codex_home: &Path) -> PathBuf {
    std::env::var_os(BB_CODEX_ACCOUNTS_FILE_ENV)
        .or_else(|| std::env::var_os(BB_CODEX_DEV_ACCOUNTS_FILE_ENV))
        .map(PathBuf::from)
        .unwrap_or_else(|| home_dir(codex_home).join(DEFAULT_ACCOUNTS_FILE))
}

fn home_dir(codex_home: &Path) -> PathBuf {
    std::env::var_os("HOME")
        .map(PathBuf::from)
        .or_else(|| codex_home.parent().map(Path::to_path_buf))
        .unwrap_or_else(|| PathBuf::from("."))
}

fn forced_account_id() -> Option<String> {
    std::env::var(BB_CODEX_ACCOUNT_ENV)
        .or_else(|_| std::env::var(BB_CODEX_DEV_ACCOUNT_ENV))
        .ok()
        .filter(|value| !value.trim().is_empty())
}

fn required_field<'a>(value: Option<&'a str>, field: &str) -> std::io::Result<&'a str> {
    value
        .filter(|value| !value.is_empty())
        .ok_or_else(|| std::io::Error::other(format!("Codex OAuth account is missing {field}.")))
}

fn model_matches_pattern(model_id: &str, pattern: &str) -> bool {
    if pattern == "*" || pattern.eq_ignore_ascii_case(model_id) {
        return true;
    }
    let Some((prefix, suffix)) = pattern.split_once('*') else {
        return false;
    };
    model_id.starts_with(prefix) && model_id.ends_with(suffix)
}

fn selectable_model_ids(model_id: &str) -> Vec<String> {
    let mut candidates = vec![model_id.to_string()];
    if let Some(base) = model_id.strip_suffix("-codex-fast") {
        candidates.push(format!("{base}-fast"));
        candidates.push(base.to_string());
    }
    if let Some(base) = model_id.strip_suffix("-fast") {
        candidates.push(base.to_string());
    }
    if let Some(base) = model_id.strip_suffix("-codex") {
        candidates.push(base.to_string());
    }
    if model_id == "gpt-5.5-fast" {
        candidates.push("gpt-5.5".to_string());
    }
    candidates
}

fn token_expiration_millis(access_token: &str) -> Option<u64> {
    parse_jwt_expiration(access_token)
        .ok()
        .flatten()
        .and_then(|expires_at| u64::try_from(expires_at.timestamp_millis()).ok())
}

fn write_json_secure<T: Serialize>(path: &Path, value: &T) -> std::io::Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let tmp_path = path.with_extension(format!(
        "tmp.{}.{}",
        std::process::id(),
        unix_timestamp_millis()
    ));
    let mut file = File::create(&tmp_path)?;
    serde_json::to_writer_pretty(&mut file, value).map_err(std::io::Error::other)?;
    file.write_all(b"\n")?;
    file.flush()?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&tmp_path, fs::Permissions::from_mode(0o600))?;
    }
    fs::rename(tmp_path, path)?;
    Ok(())
}

fn unix_timestamp_millis() -> u64 {
    Utc::now().timestamp_millis().try_into().unwrap_or_default()
}

fn duration_millis(duration: Duration) -> u64 {
    duration.as_millis().try_into().unwrap_or(u64::MAX)
}

fn registry_version() -> u64 {
    2
}

fn default_enabled() -> bool {
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wildcard_model_patterns_match_supported_aliases() {
        assert!(model_matches_pattern("gpt-5.5", "gpt-*"));
        assert!(!model_matches_pattern("gpt-5.5", "o3-*"));
        assert!(selectable_model_ids("gpt-5.5-codex-fast").contains(&"gpt-5.5".to_string()));
    }
}
