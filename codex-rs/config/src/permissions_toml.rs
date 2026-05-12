use std::collections::BTreeMap;

use codex_network_proxy::NetworkDomainPermission as ProxyNetworkDomainPermission;
use codex_network_proxy::NetworkMode;
use codex_network_proxy::NetworkProxyConfig;
use codex_network_proxy::NetworkUnixSocketPermission as ProxyNetworkUnixSocketPermission;
use codex_network_proxy::normalize_host;
use codex_protocol::permissions::FileSystemAccessMode;
use schemars::JsonSchema;
use serde::Deserialize;
use serde::Serialize;
use thiserror::Error;

#[derive(Serialize, Deserialize, Debug, Clone, Default, PartialEq, Eq, JsonSchema)]
pub struct PermissionsToml {
    #[serde(flatten)]
    pub entries: BTreeMap<String, PermissionProfileToml>,
}

impl PermissionsToml {
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    pub fn resolve_profile<F>(
        &self,
        profile_name: &str,
        mut parent_profile: F,
    ) -> Result<PermissionProfileToml, PermissionProfileResolutionError>
    where
        F: FnMut(&str) -> Option<PermissionProfileToml>,
    {
        let mut stack = Vec::new();
        let mut resolved_profile = None;
        let mut next_profile_name = profile_name.to_string();
        let mut referenced_by: Option<String> = None;

        loop {
            if let Some(cycle_start) = stack.iter().position(|name| name == &next_profile_name) {
                let cycle = stack[cycle_start..]
                    .iter()
                    .cloned()
                    .chain(std::iter::once(next_profile_name))
                    .collect::<Vec<_>>();
                return Err(PermissionProfileResolutionError::Cycle { cycle });
            }

            let profile = self
                .entries
                .get(&next_profile_name)
                .cloned()
                .or_else(|| parent_profile(&next_profile_name))
                .ok_or_else(|| {
                    referenced_by.as_deref().map_or_else(
                        || PermissionProfileResolutionError::UndefinedProfile {
                            profile_name: next_profile_name.clone(),
                        },
                        |referenced_by| PermissionProfileResolutionError::UndefinedParent {
                            profile_name: referenced_by.to_string(),
                            parent_profile_name: next_profile_name.clone(),
                        },
                    )
                })?;

            if let Some(parent_profile_name) = profile.extends.clone() {
                stack.push(next_profile_name.clone());
                resolved_profile = Some(match resolved_profile {
                    Some(child) => merge_permission_profiles(profile, child),
                    None => profile,
                });
                referenced_by = Some(next_profile_name);
                next_profile_name = parent_profile_name;
                continue;
            }

            return Ok(match resolved_profile {
                Some(child) => merge_permission_profiles(profile, child),
                None => profile,
            });
        }
    }
}

#[derive(Serialize, Deserialize, Debug, Clone, Default, PartialEq, Eq, JsonSchema)]
#[schemars(deny_unknown_fields)]
pub struct PermissionProfileToml {
    pub extends: Option<String>,
    pub filesystem: Option<FilesystemPermissionsToml>,
    pub network: Option<NetworkToml>,
}

#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum PermissionProfileResolutionError {
    #[error("default_permissions refers to undefined profile `{profile_name}`")]
    UndefinedProfile { profile_name: String },
    #[error(
        "permissions profile `{profile_name}` extends undefined profile `{parent_profile_name}`"
    )]
    UndefinedParent {
        profile_name: String,
        parent_profile_name: String,
    },
    #[error(
        "permissions profile inheritance cycle detected: {}",
        cycle.join(" -> ")
    )]
    Cycle { cycle: Vec<String> },
}

fn merge_permission_profiles(
    parent: PermissionProfileToml,
    child: PermissionProfileToml,
) -> PermissionProfileToml {
    PermissionProfileToml {
        extends: child.extends,
        filesystem: merge_filesystem_permissions(parent.filesystem, child.filesystem),
        network: merge_network_permissions(parent.network, child.network),
    }
}

fn merge_filesystem_permissions(
    parent: Option<FilesystemPermissionsToml>,
    child: Option<FilesystemPermissionsToml>,
) -> Option<FilesystemPermissionsToml> {
    match (parent, child) {
        (Some(mut parent), Some(child)) => {
            if child.glob_scan_max_depth.is_some() {
                parent.glob_scan_max_depth = child.glob_scan_max_depth;
            }
            for (path, child_permission) in child.entries {
                match (parent.entries.remove(&path), child_permission) {
                    (
                        Some(FilesystemPermissionToml::Scoped(mut parent_entries)),
                        FilesystemPermissionToml::Scoped(child_entries),
                    ) => {
                        parent_entries.extend(child_entries);
                        parent
                            .entries
                            .insert(path, FilesystemPermissionToml::Scoped(parent_entries));
                    }
                    (_, child_permission) => {
                        parent.entries.insert(path, child_permission);
                    }
                }
            }
            Some(parent)
        }
        (Some(parent), None) => Some(parent),
        (None, Some(child)) => Some(child),
        (None, None) => None,
    }
}

fn merge_network_permissions(
    parent: Option<NetworkToml>,
    child: Option<NetworkToml>,
) -> Option<NetworkToml> {
    match (parent, child) {
        (Some(mut parent), Some(child)) => {
            parent.enabled = child.enabled.or(parent.enabled);
            parent.proxy_url = child.proxy_url.or(parent.proxy_url);
            parent.enable_socks5 = child.enable_socks5.or(parent.enable_socks5);
            parent.socks_url = child.socks_url.or(parent.socks_url);
            parent.enable_socks5_udp = child.enable_socks5_udp.or(parent.enable_socks5_udp);
            parent.allow_upstream_proxy =
                child.allow_upstream_proxy.or(parent.allow_upstream_proxy);
            parent.dangerously_allow_non_loopback_proxy = child
                .dangerously_allow_non_loopback_proxy
                .or(parent.dangerously_allow_non_loopback_proxy);
            parent.dangerously_allow_all_unix_sockets = child
                .dangerously_allow_all_unix_sockets
                .or(parent.dangerously_allow_all_unix_sockets);
            parent.mode = child.mode.or(parent.mode);
            parent.allow_local_binding = child.allow_local_binding.or(parent.allow_local_binding);
            parent.domains = merge_network_domain_permissions(parent.domains, child.domains);
            parent.unix_sockets =
                merge_network_unix_socket_permissions(parent.unix_sockets, child.unix_sockets);
            Some(parent)
        }
        (Some(parent), None) => Some(parent),
        (None, Some(child)) => Some(child),
        (None, None) => None,
    }
}

fn merge_network_domain_permissions(
    parent: Option<NetworkDomainPermissionsToml>,
    child: Option<NetworkDomainPermissionsToml>,
) -> Option<NetworkDomainPermissionsToml> {
    match (parent, child) {
        (Some(parent), Some(child)) => {
            let mut entries = BTreeMap::new();
            for (pattern, permission) in parent.entries {
                entries.insert(normalize_host(&pattern), permission);
            }
            for (pattern, permission) in child.entries {
                entries.insert(normalize_host(&pattern), permission);
            }
            Some(NetworkDomainPermissionsToml { entries })
        }
        (Some(parent), None) => Some(parent),
        (None, Some(child)) => Some(child),
        (None, None) => None,
    }
}

fn merge_network_unix_socket_permissions(
    parent: Option<NetworkUnixSocketPermissionsToml>,
    child: Option<NetworkUnixSocketPermissionsToml>,
) -> Option<NetworkUnixSocketPermissionsToml> {
    match (parent, child) {
        (Some(mut parent), Some(child)) => {
            parent.entries.extend(child.entries);
            Some(parent)
        }
        (Some(parent), None) => Some(parent),
        (None, Some(child)) => Some(child),
        (None, None) => None,
    }
}

#[derive(Serialize, Deserialize, Debug, Clone, Default, PartialEq, Eq, JsonSchema)]
pub struct FilesystemPermissionsToml {
    /// Optional maximum depth for expanding unreadable glob patterns on
    /// platforms that snapshot glob matches before sandbox startup.
    #[schemars(range(min = 1))]
    pub glob_scan_max_depth: Option<usize>,
    #[serde(flatten)]
    pub entries: BTreeMap<String, FilesystemPermissionToml>,
}

impl FilesystemPermissionsToml {
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq, JsonSchema)]
#[serde(untagged)]
pub enum FilesystemPermissionToml {
    Access(FileSystemAccessMode),
    Scoped(BTreeMap<String, FileSystemAccessMode>),
}

#[derive(Serialize, Deserialize, Debug, Clone, Default, PartialEq, Eq, JsonSchema)]
pub struct NetworkDomainPermissionsToml {
    #[serde(flatten)]
    pub entries: BTreeMap<String, NetworkDomainPermissionToml>,
}

impl NetworkDomainPermissionsToml {
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    pub fn allowed_domains(&self) -> Option<Vec<String>> {
        let allowed_domains: Vec<String> = self
            .entries
            .iter()
            .filter(|(_, permission)| matches!(permission, NetworkDomainPermissionToml::Allow))
            .map(|(pattern, _)| pattern.clone())
            .collect();
        (!allowed_domains.is_empty()).then_some(allowed_domains)
    }

    pub fn denied_domains(&self) -> Option<Vec<String>> {
        let denied_domains: Vec<String> = self
            .entries
            .iter()
            .filter(|(_, permission)| matches!(permission, NetworkDomainPermissionToml::Deny))
            .map(|(pattern, _)| pattern.clone())
            .collect();
        (!denied_domains.is_empty()).then_some(denied_domains)
    }
}

#[derive(
    Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, JsonSchema,
)]
#[serde(rename_all = "lowercase")]
pub enum NetworkDomainPermissionToml {
    Allow,
    Deny,
}

impl std::fmt::Display for NetworkDomainPermissionToml {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let permission = match self {
            Self::Allow => "allow",
            Self::Deny => "deny",
        };
        f.write_str(permission)
    }
}

#[derive(Serialize, Deserialize, Debug, Clone, Default, PartialEq, Eq, JsonSchema)]
pub struct NetworkUnixSocketPermissionsToml {
    #[serde(flatten)]
    pub entries: BTreeMap<String, NetworkUnixSocketPermissionToml>,
}

impl NetworkUnixSocketPermissionsToml {
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    pub fn allow_unix_sockets(&self) -> Vec<String> {
        self.entries
            .iter()
            .filter(|(_, permission)| matches!(permission, NetworkUnixSocketPermissionToml::Allow))
            .map(|(path, _)| path.clone())
            .collect()
    }
}

#[derive(
    Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, JsonSchema,
)]
#[serde(rename_all = "lowercase")]
pub enum NetworkUnixSocketPermissionToml {
    Allow,
    None,
}

impl std::fmt::Display for NetworkUnixSocketPermissionToml {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let permission = match self {
            Self::Allow => "allow",
            Self::None => "none",
        };
        f.write_str(permission)
    }
}

#[derive(Serialize, Deserialize, Debug, Clone, Default, PartialEq, Eq, JsonSchema)]
#[schemars(deny_unknown_fields)]
pub struct NetworkToml {
    pub enabled: Option<bool>,
    pub proxy_url: Option<String>,
    pub enable_socks5: Option<bool>,
    pub socks_url: Option<String>,
    pub enable_socks5_udp: Option<bool>,
    pub allow_upstream_proxy: Option<bool>,
    pub dangerously_allow_non_loopback_proxy: Option<bool>,
    pub dangerously_allow_all_unix_sockets: Option<bool>,
    #[schemars(with = "Option<NetworkModeSchema>")]
    pub mode: Option<NetworkMode>,
    pub domains: Option<NetworkDomainPermissionsToml>,
    pub unix_sockets: Option<NetworkUnixSocketPermissionsToml>,
    pub allow_local_binding: Option<bool>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, JsonSchema)]
#[serde(rename_all = "lowercase")]
enum NetworkModeSchema {
    Limited,
    Full,
}

impl NetworkToml {
    pub fn apply_to_network_proxy_config(&self, config: &mut NetworkProxyConfig) {
        if let Some(enabled) = self.enabled {
            config.network.enabled = enabled;
        }
        if let Some(proxy_url) = self.proxy_url.as_ref() {
            config.network.proxy_url = proxy_url.clone();
        }
        if let Some(enable_socks5) = self.enable_socks5 {
            config.network.enable_socks5 = enable_socks5;
        }
        if let Some(socks_url) = self.socks_url.as_ref() {
            config.network.socks_url = socks_url.clone();
        }
        if let Some(enable_socks5_udp) = self.enable_socks5_udp {
            config.network.enable_socks5_udp = enable_socks5_udp;
        }
        if let Some(allow_upstream_proxy) = self.allow_upstream_proxy {
            config.network.allow_upstream_proxy = allow_upstream_proxy;
        }
        if let Some(dangerously_allow_non_loopback_proxy) =
            self.dangerously_allow_non_loopback_proxy
        {
            config.network.dangerously_allow_non_loopback_proxy =
                dangerously_allow_non_loopback_proxy;
        }
        if let Some(dangerously_allow_all_unix_sockets) = self.dangerously_allow_all_unix_sockets {
            config.network.dangerously_allow_all_unix_sockets = dangerously_allow_all_unix_sockets;
        }
        if let Some(mode) = self.mode {
            config.network.mode = mode;
        }
        if let Some(domains) = self.domains.as_ref() {
            overlay_network_domain_permissions(config, domains);
        }
        if let Some(unix_sockets) = self.unix_sockets.as_ref() {
            let mut proxy_unix_sockets = config.network.unix_sockets.take().unwrap_or_default();
            for (path, permission) in &unix_sockets.entries {
                let permission = match permission {
                    NetworkUnixSocketPermissionToml::Allow => {
                        ProxyNetworkUnixSocketPermission::Allow
                    }
                    NetworkUnixSocketPermissionToml::None => ProxyNetworkUnixSocketPermission::None,
                };
                proxy_unix_sockets.entries.insert(path.clone(), permission);
            }
            config.network.unix_sockets =
                (!proxy_unix_sockets.entries.is_empty()).then_some(proxy_unix_sockets);
        }
        if let Some(allow_local_binding) = self.allow_local_binding {
            config.network.allow_local_binding = allow_local_binding;
        }
    }

    pub fn to_network_proxy_config(&self) -> NetworkProxyConfig {
        let mut config = NetworkProxyConfig::default();
        self.apply_to_network_proxy_config(&mut config);
        config
    }
}

pub fn overlay_network_domain_permissions(
    config: &mut NetworkProxyConfig,
    domains: &NetworkDomainPermissionsToml,
) {
    for (pattern, permission) in &domains.entries {
        let permission = match permission {
            NetworkDomainPermissionToml::Allow => ProxyNetworkDomainPermission::Allow,
            NetworkDomainPermissionToml::Deny => ProxyNetworkDomainPermission::Deny,
        };
        config
            .network
            .upsert_domain_permission(pattern.clone(), permission, normalize_host);
    }
}
