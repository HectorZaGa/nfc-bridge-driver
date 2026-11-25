//! Gestión de tokens efímeros de vinculación (QR / Link único), dispositivos de confianza
//! persistentes (`device_token`) y configuración del canal Cloud Relay.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::UdpSocket;
use std::path::PathBuf;
use std::sync::Mutex;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use subtle::ConstantTimeEq;

use crate::ipc::events::TrustedDeviceInfo;
use ring::aead::{Aad, LessSafeKey, Nonce, UnboundKey, AES_256_GCM};
use ring::digest;

const QR_PAIR_TTL_SECS: u64 = 30;
const RELAY_LINK_TTL_SECS: u64 = 90;
const RELAY_ENVELOPE_DOMAIN: &[u8] = b"NFC-BRIDGE-RELAY-LINK-ENVELOPE-V1|v1|2026";
const RELAY_ENVELOPE_AAD: &[u8] = b"nb-link-v1";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrustedDevice {
    pub device_token: String,
    pub device_name: String,
    pub created_unix: u64,
    #[serde(default)]
    pub mobile_id: Option<String>,
    #[serde(default)]
    pub device_os: Option<String>,
    #[serde(default)]
    pub transport: Option<String>,
    #[serde(default)]
    pub endpoint: Option<String>,
    #[serde(default)]
    pub custom_name: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
struct RelayConfigFile {
    pub relay_url: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
struct HelloSynPayload {
    #[serde(default)]
    device_name: Option<String>,
    #[serde(default)]
    mobile_id: Option<String>,
    #[serde(default)]
    device_os: Option<String>,
    #[serde(default)]
    transport: Option<String>,
    #[serde(default)]
    pair_token: Option<String>,
    #[serde(default)]
    device_token: Option<String>,
    #[serde(default)]
    paused: Option<bool>,
}

#[derive(Debug, Clone)]
pub struct HelloAuthResult {
    pub outcome: HelloAuthOutcome,
    pub device_id: Option<String>,
    pub mobile_id: Option<String>,
    pub device_os: String,
    pub transport: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HelloAuthOutcome {
    Paired {
        device_name: Option<String>,
        new_device_token: String,
    },
    Trusted {
        device_name: Option<String>,
    },
    LegacyAllowed {
        device_name: Option<String>,
    },
    Rejected {
        reason: String,
    },
}

struct EphemeralEntry {
    expires_at: Instant,
}

pub struct PairingManager {
    data_dir: PathBuf,
    pc_name: String,
    ephemeral_tokens: Mutex<HashMap<String, EphemeralEntry>>,
    trusted_devices: Mutex<Vec<TrustedDevice>>,
    relay_channel: Mutex<String>,
    relay_host_secret: Mutex<String>,
    relay_url: Mutex<Option<String>>,
    tcp_cert_sha256: Mutex<Option<String>>,
}

impl PairingManager {
    pub fn new(pc_name: String) -> Self {
        let dir = PathBuf::from(
            std::env::var("ProgramData").unwrap_or_else(|_| "C:\\ProgramData".to_string()),
        )
        .join("NFC Bridge");
        Self::with_data_dir(dir, pc_name)
    }

    pub fn with_data_dir(data_dir: PathBuf, pc_name: String) -> Self {
        let trusted = load_trusted_devices(&data_dir.join("trusted_devices.json"));
        let channel = load_or_create_channel(&data_dir.join("relay_channel.txt"));
        let host_secret = load_or_create_host_secret(&data_dir.join("relay_host_secret.txt"));
        let relay_url = load_relay_url(&data_dir.join("relay_config.json"));

        Self {
            data_dir,
            pc_name,
            ephemeral_tokens: Mutex::new(HashMap::new()),
            trusted_devices: Mutex::new(trusted),
            relay_channel: Mutex::new(channel),
            relay_host_secret: Mutex::new(host_secret),
            relay_url: Mutex::new(relay_url),
            tcp_cert_sha256: Mutex::new(None),
        }
    }

    pub fn set_tcp_cert_sha256(&self, sha256: Option<String>) {
        if let Ok(mut guard) = self.tcp_cert_sha256.lock() {
            *guard = sha256.map(|s| s.trim().to_lowercase()).filter(|s| s.len() == 64);
        }
    }

    pub fn get_tcp_cert_sha256(&self) -> Option<String> {
        self.tcp_cert_sha256.lock().ok().and_then(|g| g.clone())
    }

    pub fn pc_name(&self) -> &str {
        &self.pc_name
    }

    pub fn get_relay_channel(&self) -> String {
        self.relay_channel
            .lock()
            .map(|g| g.clone())
            .unwrap_or_else(|_| "nb-default".to_string())
    }

    pub fn get_relay_host_secret(&self) -> String {
        self.relay_host_secret
            .lock()
            .map(|g| g.clone())
            .unwrap_or_default()
    }

    pub fn get_relay_url(&self) -> Option<String> {
        self.relay_url.lock().ok().and_then(|g| g.clone())
    }

    pub fn set_relay_url(&self, raw: Option<String>) -> Option<String> {
        let normalized = raw
            .map(|s| s.trim().trim_end_matches('/').to_string())
            .filter(|s| !s.is_empty() && is_allowed_relay_url(s));

        if let Ok(mut guard) = self.relay_url.lock() {
            *guard = normalized.clone();
        }
        let cfg = RelayConfigFile {
            relay_url: normalized.clone(),
        };
        let path = self.data_dir.join("relay_config.json");
        if let Some(parent) = path.parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        if let Ok(json) = serde_json::to_string_pretty(&cfg) {
            let _ = std::fs::write(path, json);
        }
        normalized
    }

    /// Emite un token temporal único de un solo uso según el método (`30s` QR, `90s` Enlace remoto).
    pub fn issue_ephemeral_token(&self) -> (String, u64) {
        self.issue_ephemeral_token_for_method("qr")
    }

    pub fn issue_ephemeral_token_for_method(&self, method: &str) -> (String, u64) {
        let ttl_secs = if method == "relay_link" {
            RELAY_LINK_TTL_SECS
        } else {
            QR_PAIR_TTL_SECS
        };
        let now = Instant::now();
        let token = generate_random_hex_token("PAIR", 8);
        if let Ok(mut map) = self.ephemeral_tokens.lock() {
            map.retain(|_, v| v.expires_at > now);
            map.insert(
                token.clone(),
                EphemeralEntry {
                    expires_at: now + Duration::from_secs(ttl_secs),
                },
            );
        }
        (token, ttl_secs)
    }

    /// Valida el payload de `HELLO_SYN`. Si recibe un `pair_token` vigente, lo consume y genera
    /// un `device_token` permanente para el perfil guardado del móvil.
    pub fn validate_hello_payload(&self, payload: &[u8]) -> HelloAuthOutcome {
        self.validate_hello_payload_for_transport(payload, false)
    }

    pub fn validate_hello_payload_for_transport(
        &self,
        payload: &[u8],
        require_token: bool,
    ) -> HelloAuthOutcome {
        self.validate_hello_payload_with_meta(payload, require_token, "tcp", "")
            .outcome
    }

    pub fn validate_hello_payload_with_meta(
        &self,
        payload: &[u8],
        require_token: bool,
        fallback_transport: &str,
        endpoint: &str,
    ) -> HelloAuthResult {
        let default_transport = normalize_transport_name(fallback_transport);
        let endpoint_opt = {
            let trimmed = endpoint.trim();
            if trimmed.is_empty() {
                None
            } else {
                Some(trimmed.to_string())
            }
        };

        if payload.is_empty() {
            let outcome = if require_token {
                HelloAuthOutcome::Rejected {
                    reason: "token_required".to_string(),
                }
            } else {
                HelloAuthOutcome::LegacyAllowed { device_name: None }
            };
            return HelloAuthResult {
                outcome,
                device_id: None,
                mobile_id: None,
                device_os: "android".to_string(),
                transport: default_transport,
            };
        }

        let Ok(parsed) = serde_json::from_slice::<HelloSynPayload>(payload) else {
            let outcome = if require_token {
                HelloAuthOutcome::Rejected {
                    reason: "invalid_hello_payload".to_string(),
                }
            } else {
                HelloAuthOutcome::LegacyAllowed { device_name: None }
            };
            return HelloAuthResult {
                outcome,
                device_id: None,
                mobile_id: None,
                device_os: "android".to_string(),
                transport: default_transport,
            };
        };

        let clean_name = parsed
            .device_name
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty());
        let mobile_id = parsed
            .mobile_id
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty());
        let device_os = normalize_device_os(parsed.device_os.as_deref());
        let transport = parsed
            .transport
            .as_deref()
            .map(normalize_transport_name)
            .filter(|s| !s.is_empty())
            .unwrap_or(default_transport);

        if let Some(pair_tok) = parsed
            .pair_token
            .as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty())
        {
            let now = Instant::now();
            let valid = if let Ok(mut map) = self.ephemeral_tokens.lock() {
                map.retain(|_, v| v.expires_at > now);
                map.remove(pair_tok).is_some()
            } else {
                false
            };

            if valid {
                let fallback_label = if device_os == "ios" {
                    "iPhone"
                } else {
                    "Android Phone"
                };
                let device_label = clean_name.clone().unwrap_or_else(|| fallback_label.to_string());
                let (permanent, effective_name) = self.upsert_trusted_device(
                    &device_label,
                    mobile_id.clone(),
                    Some(device_os.clone()),
                    Some(transport.clone()),
                    endpoint_opt,
                    None,
                );
                let device_id = Some(device_public_id(&permanent));
                return HelloAuthResult {
                    outcome: HelloAuthOutcome::Paired {
                        device_name: Some(effective_name),
                        new_device_token: permanent,
                    },
                    device_id,
                    mobile_id,
                    device_os,
                    transport,
                };
            }

            if !require_token {
                if let Some(dev_tok) = parsed
                    .device_token
                    .as_deref()
                    .map(str::trim)
                    .filter(|s| !s.is_empty())
                {
                    if let Some((effective_name, device_id)) = self.match_trusted_device_token(
                        dev_tok,
                        clean_name.as_ref(),
                        mobile_id.as_ref(),
                        Some(&device_os),
                        Some(&transport),
                        endpoint_opt.as_deref(),
                    ) {
                        return HelloAuthResult {
                            outcome: HelloAuthOutcome::Trusted {
                                device_name: Some(effective_name),
                            },
                            device_id: Some(device_id),
                            mobile_id,
                            device_os,
                            transport,
                        };
                    }
                }
            }

            return HelloAuthResult {
                outcome: HelloAuthOutcome::Rejected {
                    reason: "pair_token_expired".to_string(),
                },
                device_id: None,
                mobile_id,
                device_os,
                transport,
            };
        }

        if let Some(dev_tok) = parsed
            .device_token
            .as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty())
        {
            if let Some((effective_name, device_id)) = self.match_trusted_device_token(
                dev_tok,
                clean_name.as_ref(),
                mobile_id.as_ref(),
                Some(&device_os),
                Some(&transport),
                endpoint_opt.as_deref(),
            ) {
                return HelloAuthResult {
                    outcome: HelloAuthOutcome::Trusted {
                        device_name: Some(effective_name),
                    },
                    device_id: Some(device_id),
                    mobile_id,
                    device_os,
                    transport,
                };
            }
            return HelloAuthResult {
                outcome: HelloAuthOutcome::Rejected {
                    reason: "device_token_unknown".to_string(),
                },
                device_id: None,
                mobile_id,
                device_os,
                transport,
            };
        }

        if require_token {
            HelloAuthResult {
                outcome: HelloAuthOutcome::Rejected {
                    reason: "token_required".to_string(),
                },
                device_id: None,
                mobile_id,
                device_os,
                transport,
            }
        } else if let Some(ref label) = clean_name {
            let (permanent, effective_name) = self.upsert_trusted_device(
                label,
                mobile_id.clone(),
                Some(device_os.clone()),
                Some(transport.clone()),
                endpoint_opt,
                None,
            );
            let device_id = Some(device_public_id(&permanent));
            HelloAuthResult {
                outcome: HelloAuthOutcome::Paired {
                    device_name: Some(effective_name),
                    new_device_token: permanent,
                },
                device_id,
                mobile_id,
                device_os,
                transport,
            }
        } else {
            HelloAuthResult {
                outcome: HelloAuthOutcome::LegacyAllowed {
                    device_name: clean_name,
                },
                device_id: None,
                mobile_id,
                device_os,
                transport,
            }
        }
    }

    pub fn list_trusted_devices(&self) -> Vec<TrustedDeviceInfo> {
        let Ok(list) = self.trusted_devices.lock() else {
            return Vec::new();
        };
        list.iter()
            .map(|d| TrustedDeviceInfo {
                device_id: device_public_id(&d.device_token),
                device_name: d
                    .custom_name
                    .as_deref()
                    .filter(|s| !s.trim().is_empty())
                    .unwrap_or(&d.device_name)
                    .to_string(),
                created_unix: d.created_unix,
                mobile_id: d.mobile_id.clone(),
                device_os: d.device_os.clone(),
                transport: d.transport.clone(),
                endpoint: d.endpoint.clone(),
            })
            .collect()
    }

    pub fn get_trusted_device(&self, device_id: &str) -> Option<TrustedDeviceInfo> {
        self.list_trusted_devices()
            .into_iter()
            .find(|d| d.device_id == device_id)
    }

    pub fn rename_trusted_device(&self, device_id: &str, new_name: &str) -> Option<String> {
        let clean = new_name.trim();
        if clean.is_empty() {
            return None;
        }
        let mut list = self.trusted_devices.lock().ok()?;
        let found = list
            .iter_mut()
            .find(|d| device_public_id(&d.device_token) == device_id)?;
        found.custom_name = Some(clean.to_string());
        let final_name = clean.to_string();
        save_trusted_devices(&self.data_dir.join("trusted_devices.json"), &list);
        Some(final_name)
    }

    fn upsert_trusted_device(
        &self,
        device_label: &str,
        mobile_id: Option<String>,
        device_os: Option<String>,
        transport: Option<String>,
        endpoint: Option<String>,
        preferred_token: Option<String>,
    ) -> (String, String) {
        let path = self.data_dir.join("trusted_devices.json");
        let permanent = preferred_token.unwrap_or_else(|| generate_random_hex_token("DEV", 32));
        let Ok(mut list) = self.trusted_devices.lock() else {
            return (permanent, device_label.to_string());
        };

        let existing_idx = list.iter().position(|d| {
            let same_transport = match (&d.transport, &transport) {
                (Some(a), Some(b)) => a == b,
                (None, _) => true,
                _ => false,
            };
            if !same_transport {
                return false;
            }
            if let (Some(mid_a), Some(mid_b)) = (&d.mobile_id, &mobile_id) {
                return mid_a.eq_ignore_ascii_case(mid_b);
            }
            d.device_name == device_label && (d.mobile_id.is_none() || mobile_id.is_none())
        });

        let effective_name = if let Some(idx) = existing_idx {
            let existing = &mut list[idx];
            existing.device_token = permanent.clone();
            existing.device_name = device_label.to_string();
            existing.created_unix = unix_now_secs();
            if mobile_id.is_some() {
                existing.mobile_id = mobile_id;
            }
            if device_os.is_some() {
                existing.device_os = device_os;
            }
            if transport.is_some() {
                existing.transport = transport;
            }
            if endpoint.is_some() {
                existing.endpoint = endpoint;
            }
            existing
                .custom_name
                .as_deref()
                .filter(|s| !s.trim().is_empty())
                .unwrap_or(&existing.device_name)
                .to_string()
        } else {
            list.push(TrustedDevice {
                device_token: permanent.clone(),
                device_name: device_label.to_string(),
                created_unix: unix_now_secs(),
                mobile_id,
                device_os,
                transport,
                endpoint,
                custom_name: None,
            });
            device_label.to_string()
        };

        save_trusted_devices(&path, &list);
        (permanent, effective_name)
    }

    fn match_trusted_device_token(
        &self,
        dev_tok: &str,
        clean_name: Option<&String>,
        mobile_id: Option<&String>,
        device_os: Option<&str>,
        transport: Option<&str>,
        endpoint: Option<&str>,
    ) -> Option<(String, String)> {
        let path = self.data_dir.join("trusted_devices.json");
        let Ok(mut list) = self.trusted_devices.lock() else {
            return None;
        };

        if list
            .iter()
            .all(|d| !bool::from(d.device_token.as_bytes().ct_eq(dev_tok.as_bytes())))
        {
            let disk = load_trusted_devices(&path);
            if disk
                .iter()
                .any(|d| bool::from(d.device_token.as_bytes().ct_eq(dev_tok.as_bytes())))
            {
                *list = disk;
            }
        }

        let found = list
            .iter_mut()
            .find(|d| bool::from(d.device_token.as_bytes().ct_eq(dev_tok.as_bytes())))?;

        let mut dirty = false;
        if let Some(name) = clean_name {
            if found.device_name != *name {
                found.device_name = name.clone();
                dirty = true;
            }
        }
        if let Some(mid) = mobile_id {
            if found.mobile_id.as_deref() != Some(mid.as_str()) {
                found.mobile_id = Some(mid.clone());
                dirty = true;
            }
        }
        if let Some(os) = device_os {
            if found.device_os.as_deref() != Some(os) {
                found.device_os = Some(os.to_string());
                dirty = true;
            }
        }
        if let Some(tr) = transport {
            if found.transport.as_deref() != Some(tr) {
                found.transport = Some(tr.to_string());
                dirty = true;
            }
        }
        if let Some(ep) = endpoint {
            if found.endpoint.as_deref() != Some(ep) {
                found.endpoint = Some(ep.to_string());
                dirty = true;
            }
        }
        let display_name = found
            .custom_name
            .as_deref()
            .filter(|s| !s.trim().is_empty())
            .unwrap_or(&found.device_name)
            .to_string();
        let dev_id = device_public_id(&found.device_token);
        if dirty {
            save_trusted_devices(&path, &list);
        }
        Some((display_name, dev_id))
    }

    pub fn revoke_trusted_device(&self, device_id: &str) -> Option<TrustedDeviceInfo> {
        let mut list = self.trusted_devices.lock().ok()?;
        let pos = list
            .iter()
            .position(|d| device_public_id(&d.device_token) == device_id)?;
        let removed = list.remove(pos);
        save_trusted_devices(&self.data_dir.join("trusted_devices.json"), &list);
        Some(TrustedDeviceInfo {
            device_id: device_public_id(&removed.device_token),
            device_name: removed
                .custom_name
                .as_deref()
                .filter(|s| !s.trim().is_empty())
                .unwrap_or(&removed.device_name)
                .to_string(),
            created_unix: removed.created_unix,
            mobile_id: removed.mobile_id,
            device_os: removed.device_os,
            transport: removed.transport,
            endpoint: removed.endpoint,
        })
    }

    pub fn build_qr_and_link(
        &self,
        method: &str,
        pair_token: &str,
        tcp_ip: Option<&str>,
        tcp_port: u16,
        bt_mac: Option<&str>,
        wfd_ssid: Option<&str>,
        wfd_pass: Option<&str>,
        wfd_ip: Option<&str>,
    ) -> (String, Option<String>) {
        let encoded_name = percent_encode_query(&self.pc_name);
        match method {
            "wifi_direct" => {
                let host = wfd_ip.unwrap_or("192.168.137.1");
                let ssid = wfd_ssid.unwrap_or("");
                let pass = wfd_pass.unwrap_or("");
                let cert_suffix = self
                    .get_tcp_cert_sha256()
                    .map(|c| format!("&cert={}", percent_encode_query(&c)))
                    .unwrap_or_default();
                let uri = format!(
                    "nfcbridge://{}:{}?name={}&transport=wifi_direct&ssid={}&pass={}&pair={}{}",
                    host,
                    tcp_port,
                    encoded_name,
                    percent_encode_query(ssid),
                    percent_encode_query(pass),
                    percent_encode_query(pair_token),
                    cert_suffix,
                );
                (uri, None)
            }
            "bluetooth" => {
                let mac = bt_mac.unwrap_or("00:00:00:00:00:00");
                let uri = format!(
                    "nfcbridge://bt/{}?name={}&transport=bluetooth&pair={}",
                    mac,
                    encoded_name,
                    percent_encode_query(pair_token),
                );
                (uri, None)
            }
            "relay" | "relay_link" => {
                let channel = self.get_relay_channel();
                let base = self.get_relay_url().unwrap_or_default();
                let ws_base = to_ws_base(&base);
                let http_base = to_http_base(&base);
                let qr_envelope = encrypt_relay_envelope(&channel, &self.pc_name, &ws_base, pair_token);
                let uri = format!("nfcbridge://relay?d={}", percent_encode_query(&qr_envelope));
                let share = if !http_base.is_empty() {
                    let link_envelope = encrypt_relay_envelope(&channel, &self.pc_name, "", pair_token);
                    Some(format!("{}/c?d={}", http_base, percent_encode_query(&link_envelope)))
                } else {
                    None
                };
                (uri, share)
            }
            _ => {
                // tcp (Red Local)
                let ip = tcp_ip.unwrap_or("127.0.0.1");
                let cert_suffix = self
                    .get_tcp_cert_sha256()
                    .map(|c| format!("&cert={}", percent_encode_query(&c)))
                    .unwrap_or_default();
                let uri = format!(
                    "nfcbridge://{}:{}?name={}&transport=tcp&pair={}{}",
                    ip,
                    tcp_port,
                    encoded_name,
                    percent_encode_query(pair_token),
                    cert_suffix,
                );
                (uri, None)
            }
        }
    }
}

pub fn device_public_id(token: &str) -> String {
    let mut hash: u64 = 0xcbf29ce484222325;
    for b in token.as_bytes() {
        hash ^= *b as u64;
        hash = hash.wrapping_mul(0x100000001b3);
    }
    format!("dev-{:012x}", hash & 0x0000_FFFF_FFFF_FFFF)
}

pub fn parse_hello_paused(payload: &[u8]) -> bool {
    if payload.is_empty() {
        return false;
    }
    serde_json::from_slice::<HelloSynPayload>(payload)
        .ok()
        .and_then(|p| p.paused)
        .unwrap_or(false)
}

pub fn detect_lan_ipv4() -> Option<String> {
    let sock = UdpSocket::bind("0.0.0.0:0").ok()?;
    sock.connect("8.8.8.8:80").ok()?;
    sock.local_addr().ok().map(|a| a.ip().to_string())
}

pub fn to_ws_base(raw: &str) -> String {
    let trimmed = raw.trim().trim_end_matches('/');
    if trimmed.starts_with("https://") {
        format!("wss://{}", &trimmed[8..])
    } else if trimmed.starts_with("http://") {
        format!("ws://{}", &trimmed[7..])
    } else {
        trimmed.to_string()
    }
}

pub fn to_http_base(raw: &str) -> String {
    let trimmed = raw.trim().trim_end_matches('/');
    if trimmed.starts_with("wss://") {
        format!("https://{}", &trimmed[6..])
    } else if trimmed.starts_with("ws://") {
        format!("http://{}", &trimmed[5..])
    } else {
        trimmed.to_string()
    }
}

fn normalize_transport_name(raw: &str) -> String {
    let lower = raw.trim().to_lowercase();
    if lower.contains("usb") {
        "usb".to_string()
    } else if lower.contains("bluetooth") || lower == "bt" {
        "bluetooth".to_string()
    } else if lower.contains("relay") {
        "relay".to_string()
    } else if lower.contains("wifi_direct") || lower.contains("wifi-direct") || lower.contains("p2p") {
        "wifi_direct".to_string()
    } else {
        "tcp".to_string()
    }
}

fn normalize_device_os(raw: Option<&str>) -> String {
    let Some(val) = raw else {
        return "android".to_string();
    };
    let lower = val.trim().to_lowercase();
    if lower.contains("ios")
        || lower.contains("iphone")
        || lower.contains("ipad")
        || lower.contains("apple")
    {
        "ios".to_string()
    } else {
        "android".to_string()
    }
}

fn relay_envelope_key() -> LessSafeKey {
    let key_hash = digest::digest(&digest::SHA256, RELAY_ENVELOPE_DOMAIN);
    let unbound = UnboundKey::new(&AES_256_GCM, key_hash.as_ref()).expect("valid AES-256 key");
    LessSafeKey::new(unbound)
}

fn encode_hex_if_prefixed(input: &str, prefix: &str) -> Option<Vec<u8>> {
    let rest = input.strip_prefix(prefix)?;
    if rest.is_empty() || rest.len() % 2 != 0 || rest.len() > 64 {
        return None;
    }
    let bytes = rest.as_bytes();
    let mut out = Vec::with_capacity(bytes.len() / 2);
    for pair in bytes.chunks_exact(2) {
        let hi = (pair[0] as char).to_digit(16)? as u8;
        let lo = (pair[1] as char).to_digit(16)? as u8;
        out.push((hi << 4) | lo);
    }
    Some(out)
}

fn push_len_bytes(buf: &mut Vec<u8>, bytes: &[u8]) {
    let capped = bytes.len().min(u8::MAX as usize);
    buf.push(capped as u8);
    buf.extend_from_slice(&bytes[..capped]);
}

pub fn encrypt_relay_envelope(
    channel: &str,
    pc_name: &str,
    relay_ws: &str,
    pair_token: &str,
) -> String {
    let mut flags = 0u8;
    let ch_bytes = if let Some(raw) = encode_hex_if_prefixed(channel, "nb-") {
        flags |= 0x01;
        raw
    } else {
        channel.as_bytes().to_vec()
    };
    let pair_bytes = if let Some(raw) = encode_hex_if_prefixed(pair_token, "PAIR-") {
        flags |= 0x02;
        raw
    } else {
        pair_token.as_bytes().to_vec()
    };

    let mut plain = Vec::with_capacity(1 + 4 + ch_bytes.len() + pair_bytes.len() + pc_name.len() + relay_ws.len());
    plain.push(flags);
    push_len_bytes(&mut plain, &ch_bytes);
    push_len_bytes(&mut plain, &pair_bytes);
    push_len_bytes(&mut plain, pc_name.as_bytes());
    push_len_bytes(&mut plain, relay_ws.as_bytes());

    let mut nonce_bytes = [0u8; 12];
    if getrandom::getrandom(&mut nonce_bytes).is_err() {
        let nanos = unix_now_secs() ^ (std::process::id() as u64);
        nonce_bytes[..8].copy_from_slice(&nanos.to_le_bytes());
    }

    let key = relay_envelope_key();
    let nonce = Nonce::assume_unique_for_key(nonce_bytes);
    let _ = key.seal_in_place_append_tag(nonce, Aad::from(RELAY_ENVELOPE_AAD), &mut plain);

    let mut combined = Vec::with_capacity(12 + plain.len());
    combined.extend_from_slice(&nonce_bytes);
    combined.extend_from_slice(&plain);
    format!("v2.{}", base64url_encode_nopad(&combined))
}

#[cfg(test)]
fn read_len_bytes<'a>(data: &'a [u8], pos: &mut usize) -> Option<&'a [u8]> {
    let len = *data.get(*pos)? as usize;
    *pos += 1;
    let end = pos.checked_add(len)?;
    let slice = data.get(*pos..end)?;
    *pos = end;
    Some(slice)
}

#[cfg(test)]
fn decrypt_relay_envelope(encoded: &str) -> Option<(String, String, String, String)> {
    if let Some(body) = encoded.strip_prefix("v2.") {
        let raw = base64url_decode_nopad(body)?;
        if raw.len() <= 12 {
            return None;
        }
        let (nonce_slice, cipher_slice) = raw.split_at(12);
        let nonce_arr: [u8; 12] = nonce_slice.try_into().ok()?;
        let key = relay_envelope_key();
        let mut buf = cipher_slice.to_vec();
        let plain = key
            .open_in_place(
                Nonce::assume_unique_for_key(nonce_arr),
                Aad::from(RELAY_ENVELOPE_AAD),
                &mut buf,
            )
            .ok()?;
        let mut pos = 0usize;
        let flags = *plain.get(pos)?;
        pos += 1;
        let ch_raw = read_len_bytes(plain, &mut pos)?;
        let pair_raw = read_len_bytes(plain, &mut pos)?;
        let name_raw = read_len_bytes(plain, &mut pos)?;
        let relay_raw = read_len_bytes(plain, &mut pos)?;

        let channel = if (flags & 0x01) != 0 {
            let mut s = String::from("nb-");
            for b in ch_raw {
                s.push_str(&format!("{:02x}", b));
            }
            s
        } else {
            String::from_utf8(ch_raw.to_vec()).ok()?
        };
        let pair_token = if (flags & 0x02) != 0 {
            let mut s = String::from("PAIR-");
            for b in pair_raw {
                s.push_str(&format!("{:02X}", b));
            }
            s
        } else {
            String::from_utf8(pair_raw.to_vec()).ok()?
        };
        let pc_name = String::from_utf8(name_raw.to_vec()).ok()?;
        let relay_ws = String::from_utf8(relay_raw.to_vec()).ok()?;
        return Some((channel, pc_name, relay_ws, pair_token));
    }

    let body = encoded.strip_prefix("v1.")?;
    let raw = base64url_decode_nopad(body)?;
    if raw.len() <= 12 {
        return None;
    }
    let (nonce_slice, cipher_slice) = raw.split_at(12);
    let nonce_arr: [u8; 12] = nonce_slice.try_into().ok()?;
    let key = relay_envelope_key();
    let mut buf = cipher_slice.to_vec();
    let plain = key
        .open_in_place(
            Nonce::assume_unique_for_key(nonce_arr),
            Aad::from(RELAY_ENVELOPE_AAD),
            &mut buf,
        )
        .ok()?;
    #[derive(Deserialize)]
    struct EnvelopeJson {
        c: String,
        n: String,
        r: String,
        p: String,
    }
    let parsed: EnvelopeJson = serde_json::from_slice(plain).ok()?;
    Some((parsed.c, parsed.n, parsed.r, parsed.p))
}

fn base64url_encode_nopad(data: &[u8]) -> String {
    const TABLE: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut out = String::with_capacity((data.len() * 4 + 2) / 3);
    let mut i = 0;
    while i < data.len() {
        let b0 = data[i] as u32;
        let b1 = if i + 1 < data.len() { data[i + 1] as u32 } else { 0 };
        let b2 = if i + 2 < data.len() { data[i + 2] as u32 } else { 0 };
        let triple = (b0 << 16) | (b1 << 8) | b2;
        out.push(TABLE[((triple >> 18) & 0x3F) as usize] as char);
        out.push(TABLE[((triple >> 12) & 0x3F) as usize] as char);
        if i + 1 < data.len() {
            out.push(TABLE[((triple >> 6) & 0x3F) as usize] as char);
        }
        if i + 2 < data.len() {
            out.push(TABLE[(triple & 0x3F) as usize] as char);
        }
        i += 3;
    }
    out
}

#[cfg(test)]
fn base64url_decode_nopad(s: &str) -> Option<Vec<u8>> {
    fn val(b: u8) -> Option<u32> {
        match b {
            b'A'..=b'Z' => Some((b - b'A') as u32),
            b'a'..=b'z' => Some((b - b'a' + 26) as u32),
            b'0'..=b'9' => Some((b - b'0' + 52) as u32),
            b'-' => Some(62),
            b'_' => Some(63),
            _ => None,
        }
    }
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len() * 3 / 4);
    let mut i = 0;
    while i < bytes.len() {
        let c0 = val(*bytes.get(i)?)?;
        let c1 = val(*bytes.get(i + 1)?)?;
        let c2 = match bytes.get(i + 2).copied() {
            Some(b) => Some(val(b)?),
            None => None,
        };
        let c3 = match bytes.get(i + 3).copied() {
            Some(b) => Some(val(b)?),
            None => None,
        };
        let triple = (c0 << 18) | (c1 << 12) | (c2.unwrap_or(0) << 6) | c3.unwrap_or(0);
        out.push(((triple >> 16) & 0xFF) as u8);
        if c2.is_some() {
            out.push(((triple >> 8) & 0xFF) as u8);
        }
        if c3.is_some() {
            out.push((triple & 0xFF) as u8);
        }
        i += 4;
    }
    Some(out)
}

fn percent_encode_query(raw: &str) -> String {
    let mut out = String::with_capacity(raw.len());
    for byte in raw.as_bytes() {
        let ch = *byte as char;
        if ch.is_ascii_alphanumeric() || matches!(ch, '-' | '_' | '.' | '~') {
            out.push(ch);
        } else {
            out.push_str(&format!("%{:02X}", byte));
        }
    }
    out
}

fn unix_now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn generate_random_hex_token(prefix: &str, hex_chars: usize) -> String {
    let byte_len = (hex_chars + 1) / 2;
    let mut bytes = vec![0u8; byte_len.max(8)];
    if getrandom::getrandom(&mut bytes).is_err() {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_nanos() as u64)
            .unwrap_or(0xCAFE_BABE_1234_5678);
        let pid = std::process::id() as u64;
        let mut state = nanos ^ pid.wrapping_mul(0x9E37_79B9_7F4A_7C15);
        for b in &mut bytes {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            *b = (state & 0xFF) as u8;
        }
    }
    let mut hex = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        hex.push_str(&format!("{:02X}", b));
    }
    hex.truncate(hex_chars);
    format!("{}-{}", prefix, hex)
}

pub fn is_allowed_relay_url(raw: &str) -> bool {
    let trimmed = raw.trim();
    if trimmed.is_empty()
        || trimmed.len() > 256
        || trimmed.chars().any(|c| c.is_whitespace())
        || trimmed.contains("..")
        || trimmed.contains('?')
        || trimmed.contains('#')
        || trimmed.contains('@')
    {
        return false;
    }
    if trimmed.starts_with("https://") || trimmed.starts_with("wss://") {
        let after = trimmed.split("://").nth(1).unwrap_or("");
        return !after.is_empty() && !after.starts_with('/');
    }
    for prefix in [
        "http://127.0.0.1",
        "ws://127.0.0.1",
        "http://localhost",
        "ws://localhost",
    ] {
        if let Some(rest) = trimmed.strip_prefix(prefix) {
            return rest.is_empty() || rest.starts_with(':') || rest.starts_with('/');
        }
    }
    false
}

fn load_trusted_devices(path: &PathBuf) -> Vec<TrustedDevice> {
    std::fs::read_to_string(path)
        .ok()
        .and_then(|s| serde_json::from_str::<Vec<TrustedDevice>>(&s).ok())
        .unwrap_or_default()
}

fn save_trusted_devices(path: &PathBuf, list: &[TrustedDevice]) {
    if let Some(parent) = path.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    if let Ok(json) = serde_json::to_string_pretty(list) {
        let _ = std::fs::write(path, json);
    }
}

fn load_or_create_channel(path: &PathBuf) -> String {
    if let Ok(existing) = std::fs::read_to_string(path) {
        let trimmed = existing.trim();
        if trimmed.len() >= 8 {
            return trimmed.to_string();
        }
    }
    let ch = generate_random_hex_token("nb", 16).to_lowercase();
    if let Some(parent) = path.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    let _ = std::fs::write(path, &ch);
    ch
}

fn load_or_create_host_secret(path: &PathBuf) -> String {
    if let Ok(existing) = std::fs::read_to_string(path) {
        let trimmed = existing.trim();
        if trimmed.len() >= 24 {
            return trimmed.to_string();
        }
    }
    let secret = generate_random_hex_token("host", 32).to_lowercase();
    if let Some(parent) = path.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    let _ = std::fs::write(path, &secret);
    secret
}

const BUILTIN_DEFAULT_RELAY_URL: &str = "https://nfc-bridge.hectorzaga96.workers.dev";

fn load_relay_url(path: &PathBuf) -> Option<String> {
    if let Ok(env_url) = std::env::var("NFC_BRIDGE_RELAY_URL") {
        let t = env_url.trim().trim_end_matches('/').to_string();
        if is_allowed_relay_url(&t) {
            return Some(t);
        }
    }
    if let Some(saved) = std::fs::read_to_string(path)
        .ok()
        .and_then(|s| serde_json::from_str::<RelayConfigFile>(&s).ok())
        .and_then(|c| c.relay_url)
        .map(|s| s.trim().trim_end_matches('/').to_string())
        .filter(|s| is_allowed_relay_url(s))
    {
        return Some(saved);
    }
    let default_url = option_env!("NFC_BRIDGE_DEFAULT_RELAY_URL").unwrap_or(BUILTIN_DEFAULT_RELAY_URL);
    Some(default_url.trim().trim_end_matches('/').to_string())
        .filter(|s| is_allowed_relay_url(s))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_dir(name: &str) -> PathBuf {
        let mut p = std::env::temp_dir();
        p.push(format!("nfc_bridge_test_{}_{}", name, std::process::id()));
        let _ = std::fs::remove_dir_all(&p);
        p
    }

    #[test]
    fn test_ephemeral_token_single_use_and_permanent_device_token() {
        let dir = temp_dir("pair_once");
        let mgr = PairingManager::with_data_dir(dir.clone(), "HECTOR-MASTER".to_string());
        let (pair_token, ttl) = mgr.issue_ephemeral_token();
        assert_eq!(ttl, 30);
        let (_, link_ttl) = mgr.issue_ephemeral_token_for_method("relay_link");
        assert_eq!(link_ttl, 90);

        let syn1 = format!(r#"{{"device_name":"Morduuk","pair_token":"{}"}}"#, pair_token);
        let outcome1 = mgr.validate_hello_payload(syn1.as_bytes());
        let permanent = match outcome1 {
            HelloAuthOutcome::Paired {
                device_name,
                new_device_token,
            } => {
                assert_eq!(device_name.as_deref(), Some("Morduuk"));
                assert!(new_device_token.starts_with("DEV-"));
                new_device_token
            }
            other => panic!("expected Paired, got {:?}", other),
        };

        // Reusing the same QR pair_token must be rejected
        let outcome_replay = mgr.validate_hello_payload(syn1.as_bytes());
        assert!(matches!(outcome_replay, HelloAuthOutcome::Rejected { .. }));

        // Reconnecting with the permanent device_token succeeds even after restart
        let mgr_reloaded = PairingManager::with_data_dir(dir.clone(), "HECTOR-MASTER".to_string());
        let syn2 = format!(r#"{{"device_name":"Morduuk","device_token":"{}"}}"#, permanent);
        assert_eq!(
            mgr_reloaded.validate_hello_payload(syn2.as_bytes()),
            HelloAuthOutcome::Trusted {
                device_name: Some("Morduuk".to_string())
            }
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_build_qr_and_share_link_for_relay() {
        let dir = temp_dir("relay_uri");
        let mgr = PairingManager::with_data_dir(dir.clone(), "PC ONE".to_string());
        mgr.set_relay_url(Some("https://nfc-relay.example.workers.dev/".to_string()));
        let (uri, share) = mgr.build_qr_and_link(
            "relay",
            "PAIR-1234",
            None,
            45362,
            None,
            None,
            None,
            None,
        );
        assert!(uri.starts_with("nfcbridge://relay?d=v2."));
        assert!(!uri.contains("channel="));
        assert!(!uri.contains("PAIR-1234"));
        let link = share.expect("share link expected when relay URL set");
        assert!(link.starts_with("https://nfc-relay.example.workers.dev/c?d=v2."));
        assert!(!link.contains("channel="));
        assert!(!link.contains("PAIR-1234"));

        let d_enc = uri.strip_prefix("nfcbridge://relay?d=").unwrap();
        let d_raw = d_enc.replace("%2D", "-").replace("%5F", "_").replace("%2E", ".");
        let (c, n, r, p) = decrypt_relay_envelope(&d_raw).expect("decrypt qr envelope");
        assert!(c.starts_with("nb-"));
        assert_eq!(n, "PC ONE");
        assert_eq!(r, "wss://nfc-relay.example.workers.dev");
        assert_eq!(p, "PAIR-1234");

        let link_d = link.strip_prefix("https://nfc-relay.example.workers.dev/c?d=").unwrap();
        let (lc, ln, lr, lp) = decrypt_relay_envelope(link_d).expect("decrypt short share envelope");
        assert_eq!(lc, c);
        assert_eq!(ln, "PC ONE");
        assert_eq!(lr, "");
        assert_eq!(lp, "PAIR-1234");
        assert_eq!(p, "PAIR-1234");

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_relay_requires_token_and_validates_urls() {
        let dir = temp_dir("relay_sec");
        let mgr = PairingManager::with_data_dir(dir.clone(), "HECTOR-MASTER".to_string());
        assert!(mgr.get_relay_host_secret().starts_with("host-"));
        assert!(!is_allowed_relay_url("https://evil.com/path/../../"));
        assert!(is_allowed_relay_url("https://nfc-bridge-relay.example.workers.dev"));
        assert!(!is_allowed_relay_url("ws://public.example.com"));
        assert!(is_allowed_relay_url("ws://127.0.0.1:8787"));

        let rejected = mgr.validate_hello_payload_for_transport(b"", true);
        assert!(matches!(rejected, HelloAuthOutcome::Rejected { .. }));

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_list_and_revoke_trusted_devices_without_leaking_token() {
        let dir = temp_dir("trusted_list");
        let mgr = PairingManager::with_data_dir(dir.clone(), "HECTOR-MASTER".to_string());
        let (tok, _) = mgr.issue_ephemeral_token();
        let syn = format!(
            r#"{{"device_name":"HectorZaGa","pair_token":"{}","paused":true}}"#,
            tok
        );
        assert!(parse_hello_paused(syn.as_bytes()));
        assert!(matches!(
            mgr.validate_hello_payload(syn.as_bytes()),
            HelloAuthOutcome::Paired { .. }
        ));

        let listed = mgr.list_trusted_devices();
        assert_eq!(listed.len(), 1);
        assert_eq!(listed[0].device_name, "HectorZaGa");
        assert!(listed[0].device_id.starts_with("dev-"));

        let removed = mgr.revoke_trusted_device(&listed[0].device_id);
        assert_eq!(removed.as_ref().map(|d| d.device_name.as_str()), Some("HectorZaGa"));
        assert!(mgr.list_trusted_devices().is_empty());

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_expired_pair_falls_back_to_valid_device_token_for_local_transport() {
        let dir = temp_dir("pair_fallback");
        let mgr = PairingManager::with_data_dir(dir.clone(), "HECTOR-MASTER".to_string());
        let (tok, _) = mgr.issue_ephemeral_token();
        let first = format!(r#"{{"device_name":"HectorZaG","pair_token":"{}"}}"#, tok);
        let dev_token = match mgr.validate_hello_payload(first.as_bytes()) {
            HelloAuthOutcome::Paired { new_device_token, .. } => new_device_token,
            other => panic!("expected Paired, got {:?}", other),
        };

        let stale_local = format!(
            r#"{{"device_name":"HectorZaG","pair_token":"PAIR-EXPIRED","device_token":"{}"}}"#,
            dev_token
        );
        assert!(matches!(
            mgr.validate_hello_payload_for_transport(stale_local.as_bytes(), false),
            HelloAuthOutcome::Trusted { .. }
        ));
        assert!(matches!(
            mgr.validate_hello_payload_for_transport(stale_local.as_bytes(), true),
            HelloAuthOutcome::Rejected { .. }
        ));

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_device_os_normalization_and_persistence() {
        let dir = temp_dir("device_os_meta");
        let mgr = PairingManager::with_data_dir(dir.clone(), "HECTOR-MASTER".to_string());

        let (tok_ios, _) = mgr.issue_ephemeral_token();
        let syn_ios = format!(
            r#"{{"device_name":"iPhone de Hector","mobile_id":"IOS1-2222-3333","device_os":"iOS","transport":"relay","pair_token":"{}"}}"#,
            tok_ios
        );
        let res_ios = mgr.validate_hello_payload_with_meta(
            syn_ios.as_bytes(),
            true,
            "relay",
            "wss://relay.example/nb-1",
        );
        assert_eq!(res_ios.device_os, "ios");

        let (tok_and, _) = mgr.issue_ephemeral_token();
        let syn_and = format!(
            r#"{{"device_name":"Pixel","mobile_id":"AND1-2222-3333","device_os":"Android","transport":"tcp","pair_token":"{}"}}"#,
            tok_and
        );
        let res_and = mgr.validate_hello_payload_with_meta(
            syn_and.as_bytes(),
            false,
            "tcp",
            "192.168.15.2:50000",
        );
        assert_eq!(res_and.device_os, "android");

        let listed = mgr.list_trusted_devices();
        assert_eq!(listed.len(), 2);
        assert_eq!(listed[0].device_os.as_deref(), Some("ios"));
        assert_eq!(listed[1].device_os.as_deref(), Some("android"));

        let _ = std::fs::remove_dir_all(&dir);
    }
}
