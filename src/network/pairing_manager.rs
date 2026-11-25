//! Gestión de tokens efímeros de vinculación (QR / Link único), dispositivos de confianza
//! persistentes (`device_token`) y configuración del canal Cloud Relay.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::UdpSocket;
use std::path::PathBuf;
use std::sync::Mutex;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use subtle::ConstantTimeEq;

const DEFAULT_PAIR_TTL_SECS: u64 = 90;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrustedDevice {
    pub device_token: String,
    pub device_name: String,
    pub created_unix: u64,
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
    pair_token: Option<String>,
    #[serde(default)]
    device_token: Option<String>,
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
        }
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

    /// Emite un token temporal único de un solo uso (válido por 90 segundos).
    pub fn issue_ephemeral_token(&self) -> (String, u64) {
        let now = Instant::now();
        let token = generate_random_hex_token("PAIR", 8);
        if let Ok(mut map) = self.ephemeral_tokens.lock() {
            map.retain(|_, v| v.expires_at > now);
            map.insert(
                token.clone(),
                EphemeralEntry {
                    expires_at: now + Duration::from_secs(DEFAULT_PAIR_TTL_SECS),
                },
            );
        }
        (token, DEFAULT_PAIR_TTL_SECS)
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
        if payload.is_empty() {
            return if require_token {
                HelloAuthOutcome::Rejected {
                    reason: "token_required".to_string(),
                }
            } else {
                HelloAuthOutcome::LegacyAllowed { device_name: None }
            };
        }

        let Ok(parsed) = serde_json::from_slice::<HelloSynPayload>(payload) else {
            return if require_token {
                HelloAuthOutcome::Rejected {
                    reason: "invalid_hello_payload".to_string(),
                }
            } else {
                HelloAuthOutcome::LegacyAllowed { device_name: None }
            };
        };

        let clean_name = parsed
            .device_name
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty());

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

            if !valid {
                return HelloAuthOutcome::Rejected {
                    reason: "pair_token_expired".to_string(),
                };
            }

            let permanent = generate_random_hex_token("DEV", 32);
            let device_label = clean_name.clone().unwrap_or_else(|| "Android Phone".to_string());
            let record = TrustedDevice {
                device_token: permanent.clone(),
                device_name: device_label,
                created_unix: unix_now_secs(),
            };
            if let Ok(mut list) = self.trusted_devices.lock() {
                list.push(record);
                save_trusted_devices(&self.data_dir.join("trusted_devices.json"), &list);
            }
            return HelloAuthOutcome::Paired {
                device_name: clean_name,
                new_device_token: permanent,
            };
        }

        if let Some(dev_tok) = parsed
            .device_token
            .as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty())
        {
            if let Ok(mut list) = self.trusted_devices.lock() {
                if let Some(found) = list
                    .iter_mut()
                    .find(|d| bool::from(d.device_token.as_bytes().ct_eq(dev_tok.as_bytes())))
                {
                    if let Some(ref name) = clean_name {
                        if found.device_name != *name {
                            found.device_name = name.clone();
                            save_trusted_devices(
                                &self.data_dir.join("trusted_devices.json"),
                                &list,
                            );
                        }
                    }
                    return HelloAuthOutcome::Trusted {
                        device_name: clean_name,
                    };
                }
            }
            return HelloAuthOutcome::Rejected {
                reason: "device_token_unknown".to_string(),
            };
        }

        if require_token {
            HelloAuthOutcome::Rejected {
                reason: "token_required".to_string(),
            }
        } else {
            HelloAuthOutcome::LegacyAllowed {
                device_name: clean_name,
            }
        }
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
                let uri = format!(
                    "nfcbridge://{}:{}?name={}&transport=wifi_direct&ssid={}&pass={}&pair={}",
                    host,
                    tcp_port,
                    encoded_name,
                    percent_encode_query(ssid),
                    percent_encode_query(pass),
                    percent_encode_query(pair_token),
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
            "relay" => {
                let channel = self.get_relay_channel();
                let base = self.get_relay_url().unwrap_or_default();
                let ws_base = to_ws_base(&base);
                let http_base = to_http_base(&base);
                let query = format!(
                    "channel={}&name={}&transport=relay&relay={}&pair={}",
                    percent_encode_query(&channel),
                    encoded_name,
                    percent_encode_query(&ws_base),
                    percent_encode_query(pair_token),
                );
                let uri = format!("nfcbridge://relay?{}", query);
                let share = if !http_base.is_empty() {
                    Some(format!("{}/connect?{}", http_base, query))
                } else {
                    None
                };
                (uri, share)
            }
            _ => {
                // tcp (Red Local)
                let ip = tcp_ip.unwrap_or("127.0.0.1");
                let uri = format!(
                    "nfcbridge://{}:{}?name={}&transport=tcp&pair={}",
                    ip,
                    tcp_port,
                    encoded_name,
                    percent_encode_query(pair_token),
                );
                (uri, None)
            }
        }
    }
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

const DEFAULT_OFFICIAL_RELAY_URL: &str = "https://nfc-bridge-relay.hectorzaga96.workers.dev";

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
    option_env!("NFC_BRIDGE_DEFAULT_RELAY_URL")
        .or(Some(DEFAULT_OFFICIAL_RELAY_URL))
        .map(|s| s.trim().trim_end_matches('/').to_string())
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
        assert_eq!(ttl, 90);

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
        assert!(uri.starts_with("nfcbridge://relay?channel=nb-"));
        assert!(uri.contains("relay=wss%3A%2F%2Fnfc-relay.example.workers.dev"));
        assert!(uri.contains("pair=PAIR-1234"));
        let link = share.expect("share link expected when relay URL set");
        assert!(link.starts_with("https://nfc-relay.example.workers.dev/connect?"));

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
}
