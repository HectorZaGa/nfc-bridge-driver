//! Servidor Wi-Fi Direct nativo de Windows (`Windows.Devices.WiFiDirect`) para NFC Bridge Driver.
//!
//! Combina dos modos automáticos en el mismo adaptador inalámbrico de Windows 10/11:
//! 1. **P2P Nativo (`WiFiDirectConnectionListener` + `WiFiDirectDevice`)**: acepta solicitudes
//!    entrantes de `WifiP2pManager` en Android sin intervención manual y mantiene vivo el enlace.
//! 2. **Legacy SoftAP automático (`WiFiDirectLegacySettings`)**: publica un punto de acceso
//!    temporal (`DIRECT-NB-...`) con contraseña WPA2 persistida para conexión directa o vía QR.
//!
//! El transporte de datos binario (tramas NFC Bridge) fluye directamente sobre TCP `45362`
//! una vez establecido el grupo P2P o SoftAP, sin necesidad de router externo.

use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex as StdMutex};
use std::time::Duration;
use tokio::sync::broadcast;
use tracing::{info, warn};

use crate::ipc::events::IpcEvent;
use crate::protocol::constants::DEFAULT_TCP_PORT;

#[derive(Debug, Clone)]
pub struct WifiDirectRuntimeInfo {
    pub available: bool,
    pub active: bool,
    pub pc_name: String,
    pub ssid: Option<String>,
    pub passphrase: Option<String>,
    pub ip: Option<String>,
    pub port: u16,
    pub reason: Option<String>,
}

impl WifiDirectRuntimeInfo {
    pub fn unavailable(pc_name: String, reason: String) -> Self {
        Self {
            available: false,
            active: false,
            pc_name,
            ssid: None,
            passphrase: None,
            ip: None,
            port: DEFAULT_TCP_PORT,
            reason: Some(reason),
        }
    }

    pub fn to_ipc_event(&self) -> IpcEvent {
        IpcEvent::WifiDirectStatus {
            available: self.available,
            active: self.active,
            pc_name: self.pc_name.clone(),
            ssid: self.ssid.clone(),
            passphrase: self.passphrase.clone(),
            ip: self.ip.clone(),
            port: self.port,
            reason: self.reason.clone(),
        }
    }
}

pub struct WifiDirectServer {
    event_tx: broadcast::Sender<IpcEvent>,
    state: Arc<StdMutex<WifiDirectRuntimeInfo>>,
}

impl WifiDirectServer {
    pub fn new(event_tx: broadcast::Sender<IpcEvent>) -> Self {
        let pc_name =
            std::env::var("COMPUTERNAME").unwrap_or_else(|_| "NFC-Bridge-PC".to_string());
        Self {
            event_tx,
            state: Arc::new(StdMutex::new(WifiDirectRuntimeInfo::unavailable(
                pc_name,
                "Inicializando Wi-Fi Direct...".to_string(),
            ))),
        }
    }

    pub fn current_snapshot(&self) -> WifiDirectRuntimeInfo {
        self.state
            .lock()
            .map(|g| g.clone())
            .unwrap_or_else(|_| {
                WifiDirectRuntimeInfo::unavailable(
                    "NFC-Bridge-PC".to_string(),
                    "Estado bloqueado".to_string(),
                )
            })
    }

    pub fn get_status_event(&self) -> IpcEvent {
        match self.state.lock() {
            Ok(guard) => guard.to_ipc_event(),
            Err(_) => IpcEvent::WifiDirectStatus {
                available: false,
                active: false,
                pc_name: "NFC-Bridge-PC".to_string(),
                ssid: None,
                passphrase: None,
                ip: None,
                port: DEFAULT_TCP_PORT,
                reason: Some("Estado Wi-Fi Direct temporalmente bloqueado".to_string()),
            },
        }
    }

    pub async fn run(self: Arc<Self>) {
        #[cfg(windows)]
        {
            info!("Monitor Wi-Fi Direct (P2P + Legacy SoftAP) iniciado.");
            let mut last_logged_reason: Option<String> = None;

            loop {
                match windows_wfd::check_wlan_ready() {
                    Ok(()) => {
                        last_logged_reason = None;
                        let state = Arc::clone(&self.state);
                        let event_tx = self.event_tx.clone();
                        let res = tokio::task::spawn_blocking(move || {
                            windows_wfd::run_wifi_direct_session(state, event_tx)
                        })
                        .await;

                        match res {
                            Ok(Ok(())) => {
                                warn!("Sesión Wi-Fi Direct finalizada; reintentando en 10 s...");
                            }
                            Ok(Err(e)) => {
                                let msg = e.to_string();
                                if last_logged_reason.as_deref() != Some(msg.as_str()) {
                                    warn!("Wi-Fi Direct detenido ({}). Reintento automático en 15 s...", msg);
                                    last_logged_reason = Some(msg.clone());
                                }
                                self.publish_unavailable(msg);
                            }
                            Err(e) => {
                                warn!("Hilo Wi-Fi Direct interrumpido ({}). Reintentando en 15 s...", e);
                            }
                        }
                        tokio::time::sleep(Duration::from_secs(15)).await;
                    }
                    Err(reason) => {
                        if last_logged_reason.as_deref() != Some(reason.as_str()) {
                            info!(
                                "Wi-Fi Direct en espera ({}); se activará automáticamente si se habilita un adaptador Wi-Fi.",
                                reason
                            );
                            last_logged_reason = Some(reason.clone());
                        }
                        self.publish_unavailable(reason);
                        tokio::time::sleep(Duration::from_secs(30)).await;
                    }
                }
            }
        }

        #[cfg(not(windows))]
        {
            let _ = (&self.event_tx, &self.state);
        }
    }

    fn publish_unavailable(&self, reason: String) {
        let evt = {
            let mut guard = match self.state.lock() {
                Ok(g) => g,
                Err(_) => return,
            };
            let pc_name = guard.pc_name.clone();
            *guard = WifiDirectRuntimeInfo::unavailable(pc_name, reason);
            guard.to_ipc_event()
        };
        let _ = self.event_tx.send(evt);
    }
}

/// Construye un SSID estándar Wi-Fi Direct (`DIRECT-NB-...`, máx. 32 bytes ASCII).
pub fn build_wifi_direct_ssid(pc_name: &str) -> String {
    let prefix = "DIRECT-NB-";
    let max_suffix = 32 - prefix.len();
    let cleaned: String = pc_name
        .chars()
        .filter(|c| c.is_ascii_alphanumeric() || *c == '-' || *c == '_')
        .take(max_suffix)
        .collect();
    if cleaned.is_empty() {
        format!("{}PC", prefix)
    } else {
        format!("{}{}", prefix, cleaned)
    }
}

/// Verifica si una IPv4 candidata es válida para comunicación directa P2P/SoftAP (no loopback / link-local).
pub fn is_valid_ipv4_candidate(host: &str) -> bool {
    match host.trim().parse::<std::net::Ipv4Addr>() {
        Ok(ip) => !ip.is_loopback() && !ip.is_unspecified() && !ip.is_link_local(),
        Err(_) => false,
    }
}

/// Carga o genera una clave WPA2 persistente (12 caracteres alfanuméricos sin ambigüedad).
pub fn load_or_create_passphrase(path: &Path) -> String {
    if let Ok(existing) = std::fs::read_to_string(path) {
        let trimmed = existing.trim();
        if (8..=63).contains(&trimmed.len()) && trimmed.chars().all(|c| c.is_ascii_graphic()) {
            return trimmed.to_string();
        }
    }

    let generated = generate_passphrase();
    if let Some(parent) = path.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    let _ = std::fs::write(path, &generated);
    generated
}

fn default_passphrase_path() -> PathBuf {
    PathBuf::from(std::env::var("ProgramData").unwrap_or_else(|_| "C:\\ProgramData".to_string()))
        .join("NFC Bridge")
        .join("wifi_direct_key.txt")
}

fn generate_passphrase() -> String {
    const ALPHABET: &[u8] = b"ABCDEFGHJKLMNPQRSTUVWXYZabcdefghjkmnpqrstuvwxyz23456789";
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(0x5EED_CAFE_1234_ABCD);
    let pid = std::process::id() as u64;
    let mut state = nanos ^ (pid.wrapping_mul(0x9E37_79B9_7F4A_7C15));
    if state == 0 {
        state = 0xA5A5_5A5A_1357_2468;
    }

    let mut out = String::with_capacity(12);
    for _ in 0..12 {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        let idx = (state as usize) % ALPHABET.len();
        out.push(ALPHABET[idx] as char);
    }
    out
}

#[cfg(windows)]
mod windows_wfd {
    use super::*;
    use windows::core::{Ref, HSTRING};
    use windows::Devices::WiFiDirect::{
        WiFiDirectAdvertisementListenStateDiscoverability, WiFiDirectAdvertisementPublisher,
        WiFiDirectAdvertisementPublisherStatus, WiFiDirectConnectionListener,
        WiFiDirectConnectionRequestedEventArgs, WiFiDirectDevice,
    };
    use windows::Foundation::TypedEventHandler;
    use windows::Security::Credentials::PasswordCredential;
    use windows::Win32::Foundation::{ERROR_SERVICE_NOT_ACTIVE, ERROR_SUCCESS, HANDLE, RPC_E_CHANGED_MODE};
    use windows::Win32::NetworkManagement::WiFi::{
        WlanCloseHandle, WlanEnumInterfaces, WlanFreeMemory, WlanOpenHandle,
        WLAN_INTERFACE_INFO_LIST,
    };
    use windows::Win32::System::Com::{CoInitializeEx, CoUninitialize, COINIT_MULTITHREADED};

    struct WlanHandleGuard(HANDLE);
    impl Drop for WlanHandleGuard {
        fn drop(&mut self) {
            if !self.0.is_invalid() {
                unsafe {
                    let _ = WlanCloseHandle(self.0, None);
                }
            }
        }
    }

    struct WlanListGuard(*mut WLAN_INTERFACE_INFO_LIST);
    impl Drop for WlanListGuard {
        fn drop(&mut self) {
            if !self.0.is_null() {
                unsafe {
                    WlanFreeMemory(self.0.cast());
                }
            }
        }
    }

    struct ComApartmentGuard(bool);
    impl Drop for ComApartmentGuard {
        fn drop(&mut self) {
            if self.0 {
                unsafe {
                    CoUninitialize();
                }
            }
        }
    }

    /// Verifica de forma ligera (vía `wlanapi.dll`) si existe `wlansvc` activo y al menos una interfaz Wi-Fi.
    pub fn check_wlan_ready() -> Result<(), String> {
        unsafe {
            let mut negotiated_version: u32 = 0;
            let mut raw_client = HANDLE::default();
            let open_res = WlanOpenHandle(2, None, &mut negotiated_version, &mut raw_client);
            if open_res != ERROR_SUCCESS.0 {
                if open_res == ERROR_SERVICE_NOT_ACTIVE.0 {
                    return Err("wlansvc detenido (sin hardware Wi-Fi activo)".to_string());
                }
                return Err(format!("WlanOpenHandle devolvió código {}", open_res));
            }
            let _wlan_guard = WlanHandleGuard(raw_client);

            let mut list_ptr: *mut WLAN_INTERFACE_INFO_LIST = std::ptr::null_mut();
            let enum_res = WlanEnumInterfaces(raw_client, None, &mut list_ptr);
            if enum_res != ERROR_SUCCESS.0 {
                return Err(format!("WlanEnumInterfaces devolvió código {}", enum_res));
            }
            let _list_guard = WlanListGuard(list_ptr);

            if list_ptr.is_null() || (*list_ptr).dwNumberOfItems == 0 {
                return Err("No hay interfaces Wi-Fi disponibles en este equipo".to_string());
            }

            Ok(())
        }
    }

    fn update_and_emit(
        state: &Arc<StdMutex<WifiDirectRuntimeInfo>>,
        event_tx: &broadcast::Sender<IpcEvent>,
        mutate: impl FnOnce(&mut WifiDirectRuntimeInfo),
    ) {
        let evt = {
            let mut guard = match state.lock() {
                Ok(g) => g,
                Err(_) => return,
            };
            mutate(&mut guard);
            guard.to_ipc_event()
        };
        let _ = event_tx.send(evt);
    }

    pub fn run_wifi_direct_session(
        state: Arc<StdMutex<WifiDirectRuntimeInfo>>,
        event_tx: broadcast::Sender<IpcEvent>,
    ) -> anyhow::Result<()> {
        let hr = unsafe { CoInitializeEx(None, COINIT_MULTITHREADED) };
        let _com_guard = if hr == RPC_E_CHANGED_MODE {
            ComApartmentGuard(false)
        } else {
            hr.ok()?;
            ComApartmentGuard(true)
        };

        let pc_name = state
            .lock()
            .map(|g| g.pc_name.clone())
            .unwrap_or_else(|_| "NFC-Bridge-PC".to_string());
        let ssid = build_wifi_direct_ssid(&pc_name);
        let passphrase = load_or_create_passphrase(&default_passphrase_path());

        let publisher = WiFiDirectAdvertisementPublisher::new()?;
        let adv = publisher.Advertisement()?;
        adv.SetListenStateDiscoverability(
            WiFiDirectAdvertisementListenStateDiscoverability::Intensive,
        )?;
        adv.SetIsAutonomousGroupOwnerEnabled(true)?;

        let legacy = adv.LegacySettings()?;
        legacy.SetIsEnabled(true)?;
        let ssid_h = HSTRING::from(ssid.as_str());
        let pass_h = HSTRING::from(passphrase.as_str());
        legacy.SetSsid(&ssid_h)?;
        let cred = PasswordCredential::CreatePasswordCredential(&ssid_h, &ssid_h, &pass_h)?;
        legacy.SetPassphrase(&cred)?;

        // Mantiene vivas las sesiones P2P aceptadas mientras duren conectadas
        let active_devices: Arc<StdMutex<Vec<WiFiDirectDevice>>> =
            Arc::new(StdMutex::new(Vec::new()));
        let active_devices_cb = Arc::clone(&active_devices);
        let state_cb = Arc::clone(&state);
        let tx_cb = event_tx.clone();

        let listener = WiFiDirectConnectionListener::new()?;
        let _listener_token = listener.ConnectionRequested(&TypedEventHandler::new(
            move |_sender: Ref<WiFiDirectConnectionListener>,
                  args: Ref<WiFiDirectConnectionRequestedEventArgs>|
                  -> windows::core::Result<()> {
                let args = args.ok()?;
                let req = args.GetConnectionRequest()?;
                let dev_info = req.DeviceInformation()?;
                let dev_id = dev_info.Id()?;
                let dev_name = dev_info
                    .Name()
                    .map(|n| n.to_string_lossy())
                    .unwrap_or_else(|_| "Android P2P".to_string());

                info!("Solicitud Wi-Fi Direct P2P entrante de '{}'", dev_name);

                let wfd_dev = WiFiDirectDevice::FromIdAsync(&dev_id)?.join()?;
                let mut local_ipv4: Option<String> = None;

                if let Ok(pairs) = wfd_dev.GetConnectionEndpointPairs() {
                    let count = pairs.Size().unwrap_or(0);
                    for idx in 0..count {
                        if let Ok(pair) = pairs.GetAt(idx) {
                            if let Ok(host) = pair.LocalHostName() {
                                if let Ok(raw) = host.RawName() {
                                    let host_str = raw.to_string_lossy();
                                    if is_valid_ipv4_candidate(&host_str) {
                                        local_ipv4 = Some(host_str);
                                        break;
                                    }
                                }
                            }
                        }
                    }
                }

                if let Ok(mut list) = active_devices_cb.lock() {
                    // Limitar historial de handles P2P retenidos
                    if list.len() >= 4 {
                        list.remove(0);
                    }
                    list.push(wfd_dev);
                }

                if let Some(ip) = local_ipv4 {
                    info!(
                        "Enlace Wi-Fi Direct P2P activo con '{}' (IP Group Owner Windows: {}:{})",
                        dev_name, ip, DEFAULT_TCP_PORT
                    );
                    update_and_emit(&state_cb, &tx_cb, |info| {
                        info.ip = Some(ip);
                        info.active = true;
                        info.available = true;
                        info.reason = Some(format!("Conectado vía P2P con {}", dev_name));
                    });
                }

                Ok(())
            },
        ))?;

        publisher.Start()?;
        std::thread::sleep(Duration::from_millis(450));

        let status = publisher.Status()?;
        if status == WiFiDirectAdvertisementPublisherStatus::Aborted {
            anyhow::bail!("El adaptador Wi-Fi rechazó publicar grupo Wi-Fi Direct");
        }

        let default_softap_ip = "192.168.137.1".to_string();
        info!(
            "Wi-Fi Direct activo: P2P='{}' | SoftAP SSID='{}' | Puerto TCP {}",
            pc_name, ssid, DEFAULT_TCP_PORT
        );

        update_and_emit(&state, &event_tx, |info| {
            info.available = true;
            info.active = true;
            info.ssid = Some(ssid.clone());
            info.passphrase = Some(passphrase.clone());
            info.ip = Some(default_softap_ip.clone());
            info.port = DEFAULT_TCP_PORT;
            info.reason = None;
        });

        loop {
            std::thread::sleep(Duration::from_secs(5));
            if let Err(reason) = check_wlan_ready() {
                let _ = publisher.Stop();
                anyhow::bail!("Adaptador WLAN perdido: {}", reason);
            }
            if publisher.Status()? == WiFiDirectAdvertisementPublisherStatus::Aborted {
                anyhow::bail!("El anuncio Wi-Fi Direct fue abortado por el controlador");
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_build_wifi_direct_ssid_format_and_length() {
        let ssid = build_wifi_direct_ssid("HECTOR MASTER PRO MAX SUPER LONG NAME");
        assert!(ssid.starts_with("DIRECT-NB-"));
        assert!(ssid.len() <= 32);
        assert!(!ssid.contains(' '));

        assert_eq!(build_wifi_direct_ssid("   "), "DIRECT-NB-PC");
    }

    #[test]
    fn test_is_valid_ipv4_candidate() {
        assert!(is_valid_ipv4_candidate("192.168.137.1"));
        assert!(is_valid_ipv4_candidate("192.168.49.1"));
        assert!(!is_valid_ipv4_candidate("127.0.0.1"));
        assert!(!is_valid_ipv4_candidate("169.254.1.2"));
        assert!(!is_valid_ipv4_candidate("fe80::1"));
    }

    #[test]
    fn test_load_or_create_passphrase_persists_valid_key() {
        let mut path = std::env::temp_dir();
        path.push(format!("nfc_bridge_wfd_key_{}.txt", std::process::id()));
        let _ = std::fs::remove_file(&path);

        let first = load_or_create_passphrase(&path);
        assert!((8..=63).contains(&first.len()));

        let second = load_or_create_passphrase(&path);
        assert_eq!(first, second);

        let _ = std::fs::remove_file(&path);
    }
}
