//! # Bluetooth RFCOMM SPP Server (Windows Winsock Bluetooth)
//!
//! Expone el servicio RFCOMM SPP nativo de NFC Bridge Driver directamente desde Windows
//! (`AF_BTH` / `BTHPROTO_RFCOMM` + registro SDP vía `WSASetServiceW`) sin depender de
//! Sync ni de puertos COM virtuales manuales.

use std::sync::Arc;
use tracing::{debug, info, warn};

use crate::network::BridgeTcpServer;

pub struct BluetoothRfcommServer {
    coordinator: Arc<BridgeTcpServer>,
}

impl BluetoothRfcommServer {
    pub fn new(coordinator: Arc<BridgeTcpServer>) -> Self {
        Self { coordinator }
    }

    pub async fn run(self: Arc<Self>) {
        #[cfg(windows)]
        {
            info!("Monitor Bluetooth RFCOMM SPP iniciado.");
            let mut logged_unavailable = false;

            loop {
                let coordinator = Arc::clone(&self.coordinator);
                let rt_handle = tokio::runtime::Handle::current();

                let res = tokio::task::spawn_blocking(move || {
                    windows_bt::run_rfcomm_listener(coordinator, rt_handle)
                })
                .await;

                match res {
                    Ok(Ok(())) => {
                        logged_unavailable = false;
                    }
                    Ok(Err(e)) => {
                        if !logged_unavailable {
                            logged_unavailable = true;
                            warn!(
                                "Adaptador Bluetooth no activo o no disponible en Windows ({}); \
                                 reintentando en segundo plano sin afectar TCP/USB.",
                                e
                            );
                        } else {
                            debug!("Reintento Bluetooth RFCOMM: {}", e);
                        }
                    }
                    Err(e) => {
                        debug!("Error en hilo Bluetooth RFCOMM: {}", e);
                    }
                }

                tokio::time::sleep(std::time::Duration::from_secs(5)).await;
            }
        }

        #[cfg(not(windows))]
        {
            let _ = &self.coordinator;
            warn!("Servidor Bluetooth RFCOMM solo soportado en Windows.");
        }
    }
}

#[cfg(windows)]
mod windows_bt {
    use std::mem::{size_of, zeroed};
    use std::ptr::null_mut;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::Arc;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tracing::{debug, info, warn};
    use windows_sys::core::GUID;
    use windows_sys::Win32::Devices::Bluetooth::{AF_BTH, BTHPROTO_RFCOMM, NS_BTH, SOCKADDR_BTH};
    use windows_sys::Win32::Networking::WinSock::{
        accept, bind, closesocket, getsockname, listen, recv, send, setsockopt, shutdown, socket,
        WSAGetLastError, WSASetServiceW, WSAStartup, CSADDR_INFO, INVALID_SOCKET, RNRSERVICE_DELETE,
        RNRSERVICE_REGISTER, SD_BOTH, SOCKADDR, SOCKET, SOCKET_ADDRESS, SOCKET_ERROR, SOCK_STREAM,
        SOL_SOCKET, SO_RCVTIMEO, WSADATA, WSAQUERYSETW,
    };

    use crate::network::BridgeTcpServer;

    /// UUID dedicado para NFC Bridge Bluetooth SPP ("NFCBRIDGE-SPP001").
    /// Debe coincidir exactamente con `BluetoothBridgeTransport.NFC_BRIDGE_UUID` en Android.
    const NFC_BRIDGE_BT_UUID: GUID =
        GUID::from_u128(0x4E464342_5249_4447_452D_535050303031);

    struct SocketGuard(SOCKET);

    impl Drop for SocketGuard {
        fn drop(&mut self) {
            if self.0 != INVALID_SOCKET {
                unsafe {
                    shutdown(self.0, SD_BOTH);
                    closesocket(self.0);
                }
            }
        }
    }

    fn format_bt_mac(addr: u64) -> String {
        format!(
            "{:02X}:{:02X}:{:02X}:{:02X}:{:02X}:{:02X}",
            (addr >> 40) & 0xFF,
            (addr >> 32) & 0xFF,
            (addr >> 24) & 0xFF,
            (addr >> 16) & 0xFF,
            (addr >> 8) & 0xFF,
            addr & 0xFF
        )
    }

    pub fn run_rfcomm_listener(
        coordinator: Arc<BridgeTcpServer>,
        rt_handle: tokio::runtime::Handle,
    ) -> anyhow::Result<()> {
        unsafe {
            let mut wsa_data: WSADATA = zeroed();
            let wsa_res = WSAStartup(0x0202, &mut wsa_data);
            if wsa_res != 0 {
                anyhow::bail!("WSAStartup falló con código {}", wsa_res);
            }

            let raw_listen = socket(AF_BTH as i32, SOCK_STREAM, BTHPROTO_RFCOMM as i32);
            if raw_listen == INVALID_SOCKET {
                anyhow::bail!("socket(AF_BTH) falló (WSA {})", WSAGetLastError());
            }
            let listen_guard = SocketGuard(raw_listen);

            let mut bind_addr = SOCKADDR_BTH {
                addressFamily: AF_BTH,
                btAddr: 0,
                serviceClassId: GUID::from_u128(0),
                port: u32::MAX, // BT_PORT_ANY: asigna canal RFCOMM dinámico libre
            };

            if bind(
                listen_guard.0,
                (&bind_addr as *const SOCKADDR_BTH).cast::<SOCKADDR>(),
                size_of::<SOCKADDR_BTH>() as i32,
            ) == SOCKET_ERROR
            {
                anyhow::bail!(
                    "bind(AF_BTH) falló (WSA {}, radio Bluetooth apagado o ausente)",
                    WSAGetLastError()
                );
            }

            let mut addr_len = size_of::<SOCKADDR_BTH>() as i32;
            if getsockname(
                listen_guard.0,
                (&mut bind_addr as *mut SOCKADDR_BTH).cast::<SOCKADDR>(),
                &mut addr_len,
            ) == SOCKET_ERROR
            {
                anyhow::bail!("getsockname(AF_BTH) falló (WSA {})", WSAGetLastError());
            }

            if listen(listen_guard.0, 4) == SOCKET_ERROR {
                anyhow::bail!("listen(AF_BTH) falló (WSA {})", WSAGetLastError());
            }

            let mut service_name: Vec<u16> = "NFC Bridge Driver\0".encode_utf16().collect();
            let mut comment: Vec<u16> = "NFC Bridge Virtual NFC Reader RFCOMM SPP\0"
                .encode_utf16()
                .collect();
            let mut service_uuid = NFC_BRIDGE_BT_UUID;

            let mut cs_addr = CSADDR_INFO {
                LocalAddr: SOCKET_ADDRESS {
                    lpSockaddr: (&mut bind_addr as *mut SOCKADDR_BTH).cast::<SOCKADDR>(),
                    iSockaddrLength: size_of::<SOCKADDR_BTH>() as i32,
                },
                RemoteAddr: SOCKET_ADDRESS {
                    lpSockaddr: null_mut(),
                    iSockaddrLength: 0,
                },
                iSocketType: SOCK_STREAM,
                iProtocol: BTHPROTO_RFCOMM as i32,
            };

            let mut query_set: WSAQUERYSETW = zeroed();
            query_set.dwSize = size_of::<WSAQUERYSETW>() as u32;
            query_set.lpszServiceInstanceName = service_name.as_mut_ptr();
            query_set.lpServiceClassId = &mut service_uuid;
            query_set.lpszComment = comment.as_mut_ptr();
            query_set.dwNameSpace = NS_BTH;
            query_set.dwNumberOfCsAddrs = 1;
            query_set.lpcsaBuffer = &mut cs_addr;

            if WSASetServiceW(&query_set, RNRSERVICE_REGISTER, 0) == SOCKET_ERROR {
                anyhow::bail!("WSASetServiceW(REGISTER) falló (WSA {})", WSAGetLastError());
            }

            let rfcomm_port = bind_addr.port;
            info!(
                "Driver Bluetooth RFCOMM SPP escuchando en canal {} (UUID: 4E464342-5249-4447-452D-535050303031)",
                rfcomm_port
            );

            loop {
                let mut remote_addr: SOCKADDR_BTH = zeroed();
                let mut remote_len = size_of::<SOCKADDR_BTH>() as i32;
                let client_sock = accept(
                    listen_guard.0,
                    (&mut remote_addr as *mut SOCKADDR_BTH).cast::<SOCKADDR>(),
                    &mut remote_len,
                );

                if client_sock == INVALID_SOCKET {
                    let err = WSAGetLastError();
                    warn!("accept(AF_BTH) finalizado (WSA {})", err);
                    let _ = WSASetServiceW(&query_set, RNRSERVICE_DELETE, 0);
                    anyhow::bail!("accept Bluetooth detenido (WSA {})", err);
                }

                let remote_bt_addr = remote_addr.btAddr;
                let mac = format_bt_mac(remote_bt_addr);
                info!("Cliente Android conectado por Bluetooth RFCOMM ({})", mac);

                let coord = Arc::clone(&coordinator);
                let rt = rt_handle.clone();
                std::thread::spawn(move || {
                    bridge_rfcomm_client(client_sock, mac, coord, rt);
                });
            }
        }
    }

    fn bridge_rfcomm_client(
        client_sock: SOCKET,
        mac: String,
        coordinator: Arc<BridgeTcpServer>,
        rt_handle: tokio::runtime::Handle,
    ) {
        let sock = Arc::new(SocketGuard(client_sock));
        let timeout_ms: i32 = 250;
        unsafe {
            setsockopt(
                sock.0,
                SOL_SOCKET,
                SO_RCVTIMEO,
                (&timeout_ms as *const i32).cast::<u8>(),
                size_of::<i32>() as i32,
            );
        }

        let (bridge_stream, bt_stream) = tokio::io::duplex(16 * 1024);
        let (bridge_reader, bridge_writer) = tokio::io::split(bridge_stream);
        let (mut bt_read_half, mut bt_write_half) = tokio::io::split(bt_stream);

        let running = Arc::new(AtomicBool::new(true));

        let sock_in = Arc::clone(&sock);
        let running_in = Arc::clone(&running);
        let rt_in = rt_handle.clone();
        let in_thread = std::thread::spawn(move || {
            let mut buf = [0u8; 4096];
            while running_in.load(Ordering::Relaxed) {
                let n = unsafe {
                    recv(
                        sock_in.0,
                        buf.as_mut_ptr(),
                        buf.len() as i32,
                        0,
                    )
                };
                if n > 0 {
                    if rt_in
                        .block_on(bt_write_half.write_all(&buf[..n as usize]))
                        .is_err()
                    {
                        break;
                    }
                } else if n == 0 {
                    break;
                } else {
                    let err = unsafe { WSAGetLastError() };
                    // WSAETIMEDOUT = 10060
                    if err == 10060 {
                        continue;
                    }
                    debug!("Bluetooth RFCOMM recv cerrado (WSA {})", err);
                    break;
                }
            }
            running_in.store(false, Ordering::Relaxed);
            let _ = rt_in.block_on(bt_write_half.shutdown());
        });

        let sock_out = Arc::clone(&sock);
        let running_out = Arc::clone(&running);
        let rt_out = rt_handle.clone();
        let out_thread = std::thread::spawn(move || {
            let mut buf = [0u8; 4096];
            while running_out.load(Ordering::Relaxed) {
                let n = match rt_out.block_on(bt_read_half.read(&mut buf)) {
                    Ok(0) | Err(_) => break,
                    Ok(n) => n,
                };

                let mut offset = 0;
                while offset < n && running_out.load(Ordering::Relaxed) {
                    let sent = unsafe {
                        send(
                            sock_out.0,
                            buf[offset..n].as_ptr(),
                            (n - offset) as i32,
                            0,
                        )
                    };
                    if sent <= 0 {
                        let err = unsafe { WSAGetLastError() };
                        debug!("Bluetooth RFCOMM send cerrado (WSA {})", err);
                        running_out.store(false, Ordering::Relaxed);
                        break;
                    }
                    offset += sent as usize;
                }
            }
            running_out.store(false, Ordering::Relaxed);
        });

        rt_handle.block_on(async move {
            coordinator
                .handle_stream(bridge_reader, bridge_writer, format!("Bluetooth ({})", mac))
                .await;
        });

        running.store(false, Ordering::Relaxed);
        unsafe {
            shutdown(sock.0, SD_BOTH);
        }
        let _ = out_thread.join();
        let _ = in_thread.join();
    }
}
