//! DPI VPN Tauri kabuğu: süreç-içi proxy motoru + sistem anahtarları + tepsi.
mod engine;

use engine::{EngineConfig, Stats};
use serde::Serialize;
use std::os::windows::process::CommandExt;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tauri::{AppHandle, Emitter, Manager};
use tokio::sync::{mpsc, watch};

const NO_WINDOW: u32 = 0x08000000;

struct ProxyState {
    stop_tx: Option<watch::Sender<bool>>,
    stats: Arc<Stats>,
    start: Option<Instant>,
    profile: String,
    mode: String,
}

impl Default for ProxyState {
    fn default() -> Self {
        Self { stop_tx: None, stats: Arc::new(Stats::new()), start: None, profile: String::new(), mode: String::new() }
    }
}

impl Stats {
    fn new() -> Self {
        Self::default()
    }
}

#[derive(Serialize, Clone)]
struct LogLine {
    level: String,
    text: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct Status {
    running: bool,
    uptime_sec: u64,
    conns: u64,
    bytes_up: u64,
    bytes_down: u64,
    profile: String,
    mode: String,
}

// CREATE_NO_WINDOW ile komut çalıştır, çıktıyı al.
fn quiet_output(program: &str, args: &[&str]) -> Option<String> {
    let out = std::process::Command::new(program)
        .args(args)
        .creation_flags(NO_WINDOW)
        .output()
        .ok()?;
    Some(String::from_utf8_lossy(&out.stdout).to_string())
}

// PowerShell komutunu UTF-16LE + base64 olarak kodlar (-EncodedCommand): tırnak sorunu olmaz.
fn encode_ps(script: &str) -> String {
    const T: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let bytes: Vec<u8> = script.encode_utf16().flat_map(|c| c.to_le_bytes()).collect();
    let mut out = String::new();
    for chunk in bytes.chunks(3) {
        let b = [chunk[0], *chunk.get(1).unwrap_or(&0), *chunk.get(2).unwrap_or(&0)];
        let n = ((b[0] as u32) << 16) | ((b[1] as u32) << 8) | b[2] as u32;
        for i in 0..4 {
            if i <= chunk.len() {
                out.push(T[((n >> (18 - 6 * i)) & 63) as usize] as char);
            } else {
                out.push('=');
            }
        }
    }
    out
}

// Yönetici olarak çalıştır (UAC). Komut bitene kadar bekler; başarıda true.
fn run_elevated(ps_command: &str) -> bool {
    let encoded = encode_ps(ps_command);
    let script = format!(
        "try {{ $p = Start-Process powershell -Verb RunAs -WindowStyle Hidden -Wait -PassThru \
         -ArgumentList '-NoProfile -EncodedCommand {encoded}'; if ($p.ExitCode -eq 0) {{ exit 0 }} else {{ exit 1 }} }} catch {{ exit 1 }}"
    );
    std::process::Command::new("powershell")
        .args(["-NoProfile", "-Command", &script])
        .creation_flags(NO_WINDOW)
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

#[tauri::command]
async fn proxy_start(
    app: AppHandle,
    state: tauri::State<'_, Mutex<ProxyState>>,
    profile: String,
    mode: String,
    delay_ms: u64,
    lan_share: bool,
) -> Result<String, String> {
    {
        let st = state.lock().map_err(|e| e.to_string())?;
        if st.stop_tx.is_some() {
            return Err("zaten çalışıyor".into());
        }
    }
    let auto = mode.as_str() == "otomatik";
    let strategy = match mode.as_str() {
        "parcala" => dpi_core::Strategy::Fragment { chunk_size: 32 },
        "dengeli" => dpi_core::Strategy::RecordSplit { delay_ms },
        "ters" => dpi_core::Strategy::Custom {
            cut: dpi_core::CutPos::Before,
            order: dpi_core::SendOrder::Reversed,
            delay_ms,
        },
        // otomatik: ilk pakette auto_pick seçer (aşağıda), varsayılan yedek
        _ => dpi_core::Strategy::RecordSplit { delay_ms: 0 },
    };
    let listen = if lan_share { "0.0.0.0:8888" } else { "127.0.0.1:8888" }.to_string();
    let listener = tokio::net::TcpListener::bind(&listen)
        .await
        .map_err(|e| format!("dinleme hatası {listen}: {e}"))?;
    let (log_tx, mut log_rx) = mpsc::unbounded_channel::<(String, String)>();
    let (stop_tx, stop_rx) = watch::channel(false);
    let stats = Arc::new(Stats::new());
    let stats_run = stats.clone();
    let app_log = app.clone();
    tauri::async_runtime::spawn(async move {
        while let Some((level, text)) = log_rx.recv().await {
            let _ = app_log.emit("log", LogLine { level, text });
        }
    });
    let cfg = EngineConfig { strategy, quiet: true, auto };
    tauri::async_runtime::spawn(engine::serve_listener(listen.clone(), listener, cfg, stats_run, log_tx, stop_rx));
    {
        let mut st = state.lock().map_err(|e| e.to_string())?;
        st.stop_tx = Some(stop_tx);
        st.stats = stats;
        st.start = Some(Instant::now());
        st.profile = profile.clone();
        st.mode = mode.clone();
    }
    Ok(format!("başlatıldı: {listen} ({profile}/{mode})"))
}

#[tauri::command]
async fn proxy_stop(state: tauri::State<'_, Mutex<ProxyState>>) -> Result<(), String> {
    let mut st = state.lock().map_err(|e| e.to_string())?;
    if let Some(tx) = st.stop_tx.take() {
        let _ = tx.send(true);
    }
    st.start = None;
    Ok(())
}

#[tauri::command]
async fn get_status(state: tauri::State<'_, Mutex<ProxyState>>) -> Result<Status, String> {
    use std::sync::atomic::Ordering;
    let st = state.lock().map_err(|e| e.to_string())?;
    Ok(Status {
        running: st.stop_tx.is_some(),
        uptime_sec: st.start.map(|t| t.elapsed().as_secs()).unwrap_or(0),
        conns: st.stats.conns.load(Ordering::Relaxed),
        bytes_up: st.stats.bytes_up.load(Ordering::Relaxed),
        bytes_down: st.stats.bytes_down.load(Ordering::Relaxed),
        profile: st.profile.clone(),
        mode: st.mode.clone(),
    })
}

// ---- sistem anahtarları (HKCU: admin istemez) ----

const IE_KEY: &str = r"Software\Microsoft\Windows\CurrentVersion\Internet Settings";

#[tauri::command]
fn sysproxy_set(on: bool) -> Result<String, String> {
    use winreg::{enums::*, RegKey};
    let hkcu = RegKey::predef(HKEY_CURRENT_USER);
    if on {
        let (key, _) = hkcu.create_subkey(IE_KEY).map_err(|e| e.to_string())?;
        key.set_value("ProxyEnable", &1u32).map_err(|e| e.to_string())?;
        key.set_value("ProxyServer", &"http=127.0.0.1:8888;https=127.0.0.1:8888").map_err(|e| e.to_string())?;
        key.set_value("ProxyOverride", &"<local>").map_err(|e| e.to_string())?;
        Ok("sistem proxy açık".into())
    } else {
        // Eskiyi bilmediğimiz için en güvenli geri dönüş: tamamen kapat.
        // (tk sürümü eski değeri saklardı; burada da saklamak için state gerekir —
        //  basitlik adına kapatıyoruz, Windows varsayılanı da kapalıdır.)
        let (key, _) = hkcu.create_subkey(IE_KEY).map_err(|e| e.to_string())?;
        key.set_value("ProxyEnable", &0u32).map_err(|e| e.to_string())?;
        Ok("sistem proxy kapalı".into())
    }
}

fn dns_alias() -> Option<String> {
    let out = quiet_output("powershell", &["-NoProfile", "-Command",
        "Get-DnsClientServerAddress -AddressFamily IPv4 | Where-Object {$_.ServerAddresses} | Select-Object -First 1 -ExpandProperty InterfaceAlias"])?;
    let alias = out.trim().to_string();
    if alias.is_empty() {
        None
    } else {
        Some(alias)
    }
}

#[tauri::command]
fn dns_set(on: bool) -> Result<String, String> {
    if on {
        let alias = dns_alias().ok_or("aktif arayüz bulunamadı")?;
        let cmd = format!(
            "Set-DnsClientServerAddress -InterfaceAlias \"{alias}\" -ServerAddresses 1.1.1.1,1.0.0.1; \
             Set-DnsClientServerAddress -InterfaceAlias \"{alias}\" -ServerAddresses 2606:4700:4700::1111,2606:4700:4700::1001; \
             Disable-NetAdapterBinding -InterfaceAlias \"{alias}\" -ComponentID ms_tcpip6");
        if run_elevated(&cmd) {
            Ok(format!("DNS modu açık ({alias})"))
        } else {
            Err("UAC reddedildi".into())
        }
    } else {
        // Arayüzü bulamazsak da sıfırlamayı dene (kayıtlı alias yok).
        let alias = dns_alias().unwrap_or_default();
        if !alias.is_empty() {
            let cmd = format!(
                "Set-DnsClientServerAddress -InterfaceAlias \"{alias}\" -ResetServerAddresses; \
                 Enable-NetAdapterBinding -InterfaceAlias \"{alias}\" -ComponentID ms_tcpip6");
            run_elevated(&cmd);
        }
        Ok("DNS sıfırlandı".into())
    }
}

#[tauri::command]
fn quic_status() -> bool {
    let out = quiet_output("netsh", &["advfirewall", "firewall", "show", "rule", "name=DPIVPN-QUIC"])
        .unwrap_or_default();
    out.contains("Enabled:") && out.contains("Yes") && !out.contains("No rules match")
}

#[tauri::command]
fn quic_set(on: bool) -> Result<String, String> {
    if on {
        let cmd = "netsh advfirewall firewall add rule name=\"DPIVPN-QUIC\" dir=out action=block protocol=UDP remoteport=443";
        if run_elevated(cmd) {
            Ok("QUIC engellendi".into())
        } else {
            Err("UAC reddedildi".into())
        }
    } else {
        let cmd = "netsh advfirewall firewall delete rule name=\"DPIVPN-QUIC\"";
        run_elevated(cmd);
        Ok("QUIC engeli kalktı".into())
    }
}

#[tauri::command]
fn analyze() -> serde_json::Value {
    let out = quiet_output("nslookup", &["updates.discord.com"]).unwrap_or_default();
    if out.contains("195.175.254.2") {
        serde_json::json!({"verdict": "poison", "detail": "195.175.254.2"})
    } else if out.contains("162.159") {
        serde_json::json!({"verdict": "clean", "detail": "Cloudflare aralığı"})
    } else {
        serde_json::json!({"verdict": "vague", "detail": out.chars().take(400).collect::<String>()})
    }
}

/// Süreç-içi mikro-bench: cargo gerektirmez, bu makinede gerçek ölçüm.
#[tauri::command]
fn bench() -> String {
    // sentetik 240B TLS-benzeri hello (SNI=bench.local, 11B)
    let sni = b"bench.local";
    let mut entry = vec![0u8];
    entry.extend_from_slice(&(sni.len() as u16).to_be_bytes());
    entry.extend_from_slice(sni);
    let mut sn = vec![0u8, 0u8];
    sn.extend_from_slice(&((entry.len() + 2) as u16).to_be_bytes());
    sn.extend_from_slice(&(entry.len() as u16).to_be_bytes());
    sn.extend_from_slice(&entry);
    let mut body = vec![0x03u8, 0x03];
    body.extend_from_slice(&[0xAAu8; 32]);
    body.extend_from_slice(&[0x00, 0x00, 0x02, 0x13, 0x01, 0x01, 0x00]);
    body.extend_from_slice(&(sn.len() as u16).to_be_bytes());
    body.extend_from_slice(&sn);
    let mut hs = vec![0x01u8, 0, 0, 0];
    let bl = body.len() as u32;
    hs[1..4].copy_from_slice(&[(bl >> 16) as u8, (bl >> 8) as u8, bl as u8]);
    hs.extend_from_slice(&body);
    let mut pkt = vec![0x16u8, 0x03, 0x01, 0, 0];
    let hl = hs.len() as u16;
    pkt[3..5].copy_from_slice(&hl.to_be_bytes());
    pkt.extend_from_slice(&hs);

    let iters = 20_000u32;
    let t0 = std::time::Instant::now();
    let mut n = 0usize;
    for _ in 0..iters {
        let (s, p) = dpi_core::split_once(&pkt, dpi_core::Strategy::RecordSplit { delay_ms: 0 });
        n += p.len() + s.is_some() as usize;
    }
    let el = t0.elapsed();
    format!("one-parse={:.0}ns/op (n={n})", el.as_nanos() as f64 / iters as f64)
}

fn main() {
    // Başsız öz-test: arayüz tıklaması olmadan motoru doğrular.
    if std::env::args().any(|a| a == "--self-test") {
        std::process::exit(self_test());
    }
    tauri::Builder::default()
        .plugin(tauri_plugin_single_instance::init(|app, _args, _cwd| {
            if let Some(w) = app.get_webview_window("main") {
                let _ = w.show();
                let _ = w.set_focus();
            }
        }))
        .manage(Mutex::new(ProxyState::default()))
        .invoke_handler(tauri::generate_handler![
            proxy_start, proxy_stop, get_status,
            sysproxy_set, dns_set, quic_status, quic_set,
            analyze, bench
        ])
        .setup(|app| {
            use tauri::tray::{MouseButton, MouseButtonState, TrayIconBuilder, TrayIconEvent};
            use tauri::menu::{MenuBuilder, MenuItemBuilder};
            let show = MenuItemBuilder::with_id("show", "Göster").build(app)?;
            let toggle = MenuItemBuilder::with_id("toggle", "BAŞLAT/DURDUR").build(app)?;
            let quit = MenuItemBuilder::with_id("quit", "Çıkış").build(app)?;
            let menu = MenuBuilder::new(app).items(&[&show, &toggle, &quit]).build()?;
            let _tray = TrayIconBuilder::with_id("main")
                .menu(&menu)
                .tooltip("DPI VPN")
                .on_menu_event(|app, event| match event.id().as_ref() {
                    "show" => {
                        if let Some(w) = app.get_webview_window("main") {
                            let _ = w.show();
                            let _ = w.set_focus();
                        }
                    }
                    "toggle" => {
                        if let Some(w) = app.get_webview_window("main") {
                            let _ = w.emit("tray-toggle", ());
                        }
                    }
                    "quit" => app.exit(0),
                    _ => {}
                })
                .on_tray_icon_event(|tray, event| {
                    if let TrayIconEvent::Click { button: MouseButton::Left, button_state: MouseButtonState::Up, .. } = event {
                        let app = tray.app_handle();
                        if let Some(w) = app.get_webview_window("main") {
                            let _ = w.show();
                            let _ = w.set_focus();
                        }
                    }
                })
                .build(app)?;
            // pencere kapatılınca tepsiye in (uygulama kapanmaz)
            if let Some(w) = app.get_webview_window("main") {
                let w2 = w.clone();
                w.on_window_event(move |ev| {
                    if let tauri::WindowEvent::CloseRequested { api, .. } = ev {
                        api.prevent_close();
                        let _ = w2.hide();
                    }
                });
            }
            Ok(())
        })
        .run(tauri::generate_context!())
        .expect("tauri çalışmadı");
}

/// Başsız öz-test: CONNECT + record-split hello → 200 + sunucu baytı.
/// Çıkış kodu: 0 geçtı, 1 ağ/DPI sorunu, 2 iç hata.
fn self_test() -> i32 {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let rt = match tokio::runtime::Builder::new_multi_thread().enable_all().build() {
        Ok(rt) => rt,
        Err(e) => {
            eprintln!("SELFTEST runtime: {e}");
            return 2;
        }
    };
    rt.block_on(async {
        let (log_tx, _log_rx) = tokio::sync::mpsc::unbounded_channel();
        let stats = Arc::new(Stats::new());
        let (_stop_tx, stop_rx) = tokio::sync::watch::channel(false);
        let listener = match tokio::net::TcpListener::bind("127.0.0.1:0").await {
            Ok(l) => l,
            Err(e) => {
                eprintln!("SELFTEST bind: {e}");
                return 2;
            }
        };
        let port = listener.local_addr().map(|a| a.port()).unwrap_or(0);
        drop(listener);
        let cfg = EngineConfig { strategy: dpi_core::Strategy::RecordSplit { delay_ms: 0 }, quiet: true, auto: false };
        tokio::spawn(engine::serve(format!("127.0.0.1:{port}"), cfg, stats, log_tx, stop_rx));
        tokio::time::sleep(Duration::from_millis(300)).await;
        let sni = b"t.selftest";
        let mut entry = vec![0u8];
        entry.extend_from_slice(&(sni.len() as u16).to_be_bytes());
        entry.extend_from_slice(sni);
        let mut sn = vec![0u8, 0u8];
        sn.extend_from_slice(&((entry.len() + 2) as u16).to_be_bytes());
        sn.extend_from_slice(&(entry.len() as u16).to_be_bytes());
        sn.extend_from_slice(&entry);
        let mut body = vec![0x03u8, 0x03];
        body.extend_from_slice(&[0xAAu8; 32]);
        body.extend_from_slice(&[0x00, 0x00, 0x02, 0x13, 0x01, 0x01, 0x00]);
        body.extend_from_slice(&(sn.len() as u16).to_be_bytes());
        body.extend_from_slice(&sn);
        let mut hs = vec![0x01u8, 0, 0, 0];
        let bl = body.len() as u32;
        hs[1..4].copy_from_slice(&[(bl >> 16) as u8, (bl >> 8) as u8, bl as u8]);
        hs.extend_from_slice(&body);
        let mut hello = vec![0x16u8, 0x03, 0x01, 0, 0];
        let hl = hs.len() as u16;
        hello[3..5].copy_from_slice(&hl.to_be_bytes());
        hello.extend_from_slice(&hs);

        let mut cli = match tokio::net::TcpStream::connect(format!("127.0.0.1:{port}")).await {
            Ok(c) => c,
            Err(e) => {
                eprintln!("SELFTEST connect: {e}");
                return 2;
            }
        };
        if cli.write_all(b"CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\n").await.is_err() {
            eprintln!("SELFTEST send-connect");
            return 2;
        }
        let mut resp = vec![0u8; 64];
        let n = match tokio::time::timeout(Duration::from_secs(5), cli.read(&mut resp)).await {
            Ok(Ok(n)) => n,
            _ => {
                eprintln!("SELFTEST no-200");
                return 1;
            }
        };
        if !resp[..n].windows(3).any(|w| w == b"200") {
            eprintln!("SELFTEST bad-200");
            return 1;
        }
        if cli.write_all(&hello).await.is_err() {
            eprintln!("SELFTEST send-hello");
            return 2;
        }
        let mut back = vec![0u8; 16];
        match tokio::time::timeout(Duration::from_secs(15), cli.read(&mut back)).await {
            Ok(Ok(n)) if n > 0 => {
                println!("SELFTEST PASS (200 + {n}B sunucu yanıtı)");
                0
            }
            _ => {
                eprintln!("SELFTEST no-server-bytes");
                1
            }
        }
    })
}
