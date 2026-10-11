//! dpi-app motoru: dpi-proxy'nin süreç-içi hali.
//! println yerine verilen log kanalına yazar; hedef çözümleme ve relay aynı.
use dpi_core::{Strategy};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::mpsc::UnboundedSender;
use tokio::time::{sleep, Duration};

#[derive(Debug, Default)]
pub struct Stats {
    pub conns: AtomicU64,
    pub bytes_up: AtomicU64,
    pub bytes_down: AtomicU64,
}

pub type Log = UnboundedSender<(String, String)>;

pub fn tag(line: &str) -> &str {
    if line.starts_with("[=]") || line.contains("temiz") || line.contains("clean") {
        "ok"
    } else if line.starts_with("[!]") || line.contains("ZEHİR") || line.contains("hata") {
        "err"
    } else if line.starts_with("[+]") || line.starts_with("[.]") {
        "warn"
    } else {
        "info"
    }
}

pub fn emit(log: &Log, text: String) {
    let level = tag(&text).to_string();
    let _ = log.send((level, text));
}

fn host_of(connect_host: &Option<String>, buf: &[u8], sni: Option<(usize, usize)>) -> Option<String> {
    if let Some(h) = connect_host {
        let stripped = if h.starts_with('[') {
            h.split("]:").next().map(|s| format!("{s}]")).unwrap_or_else(|| h.clone())
        } else {
            h.split(':').next().unwrap_or(h).to_string()
        };
        return Some(stripped);
    }
    sni.map(|(s, e)| String::from_utf8_lossy(&buf[s..e]).to_string())
}

fn resolve_target_with_sni(buf: &[u8], sni: Option<(usize, usize)>) -> Option<String> {
    sni.map(|(s, e)| {
        let host = String::from_utf8_lossy(&buf[s..e]).to_string();
        let clean: String = host.chars().filter(|c| c.is_alphanumeric() || *c == '.' || *c == '-').collect();
        if clean.is_empty() {
            return String::new();
        }
        format!("{clean}:443")
    })
}

fn http_method(buf: &[u8]) -> bool {
    const METHODS: [&[u8]; 7] = [b"GET ", b"POST ", b"HEAD ", b"PUT ", b"DELETE ", b"OPTIONS ", b"PATCH "];
    METHODS.iter().any(|m| buf.len() >= m.len() && buf[..m.len()].eq_ignore_ascii_case(m))
}

fn plain_http_target(header: &[u8]) -> Option<String> {
    let text = String::from_utf8_lossy(header);
    let mut lines = text.lines();
    let first = lines.next().unwrap_or("");
    let mut parts = first.split_whitespace();
    let _method = parts.next()?;
    let target = parts.next()?;
    let hostport = if let Some(rest) = target.strip_prefix("http://") {
        rest.split('/').next().unwrap_or("").to_string()
    } else if target.starts_with('/') {
        let mut h = String::new();
        for line in lines {
            let l = line.trim();
            if l.len() > 5 && l[..5].eq_ignore_ascii_case("host:") {
                h = l[5..].trim().to_string();
                break;
            }
            if l.is_empty() {
                break;
            }
        }
        h
    } else {
        return None;
    };
    if hostport.is_empty() {
        return None;
    }
    let clean: String = hostport
        .chars()
        .filter(|c| c.is_alphanumeric() || *c == '.' || *c == '-' || *c == ':' || *c == '[' || *c == ']')
        .collect();
    if clean.is_empty() {
        return None;
    }
    if clean.contains(':') {
        Some(clean)
    } else {
        Some(format!("{clean}:80"))
    }
}

#[derive(Debug, Clone, Copy)]
pub struct EngineConfig {
    pub strategy: Strategy,
    pub quiet: bool,
}

async fn handle_client(
    mut inbound: TcpStream,
    strategy: Strategy,
    quiet: bool,
    stats: Arc<Stats>,
    log: Log,
) {
    let _ = inbound.set_nodelay(true);
    let mut head = vec![0u8; 4096];
    let n = match tokio::time::timeout(Duration::from_secs(5), inbound.read(&mut head)).await {
        Ok(Ok(0)) | Ok(Err(_)) | Err(_) => return,
        Ok(Ok(n)) => n,
    };
    head.truncate(n);

    let mut buf: Vec<u8>;
    let mut connect_host: Option<String> = None;
    if head.len() >= 8 && head[..8].eq_ignore_ascii_case(b"CONNECT ") {
        let mut raw = head.clone();
        while !raw.windows(4).any(|w| w == b"\r\n\r\n") {
            if raw.len() > 8192 {
                return;
            }
            let mut more = vec![0u8; 1024];
            match tokio::time::timeout(Duration::from_secs(5), inbound.read(&mut more)).await {
                Ok(Ok(0)) | Ok(Err(_)) | Err(_) => return,
                Ok(Ok(m)) => raw.extend_from_slice(&more[..m]),
            }
        }
        let header_end = raw.windows(4).position(|w| w == b"\r\n\r\n").unwrap() + 4;
        let first_line = String::from_utf8_lossy(&raw[..header_end]).lines().next().unwrap_or("").to_string();
        let hostport = first_line.split_whitespace().nth(1).unwrap_or("");
        let clean: String = hostport
            .chars()
            .filter(|c| c.is_alphanumeric() || *c == '.' || *c == '-' || *c == ':' || *c == '[' || *c == ']')
            .collect();
        if clean.is_empty() || !clean.contains(':') {
            return;
        }
        connect_host = Some(clean);
        buf = raw[header_end..].to_vec();
        if inbound.write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n").await.is_err() {
            return;
        }
        if buf.len() < 3 {
            let mut tls = vec![0u8; 8192];
            match tokio::time::timeout(Duration::from_secs(10), inbound.read(&mut tls)).await {
                Ok(Ok(0)) | Ok(Err(_)) | Err(_) => return,
                Ok(Ok(m)) => buf.extend_from_slice(&tls[..m]),
            }
        }
    } else if head.len() >= 4 && http_method(&head) {
        let mut raw = head.clone();
        while !raw.windows(4).any(|w| w == b"\r\n\r\n") {
            if raw.len() > 16384 {
                return;
            }
            let mut more = vec![0u8; 1024];
            match tokio::time::timeout(Duration::from_secs(5), inbound.read(&mut more)).await {
                Ok(Ok(0)) | Ok(Err(_)) | Err(_) => return,
                Ok(Ok(m)) => raw.extend_from_slice(&more[..m]),
            }
        }
        let target = match plain_http_target(&raw) {
            Some(t) => t,
            None => return,
        };
        emit(&log, format!("[+] hedef(http): {target}"));
        let mut outbound = match TcpStream::connect(&target).await {
            Ok(s) => s,
            Err(e) => {
                emit(&log, format!("[-] bağlanamadı {target}: {e}"));
                return;
            }
        };
        let _ = outbound.set_nodelay(true);
        stats.conns.fetch_add(1, Ordering::Relaxed);
        let raw = dpi_core::disguise_host(&raw);
        let plain_excluded = target.split(':').next().map(|h| dpi_core::is_excluded(h)).unwrap_or(false);
        let cut = raw.len() / 2;
        let (first, second) = if !plain_excluded && raw.len() >= 16 && cut > 0 && cut < raw.len() {
            (&raw[..cut], &raw[cut..])
        } else {
            (&raw[..], &[][..])
        };
        let mut pre = 0u64;
        for p in [first, second] {
            if p.is_empty() {
                continue;
            }
            if let Err(e) = outbound.write_all(p).await {
                emit(&log, format!("[-] yazma hatası: {e}"));
                return;
            }
            pre += p.len() as u64;
        }
        relay(inbound, outbound, stats, &target, pre, quiet, log).await;
        return;
    } else {
        buf = head;
    }

    let (sni_opt, mut parts) = dpi_core::split_once(&buf, strategy);
    let mut delay = match strategy {
        Strategy::SplitWithDelay { delay_ms, .. } => delay_ms,
        Strategy::RecordSplit { delay_ms } => delay_ms,
        Strategy::Custom { delay_ms, .. } => delay_ms,
        _ => 0,
    };
    let reversed = matches!(strategy, Strategy::Custom { order: dpi_core::SendOrder::Reversed, .. });
    if reversed && parts.len() == 2 {
        parts.swap(0, 1);
    }
    let excluded = host_of(&connect_host, &buf, sni_opt).map(|h| dpi_core::is_excluded(&h)).unwrap_or(false);
    if excluded {
        parts = vec![buf.clone()];
        delay = 0;
    }

    let target = match &connect_host {
        Some(h) => h.clone(),
        _ => match resolve_target_with_sni(&buf, sni_opt) {
            Some(t) if !t.is_empty() => t,
            _ => {
                emit(&log, format!("[!] SNI bulunamadı, ilk {} byte", buf.len().min(16)));
                return;
            }
        },
    };
    emit(&log, format!("[+] hedef: {target}"));

    let mut outbound = match TcpStream::connect(&target).await {
        Ok(s) => s,
        Err(e) => {
            emit(&log, format!("[-] bağlanamadı {target}: {e}"));
            return;
        }
    };
    let _ = outbound.set_nodelay(true);
    stats.conns.fetch_add(1, Ordering::Relaxed);

    let mut total = 0u64;
    for (idx, p) in parts.iter().enumerate() {
        if let Err(e) = outbound.write_all(p).await {
            emit(&log, format!("[-] yazma hatası: {e}"));
            return;
        }
        total += p.len() as u64;
        if idx == 0 && delay > 0 && parts.len() > 1 {
            sleep(Duration::from_millis(delay)).await;
        }
    }

    relay(inbound, outbound, stats, &target, total, quiet, log).await;
}

async fn relay(
    mut inbound: TcpStream,
    mut outbound: TcpStream,
    stats: Arc<Stats>,
    target: &str,
    pre_written: u64,
    quiet: bool,
    log: Log,
) {
    let (mut ri, mut wi) = inbound.split();
    let (mut ro, mut wo) = outbound.split();
    let c2s = tokio::io::copy(&mut ri, &mut wo);
    let s2c = tokio::io::copy(&mut ro, &mut wi);
    let (up, down) = tokio::join!(c2s, s2c);
    stats.bytes_up.fetch_add(up.unwrap_or(0) + pre_written, Ordering::Relaxed);
    stats.bytes_down.fetch_add(down.unwrap_or(0), Ordering::Relaxed);
    if !quiet {
        emit(&log, format!("[.] bağlantı kapandı: {target}"));
    }
}

/// Dinleyici döngüsü; dur sinyali gelene kadar çalışır.
pub async fn serve(
    listen: String,
    cfg: EngineConfig,
    stats: Arc<Stats>,
    log: Log,
    mut stop: tokio::sync::watch::Receiver<bool>,
) {
    let listener = match TcpListener::bind(&listen).await {
        Ok(l) => l,
        Err(e) => {
            emit(&log, format!("[-] dinleme hatası {listen}: {e}"));
            return;
        }
    };
    emit(&log, format!("[*] dinliyor: {listen} ({:?})", cfg.strategy));
    loop {
        tokio::select! {
            _ = stop.changed() => break,
            acc = listener.accept() => match acc {
                Ok((sock, addr)) => {
                    if !cfg.quiet {
                        emit(&log, format!("[+] gelen: {addr}"));
                    }
                    let st = cfg.strategy;
                    let sc = stats.clone();
                    let lg = log.clone();
                    let q = cfg.quiet;
                    tokio::spawn(async move {
                        handle_client(sock, st, q, sc, lg).await;
                    });
                }
                Err(_) => break,
            },
        }
    }
}
