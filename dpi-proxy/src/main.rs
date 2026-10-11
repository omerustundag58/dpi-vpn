// SPDX-License-Identifier: GPL-3.0-or-later
//! dpi-proxy: sürücüsüz Windows test proxy'si.
//!
//! Kullanım:
//!   dpi-proxy --listen 127.0.0.1:8888 --target-suffix ":443" --split-at 2
//!
//! MVP: istemciden gelen ilk TLS paketini dpi-core ile ikiye bölüp
//! hedefe parçalı gönderir. Tarayıcıda bu proxy'ye yönlendirme yapılır.
//! (İleride: WinDivert TUN + Android VpnService aynı core'u kullanacak.)

use dpi_core::{CutPos, SendOrder, Strategy};
use std::env;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::time::{sleep, Duration};

/// Paylaşılan istatistikler (30sn'de bir stdout'a basılır).
#[derive(Debug, Default)]
struct Stats {
    conns: AtomicU64,
    bytes_up: AtomicU64,
    bytes_down: AtomicU64,
}

#[derive(Debug, Clone)]
struct Config {
    listen: String,
    strategy: Strategy,
    /// Testler için: SNI ne olursa olsun bu hedefe bağlan (örn. 127.0.0.1:PORT).
    force_target: Option<String>,
    /// Sessiz kip: bağlantı başına gelen/kapandı satırları basılmaz.
    quiet: bool,
}

fn parse_args_from(args: &[String]) -> Config {
    let mut listen = "127.0.0.1:8888".to_string();
    let mut split_at = 2usize;
    let mut delay_ms = 10u64;
    let mut fragment: Option<usize> = None;
    let mut tls_records = false;
    let mut legacy_touched = false;
    let mut cut: Option<CutPos> = None;
    let mut reverse = false;
    let mut quiet = false;
    let mut force_target: Option<String> = None;
    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--listen" if i + 1 < args.len() => {
                listen = args[i + 1].clone();
                i += 2;
            }
            "--split-at" if i + 1 < args.len() => {
                split_at = args[i + 1].parse().unwrap_or(2);
                legacy_touched = true;
                i += 2;
            }
            "--delay-ms" if i + 1 < args.len() => {
                delay_ms = args[i + 1].parse().unwrap_or(10);
                legacy_touched = true;
                i += 2;
            }
            "--fragment" if i + 1 < args.len() => {
                fragment = args[i + 1].parse().ok();
                i += 2;
            }
            "--tls-records" => {
                tls_records = true;
                i += 1;
            }
            "--cut" if i + 1 < args.len() => {
                cut = match args[i + 1].as_str() {
                    "before" => Some(CutPos::Before),
                    "mid" => Some(CutPos::Mid),
                    _ => args[i + 1].parse::<usize>().ok().map(CutPos::At),
                };
                i += 2;
            }
            "--reverse" => {
                reverse = true;
                i += 1;
            }
            "--quiet" => {
                quiet = true;
                i += 1;
            }
            "--force-target" if i + 1 < args.len() => {
                force_target = Some(args[i + 1].clone());
                i += 2;
            }
            _ => i += 1,
        }
    }
    let strategy = if tls_records {
        Strategy::RecordSplit { delay_ms }
    } else {
        match fragment {
            Some(cs) => Strategy::Fragment { chunk_size: cs.max(1) },
            // Bayrak yoksa kanıtlı varsayılan: record-split (gecikmesiz).
            // Eski TCP-bölme için açıkça --delay-ms ver.
            None if cut.is_some() || reverse => Strategy::Custom {
                cut: cut.unwrap_or(CutPos::Mid),
                order: if reverse { SendOrder::Reversed } else { SendOrder::InOrder },
                delay_ms,
            },
            None if legacy_touched => Strategy::SplitWithDelay { split_at, delay_ms },
            None => Strategy::RecordSplit { delay_ms: 0 },
        }
    };
    Config { listen, strategy, force_target, quiet }
}

fn parse_args() -> Config {
    parse_args_from(&env::args().collect::<Vec<_>>())
}

/// CONNECT/SNI'dan çıplak host çıkar (portsuz, küçük harf değil — is_excluded halleder).
/// IPv6 köşeli parantezi korunur ([::1] -> "[::1]").
fn host_of(connect_host: &Option<String>, buf: &[u8], sni: Option<(usize, usize)>) -> Option<String> {
    if let Some(h) = connect_host {
        // sondaki :portu at (IPv6'da son ':' sonrası porttur)
        let stripped = if h.starts_with('[') {
            h.split("]:").next().map(|s| format!("{s}]")).unwrap_or_else(|| h.clone())
        } else {
            h.split(':').next().unwrap_or(h).to_string()
        };
        return Some(stripped);
    }
    sni.map(|(s, e)| String::from_utf8_lossy(&buf[s..e]).to_string())
}

/// Önceden parse edilmiş SNI ile hedef üret (hızlı yol, ikinci parse yok).
/// Test edilebilir saf fonksiyon.
fn resolve_target_with_sni(
    buf: &[u8],
    sni: Option<(usize, usize)>,
    force: Option<&str>,
) -> Option<String> {
    if let Some(f) = force {
        return Some(f.to_string());
    }
    sni.map(|(s, e)| {
        let host = String::from_utf8_lossy(&buf[s..e]).to_string();
        // SNI'da port enjeksiyonu / boşluk engelle (güvenlik)
        let clean: String = host.chars().filter(|c| c.is_alphanumeric() || *c == '.' || *c == '-').collect();
        if clean.is_empty() {
            return String::new();
        }
        format!("{clean}:443")
    })
}

/// Basit hedef çözümleme: ilk pakette SNI varsa ona bağlan,
/// yoksa varsayılan hedefe. MVP'de SNI -> IP için DNS kullanıyoruz.
/// Tarayıcılar HTTP CONNECT ile gelir (örn. "CONNECT host:443 HTTP/1.1");
/// ham TLS gelirse eski SNI-sniff yolu kullanılır.
async fn handle_client(mut inbound: TcpStream, strategy: Strategy, force_target: Option<String>, stats: Arc<Stats>, quiet: bool) {
    // Nagle kapalı: bölünmüş parçalar tek TCP segmentinde birleşmesin.
    // Bu olmadan DPI bypass şansa kalır.
    let _ = inbound.set_nodelay(true);
    // Önce başlığı oku: CONNECT ise \r\n\r\n'e kadar, ham TLS ise ilk parça.
    let mut head = vec![0u8; 4096];
    let n = match tokio::time::timeout(Duration::from_secs(5), inbound.read(&mut head)).await {
        Ok(Ok(0)) | Ok(Err(_)) | Err(_) => return,
        Ok(Ok(n)) => n,
    };
    head.truncate(n);

    // HTTP CONNECT mi? ("CONNECT " ile başlar)
    let mut buf: Vec<u8>;
    let mut connect_host: Option<String> = None;
    if head.len() >= 8 && head[..8].eq_ignore_ascii_case(b"CONNECT ") {
        // başlığın tamamını topla
        let mut raw = head.clone();
        while !raw.windows(4).any(|w| w == b"\r\n\r\n") {
            if raw.len() > 8192 {
                return; // saçma büyük başlık
            }
            let mut more = vec![0u8; 1024];
            match tokio::time::timeout(Duration::from_secs(5), inbound.read(&mut more)).await {
                Ok(Ok(0)) | Ok(Err(_)) | Err(_) => return,
                Ok(Ok(m)) => raw.extend_from_slice(&more[..m]),
            }
        }
        let header_end = raw.windows(4).position(|w| w == b"\r\n\r\n").unwrap() + 4;
        let first_line = String::from_utf8_lossy(&raw[..header_end]).lines().next().unwrap_or("").to_string();
        // "CONNECT host:port HTTP/1.1" — IPv6 köşeli parantezli de olabilir ([::1]:443)
        let hostport = first_line.split_whitespace().nth(1).unwrap_or("");
        let clean: String = hostport
            .chars()
            .filter(|c| c.is_alphanumeric() || *c == '.' || *c == '-' || *c == ':' || *c == '[' || *c == ']')
            .collect();
        if clean.is_empty() || !clean.contains(':') {
            return;
        }
        connect_host = Some(clean);
        buf = raw[header_end..].to_vec(); // başlık sonrası gelen TLS baytları (genelde boş)
        // 200 onayı gönder
        if inbound.write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n").await.is_err() {
            return;
        }
        // ClientHello'yu bekle (tarayıcı 200 sonrası gönderir)
        if buf.len() < 3 {
            let mut tls = vec![0u8; 8192];
            match tokio::time::timeout(Duration::from_secs(10), inbound.read(&mut tls)).await {
                Ok(Ok(0)) | Ok(Err(_)) | Err(_) => return,
                Ok(Ok(m)) => buf.extend_from_slice(&tls[..m]),
            }
        }
    } else if head.len() >= 4 && http_method(&head) {
        // Düz HTTP (https değil): absolute-URI ya da Host başlığından hedefi bul,
        // isteği ortadan bölerek ilet (Host DPI'dan gizlenir), sonra relay.
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
        let target = match force_target.clone() {
            Some(f) => f,
            None => match plain_http_target(&raw) {
                Some(t) => t,
                None => return,
            },
        };
        println!("[+] hedef(http): {target}");
        let mut outbound = match TcpStream::connect(&target).await {
            Ok(s) => s,
            Err(e) => {
                eprintln!("[-] bağlanamadı {target}: {e}");
                return;
            }
        };
        let _ = outbound.set_nodelay(true);
        stats.conns.fetch_add(1, Ordering::Relaxed);
        // HoSt kılık değiştirme (goodbyedpi -r): başlık ismi yasal aralıkta değişir
        let raw = dpi_core::disguise_host(&raw);
        // muaf hostsa bölmeden tek parça (devlet/yerli hızlı geçer)
        let plain_excluded = target.split(':').next().is_some_and(dpi_core::is_excluded);
        // ortadan böl (16B altı istekler tek parça)
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
                eprintln!("[-] yazma hatası: {e}");
                return;
            }
            pre += p.len() as u64;
        }
        relay(inbound, outbound, stats, &target, pre, quiet).await;
        return;
    } else {
        buf = head;
    }

    // Hızlı yol: tek parse ile SNI + parçalar (Android'de pil/CPU dostu).
    let strategy_owned = strategy;
    let (sni_opt, mut parts) = dpi_core::split_once(&buf, strategy_owned);
    let mut delay = match strategy_owned {
        Strategy::SplitWithDelay { delay_ms, .. } => delay_ms,
        Strategy::RecordSplit { delay_ms } => delay_ms,
        Strategy::Custom { delay_ms, .. } => delay_ms,
        _ => 0,
    };
    // Ters sıra: parça2 önce gider (goodbyedpi --reverse-frag).
    let reversed = matches!(strategy_owned, Strategy::Custom { order: SendOrder::Reversed, .. });
    if reversed && parts.len() == 2 {
        parts.swap(0, 1);
    }
    // Muaf host (devlet/yerli): bölmeden direkt ilet — yavaşlama yok.
    let excluded = host_of(&connect_host, &buf, sni_opt).map(|h| dpi_core::is_excluded(&h)).unwrap_or(false);
    if excluded {
        parts = vec![buf.clone()];
        delay = 0;
    }

    let target = match &connect_host {
        // CONNECT yolunda hedef başlıktan gelir (force-target testleri ezer)
        Some(h) if force_target.is_none() => h.clone(),
        _ => match resolve_target_with_sni(&buf, sni_opt, force_target.as_deref()) {
            Some(t) if !t.is_empty() => t,
            _ => {
                eprintln!("[!] SNI bulunamadı, ilk {} byte: {:02X?}", buf.len().min(16), &buf[..buf.len().min(16)]);
                return;
            }
        },
    };
    println!("[+] hedef: {target}");

    let mut outbound = match TcpStream::connect(&target).await {
        Ok(s) => s,
        Err(e) => {
            eprintln!("[-] bağlanamadı {target}: {e}");
            return;
        }
    };
    let _ = outbound.set_nodelay(true);
    stats.conns.fetch_add(1, Ordering::Relaxed);

    // DPI bypass: parçalı gönder (parçalar yukarıda tek parse ile hazır)
    let mut total = 0;
    for (idx, p) in parts.iter().enumerate() {
        if let Err(e) = outbound.write_all(p).await {
            eprintln!("[-] yazma hatası: {e}");
            return;
        }
        total += p.len();
        if idx == 0 && delay > 0 && parts.len() > 1 {
            sleep(Duration::from_millis(delay)).await;
        }
    }
    let _ = total;

    // Sonrası: çift yönlü kopyala (bayt sayaçlı)
    relay(inbound, outbound, stats, &target, total as u64, quiet).await;
}

/// Çift yönlü relay + sayaç. total: önceden yazılmış bayt (bölünmüş hello).
async fn relay(
    mut inbound: TcpStream,
    mut outbound: TcpStream,
    stats: Arc<Stats>,
    target: &str,
    pre_written: u64,
    quiet: bool,
) {
    let (mut ri, mut wi) = inbound.split();
    let (mut ro, mut wo) = outbound.split();
    let c2s = tokio::io::copy(&mut ri, &mut wo);
    let s2c = tokio::io::copy(&mut ro, &mut wi);
    let (up, down) = tokio::join!(c2s, s2c);
    stats.bytes_up.fetch_add(up.unwrap_or(0) + pre_written, Ordering::Relaxed);
    stats.bytes_down.fetch_add(down.unwrap_or(0), Ordering::Relaxed);
    if !quiet {
        println!("[.] bağlantı kapandı: {target}");
    }
}

/// Düz HTTP metodu mu? ("GET /...", "POST http://...").
fn http_method(buf: &[u8]) -> bool {
    const METHODS: [&[u8]; 7] = [b"GET ", b"POST ", b"HEAD ", b"PUT ", b"DELETE ", b"OPTIONS ", b"PATCH "];
    METHODS.iter().any(|m| buf.len() >= m.len() && buf[..m.len()].eq_ignore_ascii_case(m))
}

/// Düz HTTP isteğinden hedef çıkar: absolute-URI ya da Host başlığı. "host:80" döner.
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
        // origin-form: Host başlığı şart
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

#[tokio::main]
async fn main() {
    let cfg = parse_args();
    println!("[*] dpi-proxy v0.2 dinliyor: {}", cfg.listen);
    println!("[*] strateji: {:?}", cfg.strategy);
    println!("[*] test: tarayıcıda https://example.com -> SNI bölünerek gider");

    let listener = TcpListener::bind(&cfg.listen).await.expect("bind");
    let force = cfg.force_target.clone();
    let stats = Arc::new(Stats::default());
    // 30sn istatistik: UI log kutusunda canlı görünür
    let st_bg = stats.clone();
    tokio::spawn(async move {
        loop {
            sleep(Duration::from_secs(30)).await;
            println!(
                "[=] baglanti:{} yukari:{}KB asagi:{}KB",
                st_bg.conns.load(Ordering::Relaxed),
                st_bg.bytes_up.load(Ordering::Relaxed) / 1024,
                st_bg.bytes_down.load(Ordering::Relaxed) / 1024
            );
        }
    });
    loop {
        match listener.accept().await {
            Ok((sock, addr)) => {
                if !cfg.quiet {
                    println!("[+] gelen: {addr}");
                }
                let st = cfg.strategy;
                let f = force.clone();
                let sc = stats.clone();
                let q = cfg.quiet;
                tokio::spawn(async move {
                    handle_client(sock, st, f, sc, q).await;
                });
            }
            Err(e) => eprintln!("[-] accept: {e}"),
        }
    }
}
