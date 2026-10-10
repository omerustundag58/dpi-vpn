// SPDX-License-Identifier: GPL-3.0-or-later
//! dpi-proxy agresif integration testleri.
//! Gerçek TCP ile: sahte hedef + proxy + istemci.

use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

fn fake_client_hello(sni: &[u8]) -> Vec<u8> {
    let mut sn_ext = vec![];
    let name_entry_len = 1 + 2 + sni.len();
    sn_ext.extend_from_slice(&[0x00, 0x00]);
    sn_ext.extend_from_slice(&((2 + name_entry_len) as u16).to_be_bytes());
    sn_ext.extend_from_slice(&(name_entry_len as u16).to_be_bytes());
    sn_ext.push(0x00);
    sn_ext.extend_from_slice(&(sni.len() as u16).to_be_bytes());
    sn_ext.extend_from_slice(sni);
    let mut body = vec![];
    body.extend_from_slice(&[0x03, 0x03]);
    body.extend_from_slice(&[0xAA; 32]);
    body.push(0x00);
    body.extend_from_slice(&[0x00, 0x02, 0x13, 0x01]);
    body.push(0x01);
    body.push(0x00);
    body.extend_from_slice(&(sn_ext.len() as u16).to_be_bytes());
    body.extend_from_slice(&sn_ext);
    let mut hs = vec![0x01];
    let blen = body.len() as u32;
    hs.extend_from_slice(&[(blen >> 16) as u8, (blen >> 8) as u8, blen as u8]);
    hs.extend_from_slice(&body);
    let mut rec = vec![0x16, 0x03, 0x01];
    rec.extend_from_slice(&(hs.len() as u16).to_be_bytes());
    rec.extend_from_slice(&hs);
    rec
}

async fn free_port() -> u16 {
    TcpListener::bind("127.0.0.1:0").await.unwrap().local_addr().unwrap().port()
}

/// Sahte hedef: geleni tek buffer'da topla, parça varış zamanlarını kaydet.
/// Dönüş: (addr, received_rx, gaps_rx)
async fn spawn_fake_target() -> (String, tokio::sync::mpsc::UnboundedReceiver<Vec<u8>>, tokio::sync::mpsc::UnboundedReceiver<Duration>) {
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = l.local_addr().unwrap().to_string();
    let (tx_data, rx_data) = tokio::sync::mpsc::unbounded_channel();
    let (tx_gap, rx_gap) = tokio::sync::mpsc::unbounded_channel();
    tokio::spawn(async move {
        if let Ok((mut s, _)) = l.accept().await {
            let mut all = vec![];
            let mut times = vec![];
            let mut buf = [0u8; 4096];
            // 2 read yap: ilk parça + ikinci parça ayrı gelmeli
            s.set_nodelay(true).ok();
            loop {
                match tokio::time::timeout(Duration::from_secs(3), s.read(&mut buf)).await {
                    Ok(Ok(0)) | Err(_) => break,
                    Ok(Ok(n)) => {
                        times.push(Instant::now());
                        all.extend_from_slice(&buf[..n]);
                        // ClientHello tamamı geldiyse dur (uzunluğu parse etmeden basit: 2 parça ya da timeout)
                        if times.len() >= 2 && all.len() >= 50 {
                            // biraz daha bekle, ek parça var mı?
                            match tokio::time::timeout(Duration::from_millis(200), s.read(&mut buf)).await {
                                Ok(Ok(0)) | Err(_) => break,
                                Ok(Ok(n2)) => {
                                    times.push(Instant::now());
                                    all.extend_from_slice(&buf[..n2]);
                                    break;
                                }
                                _ => break,
                            }
                        }
                        if times.len() >= 5 {
                            break;
                        }
                    }
                    Ok(Err(_)) => break,
                }
            }
            if times.len() >= 2 {
                let _ = tx_gap.send(times[1] - times[0]);
            }
            let _ = tx_data.send(all);
        }
    });
    (addr, rx_data, rx_gap)
}

fn proxy_bin() -> std::path::PathBuf {
    let mut p = std::env::current_exe().unwrap();
    p.pop(); // deps
    p.pop(); // debug
    p.join("dpi-proxy.exe")
}

#[tokio::test]
async fn proxy_splits_sni_and_preserves_bytes() {
    let (target_addr, mut rx_data, mut rx_gap) = spawn_fake_target().await;
    let proxy_port = free_port().await;

    let mut proxy = tokio::process::Command::new(proxy_bin())
        .args(["--listen", &format!("127.0.0.1:{proxy_port}"),
               "--delay-ms", "50",
               "--force-target", &target_addr])
        .spawn()
        .expect("proxy başlatılamadı");

    tokio::time::sleep(Duration::from_millis(300)).await;

    let hello = fake_client_hello(b"ornek-test.com");
    let mut cli = TcpStream::connect(format!("127.0.0.1:{proxy_port}")).await.unwrap();
    cli.write_all(&hello).await.unwrap();
    cli.flush().await.unwrap();

    // hedefe veri ulaşmalı
    let got = tokio::time::timeout(Duration::from_secs(5), rx_data.recv())
        .await.expect("timeout").expect("kanal");
    assert_eq!(got, hello, "hedefe eksik/bozuk veri gitti");

    // 2 parça ayrı TCP read olmalı + gecikme gözlenmeli (>=30ms, 50 istedik)
    if let Ok(Some(gap)) = tokio::time::timeout(Duration::from_secs(2), rx_gap.recv()).await {
        assert!(gap >= Duration::from_millis(20), "parçalar arası gecikme yok: {gap:?} (Nagle birleştirmiş olabilir)");
        println!("gap={gap:?} ok");
    } else {
        panic!("hedef tek read'de aldı — bölme TCP'de birleşmiş (Nagle?). send_split mantığı core testinde doğrulandı ama soket birleştirdi.");
    }
    proxy.kill().await.ok();
}

#[tokio::test]
async fn proxy_drops_non_sni_gracefully() {    let (target_addr, mut rx_data, _rx_gap) = spawn_fake_target().await;
    let proxy_port = free_port().await;
    let mut proxy = tokio::process::Command::new(proxy_bin())
        .args(["--listen", &format!("127.0.0.1:{proxy_port}"),
               "--force-target", &target_addr])
        .spawn().unwrap();
    tokio::time::sleep(Duration::from_millis(300)).await;

    // SNI'sız HTTP gönder — force-target olsa bile proxy SNI arar mı?
    // Not: force-target varsa SNI'sız da iletilir (test kolaylığı). Burada davranış: iletilir.
    // Bu test proxy'nin çökmemesini doğrular.
    let mut cli = TcpStream::connect(format!("127.0.0.1:{proxy_port}")).await.unwrap();
    cli.write_all(b"GET / HTTP/1.1\r\nHost: x\r\n\r\n").await.unwrap();
    cli.flush().await.unwrap();
    // proxy panic yapmadan bağlantıyı kapatmalı ya da iletmeli — 3 sn içinde çökme yoksa pass
    tokio::time::sleep(Duration::from_millis(800)).await;
    let _ = tokio::time::timeout(Duration::from_millis(300), rx_data.recv()).await;
    // hala yaşıyor mu?
    assert!(proxy.try_wait().unwrap().is_none(), "proxy çöktü!");
    proxy.kill().await.ok();
}

#[tokio::test]
async fn proxy_50_concurrent_no_crash() {
    let (target_addr, _rx, _gap) = spawn_fake_target().await;
    // sahte hedef tek bağlantı kabul ediyor; bu testte hedef olarak blackhole (kabul edip kapatan) kullan
    let hole = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let hole_addr = hole.local_addr().unwrap().to_string();
    tokio::spawn(async move {
        while let Ok((s, _)) = hole.accept().await {
            drop(s);
        }
    });
    let _ = target_addr;
    let proxy_port = free_port().await;
    let mut proxy = tokio::process::Command::new(proxy_bin())
        .args(["--listen", &format!("127.0.0.1:{proxy_port}"),
               "--delay-ms", "1",
               "--force-target", &hole_addr])
        .spawn().unwrap();
    tokio::time::sleep(Duration::from_millis(300)).await;

    let hello = fake_client_hello(b"yuk-test.com");
    let mut handles = vec![];
    for _ in 0..50 {
        let h = hello.clone();
        let addr = format!("127.0.0.1:{proxy_port}");
        handles.push(tokio::spawn(async move {
            if let Ok(mut c) = TcpStream::connect(&addr).await {
                let _ = c.write_all(&h).await;
            }
        }));
    }
    for h in handles {
        let _ = tokio::time::timeout(Duration::from_secs(5), h).await;
    }
    tokio::time::sleep(Duration::from_millis(500)).await;
    assert!(proxy.try_wait().unwrap().is_none(), "proxy 50 bağlantıda çöktü");
    proxy.kill().await.ok();
}
#[tokio::test]
async fn proxy_http_connect_flow() {
    // Tarayici akisi: CONNECT + 200 + ClientHello -> hedefe bolunmus gitmeli.
    let (target_addr, mut rx_data, mut rx_gap) = spawn_fake_target().await;
    let proxy_port = free_port().await;
    let mut proxy = tokio::process::Command::new(proxy_bin())
        .args(["--listen", &format!("127.0.0.1:{proxy_port}"),
               "--delay-ms", "50",
               "--force-target", &target_addr])
        .spawn().unwrap();
    tokio::time::sleep(Duration::from_millis(300)).await;

    let hello = fake_client_hello(b"connect-test.com");
    let mut cli = TcpStream::connect(format!("127.0.0.1:{proxy_port}")).await.unwrap();
    cli.write_all(b"CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\n").await.unwrap();
    let mut resp = vec![0u8; 64];
    let n = tokio::time::timeout(Duration::from_secs(3), cli.read(&mut resp)).await.expect("200 yok").unwrap();
    assert!(String::from_utf8_lossy(&resp[..n]).contains("200"), "CONNECT 200 d�nmedi");
    cli.write_all(&hello).await.unwrap();
    cli.flush().await.unwrap();

    let got = tokio::time::timeout(Duration::from_secs(5), rx_data.recv()).await.expect("timeout").expect("kanal");
    assert_eq!(got, hello, "CONNECT sonrasi veri bozuk");
    if let Ok(Some(gap)) = tokio::time::timeout(Duration::from_secs(2), rx_gap.recv()).await {
        assert!(gap >= Duration::from_millis(20), "gecikme yok");
        println!("connect gap ok");
    } else {
        panic!("CONNECT bolme gozlenmedi");
    }
    proxy.kill().await.ok();
}

#[tokio::test]
async fn proxy_plain_http_flow() {
    // Duz HTTP: GET absolute-URI -> hedefe eksiksiz gitmeli.
    let (target_addr, mut rx_data, _rx_gap) = spawn_fake_target().await;
    let proxy_port = free_port().await;
    let mut proxy = tokio::process::Command::new(proxy_bin())
        .args(["--listen", &format!("127.0.0.1:{proxy_port}"),
               "--force-target", &target_addr])
        .spawn().unwrap();
    tokio::time::sleep(Duration::from_millis(300)).await;

    let req = b"GET http://ornek.test/sayfa?q=1 HTTP/1.1\r\nHost: ornek.test\r\nConnection: close\r\n\r\n";
    let mut cli = TcpStream::connect(format!("127.0.0.1:{proxy_port}")).await.unwrap();
    cli.write_all(req).await.unwrap();
    cli.flush().await.unwrap();

    let got = tokio::time::timeout(Duration::from_secs(5), rx_data.recv()).await.expect("timeout").expect("kanal");
    assert_eq!(got, req.to_vec(), "HTTP istek bozuldu");
    proxy.kill().await.ok();
}
