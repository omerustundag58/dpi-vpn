//! Port kısıtı testi (güvenlik güncellemesi eki).

use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

fn proxy_bin2() -> std::path::PathBuf {
    let mut p = std::env::current_exe().unwrap();
    p.pop();
    p.pop();
    p.join("dpi-proxy.exe")
}

async fn free_port2() -> u16 {
    tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap().local_addr().unwrap().port()
}

#[tokio::test]
async fn proxy_rejects_bad_ports() {
    // SMTP(25)/SSH(22) tüneli: 200 dönmemeli, bağlantı kapanmalı.
    let proxy_port = free_port2().await;
    let mut proxy = tokio::process::Command::new(proxy_bin2())
        .args(["--listen", &format!("127.0.0.1:{proxy_port}")])
        .kill_on_drop(true).spawn().unwrap();
    tokio::time::sleep(Duration::from_millis(300)).await;

    for target in ["smtp.ornek.test:25", "ornek.test:22", "ornek.test:8080"] {
        let mut cli = TcpStream::connect(format!("127.0.0.1:{proxy_port}")).await.unwrap();
        cli.write_all(format!("CONNECT {target} HTTP/1.1\r\nHost: {target}\r\n\r\n").as_bytes())
            .await.unwrap();
        let mut resp = vec![0u8; 64];
        // 200 gelirse FAIL; kapanma/timeout beklenir
        match tokio::time::timeout(Duration::from_secs(3), cli.read(&mut resp)).await {
            Ok(Ok(n)) => {
                assert!(!String::from_utf8_lossy(&resp[..n]).contains("200"),
                        "{target} tüneli açılmamalıydı");
            }
            _ => {} // kapandı/timeout: doğru davranış
        }
    }
    // izinli portlar (80/443/563/8443) bu testin konusu değil (ayrı akış testleri var).
    proxy.kill().await.ok();
}
