#[tokio::test]
async fn proxy_auto_mode_flow() {
    // Otomatik mod: ilk baglantida taktik secilir, veri butun gider.
    // Not: ayri dosya cakismasin diye bu test aggressive.rs sonuna eklenemedi,
    // buradaki helper'lar kopyadir.
    use std::time::Duration;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::{TcpListener, TcpStream};

    fn hello2(sni: &[u8]) -> Vec<u8> {
        let mut sn = vec![0x00, 0x00];
        sn.extend_from_slice(&((2 + 1 + 2 + sni.len()) as u16).to_be_bytes());
        sn.extend_from_slice(&((1 + 2 + sni.len()) as u16).to_be_bytes());
        sn.push(0x00);
        sn.extend_from_slice(&(sni.len() as u16).to_be_bytes());
        sn.extend_from_slice(sni);
        let mut body = vec![0x03, 0x03];
        body.extend_from_slice(&[0xAA; 32]);
        body.push(0x00);
        body.extend_from_slice(&[0x00, 0x02, 0x13, 0x01, 0x01, 0x00]);
        body.extend_from_slice(&(sn.len() as u16).to_be_bytes());
        body.extend_from_slice(&sn);
        let mut hs = vec![0x01, 0, 0, 0];
        let bl = body.len() as u32;
        hs[1..4].copy_from_slice(&[(bl >> 16) as u8, (bl >> 8) as u8, bl as u8]);
        hs.extend_from_slice(&body);
        let mut rec = vec![0x16, 0x03, 0x01, 0, 0];
        let hl = hs.len() as u16;
        rec[3..5].copy_from_slice(&hl.to_be_bytes());
        rec.extend_from_slice(&hs);
        rec
    }

    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let taddr = l.local_addr().unwrap().to_string();
    let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel::<Vec<u8>>();
    tokio::spawn(async move {
        for _ in 0..2 {
            let Ok(conn) = tokio::time::timeout(Duration::from_secs(8), l.accept()).await else {
                break;
            };
            let Ok((mut s, _)) = conn else { break };
            let mut all = vec![];
            let mut buf = [0u8; 4096];
            while let Ok(Ok(n)) =
                tokio::time::timeout(Duration::from_secs(3), s.read(&mut buf)).await
            {
                if n == 0 {
                    break;
                }
                all.extend_from_slice(&buf[..n]);
                if all.len() >= 60 {
                    break;
                }
            }
            let _ = tx.send(all);
        }
    });
    let pl = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let pport = pl.local_addr().unwrap().port();
    drop(pl);
    let mut exe = std::env::current_exe().unwrap();
    exe.pop();
    exe.pop();
    exe.push("dpi-proxy.exe");
    let mut proxy = tokio::process::Command::new(exe)
        .args(["--listen", &format!("127.0.0.1:{pport}"), "--auto", "--force-target", &taddr])
        .kill_on_drop(true)
        .spawn()
        .unwrap();
    tokio::time::sleep(Duration::from_millis(400)).await;

    let hello = hello2(b"oto-ornek.com");
    // iki baglanti: ilki secer, ikincisi onbellekten alir
    for _ in 0..2 {
        let mut cli = TcpStream::connect(format!("127.0.0.1:{pport}")).await.unwrap();
        cli.write_all(&hello).await.unwrap();
        cli.flush().await.unwrap();
        let got = tokio::time::timeout(Duration::from_secs(5), rx.recv())
            .await
            .expect("timeout")
            .expect("kanal");
        assert!(!got.is_empty(), "oto mod veri goturmedi");
    }
    proxy.kill().await.ok();
}
