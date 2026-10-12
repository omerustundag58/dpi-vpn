//! Gerçek dünyadan hello korpusu (Python ssl ile üretilmiş).
//! Her dosya: SNI bulunur + bölme gizler + record framing geçerli olmalı.

fn check(name: &str, pkt: &[u8], sni: &[u8]) {
    assert!(pkt.len() > 200, "{name} küçük");
    let (s, e) = dpi_core::find_sni(pkt).unwrap_or_else(|| panic!("{name} SNI yok"));
    assert_eq!(&pkt[s..e], sni, "{name} SNI yanlış");
    for st in [
        dpi_core::Strategy::Split { split_at: 2 },
        dpi_core::Strategy::Custom {
            cut: dpi_core::CutPos::Before,
            order: dpi_core::SendOrder::Reversed,
            delay_ms: 0,
        },
    ] {
        let parts = dpi_core::split_client_hello(pkt, st);
        assert!(parts.len() >= 2, "{name} {st:?} parça");
        // ters sırada bile liste [birinci, ikinci] sırasındadır
        assert_eq!(parts.concat(), pkt, "{name} {st:?} roundtrip");
    }
    // record-split yeniden çerçeveler: yük eşitliği + başlık geçerliliği
    let rp = dpi_core::split_client_hello(pkt, dpi_core::Strategy::RecordSplit { delay_ms: 0 });
    assert_eq!(rp.len(), 2);
    let mut payload = vec![];
    for p in &rp {
        assert_eq!(p[0], 0x16);
        let rl = u16::from_be_bytes([p[3], p[4]]) as usize;
        assert_eq!(5 + rl, p.len(), "{name} record boyu");
        payload.extend_from_slice(&p[5..]);
    }
    assert_eq!(payload, &pkt[5..], "{name} record yükü");
    assert!(matches!(dpi_core::assess(pkt, dpi_core::Strategy::default()), dpi_core::Visibility::Hidden),
            "{name} varsayılan gizlemeli");
}

#[test]
fn corpus_youtube_alpn() {
    check("yt", include_bytes!("data/hello_yt_alpn.bin"), b"youtube.com");
}

#[test]
fn corpus_discord_noalpn() {
    check("noalpn", include_bytes!("data/hello_noalpn.bin"), b"discord.com");
}

#[test]
fn corpus_long_sni() {
    check("long", include_bytes!("data/hello_long.bin"),
          b"cok-uzun-bir-alt-alan-adi-ornegi.roblox.com");
}
