// SPDX-License-Identifier: GPL-3.0-or-later
//! Gerçek dünyadan ClientHello testi (Python ssl ile üretilmiş, SNI=youtube.com).

#[test]
fn real_client_hello_sni_found_and_split() {
    let pkt = include_bytes!("../../real_hello.bin");
    assert!(pkt.len() > 100, "real_hello.bin boş/küçük");
    assert_eq!(pkt[0], 0x16);
    assert_eq!(pkt[5], 0x01);
    let (s, e) = dpi_core::find_sni(pkt).expect("gerçek hello'da SNI bulunmalı");
    assert_eq!(&pkt[s..e], b"youtube.com", "SNI youtube.com olmalı");
    // bölme gizlemeli (düz TCP bölme; record-split yeniden çerçeveler)
    let parts = dpi_core::split_client_hello(pkt, dpi_core::Strategy::Split { split_at: 2 });
    assert_eq!(parts.len(), 2);
    for p in &parts {
        assert!(!p.windows(11).any(|w| w == b"youtube.com"), "SNI tek parçada görünmemeli");
    }
    assert_eq!(parts.concat(), pkt.to_vec());
}
