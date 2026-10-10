// SPDX-License-Identifier: GPL-3.0-or-later
//! zapret-win-turkey'den çıkarılan Türkiye profilleri.
//! Kaynak: ~/Downloads/zapret-win-turkey/zapret-win-turkey.au3 (_GetActiveStrategyString)
//! + config/strategy2.txt. winws komut satırları birebir korundu.
//!
//! Not: fake/md5sig/badseq/multidisorder ham soket ister (WinDivert).
//! Kullanıcı-alanı proxy'de en yakın `Strategy` ile yaklaştırılır;
//! `winws_args()` sürücü moduna geçince doğrudan kullanılır.

use crate::Strategy;

/// Türkiye ISS profili.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ZapretProfile {
    TurkTelekom,
    TtAlternatif,
    Superonline,
    SolAlternatif,
    Vodafone,
    TurkcellMobil,
    VodafoneMobil,
    TelekomMobil,
}

impl ZapretProfile {
    pub fn all() -> &'static [ZapretProfile] {
        use ZapretProfile::*;
        &[
            TurkTelekom,
            TtAlternatif,
            Superonline,
            SolAlternatif,
            Vodafone,
            TurkcellMobil,
            VodafoneMobil,
            TelekomMobil,
        ]
    }

    pub fn name_tr(self) -> &'static str {
        use ZapretProfile::*;
        match self {
            TurkTelekom => "Türk Telekom",
            TtAlternatif => "TT Alternatif",
            Superonline => "Superonline",
            SolAlternatif => "SOL Alternatif",
            Vodafone => "Vodafone",
            TurkcellMobil => "Turkcell Mobil",
            VodafoneMobil => "Vodafone Mobil",
            TelekomMobil => "Telekom Mobil",
        }
    }

    /// Orijinal winws komut satırı (Zapret1 motoru, winws.exe).
    pub fn winws_args(self) -> &'static str {
        use ZapretProfile::*;
        match self {
            TurkTelekom => "--dpi-desync=fake --dpi-desync-ttl=4",
            TtAlternatif => "--dpi-desync=fake --dpi-desync-ttl=3",
            Superonline => "--dpi-desync=fake --dpi-desync-fooling=md5sig",
            SolAlternatif => {
                "--dpi-desync=fake --dpi-desync-fooling=md5sig --dpi-desync-ttl=3"
            }
            Vodafone => "--dpi-desync=fake,multisplit --dpi-desync-fooling=badseq --dpi-desync-split-pos=1,midsld",
            TurkcellMobil => "--dpi-desync=fake --dpi-desync-ttl=1 --dpi-desync-autottl=3",
            VodafoneMobil => "--dpi-desync=multisplit --dpi-desync-split-pos=2",
            TelekomMobil => "--dpi-desync=fake --dpi-desync-ttl=5",
        }
    }

    /// Zapret2 (lua) motoru karşılığı. strategy2.txt = TurkTelekom satırı.
    pub fn winws2_args(self) -> &'static str {
        use ZapretProfile::*;
        match self {
            TurkTelekom | Superonline | TurkcellMobil | VodafoneMobil => {
                "--payload=tls_client_hello --lua-desync=multidisorder:pos=2:seqovl=1"
            }
            Vodafone => "--payload=tls_client_hello --lua-desync=multisplit:blob=fake_default_tls:ip_ttl=5:pos=2:nodrop:repeats=1",
            TelekomMobil => {
                "--payload=tls_client_hello --lua-desync=fake:blob=0x00000000:ip_ttl=5:repeats=1"
            }
            // Zapret2 listesinde TT Alternatif / SOL Alternatif yok → en yakın
            TtAlternatif | SolAlternatif => {
                "--payload=tls_client_hello --lua-desync=multidisorder:pos=2:seqovl=1"
            }
        }
    }

    /// Kullanıcı-alanı proxy'de uygulanabilir en yakın strateji.
    /// fake/*fooling ham soket ister → bölme ile yaklaştırılır.
    pub fn to_strategy(self) -> Strategy {
        use ZapretProfile::*;
        match self {
            // multisplit pos=2 == SNI ortası bölme (birebir)
            VodafoneMobil => Strategy::Split { split_at: 2 },
            // multisplit pos=1,midsld == başa yakın + SNI ortası; tek kesit hakkımız
            // var → SNI ortası (Middle of SNI Letter Domain) öncelikli
            Vodafone => Strategy::SplitWithDelay { split_at: 1, delay_ms: 0 },
            // fake profilleri: kullanıcı alanında fake atılamaz → gecikmeli bölme
            // (DPI kutusu ikinci parçayı kaçırır; TTL numarası gecikmeye gömülür)
            TurkTelekom => Strategy::SplitWithDelay { split_at: 2, delay_ms: 4 },
            TtAlternatif => Strategy::SplitWithDelay { split_at: 2, delay_ms: 3 },
            Superonline => Strategy::SplitWithDelay { split_at: 2, delay_ms: 5 },
            SolAlternatif => Strategy::SplitWithDelay { split_at: 2, delay_ms: 3 },
            TurkcellMobil => Strategy::SplitWithDelay { split_at: 2, delay_ms: 1 },
            TelekomMobil => Strategy::SplitWithDelay { split_at: 2, delay_ms: 5 },
        }
    }
}

/// Türk Telekom DNS zehirleme parmak izi (au3 CheckDnsPoisoningSilent).
pub mod poison {
    pub const TEST_DOMAIN: &str = "updates.discord.com";
    pub const POISON_IP: &str = "195.175.254.2";
    pub const SAFE_PREFIX: &str = "162.159";

    /// nslookup çıktısı zehirli IP içeriyorsa true.
    pub fn is_poisoned(nslookup_stdout: &str) -> bool {
        nslookup_stdout.contains(POISON_IP)
    }
    pub fn looks_clean(nslookup_stdout: &str) -> bool {
        nslookup_stdout.contains(SAFE_PREFIX)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::split_client_hello;

    fn hello() -> Vec<u8> {
        // küçük sentetik ClientHello (SNI=ornek.com)
        let sni = b"ornek.com";
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
        let mut hs = vec![0x01, 0x00, 0x00, 0x00];
        let bl = body.len() as u32;
        hs[1..4].copy_from_slice(&[(bl >> 16) as u8, (bl >> 8) as u8, bl as u8]);
        hs.extend_from_slice(&body);
        let mut rec = vec![0x16, 0x03, 0x01, 0x00, 0x00];
        let hl = hs.len() as u16;
        rec[3..5].copy_from_slice(&hl.to_be_bytes());
        rec.extend_from_slice(&hs);
        rec
    }

    #[test]
    fn all_profiles_have_args_and_hide_sni() {
        let pkt = hello();
        assert!(crate::find_sni(&pkt).is_some());
        for p in ZapretProfile::all() {
            assert!(!p.winws_args().is_empty(), "{p:?}");
            assert!(!p.winws2_args().is_empty(), "{p:?}");
            assert!(!p.name_tr().is_empty());
            let parts = split_client_hello(&pkt, p.to_strategy());
            assert_eq!(parts.concat(), pkt, "{p:?} roundtrip");
            // bölme SNI'ı tek parçada göstermemeli
            for part in &parts {
                assert!(
                    !part.windows(9).any(|w| w == b"ornek.com"),
                    "{p:?} SNI sızıyor"
                );
            }
        }
    }

    #[test]
    fn exact_strings_match_source() {
        // au3'ten birebir — kaynak değişirse test patlar, bilerek.
        assert_eq!(
            ZapretProfile::TurkTelekom.winws_args(),
            "--dpi-desync=fake --dpi-desync-ttl=4"
        );
        assert_eq!(
            ZapretProfile::Vodafone.winws_args(),
            "--dpi-desync=fake,multisplit --dpi-desync-fooling=badseq --dpi-desync-split-pos=1,midsld"
        );
        assert_eq!(
            ZapretProfile::TurkTelekom.winws2_args(),
            "--payload=tls_client_hello --lua-desync=multidisorder:pos=2:seqovl=1"
        );
    }

    #[test]
    fn poison_detect() {
        assert!(poison::is_poisoned("Address: 195.175.254.2"));
        assert!(!poison::is_poisoned("Address: 162.159.1.1"));
        assert!(poison::looks_clean("Address: 162.159.1.1"));
    }
}
