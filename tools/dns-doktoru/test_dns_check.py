"""DNS Doktoru testleri - ag gerektirmez (saf fonksiyonlar)."""
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from dns_check import (
    DURUM_COZULEMEDI,
    DURUM_ENGELLI,
    DURUM_TAMAM,
    doh_json_coz,
    sinifla,
    sonuc_metni,
)


class TestSinifla(unittest.TestCase):
    def test_ayni_ip_tamam(self):
        d = sinifla(["1.2.3.4"], ["1.2.3.4"], None, None)
        self.assertEqual(d, DURUM_TAMAM)

    def test_sistem_hata_doh_ip_engelli(self):
        d = sinifla([], ["1.1.1.1"], "No such host is known", None)
        self.assertEqual(d, DURUM_ENGELLI)

    def test_farkli_ip_engelli(self):
        d = sinifla(["9.9.9.9"], ["1.1.1.1"], None, None)
        self.assertEqual(d, DURUM_ENGELLI)

    def test_ikisi_hata_cozulemedi(self):
        d = sinifla([], [], "hata1", "hata2")
        self.assertEqual(d, DURUM_COZULEMEDI)

    def test_ikisi_bos_cozulemedi(self):
        d = sinifla([], [], None, None)
        self.assertEqual(d, DURUM_COZULEMEDI)

    def test_sistem_ip_doh_hata_tamam(self):
        d = sinifla(["1.2.3.4"], [], None, "ag yok")
        self.assertEqual(d, DURUM_TAMAM)

    def test_sira_farkli_ayni_kume_tamam(self):
        d = sinifla(["2.2.2.2", "1.1.1.1"], ["1.1.1.1", "2.2.2.2"],
                    None, None)
        self.assertEqual(d, DURUM_TAMAM)


class TestDohJsonCoz(unittest.TestCase):
    def test_gecerli_a_kaydi(self):
        yanit = {"Answer": [{"name": "x.com", "type": 1, "data": "93.184.216.34"}]}
        ipler, hata = doh_json_coz(yanit)
        self.assertEqual(ipler, ["93.184.216.34"])
        self.assertIsNone(hata)

    def test_answer_yok(self):
        ipler, hata = doh_json_coz({"Status": 3})
        self.assertEqual(ipler, [])
        self.assertIsNotNone(hata)

    def test_yalnizca_aaaa_yok_sayilir(self):
        yanit = {"Answer": [{"name": "x.com", "type": 28,
                             "data": "::1"}]}
        ipler, hata = doh_json_coz(yanit)
        self.assertEqual(ipler, [])
        self.assertIsNotNone(hata)

    def test_karisik_kayitlar(self):
        yanit = {"Answer": [
            {"name": "x.com", "type": 5, "data": "cdn.x.com"},
            {"name": "x.com", "type": 28, "data": "::1"},
            {"name": "x.com", "type": 1, "data": "9.9.9.9"},
            {"name": "x.com", "type": 1, "data": "1.1.1.1"},
        ]}
        ipler, hata = doh_json_coz(yanit)
        self.assertEqual(ipler, ["1.1.1.1", "9.9.9.9"])
        self.assertIsNone(hata)

    def test_gecersiz_yanit(self):
        ipler, hata = doh_json_coz(None)
        self.assertEqual(ipler, [])
        self.assertIsNotNone(hata)


class TestSonucMetni(unittest.TestCase):
    def test_duz_metin(self):
        s = sonuc_metni("a.com", ["1.1.1.1"], ["1.1.1.1"], DURUM_TAMAM)
        self.assertIn("a.com", s)
        self.assertIn("1.1.1.1", s)
        self.assertIn(DURUM_TAMAM, s)

    def test_bos_liste_tire(self):
        s = sonuc_metni("a.com", [], [], DURUM_COZULEMEDI)
        self.assertIn("-", s)


if __name__ == "__main__":
    unittest.main()
