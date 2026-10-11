# GoodbyeDPI 0.2.2 — kod haritası (işimize yarayanlar)

Kaynak: `~/Downloads/goodbyedpi-0.2.2.zip` (açılmadı, TEMP'te incelendi) +
README (github master). Lisans: MIT tarzı (LICENSE-goodbyedpi.txt).

## Genel profil
`goodbyedpi.exe -5` = `-f 2 -e 2 --auto-ttl --reverse-frag --max-payload`
(WinDivert sürücülü, admin ister — bizde karşılığı parantezde).

## Bizim alabileceklerimiz (sürücüsüz, hemen)

1. **reverse-frag** — parçaları TERSTEN gönder. DPI sırayı beklerken
   sunucu TCP'si birleştirir. Biz hep sıralı gönderiyoruz
   (`split_once` + proxy + Android relay). Eklenecek: `Reversed` varyantı.
2. **Host hileleri** (`-r`: `Host`→`hoSt`, `-s`: boşluksuz, `-m`: karışık
   büyük/küçük) — HTTP başlık İSMİ büyük/küçük harf duyarsız, tamamen yasal.
   Bizim port-80 yolumuz sadece ortadan bölüyor; `hoSt` tek satırla eklenir.
3. **frag-by-sni** — SNI ORTASINDAN değil, SNI ÖNCESİNDEN böl. Bizim kesim
   hep orta; `pos` parametresi (önce/orta) eklenebilir, testle seçilir.
4. **max-payload** — ilk yükten sonrasını hiç işleme. Zaten öyle yapıyoruz ✓.
5. **blacklist modu** — yalnızca listedeki hostlara dokun, gerisi direkt.
   Biz tam-tüneliz; diag çıktısıyla beslenen "yalnızca sansürlü" modu
   hız + pil kazandırır (gelecek iş).
6. **-q (QUIC engelle)** — bizim QUIC düğmesiyle aynı fikir, doğrulandı ✓.

## Sürücülü (WinDivert) işler — kullanıcı-alanında OLMAZ

- `--set-ttl/--auto-ttl`, `--wrong-chksum`, `--wrong-seq`, `--fake-with-sni`
  (Firefox taklidi sahte hello): ham soket ister. Bizim WinDivert motoru
  zaten winws2 üzerinden veriyor; goodbyedpi.exe'yi ayrı motor olarak
  eklemek istersek `x86_64/goodbyedpi.exe -5` tek satırla çalışır.
- Pasif DPI parmak izi: RST paketlerinde IP ID `0x0000/0x0001` — tanı için
  ham soket gerekir, diag'da yok (not).

## Dosya notları
- `2_any_country.cmd` = genel profil, `1_russia_blacklist.cmd` = listeli.
- `service_install_*.cmd` = otomatik başlatma kalıbı (bizim autostart işine örnek).
- Kaynak kod zip'te YOK (sadece ikili); kaynak github'da, Makefile+mingw ile derlenir.
