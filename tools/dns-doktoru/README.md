# DNS Doktoru

Sistem DNS'i ile DoH (Cloudflare) sonucunu yan yana gosteren kucuk
Windows yardimcisi. Discord/Roblox gibi adlarin ISS tarafindan
zehirlenip zehirlenmedigini anlamaya yarar.

Ag paketlerine dokunmaz, surucu kullanmaz.

## Kullanim

```powershell
python tools/dns-doktoru/app.py
```

1. Host listesini duzenle (istersen kendi host'unu ekle).
2. "Kontrol et"e bas. Durumlar:
   - TAMAM: iki cozum ayni.
   - ENGELLI/ZEHIRLI olabilir: sistem cozemiyor ama DoH cozuyor
     (ya da farkli IP donuyor).
   - COZULEMEDI: ikisi de cozemedi.
3. "Sonucu kopyala" ile destegre paylas.

## Windows DoH ayari (istege bagli, yonetici ister)

- "DoH'u uygula": aktif adaptorun DNS'ini `1.1.1.1, 1.0.0.1` yapar ve
  Cloudflare DoH sablonunu kaydeder. UAC sorar.
- "Onceki ayara don": degisim oncesi ayari
  (`%LOCALAPPDATA%\DNSDoktoru\onceki.json`) geri yukler.
- Eski Windows'ta DoH destegi yoksa DNS ayarlanir, bu durum raporlanir.

## Derleme

Proje kokunden:

```powershell
python -m PyInstaller --noconfirm --onefile --noconsole --name DNS-Doktoru tools/dns-doktoru/app.py
```

Cikti `dist\DNS-Doktoru.exe` altina gider, git'e girmez.

## Testler

```powershell
python -m unittest discover -s tools/dns-doktoru -p "test_*.py"
```

Testler ag gerektirmez.
