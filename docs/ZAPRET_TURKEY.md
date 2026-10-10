# Zapret-win-turkey — çıkarılan strateji haritası

Kaynak: `~/Downloads/zapret-win-turkey/` (au3 `_GetActiveStrategyString` + `config/strategy2.txt`).
Kod karşılığı: `dpi-core/src/zapret.rs` (`ZapretProfile`).

## Zapret1 (winws.exe, v72.12)

| Profil | Komut |
|---|---|
| Türk Telekom | `--dpi-desync=fake --dpi-desync-ttl=4` |
| TT Alternatif | `--dpi-desync=fake --dpi-desync-ttl=3` |
| Superonline | `--dpi-desync=fake --dpi-desync-fooling=md5sig` |
| SOL Alternatif | `--dpi-desync=fake --dpi-desync-fooling=md5sig --dpi-desync-ttl=3` |
| Vodafone | `--dpi-desync=fake,multisplit --dpi-desync-fooling=badseq --dpi-desync-split-pos=1,midsld` |
| Turkcell Mobil | `--dpi-desync=fake --dpi-desync-ttl=1 --dpi-desync-autottl=3` |
| Vodafone Mobil | `--dpi-desync=multisplit --dpi-desync-split-pos=2` |
| Telekom Mobil | `--dpi-desync=fake --dpi-desync-ttl=5` |

## Zapret2 (winws2.exe, lua)

- TT/Superonline/Turksat/Turkcell/VodafoneMobil: `multidisorder:pos=2:seqovl=1`
- Vodafone: `multisplit:blob=fake_default_tls:ip_ttl=5:pos=2:nodrop:repeats=1`
- Telekom Mobil: `fake:blob=0x00000000:ip_ttl=5:repeats=1`

## Diğer bulgular

- DNS zehirleme parmak izi: test `updates.discord.com`, zehirli IP `195.175.254.2`, temiz önek `162.159` → `zapret::poison`.
- Hostlist odağı: discord.*, roblox.*, protonvpn, cloudflare-dns.
- Motor: WinDivert (`WinDivert.dll` + `Monkey64.sys`) — bizde henüz yok, proxy kullanıcı-alanı yaklaşıklama kullanır.
