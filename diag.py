# SPDX-License-Identifier: GPL-3.0-or-later
#!/usr/bin/env python3
# Gelismis DPI tani scripti: her hedefte DNS -> TCP -> butun/parcali ClientHello
# -> proxy modunu dener ve kirilma noktasini raporlar.
import socket
import ssl
import subprocess
import sys
import time
import os

BASE = os.path.dirname(os.path.abspath(__file__))
PROXY_EXE = os.path.join(BASE, "target", "debug", "dpi-proxy.exe")
PROXY_ADDR = ("127.0.0.1", 8898)
PROBE_TIMEOUT = 6.0
POISON_IP = "195.175.254.2"


def build_hello(sni: bytes) -> bytes:
    entry = b"\x00" + len(sni).to_bytes(2, "big") + sni
    sn = b"\x00\x00" + (len(entry) + 2).to_bytes(2, "big") + len(entry).to_bytes(2, "big") + entry
    body = b"\x03\x03" + b"\xAA" * 32 + b"\x00" + b"\x00\x02\x13\x01" + b"\x01\x00"
    body += len(sn).to_bytes(2, "big") + sn
    hs = b"\x01" + len(body).to_bytes(3, "big") + body
    return b"\x16\x03\x01" + len(hs).to_bytes(2, "big") + hs


def classify(sock: socket.socket) -> str:
    try:
        data = sock.recv(7)
    except socket.timeout:
        return "TIMEOUT(cevap yok)"
    except ConnectionResetError:
        return "RST(sifirlandi)"
    except OSError as e:
        return f"HATA({e})"
    if not data:
        return "KAPANDI(veri yok)"
    if data[0] == 0x16:
        return "ServerHello(OK)"
    return f"GARIP({data[:8].hex()})"


def probe_direct(host: str, mode: str = "whole") -> tuple:
    """mode: whole | mid | before | reversed (goodbyedpi taktikleri)."""
    hello = build_hello(host.encode())
    # SNI konumu: sabit kalıpta 'host' başlangıcı (11B SNI varsayımı yok —
    # SNI baytlarını hello içinde ara)
    sne = host.encode()
    sni_start = hello.find(sne)
    t0 = time.time()
    try:
        s = socket.create_connection((host, 443), timeout=PROBE_TIMEOUT)
        tcp_ms = (time.time() - t0) * 1000
    except Exception as e:
        return (f"TCP-BAGLANAMADI({str(e)[:50]})", -1)
    s.settimeout(PROBE_TIMEOUT)
    try:
        if mode == "whole":
            s.sendall(hello)
        else:
            if mode == "before" and sni_start > 0:
                cut = sni_start
            else:
                cut = len(hello) // 2
            p1, p2 = hello[:cut], hello[cut:]
            if mode == "reversed":
                # ters sıra: kuyruk önce (TCP birleştirir)
                s.sendall(p2)
                time.sleep(0.03)
                s.sendall(p1)
            else:
                s.sendall(p1)
                time.sleep(0.03)
                s.sendall(p2)
        res = classify(s)
    finally:
        s.close()
    return (res, tcp_ms)


def probe_proxy(host: str) -> str:
    try:
        s = socket.create_connection(PROXY_ADDR, timeout=PROBE_TIMEOUT)
    except Exception as e:
        return f"PROXY-YOK({e})"
    s.settimeout(PROBE_TIMEOUT)
    try:
        s.sendall(f"CONNECT {host}:443 HTTP/1.1\r\nHost: {host}:443\r\n\r\n".encode())
        resp = s.recv(64)
        if b"200" not in resp:
            return f"CONNECT-REDDEDILDI({resp[:30]})"
        s.sendall(build_hello(host.encode()))
        return "proxy:" + classify(s)
    except Exception as e:
        return f"PROXY-HATA({str(e)[:50]})"
    finally:
        s.close()


def dns_check(host: str) -> str:
    try:
        infos = socket.getaddrinfo(host, 443, type=socket.SOCK_STREAM)
        addrs = sorted({i[4][0] for i in infos})
    except Exception as e:
        return f"DNS-HATA({e})"
    if POISON_IP in addrs:
        return f"ZEHIRLI({','.join(addrs)})"
    return "temiz(" + ",".join(addrs[:3]) + ")"


def verdict(host, dns, tcp_ms, whole, variants, prx) -> str:
    if dns.startswith("ZEHIRLI"):
        return "DNS-ZEHIR -> DNSCrypt/DoH lazim"
    if tcp_ms < 0:
        return "IP-BLOK (TCP bile kurulmuyor) -> bolme yetmez, IP degismeli"
    if whole.startswith("GARIP(15"):
        return "ULASILABILIR (TLS alert dondu, sunucu canli)"
    if whole.endswith("(OK)"):
        return "ACIK (direkt calisiyor, proxy gereksiz)"
    for name, res in variants:
        if res.endswith("(OK)") and not whole.endswith("(OK)"):
            return f"SNI-DPI var, {name} CALISIYOR"
    if prx.endswith("(OK)"):
        return "Proxy uzerinden ACIK"
    if whole.startswith("RST"):
        return "RST yiyorsun (DPI sert) -> fake/TTL (WinDivert) gerekebilir"
    return "TIMEOUT (sunucu/DPI sessiz) -> arastirilmali"


def main():
    hosts = sys.argv[1:] or ["example.com", "discord.com", "gateway.discord.gg", "roblox.com"]
    proxy = None
    if os.path.exists(PROXY_EXE):
        proxy = subprocess.Popen([PROXY_EXE, "--listen",
                                  f"{PROXY_ADDR[0]}:{PROXY_ADDR[1]}",
                                  "--delay-ms", "4"],
                                 stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        time.sleep(0.8)
        print(f"[diag] proxy baslatildi {PROXY_ADDR[0]}:{PROXY_ADDR[1]}")
    else:
        print("[diag] proxy exe yok, proxy modu atlanacak")
    try:
        print(f"{'hedef':22} {'dns':28} {'tcp':>7} {'butun':14} {'orta':14} {'once':14} {'ters':14} {'proxy':16} karar")
        print("-" * 170)
        for h in hosts:
            dns = dns_check(h)
            whole, tcp_ms = probe_direct(h, "whole")
            variants = []
            for name, mode in [("orta", "mid"), ("once", "before"), ("ters", "reversed")]:
                r, _ = probe_direct(h, mode) if tcp_ms >= 0 else ("-", -1)
                variants.append((name, r))
            prx = probe_proxy(h) if proxy else "-"
            tcp_s = f"{tcp_ms:.0f}ms" if tcp_ms >= 0 else "yok"
            cols = " ".join(f"{r:14.14}" for _, r in variants)
            print(f"{h:22} {dns:28.28} {tcp_s:>7} {whole:14.14} {cols} {prx:16.16} {verdict(h, dns, tcp_ms, whole, variants, prx)}")
    finally:
        if proxy:
            proxy.terminate()


if __name__ == "__main__":
    main()
