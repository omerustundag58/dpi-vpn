"""Gercek TLS ClientHello korpusu uretir (dpi-core/tests/data/)."""
import socket
import ssl
import threading
import time
import os

OUT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "dpi-core", "tests", "data")
os.makedirs(OUT, exist_ok=True)
PORT = [18450]


def capture(sni, alpn=None):
    got = {}
    port = PORT[0]
    PORT[0] += 1

    def server():
        srv = socket.socket()
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind(("127.0.0.1", port))
        srv.listen(1)
        srv.settimeout(10)
        c, _ = srv.accept()
        c.settimeout(5)
        got["hello"] = c.recv(8192)
        c.close()
        srv.close()

    t = threading.Thread(target=server, daemon=True)
    t.start()
    time.sleep(0.3)
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    if alpn is not None:
        ctx.set_alpn_protocols(alpn)
    raw = socket.create_connection(("127.0.0.1", port), timeout=5)
    w = ctx.wrap_socket(raw, server_hostname=sni, do_handshake_on_connect=False)
    try:
        w.do_handshake()
    except Exception:
        pass
    t.join(timeout=5)
    return got["hello"]


cases = [
    ("hello_yt_alpn.bin", "youtube.com", ["h2", "http/1.1"]),
    ("hello_noalpn.bin", "discord.com", []),
    ("hello_long.bin", "cok-uzun-bir-alt-alan-adi-ornegi.roblox.com", ["http/1.1"]),
]
for name, sni, alpn in cases:
    h = capture(sni, alpn)
    assert h[0] == 0x16 and h[5] == 0x01, name
    assert sni.encode() in h, name
    open(os.path.join(OUT, name), "wb").write(h)
    print(f"{name}: {len(h)}B SNI={sni} alpn={alpn}")
print("korpus tamam")
