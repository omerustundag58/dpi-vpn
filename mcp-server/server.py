#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""dpi-vpn MCP sunucusu (stdio, stdlib-only).
Opencode global config'e kayitli: proje derleme/test/tani araclari.
Kullanim: python server.py  (MCP initialize -> tools/list -> tools/call)
"""
import json
import os
import subprocess
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PROJ = ROOT  # dpi-vpn koku
TIMEOUTS = {"dpi_status": 30, "dpi_test_core": 240, "dpi_proxy_tests": 400,
            "dpi_diag": 400, "android_env": 60, "ollama_status": 30}


def run(cmd, cwd=None, timeout=120):
    """Liste ya da string komut calistir, son 6000 karakteri dondur. Shell yok."""
    try:
        if isinstance(cmd, str):
            import shlex
            cmd = shlex.split(cmd, posix=False)
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout,
                           cwd=cwd or PROJ, errors="replace")
        out = (r.stdout + r.stderr)[-6000:]
        return out if out.strip() else "(bos cikti)"
    except subprocess.TimeoutExpired:
        return "(ZAMAN ASIMI)"
    except Exception as e:
        return f"(HATA: {e})"


TOOLS = {
    "dpi_status": ("Proje durumu: git log, exe tazeligi, calisan proxy/app islemleri.",
                   {"type": "object", "properties": {}}),
    "dpi_test_core": ("Rust cekirdek testleri (cargo test -p dpi-core).",
                      {"type": "object", "properties": {}}),
    "dpi_proxy_tests": ("Proxy integration testleri (4-6 test, ~2dk).",
                        {"type": "object", "properties": {}}),
    "dpi_diag": ("DPI tani: verilen hostlara DNS/TCP/parcali/proxy problari.",
                 {"type": "object",
                  "properties": {"hosts": {"type": "array", "items": {"type": "string"}}},
                  "required": []}),
    "android_env": ("Android ortami: adb cihazlar, emulator, NDK, .so dosyalari.",
                    {"type": "object", "properties": {}}),
    "ollama_status": ("Yerel model durumu: ollama list + calisan surec.",
                      {"type": "object", "properties": {}}),
}


def call_tool(name, args):
    if name == "dpi_status":
        a = run(["git", "log", "--oneline", "-5"], PROJ, 30)
        b = run(["git", "status", "--short"], PROJ, 30)
        c = run(["powershell", "-NoProfile", "-Command",
                 "Get-Process dpi-proxy,DPI-VPN-Turkiye -ErrorAction SilentlyContinue | Select-Object Name,Id | Out-String"],
                PROJ, 30)
        return f"{a}\n---\n{b[:500]}\n---\n{c}"
    if name == "dpi_test_core":
        return run(["cargo", "test", "-p", "dpi-core"], PROJ, 240)
    if name == "dpi_proxy_tests":
        return run(["cargo", "test", "-p", "dpi-proxy", "--test", "aggressive"], PROJ, 400)
    if name == "dpi_diag":
        hosts = (args or {}).get("hosts") or ["example.com", "discord.com"]
        return run([sys.executable, "diag.py"] + hosts, PROJ, 400)
    if name == "android_env":
        sdk = os.path.expandvars(r"%LOCALAPPDATA%\Android\Sdk")
        adb = os.path.join(sdk, "platform-tools", "adb.exe")
        a = run([adb, "devices"], PROJ, 60)
        b = run(["tasklist", "/FI", "IMAGENAME eq emulator.exe"], PROJ, 30)
        return f"{a}\n---\n{b}"
    if name == "ollama_status":
        a = run(["ollama", "list"], PROJ, 30)
        b = run(["tasklist", "/FI", "IMAGENAME eq ollama*"], PROJ, 30)
        return f"{a}\n---\n{b}"
    return f"Bilinmeyen arac: {name}"


def reply(mid, result=None, error=None):
    msg = {"jsonrpc": "2.0", "id": mid}
    if error is not None:
        msg["error"] = error
    else:
        msg["result"] = result
    sys.stdout.write(json.dumps(msg) + "\n")
    sys.stdout.flush()


def main():
    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        try:
            req = json.loads(line)
        except Exception:
            continue
        mid, method, params = req.get("id"), req.get("method"), req.get("params", {}) or {}
        if method == "initialize":
            reply(mid, {"protocolVersion": "2024-11-05",
                        "capabilities": {"tools": {}},
                        "serverInfo": {"name": "dpi-vpn", "version": "0.3"}})
        elif method in ("notifications/initialized", "notifications/cancelled"):
            pass
        elif method == "ping":
            reply(mid, {})
        elif method == "tools/list":
            reply(mid, {"tools": [{"name": n, "description": d, "inputSchema": s}
                                  for n, (d, s) in TOOLS.items()]})
        elif method == "tools/call":
            name = params.get("name", "")
            args = params.get("arguments", {}) or {}
            if name not in TOOLS:
                reply(mid, error={"code": -32602, "message": f"unknown tool {name}"})
                continue
            try:
                text = call_tool(name, args)
                reply(mid, {"content": [{"type": "text", "text": text}]})
            except Exception as e:
                reply(mid, {"content": [{"type": "text", "text": f"HATA: {e}"}], "isError": True})
        else:
            reply(mid, error={"code": -32601, "message": f"unknown method {method}"})


if __name__ == "__main__":
    main()
