#!/usr/bin/env python3
"""
MajorLogin → JWT (Dual Mode)
=============================
Mode 1:  UID + Password     → token grant → MajorLogin → JWT
Mode 2:  Access Token       → inspect → open_id + platform → MajorLogin → JWT

Shows the full decoded MajorLogin response (all fields, JWT claims, session keys).

Usage:
    python majorlogin_jwt.py                    # interactive
    python majorlogin_jwt.py --uid <UID> --password <PASS>
    python majorlogin_jwt.py --access-token <AT>

Made by Rishu
"""

import os
import sys
import json
import time
import base64
import argparse
from datetime import datetime

import requests
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


# ============================================================
# CONFIG
# ============================================================
AES_KEY = bytes([89, 103, 38, 116, 99, 37, 68, 69, 117, 104, 54, 37, 90, 99, 94, 56])
AES_IV  = bytes([54, 111, 121, 90, 68, 114, 50, 50, 69, 51, 121, 99, 104, 106, 77, 37])

CLIENT_SECRET = "2ee44819e9b4598845141067b281621874d0d5d7af9d8f7e00c1e54715b7d1e3"
APP_ID        = 100067

OAUTH_TOKEN_URL = "https://100067.connect.garena.com/oauth/guest/token/grant"
INSPECT_URL     = "https://100067.connect.garena.com/oauth/token/inspect"
MAJOR_LOGIN_URL = "https://loginbp.ppmainecoonghj.com/MajorLogin"

REGION = "IND"


# ============================================================
# COLORS
# ============================================================
try:
    from colorama import init, Fore, Style
    init(autoreset=True)
    G = Fore.GREEN; Y = Fore.YELLOW; R = Fore.RED
    C = Fore.CYAN; M = Fore.MAGENTA; B = Fore.BLUE; W = Fore.WHITE
    BOLD = Style.BRIGHT; DIM = Style.DIM; RST = Style.RESET_ALL
except ImportError:
    G = Y = R = C = M = B = W = BOLD = DIM = RST = ""


def ok(m):   print(f"{G}[+]{RST} {m}", flush=True)
def info(m): print(f"{C}[i]{RST} {m}", flush=True)
def warn(m): print(f"{Y}[!]{RST} {m}", flush=True)
def err(m):  print(f"{R}[-]{RST} {m}", flush=True)
def dbg(m):  print(f"{DIM}    {m}{RST}", flush=True)
def line(c="─", n=72): print(f"{DIM}{c * n}{RST}")


# ============================================================
# AES
# ============================================================
def aes_encrypt(data, key=AES_KEY, iv=AES_IV):
    return AES.new(key, AES.MODE_CBC, iv).encrypt(pad(data, AES.block_size))


def aes_decrypt(data, key=AES_KEY, iv=AES_IV):
    if not data or len(data) % 16 != 0:
        return None
    try:
        try:
            return unpad(AES.new(key, AES.MODE_CBC, iv).decrypt(data),
                         AES.block_size)
        except ValueError:
            return AES.new(key, AES.MODE_CBC, iv).decrypt(data)
    except Exception:
        return None


# ============================================================
# PROTOBUF WRITER
# ============================================================
def _wv(v):
    out = bytearray()
    while v > 0x7F:
        out.append((v & 0x7F) | 0x80)
        v >>= 7
    out.append(v)
    return bytes(out)


def _fv(n, v): return _wv((n << 3) | 0) + _wv(int(v))


def _fs(n, s):
    b = s.encode("utf-8") if isinstance(s, str) else bytes(s)
    return _wv((n << 3) | 2) + _wv(len(b)) + b


def _fb(n, b):
    return _wv((n << 3) | 2) + _wv(len(b)) + bytes(b)


def build_proto(fields):
    out = bytearray()
    for k, v in fields.items():
        if isinstance(v, int):
            out += _fv(k, v)
        elif isinstance(v, str):
            out += _fs(k, v)
        elif isinstance(v, (bytes, bytearray)):
            out += _fb(k, v)
    return bytes(out)


# ============================================================
# PROTOBUF READER (recursive, ordered)
# ============================================================
def _rv(data, off):
    r, s = 0, 0
    while True:
        if off >= len(data):
            raise ValueError("end")
        b = data[off]; off += 1
        r |= (b & 0x7F) << s
        if not (b & 0x80):
            return r, off
        s += 7
        if s > 63:
            raise ValueError("long")


def looks_like_proto(data, min_len=2):
    if not data or len(data) < min_len:
        return False
    try:
        tag, _ = _rv(data, 0)
    except Exception:
        return False
    f = tag >> 3
    w = tag & 7
    return 1 <= f <= 536870911 and w in (0, 1, 2, 5)


def parse_proto(data, depth=0, max_depth=12):
    """Return list of (field, wire, value, raw, nested)."""
    out = []
    off = 0
    while off < len(data):
        start = off
        try:
            tag, off = _rv(data, off)
        except Exception:
            break
        f = tag >> 3
        w = tag & 7
        if f == 0:
            break
        try:
            if w == 0:
                v, off = _rv(data, off)
                out.append((f, 0, v, None, None))
            elif w == 1:
                chunk = data[off:off+8]; off += 8
                out.append((f, 1, int.from_bytes(chunk, "little"), chunk, None))
            elif w == 2:
                ln, off = _rv(data, off)
                chunk = data[off:off+ln]; off += ln

                text = None
                try:
                    s = chunk.decode("utf-8")
                    if all(32 <= ord(c) < 127 or c in "\r\n\t" for c in s):
                        text = s
                except Exception:
                    pass

                nested = None
                if text is None and depth < max_depth and looks_like_proto(chunk):
                    try:
                        nested = parse_proto(chunk, depth+1, max_depth)
                    except Exception:
                        nested = None

                out.append((f, 2, text if text is not None else chunk, chunk, nested))
            elif w == 5:
                chunk = data[off:off+4]; off += 4
                out.append((f, 5, int.from_bytes(chunk, "little"), chunk, None))
            else:
                break
        except Exception:
            break
        if off <= start:
            break
    return out


# ============================================================
# HEX DUMP
# ============================================================
def hex_dump(data, width=32, max_bytes=256):
    lines = []
    for i in range(0, min(len(data), max_bytes), width):
        chunk = data[i:i+width]
        hx = " ".join(f"{b:02x}" for b in chunk)
        asc = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
        lines.append(f"  {i:04x}  {hx:<{width*3}}  |{asc}|")
    if len(data) > max_bytes:
        lines.append(f"  ... ({len(data) - max_bytes} more bytes)")
    return "\n".join(lines)


# ============================================================
# TOKEN GRANT (UID + Password)
# ============================================================
def token_grant(uid, password):
    info("Token grant (UID + password) …")
    r = requests.post(OAUTH_TOKEN_URL,
        data={
            "uid": uid, "password": password,
            "response_type": "token", "client_type": "2",
            "client_secret": CLIENT_SECRET, "client_id": str(APP_ID),
        },
        headers={
            "User-Agent": "GarenaMSDK/4.0.30",
            "Accept": "application/json",
            "Accept-Encoding": "gzip",
            "Connection": "Keep-Alive",
        },
        timeout=30, verify=False)
    if r.status_code != 200:
        raise RuntimeError(f"HTTP {r.status_code}: {r.text[:150]}")
    d = r.json()
    at = d.get("access_token")
    oi = d.get("open_id")
    if not at or not oi:
        raise RuntimeError(f"missing fields: {d}")
    ok(f"access_token = {at[:40]}…")
    ok(f"open_id      = {oi}")
    return at, oi


# ============================================================
# INSPECT TOKEN
# ============================================================
def inspect_token(access_token):
    info("Inspecting access_token …")
    try:
        r = requests.get(INSPECT_URL,
            params={"token": access_token},
            headers={
                "User-Agent": "GarenaMSDK/4.0.19P9",
                "Accept": "application/json",
            },
            timeout=15, verify=False)
        if r.status_code != 200:
            warn(f"inspect HTTP {r.status_code}")
            return None, None
        d = r.json()
        oi = d.get("open_id") or d.get("openid") or d.get("data", {}).get("open_id")
        plat = (d.get("platform") or d.get("main_active_platform")
                or d.get("login_platform") or d.get("data", {}).get("platform"))
        return oi, (str(plat) if plat is not None else None)
    except Exception as e:
        warn(f"inspect failed: {e}")
        return None, None


# ============================================================
# JWT DECODE (no verify)
# ============================================================
def decode_jwt_claims(jwt):
    try:
        parts = jwt.split(".")
        if len(parts) != 3:
            return None
        payload = parts[1]
        payload += "=" * (-len(payload) % 4)
        return json.loads(base64.urlsafe_b64decode(payload))
    except Exception:
        return None


# ============================================================
# MAJOR LOGIN (build + send)
# ============================================================
def build_major_login(open_id, access_token, platform="4"):
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    return build_proto({
        3: now, 4: "free fire", 5: 1, 7: "2.133.9",
        8: "Android OS 10 / API-29 (QP1A.190711.020/1617006012)",
        9: "Handheld", 10: "Vi India", 11: "WIFI",
        12: 1600, 13: 720, 14: "320",
        15: "ARM64 FP ASIMD AES | 2301 | 8", 16: 2799,
        17: "PowerVR Rogue GE8320",
        18: "OpenGL ES 3.2 build 1.11@5425693",
        19: "Google|9f7d6b8b-b10c-454a-852d-06332cd498eb",
        20: "151.158.158.220", 21: "en",
        22: open_id, 23: str(platform),
        24: "Handheld", 25: "realme RMX2189",
        26: REGION, 29: access_token, 30: 1,
        41: "Vi India", 42: "WIFI",
        57: "1ac4b80ecf0478a44203bf8fac6120f5",
        60: 19799, 61: 2536, 62: 5056, 64: 2768,
        65: 19999, 66: 2536, 67: 19799,
        73: 1,
        74: "/data/app/com.dts.freefiremax-ShI7E0dK8p1IiZ785pvuVQ==/lib/arm64",
        76: 2,
        77: "38f4751a330688ab124c2c804cec90a5|/data/app/com.dts.freefiremax-ShI7E0dK8p1IiZ785pvuVQ==/base.apk",
        78: 2, 79: 2, 81: "64", 83: "2019118527",
        86: "OpenGLES3", 87: 3071, 88: 4, 92: 67920,
        93: "android_max",
        94: "KqsHT+UrR1HKqb6+1db+Ofei+NtZr2+hbiBo3yKDL8w+8E3S5qF2IgEEe1fFQFyHRzl4iyHjHp+QsfeLbjJ6+DidTiKxm0ak2uYYa6QR4nAUdlZR",
        95: 111107,
        96: '{"cur_rate":null,"support_etc2":true}',
        97: 1, 98: 1, 99: str(platform), 100: str(platform), 102: "",
        104: 83812, 105: 1,
        106: "https://dl-bs.ggpolarbear.com/live/ABHotUpdates/|https://core-bs.ggpolarbear.com/live/ABHotUpdates/|a4332cb1c1a84e51dd77441e4856ed5a",
        107: "1.9393e7b8e53e8aeb",
    })


def send_major_login(open_id, access_token, platform="4"):
    info(f"MajorLogin (platform {platform}) …")
    body = aes_encrypt(build_major_login(open_id, access_token, platform))

    r = requests.post(MAJOR_LOGIN_URL, data=body, headers={
        "Host": "loginbp.ppmainecoonghj.com",
        "User-Agent": "UnityPlayer/2018.4.12f1 (UnityWebRequest/1.0, libcurl/8.5.0-DEV)",
        "Accept": "*/*", "Accept-Encoding": "deflate, gzip",
        "X-GA-SV": str(int(time.time())),
        "Authorization": "Bearer ", "X-GA": "v1 1",
        "ReleaseVersion": "OB55",
        "Content-Type": "application/x-www-form-urlencoded",
        "X-Unity-Version": "2018.4.12f1",
        "Content-Length": str(len(body)),
    }, timeout=30, verify=False)

    info(f"HTTP {r.status_code}  ({len(r.content)} bytes)")
    if r.status_code != 200:
        raise RuntimeError(f"HTTP {r.status_code}: {r.text[:200]}")
    return r.content


# ============================================================
# SHOW FULL DECODED MajorLogin RESPONSE
# ============================================================
FIELD_LABELS = {
    1:  "account_id",
    2:  "region",
    3:  "url",
    4:  "field_4",
    5:  "timestamp",
    6:  "nickname",
    7:  "field_7",
    8:  "JWT (token)",
    9:  "field_9",
    10: "field_10",
    11: "field_11",
    12: "field_12",
    13: "field_13",
    14: "field_14",
    15: "field_15",
    16: "field_16",
    17: "field_17",
    18: "field_18",
    19: "field_19 (location)",
    20: "field_20 (state)",
    21: "server_time",
    22: "SESSION KEY",
    23: "SESSION IV",
    24: "field_24",
    25: "field_25",
    26: "field_26",
    27: "field_27",
    28: "field_28",
    29: "field_29",
    30: "field_30",
    31: "field_31",
    32: "field_32",
}


def _fmt_value(f, w, v, raw):
    if w == 0:
        return f"{v}"
    if w == 1:
        return f"0x{v:016x}"
    if w == 5:
        return f"0x{v:08x}"
    # wire 2
    if isinstance(v, str):
        if len(v) > 120:
            return f'"{v[:120]}…"  [{len(v)} chars]'
        return f'"{v}"'
    if isinstance(v, bytes):
        if f in (22, 23) and len(v) == 16:
            return f"0x{v.hex().upper()}  ← 16-byte {'KEY' if f == 22 else 'IV'}"
        hx = v.hex()
        if len(hx) > 120:
            return f"0x{hx[:120]}…  [{len(v)} bytes]"
        return f"0x{hx}  [{len(v)} bytes]"
    return repr(v)


def show_decoded_response(raw):
    print()
    print(f"{BOLD}{C}{'═' * 74}{RST}")
    print(f"{BOLD}{C}  MajorLogin Response  —  {len(raw)} bytes{RST}")
    print(f"{BOLD}{C}{'═' * 74}{RST}")

    # try strategies
    strategies = []
    dec = aes_decrypt(raw)
    if dec:
        strategies.append(("aes (decrypted)", dec))
    if len(raw) > 64:
        strategies.append(("offset64", raw[64:]))
        dec2 = aes_decrypt(raw[64:])
        if dec2:
            strategies.append(("aes@offset64", dec2))
    strategies.append(("raw", raw))

    chosen = None
    chosen_label = None
    chosen_fields = None

    for label, buf in strategies:
        try:
            fields = parse_proto(buf)
        except Exception:
            continue

        # valid if it has fields 1, 8 or 21
        d = {f: v for f, w, v, r, n in fields}
        if 8 in d or (1 in d and 21 in d):
            chosen = buf
            chosen_label = label
            chosen_fields = fields
            break

    if not chosen:
        warn("could not decode — showing raw")
        print(hex_dump(raw))
        return None

    ok(f"decoded via: {chosen_label}")

    print()
    print(f"{BOLD}── Field-by-Field ──{RST}")
    for f, w, v, r, n in chosen_fields:
        label = FIELD_LABELS.get(f, "")
        tag = f"{BOLD}field {f:<4}{RST}"
        if label:
            tag += f" {DIM}({label}){RST}"

        wname = {0: "varint", 1: "i64", 2: "len", 5: "i32"}.get(w, str(w))

        if n:
            print(f"  {tag} {wname:<6} = MESSAGE ({len(r)} bytes)")
            for f2, w2, v2, r2, n2 in n[:8]:
                print(f"      ↳ f{f2} = {_fmt_value(f2, w2, v2, r2)}")
            if len(n) > 8:
                print(f"      ↳ … ({len(n) - 8} more)")
            continue

        print(f"  {tag} {wname:<6} = {_fmt_value(f, w, v, r)}")

    # ── JWT claims ──
    jwt = None
    for f, w, v, r, n in chosen_fields:
        if f == 8 and w == 2 and isinstance(v, str) and v.count(".") == 2:
            jwt = v
            break
        if f == 8 and w == 2 and isinstance(v, bytes):
            try:
                s = v.decode("utf-8", "ignore")
                if s.count(".") == 2:
                    jwt = s
                    break
            except Exception:
                pass

    if jwt:
        print()
        print(f"{BOLD}── JWT Claims ──{RST}")
        claims = decode_jwt_claims(jwt)
        if claims:
            for k, v in claims.items():
                if k == "nickname" and isinstance(v, str):
                    try:
                        decoded = base64.b64decode(v + "==").decode("utf-8", "ignore")
                        print(f"  {BOLD}{k:<22}{RST} = {v}  →  {decoded!r}")
                        continue
                    except Exception:
                        pass
                if k == "exp":
                    now = int(time.time())
                    delta = int(v) - now
                    status = f"{G}valid {delta}s{RST}" if delta > 0 else f"{R}EXPIRED{-delta}s ago{RST}"
                    print(f"  {BOLD}{k:<22}{RST} = {v}   ({status})")
                    continue
                print(f"  {BOLD}{k:<22}{RST} = {v}")
        else:
            warn("could not decode JWT claims")

    # ── Session keys summary ──
    session_key = None
    session_iv = None
    for f, w, v, r, n in chosen_fields:
        if f == 22 and w == 2 and isinstance(r, bytes) and len(r) == 16:
            session_key = r
        if f == 23 and w == 2 and isinstance(r, bytes) and len(r) == 16:
            session_iv = r

    print()
    print(f"{BOLD}── Session Keys ──{RST}")
    if session_key and session_iv:
        ok(f"KEY : {session_key.hex().upper()}")
        ok(f"IV  : {session_iv.hex().upper()}")
    else:
        warn("session keys not found (fields 22/23 absent or wrong size)")

    # ── Raw response hex (short view) ──
    print()
    print(f"{BOLD}── Raw Response Hex ──{RST}")
    print(f"{DIM}{hex_dump(raw, max_bytes=192)}{RST}")

    return {
        "jwt": jwt,
        "account_id": next((v for f, w, v, r, n in chosen_fields if f == 1), None),
        "region": next((v for f, w, v, r, n in chosen_fields if f == 2), None),
        "session_key": session_key,
        "session_iv": session_iv,
        "fields": chosen_fields,
    }


# ============================================================
# MODE 1 — UID + PASSWORD
# ============================================================
def mode_uid_password(uid, password):
    print()
    print(f"{BOLD}{M}{'═' * 74}{RST}")
    print(f"{BOLD}{M}  MODE 1 — UID + Password → JWT{RST}")
    print(f"{BOLD}{M}{'═' * 74}{RST}")
    print()

    at, oi = token_grant(uid, password)

    # platform — try inspect, else default 4
    plat = "4"
    io, ip = inspect_token(at)
    if ip:
        plat = ip
        ok(f"platform (from inspect) = {plat}")

    raw = send_major_login(oi, at, plat)
    result = show_decoded_response(raw)

    if result and result.get("jwt"):
        print()
        print(f"{BOLD}{G}{'═' * 74}{RST}")
        print(f"{BOLD}{G}  ✅ JWT OBTAINED{RST}")
        print(f"{BOLD}{G}{'═' * 74}{RST}")
        print(f"{G}  {result['jwt']}{RST}")
        print(f"{BOLD}{G}{'═' * 74}{RST}")


# ============================================================
# MODE 2 — ACCESS TOKEN
# ============================================================
def mode_access_token(access_token):
    print()
    print(f"{BOLD}{M}{'═' * 74}{RST}")
    print(f"{BOLD}{M}  MODE 2 — Access Token → JWT{RST}")
    print(f"{BOLD}{M}{'═' * 74}{RST}")
    print()

    info(f"access_token = {access_token[:40]}…")

    # try inspect for open_id
    oi, plat = inspect_token(access_token)
    if not oi:
        warn("inspect did not return open_id")
        oi = input("Enter open_id manually : ").strip()
        if not oi:
            err("open_id required"); return

    if not plat:
        plat = input(f"Enter platform (default 4) : ").strip() or "4"

    ok(f"open_id      = {oi}")
    ok(f"platform     = {plat}")

    raw = send_major_login(oi, access_token, plat)
    result = show_decoded_response(raw)

    if result and result.get("jwt"):
        print()
        print(f"{BOLD}{G}{'═' * 74}{RST}")
        print(f"{BOLD}{G}  ✅ JWT OBTAINED{RST}")
        print(f"{BOLD}{G}{'═' * 74}{RST}")
        print(f"{G}  {result['jwt']}{RST}")
        print(f"{BOLD}{G}{'═' * 74}{RST}")


# ============================================================
# MAIN
# ============================================================
def interactive_menu():
    print()
    print(f"{BOLD}{C}╔══════════════════════════════════════════════════════════╗")
    print("║   MajorLogin → JWT  (Dual Mode)                          ║")
    print("╚══════════════════════════════════════════════════════════╝" + RST)
    print()
    print(f"  {BOLD}1){RST} UID + Password  → JWT")
    print(f"  {BOLD}2){RST} Access Token    → JWT")
    print(f"  {BOLD}3){RST} Exit")
    print()

    while True:
        choice = input(f"{Y}Select [1/2/3] : {RST}").strip()
        if choice in ("1", "2", "3"):
            break
        warn("invalid — enter 1, 2, or 3")

    if choice == "3":
        print(f"{DIM}bye{RST}")
        return

    if choice == "1":
        uid = input(f"{C}UID      : {RST}").strip()
        if not uid:
            err("UID required"); return
        password = input(f"{C}Password : {RST}").strip()
        if not password:
            err("Password required"); return
        try:
            mode_uid_password(uid, password)
        except Exception as e:
            err(f"failed: {e}")

    elif choice == "2":
        at = input(f"{C}Access Token : {RST}").strip()
        if not at:
            err("access_token required"); return
        try:
            mode_access_token(at)
        except Exception as e:
            err(f"failed: {e}")


def main():
    p = argparse.ArgumentParser(description="MajorLogin → JWT (dual mode)")
    p.add_argument("--uid", type=str, help="UID (guest)")
    p.add_argument("--password", type=str, help="Password (guest)")
    p.add_argument("--access-token", type=str, dest="access_token", help="Access token")
    args = p.parse_args()

    if args.uid and args.password:
        try:
            mode_uid_password(args.uid, args.password)
        except Exception as e:
            err(f"failed: {e}")
        return

    if args.access_token:
        try:
            mode_access_token(args.access_token)
        except Exception as e:
            err(f"failed: {e}")
        return

    interactive_menu()


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n{Y}Stopped{RST}")