import os, secrets, importlib.util
from functools import wraps
from flask import Flask, render_template, request, jsonify, session, Response
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

BASE = os.path.dirname(os.path.abspath(__file__))
app = Flask(__name__)
app.secret_key = os.environ.get("FLASK_SECRET_KEY") or secrets.token_hex(32)
app.config.update(SESSION_COOKIE_HTTPONLY=True, SESSION_COOKIE_SAMESITE="Lax")

import os
import secrets
import importlib.util
import importlib.machinery

def load_module(name, filename):
    path = os.path.join(BASE, filename)

    if not os.path.isfile(path):
        raise FileNotFoundError(f"Module not found: {path}")

    loader = importlib.machinery.SourceFileLoader(name, path)
    spec = importlib.util.spec_from_loader(name, loader)

    if spec is None or spec.loader is None:
        raise ImportError(f"Cannot load module: {path}")

    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)

    return mod

major = load_module("major_login", "MaJorLogin.py")
friends = load_module("friend_actions", "FriEndRequEst.py")
guilds = load_module("guild_actions", "ALLinOne.PY")
bio_mod = load_module("bio_actions", "BiOCheck.py")
gallery = load_module("gallery_actions", "PROFILE-ITEM-ADDER.py")


PANEL_PASSCODE = os.environ.get("PANEL_PASSCODE", "").strip()

@app.before_request
def passcode_gate():
    if not PANEL_PASSCODE:
        return None
    auth = request.authorization
    if auth and auth.password == PANEL_PASSCODE:
        return None
    return Response(
        "RISHU CONTROL PANEL - passcode required",
        401,
        {"WWW-Authenticate": 'Basic realm="RISHU CONTROL PANEL"'},
    )

# This lightweight app is intended for one trusted operator on a private machine.
# Keep it bound to localhost or put it behind HTTPS + authentication before exposing it.
TOKENS = {}

def require_jwt(fn):
    @wraps(fn)
    def wrapped(*args, **kwargs):
        sid = session.get("sid")
        jwt = TOKENS.get(sid, {}).get("jwt") if sid else None
        if not jwt:
            return jsonify(ok=False, error="Please login first."), 401
        request.jwt = jwt
        return fn(*args, **kwargs)
    return wrapped

def response(status, body):
    if isinstance(body, bytes):
        try: body = body.decode("utf-8")
        except Exception: body = body.hex()
    return {"status_code": status, "response": str(body)[:2000]}

@app.get("/")
def index():
    return render_template("index.html")

@app.post("/api/login")
def login():
    data = request.get_json(force=True)
    mode = data.get("mode")
    try:
        if mode == "uid":
            uid, password = str(data.get("uid", "")).strip(), str(data.get("password", ""))
            if not uid or not password:
                return jsonify(ok=False, error="UID and password are required."), 400
            access_token, open_id = major.token_grant(uid, password)
            _, platform = major.inspect_token(access_token)
            raw = major.send_major_login(open_id, access_token, platform or "4")
        elif mode == "access":
            access_token = str(data.get("access_token", "")).strip()
            if not access_token:
                return jsonify(ok=False, error="Access token is required."), 400
            open_id, platform = major.inspect_token(access_token)
            if not open_id:
                open_id = str(data.get("open_id", "")).strip()
            if not platform:
                platform = str(data.get("platform", "4")).strip() or "4"
            if not open_id:
                return jsonify(ok=False, error="Token inspection did not return open_id. Supply open_id and retry."), 400
            raw = major.send_major_login(open_id, access_token, platform)
        else:
            return jsonify(ok=False, error="Choose UID/password or access token."), 400

        decoded = major.show_decoded_response(raw)
        jwt = decoded.get("jwt") if decoded else None
        if not jwt:
            return jsonify(ok=False, error="MajorLogin response did not contain a JWT."), 502
        sid = session.get("sid") or secrets.token_urlsafe(24)
        session["sid"] = sid
        TOKENS[sid] = {"jwt": jwt}
        claims = major.decode_jwt_claims(jwt) or {}
        return jsonify(ok=True, profile={
            "uid": decoded.get("account_id") or claims.get("account_id"),
            "nickname": claims.get("nickname", "Player"),
            "region": decoded.get("region") or claims.get("noti_region", "—")
        })
    except Exception as exc:
        return jsonify(ok=False, error=str(exc)[:500]), 502

@app.post("/api/logout")
def logout():
    sid = session.pop("sid", None)
    if sid: TOKENS.pop(sid, None)
    return jsonify(ok=True)

@app.post("/api/friend")
@require_jwt
def friend():
    d = request.get_json(force=True)
    try:
        target = int(d.get("uid"))
        claims = major.decode_jwt_claims(request.jwt) or {}
        own = int(claims.get("account_id"))
        result = friends.FriEnd(request.jwt, own, target)
        return jsonify(ok=True, result=response(result.get("status_code", 0), result.get("content", result.get("error", ""))))
    except Exception as exc:
        return jsonify(ok=False, error=str(exc)), 400

@app.post("/api/guild")
@require_jwt
def guild():
    d = request.get_json(force=True)
    try:
        gid = int(d.get("guild_id"))
        action = d.get("action")
        if action == "join": status, body = guilds.guild_join(request.jwt, gid)
        elif action == "leave": status, body = guilds.guild_leave(request.jwt, gid)
        else: return jsonify(ok=False, error="Invalid guild action."), 400
        return jsonify(ok=True, result=response(status, body))
    except Exception as exc:
        return jsonify(ok=False, error=str(exc)), 400

@app.post("/api/bio")
@require_jwt
def update_bio():
    d = request.get_json(force=True)
    bio = str(d.get("bio", ""))
    if not bio.strip(): return jsonify(ok=False, error="Bio cannot be empty."), 400
    if len(bio) > 200: return jsonify(ok=False, error="Bio is too long (200 character UI limit)."), 400
    try:
        plain = bio_mod.build_bio_payload(bio)
        encrypted = bio_mod.encrypt_data(plain)
        headers = bio_mod.HEADERS_TEMPLATE.copy()
        headers["Authorization"] = f"Bearer {request.jwt}"
        import requests
        last = None
        for url in bio_mod.UPDATE_URLS:
            r = requests.post(url, headers=headers, data=encrypted, timeout=20)
            last = r
            if r.status_code == 200: break
        return jsonify(ok=True, result=response(last.status_code, last.content))
    except Exception as exc:
        return jsonify(ok=False, error=str(exc)), 502

@app.post("/api/gallery")
@require_jwt
def update_gallery():
    d = request.get_json(force=True)
    try:
        raw = str(d.get("items", "")).replace(",", " ").split()
        items = [int(x) for x in raw]
        if not items or len(items) > 6: return jsonify(ok=False, error="Enter 1–6 numeric item IDs."), 400
        status, body = gallery.send_gallery_request(request.jwt, items)
        return jsonify(ok=True, result=response(status, body), note="This updates the profile gallery/showcase; it does not grant item ownership.")
    except Exception as exc:
        return jsonify(ok=False, error=str(exc)), 400

if __name__ == "__main__":
    # Do not expose this development server directly to the public internet.
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", "5000")), debug=False)
