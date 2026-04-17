"""
mfa_service.py
Member 1 — Custom MFA Microservice (standalone demo service)

Important:
This service is an ALTERNATIVE / DEMO MFA path. The primary login MFA for
this project is Keycloak native OTP. This microservice is still useful for
showing a custom TOTP flow and for independent testing.

Endpoints:
  GET  /health
  POST /mfa/setup
  POST /mfa/verify
  GET  /mfa/status
  POST /mfa/disable

Run:
  pip install flask pyotp qrcode pillow
  export MFA_ADMIN_TOKEN=change-me
  python mfa_service.py
"""

import base64
import io
import json
import logging
import os
import re
import time
from pathlib import Path
from threading import Lock

import pyotp
import qrcode
from flask import Flask, jsonify, request

APP_NAME = "EnterpriseZeroTrust"
SECRET_DIR = Path(os.getenv("MFA_SECRET_DIR", "mfa_secrets"))
SECRET_DIR.mkdir(parents=True, exist_ok=True)
ADMIN_TOKEN = os.getenv("MFA_ADMIN_TOKEN", "change-me")
USERNAME_RE = re.compile(r"^[A-Za-z0-9_.@-]{1,128}$")
_FILE_LOCK = Lock()

app = Flask(__name__)
logging.basicConfig(level=logging.INFO, format="%(asctime)s [MFA] %(levelname)s %(message)s")
log = logging.getLogger(__name__)


def _validate_username(username: str) -> str:
    username = (username or "").strip()
    if not username:
        raise ValueError("username is required")
    if not USERNAME_RE.fullmatch(username):
        raise ValueError("username contains unsupported characters")
    return username


def _secret_file(username: str) -> Path:
    return SECRET_DIR / f"{username}.json"


def _load_user(username: str) -> dict | None:
    with _FILE_LOCK:
        f = _secret_file(username)
        if not f.exists():
            return None
        return json.loads(f.read_text())


def _save_user(username: str, data: dict) -> None:
    with _FILE_LOCK:
        _secret_file(username).write_text(json.dumps(data))


def _delete_user(username: str) -> bool:
    with _FILE_LOCK:
        f = _secret_file(username)
        if not f.exists():
            return False
        f.unlink()
        return True


def _make_qr_base64(uri: str) -> str:
    img = qrcode.make(uri)
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    return base64.b64encode(buf.getvalue()).decode()


def _response_for_user(username: str, user_data: dict) -> dict:
    secret = user_data["secret"]
    uri = pyotp.TOTP(secret).provisioning_uri(name=username, issuer_name=APP_NAME)
    return {
        "username": username,
        "secret": secret,
        "uri": uri,
        "qr_code": _make_qr_base64(uri),
        "enrolled": bool(user_data.get("enrolled", False)),
        "created": user_data.get("created"),
        "last_verified": user_data.get("last_verified"),
        "message": "Scan QR code with an authenticator app, then call /mfa/verify",
    }


@app.route("/health", methods=["GET"])
def health():
    return jsonify({"status": "ok", "service": "mfa-service"}), 200


@app.route("/mfa/setup", methods=["POST"])
def setup():
    body = request.get_json(silent=True) or {}
    try:
        username = _validate_username(body.get("username", ""))
    except ValueError as exc:
        return jsonify({"error": str(exc)}), 400

    user_data = _load_user(username)
    if not user_data:
        user_data = {
            "secret": pyotp.random_base32(),
            "enrolled": False,
            "created": time.time(),
            "last_verified": None,
        }
        _save_user(username, user_data)
        log.info("MFA setup initiated for user: %s", username)
    else:
        log.info("MFA setup requested again for user: %s", username)

    return jsonify(_response_for_user(username, user_data)), 200


@app.route("/mfa/verify", methods=["POST"])
def verify():
    body = request.get_json(silent=True) or {}
    try:
        username = _validate_username(body.get("username", ""))
    except ValueError as exc:
        return jsonify({"error": str(exc)}), 400

    otp_code = str(body.get("otp", "")).strip()
    if not otp_code:
        return jsonify({"error": "otp is required"}), 400

    user_data = _load_user(username)
    if not user_data:
        log.warning("MFA verify attempt for unknown user: %s", username)
        return jsonify({"verified": False, "reason": "user not enrolled"}), 401

    valid = pyotp.TOTP(user_data["secret"]).verify(otp_code, valid_window=1)
    if not valid:
        log.warning("MFA FAILED - user: %s", username)
        return jsonify({"verified": False, "reason": "invalid or expired OTP"}), 401

    user_data["enrolled"] = True
    user_data["last_verified"] = time.time()
    _save_user(username, user_data)
    log.info("MFA verified OK - user: %s", username)
    return jsonify({"verified": True, "username": username}), 200


@app.route("/mfa/status", methods=["GET"])
def status():
    try:
        username = _validate_username(request.args.get("username", ""))
    except ValueError as exc:
        return jsonify({"error": str(exc)}), 400

    user_data = _load_user(username)
    if not user_data:
        return jsonify({"username": username, "enrolled": False, "created": None, "last_verified": None}), 200

    return jsonify({
        "username": username,
        "enrolled": bool(user_data.get("enrolled", False)),
        "created": user_data.get("created"),
        "last_verified": user_data.get("last_verified"),
    }), 200


@app.route("/mfa/disable", methods=["POST"])
def disable():
    if request.headers.get("X-Admin-Token") != ADMIN_TOKEN:
        return jsonify({"error": "admin token required"}), 403

    body = request.get_json(silent=True) or {}
    try:
        username = _validate_username(body.get("username", ""))
    except ValueError as exc:
        return jsonify({"error": str(exc)}), 400

    if _delete_user(username):
        log.info("MFA disabled for user: %s", username)
        return jsonify({"message": f"MFA disabled for {username}"}), 200
    return jsonify({"message": "user not found"}), 404


if __name__ == "__main__":
    port = int(os.getenv("MFA_PORT", "5010"))
    print(f"[MFA Service] Running on port {port}")
    app.run(host="0.0.0.0", port=port, debug=False)
