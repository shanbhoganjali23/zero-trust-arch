from flask import Flask, request, jsonify, Response, make_response
from flask_cors import CORS
from datetime import datetime
from pathlib import Path
import secrets
import requests

app = Flask(__name__)
app.secret_key = "zt-demo-secret-key"
CORS(app, supports_credentials=True)

POLICY_ENGINE_URL = "http://127.0.0.1:5005/evaluate"
MFA_SERVICE_URL = "http://127.0.0.1:5010"
BASE_DIR = Path(__file__).resolve().parent.parent
SECURITY_LOG_FILE = BASE_DIR / "security_events_tracking.txt"

SERVICE_MAP = {
    "/hr-app": "http://127.0.0.1:5001",
    "/finance-app": "http://127.0.0.1:5002",
    "/dev-app": "http://127.0.0.1:5003",
}

ROLE_ROUTES = {
    "HR": "/hr-app",
    "Finance": "/finance-app",
    "Developer": "/dev-app",
    "Admin": "/hr-app",
    "SecurityAnalyst": "/hr-app",
}

# Demo session stores for the prototype
PENDING_LOGINS = {}
ACTIVE_SESSIONS = {}


def log_event(event_type, user="unknown", role="unknown", resource="-", reason=None):
    line = (
        f"{datetime.now().isoformat()} EVENT={event_type} USER={user} ROLE={role} RESOURCE={resource}"
    )
    if reason:
        line += f" REASON={reason}"
    with open(SECURITY_LOG_FILE, "a", encoding="utf-8") as f:
        f.write(line + "\n")
    print(f"[Gateway] {line}")


def validate_bearer_token(req):
    auth_header = req.headers.get("Authorization", "")
    if not auth_header.startswith("Bearer "):
        return None
    token = auth_header.split(" ", 1)[1].strip()
    try:
        from jose import jwt as jose_jwt

        payload = jose_jwt.get_unverified_claims(token)
        username = payload.get("preferred_username") or payload.get("username") or payload.get("sub")
        role = payload.get("role")
        if not role:
            realm_roles = payload.get("realm_access", {}).get("roles", [])
            system_roles = {"offline_access", "uma_authorization", "default-roles-enterprise-zt"}
            app_roles = [r for r in realm_roles if r not in system_roles]
            role = app_roles[0] if app_roles else None
        if not username or not role:
            return None
        return {
            "user": username,
            "role": role,
            "mfa": True,
            "source": "bearer",
        }
    except Exception as exc:
        print(f"[Gateway] Token decode failed: {exc}")
        return None


def validate_demo_session(req):
    session_id = req.cookies.get("zt_session") or req.headers.get("X-Session-Id")
    if not session_id:
        return None
    session_data = ACTIVE_SESSIONS.get(session_id)
    if not session_data:
        return None
    return {
        "user": session_data["user"],
        "role": session_data["role"],
        "mfa": bool(session_data.get("mfa", False)),
        "source": "demo_session",
    }


def get_user_identity(req):
    token_user = validate_bearer_token(req)
    if token_user:
        return token_user
    return validate_demo_session(req)


def call_policy_engine(user_data, resource, action):
    payload = {
        "user": user_data["user"],
        "role": user_data["role"],
        "resource": resource,
        "action": action,
        "mfa_verified": user_data["mfa"],
    }
    response = requests.post(POLICY_ENGINE_URL, json=payload, timeout=5)
    response.raise_for_status()
    return response.json()


def get_service_url(resource):
    for prefix, url in SERVICE_MAP.items():
        if resource.startswith(prefix):
            return url
    return None


def forward_to_service(service_url, resource, original_request, user_data):
    target_url = service_url + resource
    allowed_headers = {}
    content_type = original_request.headers.get("Content-Type")
    if content_type:
        allowed_headers["Content-Type"] = content_type
    allowed_headers["X-From-Gateway"] = "true"
    allowed_headers["X-User"] = user_data["user"]
    allowed_headers["X-Role"] = user_data["role"]
    allowed_headers["X-MFA"] = "true" if user_data["mfa"] else "false"

    resp = requests.request(
        method=original_request.method,
        url=target_url,
        headers=allowed_headers,
        data=original_request.get_data(),
        timeout=10,
        allow_redirects=True,
    )
    return Response(
        resp.content,
        status=resp.status_code,
        content_type=resp.headers.get("Content-Type", "text/html"),
    )


def denied_page(user, role, resource, reason):
    return f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>Access Denied</title>
  <style>
    * {{ box-sizing: border-box; margin: 0; padding: 0; }}
    body {{ font-family: 'Segoe UI', sans-serif; background: #fff0f0; display: flex; align-items: center; justify-content: center; min-height: 100vh; }}
    .card {{ background: white; border-radius: 16px; padding: 3rem; max-width: 500px; width: 90%; box-shadow: 0 4px 24px rgba(0,0,0,0.1); text-align: center; }}
    .icon {{ font-size: 4rem; margin-bottom: 1rem; }}
    h1 {{ color: #c62828; font-size: 1.8rem; margin-bottom: 0.5rem; }}
    .subtitle {{ color: #666; margin-bottom: 2rem; font-size: 0.95rem; }}
    .details {{ background: #fff5f5; border: 1px solid #ffcdd2; border-radius: 8px; padding: 1rem 1.5rem; text-align: left; margin-bottom: 1.5rem; }}
    .details p {{ font-size: 0.88rem; color: #555; margin-bottom: 0.4rem; }}
    .details p span {{ font-weight: 600; color: #1a1a2e; }}
    .reason {{ background: #fce4ec; border-radius: 8px; padding: 0.8rem 1.2rem; color: #c62828; font-size: 0.88rem; margin-bottom: 1.5rem; }}
    .badge {{ display: inline-block; background: #c62828; color: white; padding: 0.3rem 1rem; border-radius: 20px; font-size: 0.8rem; margin-bottom: 1.5rem; }}
    .footer {{ font-size: 0.78rem; color: #aaa; margin-top: 1rem; }}
  </style>
</head>
<body>
  <div class="card">
    <div class="icon">🚫</div>
    <h1>Access Denied</h1>
    <p class="subtitle">Zero Trust Gateway blocked this request</p>
    <span class="badge">🔒 Policy Enforcement Active</span>
    <div class="details">
      <p>👤 User: <span>{user}</span></p>
      <p>🏷️ Role: <span>{role}</span></p>
      <p>📁 Resource: <span>{resource}</span></p>
      <p>🕐 Time: <span>{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</span></p>
    </div>
    <div class="reason">⚠️ Reason: {reason}</div>
    <div class="footer">This access attempt has been logged and monitored.<br>Zero Trust Architecture — Enterprise Network Security</div>
  </div>
</body>
</html>"""


@app.route("/", methods=["GET"])
def home():
    return jsonify({
        "message": "Zero Trust Gateway is running",
        "flows": [
            "POST /login -> returns pending MFA flow",
            "POST /mfa/setup -> returns QR for authenticator app",
            "POST /mfa/complete -> verifies OTP and sets session cookie",
            "GET /hr-app, /finance-app, /dev-app -> protected access via gateway",
        ],
    })


@app.route("/login", methods=["POST"])
def login():
    data = request.get_json(force=True)
    username = (data.get("username") or "").strip()
    password = data.get("password") or ""

    if not username or not password:
        return jsonify({"error": "username and password are required"}), 400

    token_url = "http://localhost:8080/realms/enterprise-zt/protocol/openid-connect/token"
    resp = requests.post(
        token_url,
        data={
            "client_id": "zt-gateway",
            "client_secret": "zt-gateway-secret",
            "grant_type": "password",
            "username": username,
            "password": password,
            "scope": "openid",
        },
        timeout=10,
    )

    if resp.status_code != 200:
        try:
            error = resp.json().get("error_description", "Login failed")
        except Exception:
            error = "Login failed"
        log_event("LOGIN_FAILED", user=username, reason=error)
        return jsonify({"error": error}), 401

    token_data = resp.json()
    access_token = token_data["access_token"]

    from jose import jwt as jose_jwt
    claims = jose_jwt.get_unverified_claims(access_token)
    role = claims.get("role")
    if not role:
        realm_roles = claims.get("realm_access", {}).get("roles", [])
        system_roles = {"offline_access", "uma_authorization", "default-roles-enterprise-zt"}
        app_roles = [r for r in realm_roles if r not in system_roles]
        role = app_roles[0] if app_roles else "HR"

    flow_id = secrets.token_urlsafe(24)
    PENDING_LOGINS[flow_id] = {
        "user": username,
        "role": role,
        "access_token": access_token,
    }
    log_event("LOGIN_SUCCESS", user=username, role=role, resource="/login")

    return jsonify({
        "username": username,
        "role": role,
        "flow_id": flow_id,
        "next_step": "mfa_required",
        "message": "Primary authentication passed. Complete MFA to continue.",
    }), 200


@app.route("/mfa/setup", methods=["POST"])
def mfa_setup():
    data = request.get_json(force=True)
    flow_id = data.get("flow_id")
    pending = PENDING_LOGINS.get(flow_id)
    if not pending:
        return jsonify({"error": "invalid or expired login flow"}), 401

    resp = requests.post(
        f"{MFA_SERVICE_URL}/mfa/setup",
        json={"username": pending["user"]},
        timeout=10,
    )
    resp.raise_for_status()
    body = resp.json()
    qr = body.get("qr_code", "")
    if qr and not qr.startswith("data:image"):
        qr = f"data:image/png;base64,{qr}"

    return jsonify({
        "username": pending["user"],
        "role": pending["role"],
        "flow_id": flow_id,
        "uri": body.get("uri"),
        "secret": body.get("secret"),
        "qr_code": qr,
        "message": body.get("message", "Scan the QR code and enter the 6-digit OTP."),
    }), 200


@app.route("/mfa/complete", methods=["POST"])
def mfa_complete():
    data = request.get_json(force=True)
    flow_id = data.get("flow_id")
    otp = str(data.get("otp", "")).strip()
    pending = PENDING_LOGINS.get(flow_id)
    if not pending:
        return jsonify({"error": "invalid or expired login flow"}), 401
    if not otp:
        return jsonify({"error": "otp is required"}), 400

    verify_resp = requests.post(
        f"{MFA_SERVICE_URL}/mfa/verify",
        json={"username": pending["user"], "otp": otp},
        timeout=10,
    )
    if verify_resp.status_code != 200:
        reason = verify_resp.json().get("reason", "invalid OTP")
        log_event("MFA_FAILED", user=pending["user"], role=pending["role"], resource="/mfa", reason=reason)
        return jsonify({"error": reason}), 401

    session_id = secrets.token_urlsafe(32)
    ACTIVE_SESSIONS[session_id] = {
        "user": pending["user"],
        "role": pending["role"],
        "mfa": True,
        "access_token": pending["access_token"],
    }
    redirect_path = ROLE_ROUTES.get(pending["role"], "/hr-app")
    user = pending["user"]
    role = pending["role"]
    PENDING_LOGINS.pop(flow_id, None)
    log_event("MFA_SUCCESS", user=user, role=role, resource=redirect_path)

    response = make_response(jsonify({
        "verified": True,
        "redirect": redirect_path,
        "message": "MFA verified. Access granted.",
    }))
    response.set_cookie("zt_session", session_id, httponly=True, samesite="Lax")
    return response


@app.route("/logout", methods=["POST"])
def logout():
    session_id = request.cookies.get("zt_session") or request.headers.get("X-Session-Id")
    if session_id:
        ACTIVE_SESSIONS.pop(session_id, None)
    response = make_response(jsonify({"message": "logged out"}))
    response.set_cookie("zt_session", "", expires=0)
    return response


@app.route("/<path:path>", methods=["GET", "POST"])
def gateway(path):
    resource = "/" + path
    action = request.method
    user_data = get_user_identity(request)

    if not user_data:
        log_event("ACCESS_DENIED", resource=resource, reason="missing or invalid token/session")
        return Response(
            denied_page("unknown", "unknown", resource, "missing or invalid token/session"),
            status=401,
            content_type="text/html",
        )

    try:
        decision = call_policy_engine(user_data, resource, action)
    except Exception as exc:
        return jsonify({"error": "policy engine unavailable", "details": str(exc)}), 500

    if decision.get("decision") != "allow":
        log_event(
            "ACCESS_DENIED",
            user=user_data["user"],
            role=user_data["role"],
            resource=resource,
            reason=decision.get("reason"),
        )
        return Response(
            denied_page(user_data["user"], user_data["role"], resource, decision.get("reason", "denied")),
            status=403,
            content_type="text/html",
        )

    service_url = get_service_url(resource)
    if not service_url:
        return Response(
            denied_page(user_data["user"], user_data["role"], resource, "unknown service route"),
            status=404,
            content_type="text/html",
        )

    log_event("ACCESS_GRANTED", user=user_data["user"], role=user_data["role"], resource=resource)
    try:
        return forward_to_service(service_url, resource, request, user_data)
    except Exception as exc:
        return jsonify({"error": "service unavailable", "details": str(exc)}), 502


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)