from flask import Flask, request, jsonify, Response, make_response
from flask_cors import CORS
from datetime import datetime, timedelta
from pathlib import Path
from collections import defaultdict
from flask import Flask, request, jsonify, Response, make_response, redirect
import secrets
import threading
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
    "/admin-panel": "http://127.0.0.1:5004",
}

ROLE_ROUTES = {
    "HR": "/hr-app",
    "Finance": "/finance-app",
    "Developer": "/dev-app",
    "Admin": "/admin-panel",
    "SecurityAnalyst": "/hr-app",
}

# ---------------------------------------------------------------------------
# In-memory state (prototype — use Redis/DB in production)
# ---------------------------------------------------------------------------
PENDING_LOGINS = {}
ACTIVE_SESSIONS = {}

# Incident response: track failed login attempts per IP
# Structure: { ip: [timestamp, timestamp, ...] }
FAILED_LOGIN_ATTEMPTS = defaultdict(list)
LOCKED_IPS = {}  # ip -> unlock_time

# Thresholds
MAX_FAILURES = 3          # max failed attempts before lock
FAILURE_WINDOW = 120      # seconds — look at failures in last 2 minutes
LOCKOUT_DURATION = 300    # seconds — lock for 5 minutes

_lock = threading.Lock()


# ---------------------------------------------------------------------------
# Incident Response Helpers
# ---------------------------------------------------------------------------

def get_client_ip(req) -> str:
    """Extract real client IP, handling proxies."""
    forwarded = req.headers.get("X-Forwarded-For")
    if forwarded:
        return forwarded.split(",")[0].strip()
    return req.remote_addr or "unknown"


def is_ip_locked(ip: str) -> bool:
    """Check if an IP is currently locked out."""
    with _lock:
        if ip in LOCKED_IPS:
            if datetime.now() < LOCKED_IPS[ip]:
                return True
            else:
                # Lock expired
                del LOCKED_IPS[ip]
                FAILED_LOGIN_ATTEMPTS[ip] = []
    return False


def record_failed_login(ip: str, username: str):
    """Record a failed login attempt and lock IP if threshold exceeded."""
    now = datetime.now()
    cutoff = now - timedelta(seconds=FAILURE_WINDOW)

    with _lock:
        # Remove old attempts outside the window
        FAILED_LOGIN_ATTEMPTS[ip] = [
            t for t in FAILED_LOGIN_ATTEMPTS[ip] if t > cutoff
        ]
        FAILED_LOGIN_ATTEMPTS[ip].append(now)
        count = len(FAILED_LOGIN_ATTEMPTS[ip])

    log_event("LOGIN_FAILED", user=username, resource="/login",
              ip=ip, reason=f"invalid credentials (attempt {count}/{MAX_FAILURES})")

    if count >= MAX_FAILURES:
        unlock_time = now + timedelta(seconds=LOCKOUT_DURATION)
        with _lock:
            LOCKED_IPS[ip] = unlock_time
        log_event("INCIDENT_LOCKOUT", user=username, resource="/login",
                  ip=ip, reason=f"IP locked for {LOCKOUT_DURATION}s after {count} failed attempts")
        print(f"[Gateway] 🔒 INCIDENT: IP {ip} locked until {unlock_time.strftime('%H:%M:%S')}")


def clear_failed_attempts(ip: str):
    """Clear failed attempts after successful login."""
    with _lock:
        FAILED_LOGIN_ATTEMPTS[ip] = []


# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------

def log_event(event_type, user="unknown", role="unknown",
              resource="-", ip="unknown", reason=None, device=None):
    line = (
        f"{datetime.now().isoformat()} EVENT={event_type} "
        f"USER={user} ROLE={role} RESOURCE={resource} IP={ip}"
    )
    if device:
        line += f" DEVICE={device}"
    if reason:
        line += f" REASON={reason}"
    with open(SECURITY_LOG_FILE, "a", encoding="utf-8") as f:
        f.write(line + "\n")
    print(f"[Gateway] {line}")


# ---------------------------------------------------------------------------
# Token / Session validation
# ---------------------------------------------------------------------------

def validate_bearer_token(req):
    auth_header = req.headers.get("Authorization", "")
    if not auth_header.startswith("Bearer "):
        return None
    token = auth_header.split(" ", 1)[1].strip()
    try:
        from jose import jwt as jose_jwt
        payload = jose_jwt.get_unverified_claims(token)
        username = (payload.get("preferred_username")
                    or payload.get("username")
                    or payload.get("sub"))
        role = payload.get("role")
        if not role:
            realm_roles = payload.get("realm_access", {}).get("roles", [])
            system_roles = {"offline_access", "uma_authorization",
                            "default-roles-enterprise-zt"}
            app_roles = [r for r in realm_roles if r not in system_roles]
            role = app_roles[0] if app_roles else None
        if not username or not role:
            return None
        return {"user": username, "role": role, "mfa": True, "source": "bearer"}
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


def validate_mock_params(req):
    """Mock mode — read user/role from query params for testing."""
    username = req.args.get("user") or req.headers.get("X-User")
    role = req.args.get("role") or req.headers.get("X-Role")
    mfa = req.args.get("mfa", "false")
    mfa = str(mfa).lower() == "true"
    if not username or not role:
        return None
    return {"user": username, "role": role, "mfa": mfa, "source": "mock"}


def get_user_identity(req):
    return validate_bearer_token(req) or validate_demo_session(req)

# ---------------------------------------------------------------------------
# Policy engine call — now includes IP and device info
# ---------------------------------------------------------------------------

def call_policy_engine(user_data, resource, action, ip, device_id="unknown"):
    payload = {
        "user": user_data["user"],
        "role": user_data["role"],
        "resource": resource,
        "action": action,
        "mfa": user_data["mfa"],
        "ip_address": ip,
        "device_id": device_id,
        "device_trust": "known" if device_id and device_id != "unknown" else "unknown",
    }
    response = requests.post(POLICY_ENGINE_URL, json=payload, timeout=5)
    response.raise_for_status()
    return response.json()


# ---------------------------------------------------------------------------
# Service forwarding
# ---------------------------------------------------------------------------

def get_service_url(resource):
    for prefix, url in SERVICE_MAP.items():
        if resource.startswith(prefix):
            return url
    return None


def forward_to_service(service_url, resource, original_request, user_data):
    target_url = service_url + resource
    headers = {
        "X-From-Gateway": "true",
        "X-User": user_data["user"],
        "X-Role": user_data["role"],
        "X-MFA": "true" if user_data["mfa"] else "false",
    }
    content_type = original_request.headers.get("Content-Type")
    if content_type:
        headers["Content-Type"] = content_type

    resp = requests.request(
        method=original_request.method,
        url=target_url,
        headers=headers,
        data=original_request.get_data(),
        timeout=10,
        allow_redirects=True,
    )
    return Response(
        resp.content,
        status=resp.status_code,
        content_type=resp.headers.get("Content-Type", "text/html"),
    )


# ---------------------------------------------------------------------------
# Denied page
# ---------------------------------------------------------------------------

def denied_page(user, role, resource, reason, ip="unknown"):
    return f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>Access Denied</title>
  <style>
    * {{ box-sizing: border-box; margin: 0; padding: 0; }}
    body {{ font-family: 'Segoe UI', sans-serif; background: #fff0f0;
           display: flex; align-items: center; justify-content: center; min-height: 100vh; }}
    .card {{ background: white; border-radius: 16px; padding: 3rem; max-width: 520px;
             width: 90%; box-shadow: 0 4px 24px rgba(0,0,0,0.1); text-align: center; }}
    .icon {{ font-size: 4rem; margin-bottom: 1rem; }}
    h1 {{ color: #c62828; font-size: 1.8rem; margin-bottom: 0.5rem; }}
    .subtitle {{ color: #666; margin-bottom: 2rem; font-size: 0.95rem; }}
    .details {{ background: #fff5f5; border: 1px solid #ffcdd2; border-radius: 8px;
                padding: 1rem 1.5rem; text-align: left; margin-bottom: 1.5rem; }}
    .details p {{ font-size: 0.88rem; color: #555; margin-bottom: 0.4rem; }}
    .details p span {{ font-weight: 600; color: #1a1a2e; }}
    .reason {{ background: #fce4ec; border-radius: 8px; padding: 0.8rem 1.2rem;
               color: #c62828; font-size: 0.88rem; margin-bottom: 1.5rem; }}
    .badge {{ display: inline-block; background: #c62828; color: white;
              padding: 0.3rem 1rem; border-radius: 20px; font-size: 0.8rem; margin-bottom: 1.5rem; }}
    .footer {{ font-size: 0.78rem; color: #aaa; margin-top: 1rem; }}
  </style>
</head>
<body>
  <div class="card">
    <div class="icon">🚫</div>
    <h1>Access Denied</h1>
    <p class="subtitle">Zero Trust Gateway blocked this request</p>
    <span class="badge">🔒 Policy Enforcement Point Active</span>
    <div class="details">
      <p>👤 User: <span>{user}</span></p>
      <p>🏷️ Role: <span>{role}</span></p>
      <p>📁 Resource: <span>{resource}</span></p>
      <p>🌐 IP Address: <span>{ip}</span></p>
      <p>🕐 Time: <span>{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</span></p>
    </div>
    <div class="reason">⚠️ Reason: {reason}</div>
    <div class="footer">
      This access attempt has been logged and monitored.<br>
      Zero Trust Architecture — Enterprise Network Security
    </div>
  </div>
</body>
</html>"""


def lockout_page(ip, unlock_time):
    return f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>Account Locked</title>
  <style>
    * {{ box-sizing: border-box; margin: 0; padding: 0; }}
    body {{ font-family: 'Segoe UI', sans-serif; background: #fff3e0;
           display: flex; align-items: center; justify-content: center; min-height: 100vh; }}
    .card {{ background: white; border-radius: 16px; padding: 3rem; max-width: 500px;
             width: 90%; box-shadow: 0 4px 24px rgba(0,0,0,0.1); text-align: center; }}
    .icon {{ font-size: 4rem; margin-bottom: 1rem; }}
    h1 {{ color: #e65100; font-size: 1.8rem; margin-bottom: 0.5rem; }}
    .subtitle {{ color: #666; margin-bottom: 2rem; font-size: 0.95rem; }}
    .info {{ background: #fff3e0; border: 1px solid #ffe0b2; border-radius: 8px;
             padding: 1rem 1.5rem; margin-bottom: 1.5rem; font-size: 0.9rem; color: #555; }}
    .info span {{ font-weight: 600; color: #e65100; }}
    .footer {{ font-size: 0.78rem; color: #aaa; margin-top: 1rem; }}
  </style>
</head>
<body>
  <div class="card">
    <div class="icon">🔒</div>
    <h1>IP Address Locked</h1>
    <p class="subtitle">Too many failed login attempts detected</p>
    <div class="info">
      <p>Your IP address <span>{ip}</span> has been temporarily locked due to
      {MAX_FAILURES} failed login attempts.</p>
      <br>
      <p>Locked until: <span>{unlock_time.strftime('%H:%M:%S')}</span></p>
      <br>
      <p>Please wait {LOCKOUT_DURATION // 60} minutes before trying again.</p>
    </div>
    <div class="footer">
      This incident has been logged and the security team has been notified.<br>
      Zero Trust Architecture — Incident Response Active
    </div>
  </div>
</body>
</html>"""


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

@app.route("/", methods=["GET"])
def home():
    return jsonify({
        "message": "Zero Trust Gateway is running",
        "version": "2.0 — with incident response and device trust",
        "flows": [
            "POST /login -> Keycloak auth, returns flow_id",
            "POST /mfa/setup -> QR code generation",
            "POST /mfa/complete -> OTP verification, sets session cookie",
            "GET /hr-app, /finance-app, /dev-app -> protected via gateway",
            "GET /monitoring -> security dashboard",
        ],
    })


@app.route("/login", methods=["POST"])
def login():
    ip = get_client_ip(request)

    # Check if IP is locked out (incident response)
    if is_ip_locked(ip):
        unlock_time = LOCKED_IPS.get(ip, datetime.now())
        log_event("LOCKOUT_BLOCKED", resource="/login", ip=ip,
                  reason="IP is locked due to repeated failures")
        return Response(
            lockout_page(ip, unlock_time),
            status=429,
            content_type="text/html"
        )

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
        record_failed_login(ip, username)
        return jsonify({"error": error}), 401

    # Successful login — clear failed attempts
    clear_failed_attempts(ip)

    token_data = resp.json()
    access_token = token_data["access_token"]

    from jose import jwt as jose_jwt
    claims = jose_jwt.get_unverified_claims(access_token)
    role = claims.get("role")
    if not role:
        realm_roles = claims.get("realm_access", {}).get("roles", [])
        system_roles = {"offline_access", "uma_authorization",
                        "default-roles-enterprise-zt"}
        app_roles = [r for r in realm_roles if r not in system_roles]
        role = app_roles[0] if app_roles else "HR"

    flow_id = secrets.token_urlsafe(24)
    PENDING_LOGINS[flow_id] = {
        "user": username,
        "role": role,
        "access_token": access_token,
        "ip": ip,
    }
    log_event("LOGIN_SUCCESS", user=username, role=role, resource="/login", ip=ip)

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
    ip = get_client_ip(request)
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
        log_event("MFA_FAILED", user=pending["user"], role=pending["role"],
                  resource="/mfa", ip=ip, reason=reason)
        return jsonify({"error": reason}), 401

    session_id = secrets.token_urlsafe(32)
    ACTIVE_SESSIONS[session_id] = {
        "user": pending["user"],
        "role": pending["role"],
        "mfa": True,
        "access_token": pending["access_token"],
        "ip": ip,
    }
    redirect_path = ROLE_ROUTES.get(pending["role"], "/hr-app")
    user = pending["user"]
    role = pending["role"]
    PENDING_LOGINS.pop(flow_id, None)
    log_event("MFA_SUCCESS", user=user, role=role, resource=redirect_path, ip=ip)

    response = make_response(jsonify({
        "verified": True,
        "redirect": redirect_path,
        "message": "MFA verified. Access granted.",
    }))

    response.set_cookie(
        "zt_session",
        session_id,
        httponly=True,
        samesite="Lax",
        path="/"
    )  
    return response


@app.route("/monitoring", methods=["GET"])
def monitoring():
    """Simple monitoring dashboard — reads and displays the security log."""
    try:
        with open(SECURITY_LOG_FILE, "r", encoding="utf-8") as f:
            lines = f.readlines()
    except FileNotFoundError:
        lines = []

    # Parse last 100 events
    events = []
    for line in lines[-100:]:
        line = line.strip()
        if not line:
            continue
        events.append(line)

    events_html = ""
    for e in reversed(events):
        color = "#e8f5e9"
        if "DENIED" in e or "FAILED" in e or "LOCKOUT" in e:
            color = "#fce4ec"
        elif "GRANTED" in e or "SUCCESS" in e:
            color = "#e8f5e9"
        elif "INCIDENT" in e:
            color = "#fff3e0"
        events_html += f'<div style="background:{color}; padding:0.5rem 1rem; border-radius:6px; margin-bottom:0.4rem; font-family:monospace; font-size:0.82rem; word-break:break-all;">{e}</div>'

    # Count stats
    total = len(events)
    granted = sum(1 for e in events if "GRANTED" in e or "LOGIN_SUCCESS" in e or "MFA_SUCCESS" in e)
    denied = sum(1 for e in events if "DENIED" in e or "FAILED" in e)
    incidents = sum(1 for e in events if "INCIDENT" in e or "LOCKOUT" in e)

    return Response(f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta http-equiv="refresh" content="10">
  <title>Security Monitoring Dashboard</title>
  <style>
    * {{ box-sizing: border-box; margin: 0; padding: 0; }}
    body {{ font-family: 'Segoe UI', sans-serif; background: #f0f4ff; color: #1a1a2e; }}
    .topbar {{ background: #1a1a2e; color: white; padding: 1rem 2rem;
               display: flex; justify-content: space-between; align-items: center; }}
    .topbar h1 {{ font-size: 1.2rem; }}
    .badge {{ background: #4caf50; color: white; padding: 0.2rem 0.7rem;
              border-radius: 20px; font-size: 0.8rem; }}
    .container {{ max-width: 1100px; margin: 2rem auto; padding: 0 1rem; }}
    .stats {{ display: grid; grid-template-columns: repeat(4, 1fr); gap: 1rem; margin-bottom: 1.5rem; }}
    .stat {{ background: white; border-radius: 12px; padding: 1.2rem 1.5rem;
             box-shadow: 0 2px 8px rgba(0,0,0,0.07); text-align: center; }}
    .stat .num {{ font-size: 2rem; font-weight: bold; }}
    .stat .label {{ font-size: 0.82rem; color: #666; margin-top: 0.2rem; }}
    .green {{ color: #2e7d32; }}
    .red {{ color: #c62828; }}
    .orange {{ color: #e65100; }}
    .blue {{ color: #1565c0; }}
    .panel {{ background: white; border-radius: 12px; padding: 1.5rem 2rem;
              box-shadow: 0 2px 8px rgba(0,0,0,0.07); }}
    .panel h2 {{ margin-bottom: 1rem; font-size: 1.1rem; }}
    .events {{ max-height: 500px; overflow-y: auto; }}
    .note {{ font-size: 0.78rem; color: #999; margin-top: 0.5rem; }}
  </style>
</head>
<body>
  <div class="topbar">
    <h1>🛡️ Zero Trust Security Monitoring Dashboard</h1>
    <span class="badge">🔴 Live — auto-refreshes every 10s</span>
  </div>
  <div class="container">
    <div class="stats">
      <div class="stat"><div class="num blue">{total}</div><div class="label">Total Events</div></div>
      <div class="stat"><div class="num green">{granted}</div><div class="label">Access Granted</div></div>
      <div class="stat"><div class="num red">{denied}</div><div class="label">Access Denied / Failed</div></div>
      <div class="stat"><div class="num orange">{incidents}</div><div class="label">Incidents / Lockouts</div></div>
    </div>
    <div class="panel">
      <h2>📋 Recent Security Events (last 100, newest first)</h2>
      <div class="events">
        {events_html if events_html else '<p style="color:#999; padding:1rem;">No events logged yet. Start testing to see events here.</p>'}
      </div>
      <p class="note">🟢 Green = granted/success &nbsp; 🔴 Red = denied/failed &nbsp; 🟡 Orange = incident/lockout</p>
    </div>
  </div>
</body>
</html>""", content_type="text/html")


@app.route("/<path:path>", methods=["GET", "POST"])
def gateway(path):
    resource = "/" + path
    action = request.method
    ip = get_client_ip(request)
    device_id = request.headers.get("X-Device-Id", "unknown")

    user_data = get_user_identity(request)

    if not user_data:
        log_event("ACCESS_DENIED", resource=resource, ip=ip,
                  reason="missing or invalid token/session")
        return Response(
            denied_page("unknown", "unknown", resource,
                        "missing or invalid token/session", ip),
            status=401,
            content_type="text/html",
        )

    try:
        decision = call_policy_engine(user_data, resource, action, ip, device_id)
    except Exception as exc:
        return jsonify({"error": "policy engine unavailable",
                        "details": str(exc)}), 500

    if decision.get("decision") != "allow":
        log_event("ACCESS_DENIED", user=user_data["user"], role=user_data["role"],
                  resource=resource, ip=ip, device=device_id,
                  reason=decision.get("reason"))
        return Response(
            denied_page(user_data["user"], user_data["role"], resource,
                        decision.get("reason", "denied"), ip),
            status=403,
            content_type="text/html",
        )

    service_url = get_service_url(resource)
    if not service_url:
        return Response(
            denied_page(user_data["user"], user_data["role"], resource,
                        "unknown service route", ip),
            status=404,
            content_type="text/html",
        )

    log_event("ACCESS_GRANTED", user=user_data["user"], role=user_data["role"],
              resource=resource, ip=ip, device=device_id)
    try:
        return forward_to_service(service_url, resource, request, user_data)
    except Exception as exc:
        return jsonify({"error": "service unavailable",
                        "details": str(exc)}), 502

@app.route("/logout", methods=["GET", "POST"])
def logout():
    session_id = request.cookies.get("zt_session") or request.headers.get("X-Session-Id")

    if session_id:
        session = ACTIVE_SESSIONS.pop(session_id, {})
        log_event(
            "LOGOUT",
            user=session.get("user", "unknown"),
            role=session.get("role", "unknown"),
            ip=get_client_ip(request)
        )

    if request.method == "GET":
        response = redirect("http://localhost:5050")
    else:
        response = make_response(jsonify({"message": "logged out"}))

    response.delete_cookie("zt_session", path="/")
    return response

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
