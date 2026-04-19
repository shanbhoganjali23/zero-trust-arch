from flask import Flask, request, jsonify, Response
from datetime import datetime
from pathlib import Path
import requests

app = Flask(__name__)

POLICY_ENGINE_URL = "http://127.0.0.1:5005/evaluate"
BASE_DIR = Path(__file__).resolve().parent.parent
SECURITY_LOG_FILE = BASE_DIR / "security_events_tracking.txt"

SERVICE_MAP = {
    "/hr-app": "http://127.0.0.1:5001",
    "/finance-app": "http://127.0.0.1:5002",
    "/dev-app": "http://127.0.0.1:5003",
}

def mock_validate_token(req):
    username = req.headers.get("X-User") or req.args.get("user")
    role = req.headers.get("X-Role") or req.args.get("role")
    mfa = req.headers.get("X-MFA") or req.args.get("mfa", "false")
    mfa = str(mfa).lower() == "true"
    if not username or not role:
        return None
    return {"user": username, "role": role, "mfa": mfa}

def validate_bearer_token(req):
    auth_header = req.headers.get("Authorization", "")
    if not auth_header.startswith("Bearer "):
        return None
    token = auth_header.split(" ", 1)[1].strip()
    try:
        from jose import jwt as jose_jwt
        payload = jose_jwt.get_unverified_claims(token)
        username = (
            payload.get("preferred_username")
            or payload.get("username")
            or payload.get("sub")
        )
        role = payload.get("role")
        if not role:
            realm_roles = payload.get("realm_access", {}).get("roles", [])
            SYSTEM_ROLES = {"offline_access", "uma_authorization", "default-roles-enterprise-zt"}
            app_roles = [r for r in realm_roles if r not in SYSTEM_ROLES]
            role = app_roles[0] if app_roles else None
        mfa = bool(payload.get("mfa_verified", True))
        if not username or not role:
            return None
        return {"user": username, "role": role, "mfa": mfa}
    except Exception as e:
        print(f"[Gateway] Token decode failed: {e}")
        return None

def get_user_identity(req):
    token_user = validate_bearer_token(req)
    if token_user:
        return token_user
    return mock_validate_token(req)

def call_policy_engine(user_data, resource, action):
    payload = {
        "user": user_data["user"],
        "role": user_data["role"],
        "resource": resource,
        "action": action,
        "mfa": user_data["mfa"],
    }
    print(f"[Gateway] Sending to policy engine: {payload}")
    response = requests.post(POLICY_ENGINE_URL, json=payload, timeout=3)
    response.raise_for_status()
    return response.json()

def get_service_url(resource):
    for prefix, url in SERVICE_MAP.items():
        if resource.startswith(prefix):
            return url
    return None

def forward_to_service(service_url, resource, original_request):
    target_url = service_url + resource
    print(f"[Gateway] Forwarding to: {target_url}")
    resp = requests.request(
        method=original_request.method,
        url=target_url,
        headers={k: v for k, v in original_request.headers if k != "Authorization"},
        params=original_request.args,
        data=original_request.get_data(),
        timeout=5,
        allow_redirects=True,
    )
    return Response(
        resp.content,
        status=resp.status_code,
        content_type=resp.headers.get("Content-Type", "text/html"),
    )

def write_log(event_type, user_data, resource, reason=None):
    with open(SECURITY_LOG_FILE, "a") as f:
        line = (
            f"{datetime.now()} {event_type} "
            f"USER={user_data['user']} ROLE={user_data['role']} RESOURCE={resource}"
        )
        if reason:
            line += f" REASON={reason}"
        f.write(line + "\n")

@app.route("/", methods=["GET"])
def home():
    return jsonify({
        "message": "Zero Trust Gateway is running",
        "test_examples": [
            "/hr-app?user=alice_hr&role=HR&mfa=true",
            "/dev-app?user=charlie_dev&role=Developer&mfa=true",
            "/finance-app?user=bob_finance&role=Finance&mfa=true",
        ],
    })

@app.route("/<path:path>", methods=["GET", "POST"])
def gateway(path):
    resource = "/" + path
    action = request.method

    print(f"[{datetime.now()}] [Gateway] Incoming request: {resource}")

    user_data = get_user_identity(request)
    if not user_data:
        print("[Gateway] Authentication failed: missing user or role")
        return jsonify({"error": "missing or invalid token"}), 401

    print(f"[Gateway] Authenticated user: {user_data}")

    try:
        decision = call_policy_engine(user_data, resource, action)
    except Exception as e:
        print(f"[Gateway] Policy engine error: {e}")
        return jsonify({"error": "policy engine unavailable", "details": str(e)}), 500

    print(f"[Gateway] Policy decision: {decision}")

    if decision["decision"] != "allow":
        print(f"[Gateway] Access DENIED for user={user_data['user']} resource={resource}")
        write_log("ACCESS_DENIED", user_data, resource, decision.get("reason"))
        return jsonify({
            "status": "denied",
            "user": user_data["user"],
            "role": user_data["role"],
            "resource": resource,
            "reason": decision.get("reason", "no reason provided"),
        }), 403

    service_url = get_service_url(resource)
    if not service_url:
        return jsonify({"status": "denied", "reason": "unknown service route"}), 404

    print(f"[Gateway] Access GRANTED for user={user_data['user']} resource={resource}")
    write_log("ACCESS_GRANTED", user_data, resource)

    try:
        return forward_to_service(service_url, resource, request)
    except Exception as e:
        print(f"[Gateway] Error forwarding to service: {e}")
        return jsonify({"error": "service unavailable", "details": str(e)}), 502

if __name__ == "__main__":
    app.run(port=5000, debug=True)
