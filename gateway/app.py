from flask import Flask, request, jsonify
from datetime import datetime
from pathlib import Path
import jwt
import requests

app = Flask(__name__)

POLICY_ENGINE_URL = "http://127.0.0.1:5005/evaluate"
BASE_DIR= Path(__file__).resolve().parent.parent
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

    return {
        "user": username,
        "role": role,
        "mfa": mfa
    }

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
        "mfa": user_data["mfa"]
    }

    print(f"[Gateway] Sending to policy engine: {payload}")

    response = requests.post(POLICY_ENGINE_URL, json=payload, timeout=3)
    response.raise_for_status()
    return response.json()


def get_service_name(resource):
    for prefix, service_name in SERVICE_MAP.items():
        if resource.startswith(prefix):
            return service_name
    return None


def simulate_service_response(resource, user_data):
    service_name = get_service_name(resource)

    if not service_name:
        return None

    return {
        "message": f"Request forwarded to {service_name}",
        "requested_by": user_data["user"],
        "resource": resource
    }


@app.route("/", methods=["GET"])
def home():
    return jsonify({
        "message": "Zero Trust Gateway is running",
        "test_examples": [
            "/hr?user=alice&role=HR&mfa=true",
            "/dev?user=charlie&role=Developer&mfa=true",
            "/finance?user=bob&role=Finance&mfa=true"
        ]
    })

def validate_bearer_token(req):
    auth_header = req.headers.get("Authorization", "")
    if not auth_header.startswith("Bearer "):
        return None

    token = auth_header.split(" ", 1)[1].strip()

    try:
        # Temporary decode without signature verification
        # Replace later with Member 1's real validator
        payload = jwt.decode(token, options={"verify_signature": False})

        username = (
            payload.get("preferred_username")
            or payload.get("username")
            or payload.get("sub")
        )

        role = None
        realm_access = payload.get("realm_access", {})
        roles = realm_access.get("roles", [])

        if "Admin" in roles:
            role = "Admin"
        elif "HR" in roles:
            role = "HR"
        elif "Finance" in roles:
            role = "Finance"
        elif "Developer" in roles:
            role = "Developer"

        # If Member 1 stores MFA explicitly, use it.
        # Otherwise default to True for now.
        mfa = payload.get("mfa_verified", True)

        if not username or not role:
            return None

        return {
            "user": username,
            "role": role,
            "mfa": bool(mfa)
        }

    except Exception as e:
        print(f"[Gateway] Token validation failed: {e}")
        return None


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
        with open(SECURITY_LOG_FILE, "a") as f:
            f.write(f"{datetime.now()} ACCESS_GRANTED USER={user_data['user']} ROLE={user_data['role']} RESOURCE={resource}\n")
    except Exception as e:
        print(f"[Gateway] Policy engine error: {e}")
        return jsonify({
            "error": "policy engine unavailable",
            "details": str(e)
        }), 500

    print(f"[Gateway] Policy decision: {decision}")

    if decision["decision"] != "allow":
        print(f"[Gateway] Access denied for user={user_data['user']} resource={resource}")
        with open(SECURITY_LOG_FILE, "a") as f:
            f.write(f"{datetime.now()} ACCESS_DENIED USER={user_data['user']} ROLE={user_data['role']} RESOURCE={resource} REASON={decision.get('reason')}\n")        
            return jsonify({
            "status": "denied",
            "user": user_data["user"],
            "role": user_data["role"],
            "resource": resource,
            "reason": decision.get("reason", "no reason provided")
        }), 403

    service_response = simulate_service_response(resource, user_data)

    if not service_response:
        print(f"[Gateway] Unknown service route: {resource}")
        return jsonify({
            "status": "denied",
            "reason": "unknown service route"
        }), 404

    print(f"[Gateway] Access granted for user={user_data['user']} resource={resource}")

    return jsonify({
        "status": "allowed",
        "user": user_data["user"],
        "role": user_data["role"],
        "resource": resource,
        "decision_reason": decision.get("reason"),
        "service_response": service_response
    }), 200


if __name__ == "__main__":
    app.run(port=5000, debug=True)