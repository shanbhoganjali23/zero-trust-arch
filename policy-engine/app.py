from flask import Flask, request, jsonify
from datetime import datetime
from pathlib import Path

app = Flask(__name__)

BASE_DIR = Path(__file__).resolve().parent.parent
LOG_FILE = BASE_DIR / "security_events_tracking.txt"

TRUSTED_IP_PREFIXES = ["127.", "10.", "172.", "192.168."]


def is_trusted_ip(ip: str) -> bool:
    if not ip:
        return False
    return any(ip.startswith(prefix) for prefix in TRUSTED_IP_PREFIXES)


def evaluate_policy(role: str, resource: str, mfa: bool,
                    ip: str = "", device_id: str = "",
                    device_trust: str = "unknown") -> dict:

    if not resource or resource == "/":
        return {"decision": "deny", "reason": "no resource specified"}

    if not is_trusted_ip(ip):
        return {
            "decision": "deny",
            "reason": f"access denied from untrusted IP: {ip}"
        }

    if role == "Admin":
        if not mfa:
            return {"decision": "deny", "reason": "admin access requires MFA"}
        return {"decision": "allow", "reason": "admin access allowed"}

    if role == "HR":
        if resource.startswith("/hr-app"):
            return {"decision": "allow", "reason": "HR allowed for HR resource"}
        return {"decision": "deny", "reason": "HR cannot access this resource"}

    if role == "Finance":
        if not mfa:
            return {"decision": "deny", "reason": "finance access requires MFA"}
        if resource.startswith("/finance-app"):
            return {"decision": "allow", "reason": "Finance allowed for finance resource"}
        return {"decision": "deny", "reason": "Finance cannot access this resource"}

    if role == "Developer":
        if resource.startswith("/dev-app"):
            return {"decision": "allow", "reason": "Developer allowed for dev resource"}
        return {"decision": "deny", "reason": "Developer cannot access this resource"}

    if role == "SecurityAnalyst":
        if resource.startswith("/hr-app"):
            return {"decision": "allow", "reason": "SecurityAnalyst read access to HR"}
        return {"decision": "deny", "reason": "SecurityAnalyst cannot access this resource"}

    return {"decision": "deny", "reason": "unknown role or unauthorized access"}


@app.route("/evaluate", methods=["POST"])
def evaluate():
    data = request.get_json(force=True)

    user = data.get("user", "unknown")
    role = data.get("role", "")
    resource = data.get("resource", "")
    action = data.get("action", "GET")
    mfa = data.get("mfa", False)
    ip = data.get("ip_address", "")
    device_id = data.get("device_id", "")
    device_trust = data.get("device_trust", "unknown")

    print(f"[Policy Engine] Request: user={user}, role={role}, resource={resource}, "
          f"action={action}, mfa={mfa}, ip={ip}, device={device_id}, trust={device_trust}")

    result = evaluate_policy(role, resource, mfa, ip, device_id, device_trust)

    with open(LOG_FILE, "a", encoding="utf-8") as f:
        f.write(f"{datetime.now().isoformat()} EVENT=POLICY_DECISION "
                f"USER={user} ROLE={role} RESOURCE={resource} "
                f"IP={ip} DEVICE={device_id} MFA={mfa} "
                f"DECISION={result['decision']} REASON={result['reason']}\n")

    print(f"[Policy Engine] Decision: {result['decision']} | Reason: {result['reason']}")
    return jsonify(result), 200


if __name__ == "__main__":
    app.run(port=5005, debug=True)