from flask import Flask, request, jsonify
from datetime import datetime
from pathlib import Path

app = Flask(__name__)

BASE_DIR = Path(__file__).resolve().parent.parent
LOG_FILE = BASE_DIR / "security_events_tracking.txt"


def evaluate_policy(role: str, resource: str, mfa: bool) -> dict:
    if not resource or resource == "/":
        return {"decision": "deny", "reason": "no resource specified"}

    if role == "Admin":
        if not mfa:
            return {"decision": "deny", "reason": "admin access requires MFA"}
        return {"decision": "allow", "reason": "admin access allowed"}

    if role == "HR":
        if resource.startswith("/hr-app"):
            return {"decision": "allow", "reason": "HR allowed for HR resource"}
        return {"decision": "deny", "reason": "HR cannot access this resource"}

    if role == "Finance":
        if not mfa and resource.startswith("/finance-app"):
            return {"decision": "deny", "reason": "finance access requires MFA"}
        if resource.startswith("/finance-app"):
            return {"decision": "allow", "reason": "Finance allowed for finance resource"}
        return {"decision": "deny", "reason": "Finance cannot access this resource"}

    if role == "Developer":
        if resource.startswith("/dev-app"):
            return {"decision": "allow", "reason": "Developer allowed for dev resource"}
        return {"decision": "deny", "reason": "Developer cannot access this resource"}

    return {"decision": "deny", "reason": "unknown role or unauthorized access"}


@app.route("/evaluate", methods=["POST"])
def evaluate():
    data = request.get_json(force=True)

    user = data.get("user", "unknown")
    role = data.get("role", "")
    resource = data.get("resource", "")
    action = data.get("action", "GET")
    mfa = data.get("mfa", False)

    print(f"[Policy Engine] Request: user={user}, role={role}, resource={resource}, action={action}, mfa={mfa}")

    result = evaluate_policy(role, resource, mfa)

    # Write to shared log file at project root
    with open(LOG_FILE, "a") as f:
        f.write(f"{datetime.now()} ROLE={role} RESOURCE={resource} DECISION={result['decision']}\n")

    print(f"[Policy Engine] Decision: {result['decision']} | Reason: {result['reason']}")

    return jsonify(result), 200


if __name__ == "__main__":
    app.run(port=5005, debug=True)
