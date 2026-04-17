from flask import Flask, request, jsonify

app = Flask(__name__)


def evaluate_policy(role: str, resource: str, mfa: bool) -> dict:
    # Unknown or empty resource
    if not resource or resource == "/":
        return {"decision": "deny", "reason": "no resource specified"}

    # Admin can access everything, but require MFA
    if role == "Admin":
        if not mfa:
            return {"decision": "deny", "reason": "admin access requires MFA"}
        return {"decision": "allow", "reason": "admin access allowed"}

    # HR rules
    if role == "HR":
        if resource.startswith("/hr-app"):
            return {"decision": "allow", "reason": "HR allowed for HR resource"}
        return {"decision": "deny", "reason": "HR cannot access this resource"}

    # Finance rules
    if role == "Finance":
        if not mfa and resource.startswith("/finance-app"):
            return {"decision": "deny", "reason": "finance access requires MFA"}
        if resource.startswith("/finance-app"):
            return {"decision": "allow", "reason": "Finance allowed for finance resource"}
        return {"decision": "deny", "reason": "Finance cannot access this resource"}

    # Developer rules
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

    print(f"[Policy Engine] Request received: user={user}, role={role}, resource={resource}, action={action}, mfa={mfa}")

    result = evaluate_policy(role, resource, mfa)

    print(f"[Policy Engine] Decision: {result['decision']} | Reason: {result['reason']}")

    return jsonify(result), 200


if __name__ == "__main__":
    app.run(port=5005, debug=True)