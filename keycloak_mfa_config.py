#!/usr/bin/env python3
"""
keycloak_mfa_config.py
Member 1 — Script to enforce MFA via Keycloak Admin REST API

This script:
  1. Enables CONFIGURE_TOTP as a DEFAULT required action for new users
  2. Enforces CONFIGURE_TOTP on selected existing users
"""

import json
import urllib.error
import urllib.parse
import urllib.request

KEYCLOAK_URL = "http://localhost:8080"
ADMIN_USER = "admin"
ADMIN_PASSWORD = "admin"
REALM = "enterprise-zt"
ENFORCE_MFA_FOR = ["alice_hr", "bob_finance", "charlie_dev", "admin_user"]


def get_admin_token() -> str:
    data = urllib.parse.urlencode(
        {
            "client_id": "admin-cli",
            "username": ADMIN_USER,
            "password": ADMIN_PASSWORD,
            "grant_type": "password",
        }
    ).encode()
    req = urllib.request.Request(
        f"{KEYCLOAK_URL}/realms/master/protocol/openid-connect/token",
        data=data,
        headers={"Content-Type": "application/x-www-form-urlencoded"},
    )
    with urllib.request.urlopen(req, timeout=10) as resp:
        return json.loads(resp.read())["access_token"]


def _req(path: str, method: str = "GET", body=None, token: str | None = None):
    url = f"{KEYCLOAK_URL}/admin/realms/{REALM}{path}"
    data = json.dumps(body).encode() if body is not None else None
    headers = {"Content-Type": "application/json"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    req = urllib.request.Request(url, data=data, headers=headers, method=method)
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            raw = resp.read()
            return json.loads(raw) if raw else {}
    except urllib.error.HTTPError as exc:
        if exc.code in (201, 204):
            return {}
        body_text = exc.read().decode()
        raise RuntimeError(f"HTTP {exc.code} {method} {url} - {body_text}") from exc


def enable_default_mfa(token: str) -> None:
    print("[*] Enabling CONFIGURE_TOTP as default required action...")
    _req(
        "/authentication/required-actions/CONFIGURE_TOTP",
        method="PUT",
        body={
            "alias": "CONFIGURE_TOTP",
            "name": "Configure OTP",
            "providerId": "CONFIGURE_TOTP",
            "enabled": True,
            "defaultAction": True,
            "priority": 10,
        },
        token=token,
    )
    print("[OK] CONFIGURE_TOTP is now default for new users.")


def enforce_mfa_on_users(token: str) -> None:
    users = _req("/users?max=200", token=token)
    user_map = {u["username"]: u["id"] for u in users}

    for username in ENFORCE_MFA_FOR:
        uid = user_map.get(username)
        if not uid:
            print(f"[WARN] User not found: {username} - skipping")
            continue

        user_detail = _req(f"/users/{uid}", token=token)
        existing = list(user_detail.get("requiredActions", []))
        if "CONFIGURE_TOTP" in existing:
            print(f"[=] MFA already required for: {username}")
            continue

        existing.append("CONFIGURE_TOTP")
        user_detail["requiredActions"] = existing
        _req(f"/users/{uid}", method="PUT", body=user_detail, token=token)
        print(f"[OK] MFA required action added for: {username}")


def verify_mfa_config(token: str) -> None:
    actions = _req("/authentication/required-actions", token=token)
    for action in actions:
        if action.get("alias") == "CONFIGURE_TOTP":
            print("\n[OK] CONFIGURE_TOTP status:")
            print(f"    enabled       : {action.get('enabled')}")
            print(f"    defaultAction : {action.get('defaultAction')}")
            return
    print("[WARN] CONFIGURE_TOTP not found in required actions list.")


if __name__ == "__main__":
    token = get_admin_token()
    enable_default_mfa(token)
    enforce_mfa_on_users(token)
    verify_mfa_config(token)
    print("\n[OK] MFA configuration complete.")
