#!/usr/bin/env python3
"""
keycloak_setup.py
Member 1 — Identity Provider Setup Script

This script can either:
  - start Keycloak directly with `docker run`, or
  - verify an already-running Keycloak instance started by docker compose.

It also prints the OIDC endpoints that Member 2 needs.
"""

import json
import os
import subprocess
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

KEYCLOAK_PORT = 8080
KEYCLOAK_ADMIN = "admin"
KEYCLOAK_PASS = "admin"
REALM = "enterprise-zt"
CLIENT_ID = "zt-gateway"
CLIENT_SECRET = "zt-gateway-secret"
KEYCLOAK_URL = f"http://localhost:{KEYCLOAK_PORT}"
CONTAINER_NAME = "keycloak-zt"


def _realm_path() -> str:
    return str((Path(__file__).resolve().parent / "enterprise-zt-realm.json").resolve())


def _http_get(url: str, timeout: int = 3):
    return urllib.request.urlopen(url, timeout=timeout)


def is_keycloak_ready() -> bool:
    try:
        with _http_get(f"{KEYCLOAK_URL}/realms/master"):
            return True
    except Exception:
        return False


def wait_for_keycloak(timeout: int = 90) -> None:
    deadline = time.time() + timeout
    while time.time() < deadline:
        if is_keycloak_ready():
            print("[OK] Keycloak is ready.")
            return
        sys.stdout.write(".")
        sys.stdout.flush()
        time.sleep(3)
    raise SystemExit("\n[ERROR] Keycloak did not start in time. Check Docker logs.")


def start_keycloak_if_needed() -> None:
    if is_keycloak_ready():
        print("[OK] Keycloak already reachable on localhost:8080.")
        return

    print("[*] Checking for existing Keycloak container...")
    result = subprocess.run(
        ["docker", "ps", "--filter", f"name={CONTAINER_NAME}", "--format", "{{.Names}}"],
        capture_output=True,
        text=True,
        check=False,
    )
    if CONTAINER_NAME in result.stdout:
        print("[*] Container exists; waiting for Keycloak to become ready...")
        wait_for_keycloak()
        return

    realm_path = _realm_path()
    if not os.path.exists(realm_path):
        raise SystemExit(f"[ERROR] Realm file not found: {realm_path}")

    print("[*] Starting Keycloak container...")
    subprocess.run(
        [
            "docker", "run", "-d",
            "--name", CONTAINER_NAME,
            "-p", f"{KEYCLOAK_PORT}:8080",
            "-e", f"KEYCLOAK_ADMIN={KEYCLOAK_ADMIN}",
            "-e", f"KEYCLOAK_ADMIN_PASSWORD={KEYCLOAK_PASS}",
            "-v", f"{realm_path}:/opt/keycloak/data/import/realm.json:ro",
            "quay.io/keycloak/keycloak:latest",
            "start-dev",
            "--import-realm",
        ],
        check=True,
    )
    print("[*] Waiting for Keycloak to become ready (up to 90 s)...")
    wait_for_keycloak()


def get_admin_token() -> str:
    data = (
        f"client_id=admin-cli"
        f"&username={KEYCLOAK_ADMIN}"
        f"&password={KEYCLOAK_PASS}"
        f"&grant_type=password"
    ).encode()
    req = urllib.request.Request(
        f"{KEYCLOAK_URL}/realms/master/protocol/openid-connect/token",
        data=data,
        headers={"Content-Type": "application/x-www-form-urlencoded"},
    )
    with urllib.request.urlopen(req, timeout=10) as resp:
        return json.loads(resp.read())["access_token"]


def verify_endpoints() -> dict:
    url = f"{KEYCLOAK_URL}/realms/{REALM}/.well-known/openid-configuration"
    print(f"\n[*] Fetching OIDC discovery: {url}")
    with urllib.request.urlopen(url, timeout=10) as resp:
        doc = json.loads(resp.read())

    print("\n==========================================")
    print("  Key endpoints (hand these to Member 2)")
    print("==========================================")
    for key in (
        "issuer",
        "authorization_endpoint",
        "token_endpoint",
        "jwks_uri",
        "userinfo_endpoint",
        "end_session_endpoint",
    ):
        print(f"  {key:30s}: {doc.get(key, 'N/A')}")
    print("==========================================\n")
    return doc


if __name__ == "__main__":
    start_keycloak_if_needed()
    token = get_admin_token()
    print("[OK] Admin token obtained.")
    verify_endpoints()
    print("[OK] Setup complete. Realm 'enterprise-zt' is live.")
    print(f"    Admin console -> {KEYCLOAK_URL}/admin")
    print(f"    Client ID     -> {CLIENT_ID}")
    print(f"    Client Secret -> {CLIENT_SECRET}")
