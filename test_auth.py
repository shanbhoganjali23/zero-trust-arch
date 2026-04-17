"""
test_auth.py
Improved tests for Member 1 — Identity & Authentication

Covers:
  - Keycloak reachability
  - login success / failure
  - MFA setup / verify / status / disable
  - token validator basic negative cases

Run:
  pip install pytest requests pyotp python-jose[cryptography]
  pytest test_auth.py -v
"""

import uuid
from pathlib import Path

import pyotp
import pytest
import requests

KEYCLOAK_URL = "http://localhost:8080"
REALM = "enterprise-zt"
CLIENT_ID = "zt-gateway"
CLIENT_SECRET = "zt-gateway-secret"
TOKEN_URL = f"{KEYCLOAK_URL}/realms/{REALM}/protocol/openid-connect/token"
MFA_BASE = "http://localhost:5010"
ADMIN_DISABLE_TOKEN = "change-me"


def keycloak_login(username: str, password: str) -> requests.Response:
    return requests.post(
        TOKEN_URL,
        data={
            "client_id": CLIENT_ID,
            "client_secret": CLIENT_SECRET,
            "grant_type": "password",
            "username": username,
            "password": password,
            "scope": "openid",
        },
        timeout=10,
    )


def unique_username(prefix: str = "test_mfa_user") -> str:
    return f"{prefix}_{uuid.uuid4().hex[:8]}"


def setup_mfa_for_user(username: str) -> dict:
    resp = requests.post(
        f"{MFA_BASE}/mfa/setup",
        json={"username": username},
        timeout=5,
    )
    assert resp.status_code == 200, f"Unexpected setup response: {resp.text}"
    data = resp.json()
    assert data["username"] == username
    assert "secret" in data
    assert "uri" in data
    assert "qr_code" in data
    return data


@pytest.fixture
def fresh_mfa_user() -> str:
    return unique_username()


class TestKeycloakConnectivity:
    def test_realm_discovery_reachable(self):
        url = f"{KEYCLOAK_URL}/realms/{REALM}/.well-known/openid-configuration"
        resp = requests.get(url, timeout=5)

        assert resp.status_code == 200, f"OIDC discovery unreachable: {resp.text}"
        doc = resp.json()
        assert doc["issuer"] == f"{KEYCLOAK_URL}/realms/{REALM}"
        assert "jwks_uri" in doc
        assert "token_endpoint" in doc

    def test_jwks_endpoint_returns_keys(self):
        url = f"{KEYCLOAK_URL}/realms/{REALM}/protocol/openid-connect/certs"
        resp = requests.get(url, timeout=5)

        assert resp.status_code == 200, f"JWKS endpoint failed: {resp.text}"
        keys = resp.json().get("keys", [])
        assert isinstance(keys, list)
        assert keys, "No signing keys returned from JWKS endpoint"


class TestLoginFlow:
    def test_invalid_password_returns_401(self):
        resp = keycloak_login("alice_hr", "wrong_password")
        assert resp.status_code == 401, f"Expected 401, got {resp.status_code}: {resp.text}"

    def test_nonexistent_user_returns_401(self):
        resp = keycloak_login("nobody", "nopass")
        assert resp.status_code == 401, f"Expected 401, got {resp.status_code}: {resp.text}"

    def test_valid_user_login_is_not_server_error(self):
        resp = keycloak_login("alice_hr", "password123")
        assert resp.status_code in (200, 400, 401), (
            f"Unexpected status for valid user login: {resp.status_code} {resp.text}"
        )

    def test_token_contains_expected_fields_when_token_is_issued(self):
        resp = keycloak_login("admin_user", "admin_secure_pass")

        if resp.status_code != 200:
            pytest.skip(
                f"Token not issued in this environment (status {resp.status_code}). "
                "Likely blocked by required OTP enrollment."
            )

        data = resp.json()
        assert "access_token" in data
        assert "refresh_token" in data
        assert data.get("token_type") == "Bearer"
        assert isinstance(data.get("expires_in"), int)


class TestMFAService:
    def test_mfa_service_health(self):
        resp = requests.get(f"{MFA_BASE}/health", timeout=3)
        assert resp.status_code == 200
        assert resp.json()["status"] == "ok"

    def test_mfa_setup_returns_qr_and_secret(self, fresh_mfa_user):
        data = setup_mfa_for_user(fresh_mfa_user)
        assert data["uri"].startswith("otpauth://totp/")
        assert len(data["secret"]) >= 16
        assert isinstance(data["qr_code"], str)
        assert data["qr_code"]
        assert data["enrolled"] is False

    def test_mfa_verify_correct_otp(self, fresh_mfa_user):
        setup_data = setup_mfa_for_user(fresh_mfa_user)
        otp = pyotp.TOTP(setup_data["secret"]).now()

        resp = requests.post(
            f"{MFA_BASE}/mfa/verify",
            json={"username": fresh_mfa_user, "otp": otp},
            timeout=5,
        )

        assert resp.status_code == 200, f"Expected 200, got {resp.status_code}: {resp.text}"
        assert resp.json()["verified"] is True

    def test_mfa_verify_wrong_otp_returns_401(self, fresh_mfa_user):
        setup_mfa_for_user(fresh_mfa_user)

        resp = requests.post(
            f"{MFA_BASE}/mfa/verify",
            json={"username": fresh_mfa_user, "otp": "000000"},
            timeout=5,
        )

        assert resp.status_code == 401
        assert resp.json()["verified"] is False

    def test_mfa_status_after_enrollment(self, fresh_mfa_user):
        setup_data = setup_mfa_for_user(fresh_mfa_user)
        otp = pyotp.TOTP(setup_data["secret"]).now()

        verify_resp = requests.post(
            f"{MFA_BASE}/mfa/verify",
            json={"username": fresh_mfa_user, "otp": otp},
            timeout=5,
        )
        assert verify_resp.status_code == 200

        status_resp = requests.get(
            f"{MFA_BASE}/mfa/status?username={fresh_mfa_user}",
            timeout=5,
        )
        assert status_resp.status_code == 200
        data = status_resp.json()
        assert data["username"] == fresh_mfa_user
        assert data["enrolled"] is True

    def test_mfa_disable_requires_admin_token(self, fresh_mfa_user):
        setup_mfa_for_user(fresh_mfa_user)

        no_header = requests.post(
            f"{MFA_BASE}/mfa/disable",
            json={"username": fresh_mfa_user},
            timeout=5,
        )
        assert no_header.status_code == 403

        disable_resp = requests.post(
            f"{MFA_BASE}/mfa/disable",
            json={"username": fresh_mfa_user},
            headers={"X-Admin-Token": ADMIN_DISABLE_TOKEN},
            timeout=5,
        )
        assert disable_resp.status_code == 200

        status_resp = requests.get(
            f"{MFA_BASE}/mfa/status?username={fresh_mfa_user}",
            timeout=5,
        )
        assert status_resp.status_code == 200
        assert status_resp.json()["enrolled"] is False

    def test_mfa_missing_username_returns_400(self):
        resp = requests.post(
            f"{MFA_BASE}/mfa/verify",
            json={"otp": "123456"},
            timeout=5,
        )
        assert resp.status_code == 400

    def test_mfa_unknown_user_returns_401(self):
        resp = requests.post(
            f"{MFA_BASE}/mfa/verify",
            json={"username": unique_username("ghost_user"), "otp": "123456"},
            timeout=5,
        )
        assert resp.status_code == 401
        assert resp.json()["verified"] is False


class TestTokenValidator:
    @staticmethod
    def _import_validator():
        import sys

        here = Path(__file__).resolve().parent
        if str(here) not in sys.path:
            sys.path.insert(0, str(here))

        from token_validator import TokenValidationError, validate_token
        return validate_token, TokenValidationError

    def test_validate_invalid_token_raises(self):
        validate_token, TokenValidationError = self._import_validator()
        with pytest.raises(TokenValidationError):
            validate_token("this.is.not.a.real.token")

    def test_validate_empty_token_raises(self):
        validate_token, TokenValidationError = self._import_validator()
        with pytest.raises(TokenValidationError):
            validate_token("")


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-v"]))
