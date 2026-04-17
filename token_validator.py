"""
token_validator.py
Member 1 — JWT Token Validation Utility

This module is the contract file that Member 1 delivers to Member 2.
It validates Keycloak-issued JWTs using the realm JWKS endpoint.

Important note about MFA:
This validator does NOT prove Keycloak MFA completion unless the token already
contains an explicit MFA-related claim. In this project, Keycloak native OTP is
enforced at login, but no custom authenticator is included here to inject an
`mfa_verified=true` claim into the token. For that reason, this module exposes
`mfa_verified` conservatively.
"""

import logging
import time
from typing import Any

import requests
from jose import ExpiredSignatureError, JWTError, jwt
from jose.exceptions import JWKError

log = logging.getLogger(__name__)

KEYCLOAK_URL = "http://localhost:8080"
REALM = "enterprise-zt"
CLIENT_ID = "zt-gateway"
CLIENT_SECRET = "zt-gateway-secret"
ISSUER = f"{KEYCLOAK_URL}/realms/{REALM}"
JWKS_URI = f"{ISSUER}/protocol/openid-connect/certs"
ALGORITHMS = ["RS256"]
AUDIENCE = CLIENT_ID


class TokenValidationError(Exception):
    pass


_jwks_cache = {"keys": [], "fetched_at": 0.0}
_JWKS_TTL = 600


def _get_jwks() -> list[dict[str, Any]]:
    now = time.time()
    if now - _jwks_cache["fetched_at"] < _JWKS_TTL and _jwks_cache["keys"]:
        return _jwks_cache["keys"]

    log.info("Fetching JWKS from %s", JWKS_URI)
    resp = requests.get(JWKS_URI, timeout=5)
    resp.raise_for_status()
    keys = resp.json().get("keys", [])
    if not keys:
        raise TokenValidationError("JWKS endpoint returned no signing keys")
    _jwks_cache.update({"keys": keys, "fetched_at": now})
    return keys


def _derive_mfa_verified(claims: dict[str, Any]) -> bool:
    if "mfa_verified" in claims:
        return bool(claims["mfa_verified"])

    amr = claims.get("amr")
    if isinstance(amr, list) and any(str(v).lower() in {"mfa", "otp", "totp"} for v in amr):
        return True

    acr = str(claims.get("acr", "")).lower()
    if acr in {"mfa", "otp", "totp"}:
        return True

    return False


def validate_token(raw_token: str) -> dict[str, Any]:
    if not raw_token:
        raise TokenValidationError("No token provided")

    if raw_token.startswith("Bearer "):
        raw_token = raw_token[7:]

    try:
        claims = jwt.decode(
            raw_token,
            _get_jwks(),
            algorithms=ALGORITHMS,
            audience=AUDIENCE,
            issuer=ISSUER,
            options={"verify_at_hash": False},
        )
    except ExpiredSignatureError as exc:
        raise TokenValidationError("Token has expired") from exc
    except JWKError as exc:
        raise TokenValidationError(f"JWKS error: {exc}") from exc
    except JWTError as exc:
        raise TokenValidationError(f"Token invalid: {exc}") from exc
    except requests.RequestException as exc:
        raise TokenValidationError(f"Failed to fetch JWKS: {exc}") from exc
    except Exception as exc:
        raise TokenValidationError(f"Validation failed: {exc}") from exc

    username = claims.get("preferred_username") or claims.get("sub", "unknown")
    role = _extract_role(claims)
    mfa_verified = _derive_mfa_verified(claims)

    log.info("Token valid - user: %s role: %s mfa: %s", username, role, mfa_verified)

    return {
        "username": username,
        "role": role,
        "mfa_verified": mfa_verified,
        "email": claims.get("email", ""),
        "exp": claims.get("exp"),
        "iss": claims.get("iss"),
        "sub": claims.get("sub"),
        "raw_claims": claims,
    }


def _extract_role(claims: dict[str, Any]) -> str:
    role = claims.get("role")
    if isinstance(role, str) and role.strip():
        return role

    realm_roles = claims.get("realm_access", {}).get("roles", [])
    app_roles = [
        r for r in realm_roles
        if r not in {"offline_access", "uma_authorization", "default-roles-enterprise-zt"}
    ]
    return app_roles[0] if app_roles else "unknown"


def decode_unverified(raw_token: str) -> dict[str, Any]:
    if raw_token.startswith("Bearer "):
        raw_token = raw_token[7:]
    return jwt.get_unverified_claims(raw_token)


ENDPOINT_REFERENCE = {
    "issuer": ISSUER,
    "authorization_endpoint": f"{ISSUER}/protocol/openid-connect/auth",
    "token_endpoint": f"{ISSUER}/protocol/openid-connect/token",
    "jwks_uri": JWKS_URI,
    "userinfo_endpoint": f"{ISSUER}/protocol/openid-connect/userinfo",
    "end_session_endpoint": f"{ISSUER}/protocol/openid-connect/logout",
    "client_id": CLIENT_ID,
    "client_secret": CLIENT_SECRET,
}


if __name__ == "__main__":
    print("=== Endpoint Reference for Member 2 ===")
    for k, v in ENDPOINT_REFERENCE.items():
        print(f"  {k:30s}: {v}")
