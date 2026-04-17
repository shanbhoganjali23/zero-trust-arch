# Member 1 - Identity and Authentication

This package contains the cleaned-up Member 1 deliverables for the Zero Trust project.

## Architecture decision

The project now uses **Keycloak native OTP as the primary MFA mechanism**.
The custom `mfa_service.py` remains in the package as a **standalone demo / alternative MFA microservice**, not as part of the live Keycloak login flow.

That avoids the earlier design problem where two MFA systems existed side by side without being integrated.

## Files

- `enterprise-zt-realm.json` - Keycloak realm, users, roles, client
- `keycloak_setup.py` - starts or verifies Keycloak and prints OIDC endpoints
- `keycloak_mfa_config.py` - enforces Keycloak OTP required action
- `token_validator.py` - JWT validation contract for Member 2
- `mfa_service.py` - standalone custom TOTP demo service
- `docker-compose.yml` - local stack for Keycloak and MFA service
- `Dockerfile.mfa` - container image for the MFA service
- `test_auth.py` - improved automated tests

## Quick start

```bash
docker compose up -d
python keycloak_setup.py
python keycloak_mfa_config.py
pip install pytest requests pyotp python-jose[cryptography]
pytest test_auth.py -v
```

## Important note about `mfa_verified`

The token validator exposes `mfa_verified`, but only sets it to true when an MFA-related claim is actually present in the token, such as `mfa_verified`, `amr`, or `acr`.

With the files in this package alone, Keycloak OTP is enforced during login, but no custom authenticator is included here to inject a guaranteed `mfa_verified=true` claim into every token.

So Member 2 should treat `mfa_verified` as **best-effort claim extraction**, not as a guaranteed proof signal, unless the gateway or Keycloak flow is extended later.

## Custom MFA service admin disable

The `/mfa/disable` endpoint now requires:

```http
X-Admin-Token: change-me
```

For real deployment, replace this with proper admin JWT validation.