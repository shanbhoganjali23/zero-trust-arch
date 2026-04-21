# What Was Changed and Why

## 1. Real two-step login flow
The gateway no longer redirects straight to the portal after username/password. It now:
1. authenticates with Keycloak
2. creates a pending login flow
3. starts MFA setup
4. verifies OTP
5. creates a gateway session cookie
6. only then allows policy-based access

## 2. Removed fake URL-driven MFA
The old `?user=...&role=...&mfa=true` shortcut was removed from the main flow. Protected access now depends on the gateway session or a bearer token.

## 3. Policy engine now enforces the correct MFA field
The policy engine now reads `mfa_verified` from the gateway payload and denies protected resources if MFA is missing.

## 4. Added device trust
A persistent browser device identifier is stored in local storage. The gateway records the first device per user as trusted. New devices become `unknown`. Finance and Admin access now require a trusted device.

## 5. Added incident response
Three failed OTP attempts lock the user for 120 seconds. This is logged as `INCIDENT_LOCKOUT`.

## 6. Blocked direct access to internal services
HR, Finance, Dev, and Monitoring services now reject requests unless they come through the gateway with `X-From-Gateway: true`.

## 7. Added a monitoring dashboard
A simple monitoring dashboard was added at `/monitor` and placed behind the gateway. Admin and SecurityAnalyst roles can view it.

## 8. Improved logging
Gateway and policy engine now write structured events to `security_events_tracking.txt`, including device trust and incident response events.
