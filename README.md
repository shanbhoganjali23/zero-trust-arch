# Zero Trust Enterprise Security Prototype

A browser-accessible **Zero Trust Architecture (ZTA)** prototype for enterprise applications. The system enforces **identity verification, MFA, centralized policy evaluation, and per-request authorization** before allowing access to protected internal services.

## Features

- **Centralized Zero Trust Gateway** for all protected routes
- **Keycloak IAM integration** for users, roles, and token issuance
- **TOTP-based MFA** with QR enrollment flow
- **Policy Engine** for role/resource/MFA/IP-based authorization
- **Protected departmental portals**:
  - HR
  - Finance
  - Developer
  - Admin
- **Security logging and monitoring**
- **Basic incident response**
  - failed login tracking
  - temporary IP lockout
  - denied-access logging

## Architecture

```text
Browser / Login UI (5050)
        |
        v
Zero Trust Gateway (5000)
   |        |         |
   |        |         +--> Policy Engine (5005)
   |        |
   |        +------------> MFA Service (5010)
   |
   +---------------------> Keycloak IAM (8080)
   |
   +---------------------> Internal Services
                            - HR App (5001)
                            - Finance App (5002)
                            - Dev App (5003)
                            - Admin App (5004)
```

### Request flow

1. User opens the login UI.
2. Browser sends username/password to the gateway.
3. Gateway authenticates against **Keycloak** and receives an access token.
4. Gateway starts MFA enrollment/verification through the **MFA service**.
5. On successful OTP verification, the gateway creates a browser session (`zt_session`).
6. For each protected request, the gateway:
   - resolves the authenticated session or bearer token
   - sends request context to the **Policy Engine**
   - receives **allow/deny** decision
   - forwards only allowed requests to the internal service
7. Security events are logged and surfaced through the monitoring view.

## Tech Stack

### Backend
- **Python**
- **Flask** for gateway, policy engine, MFA service, login server, and internal apps
- **requests** for inter-service communication

### Identity and Security
- **Keycloak** for IAM, roles, realm, and token issuance
- **JWT / bearer token flow**
- **TOTP MFA** using:
  - `pyotp`
  - `qrcode`
  - `Pillow`

### Frontend
- **HTML / CSS / JavaScript**
- Flask-rendered portal templates

### Infrastructure
- **Docker / Docker Compose**
- Local multi-service development setup

### Monitoring
- File-based security logging
- Lightweight monitoring dashboard

## Repository Structure

```text
zero-trust-arch/
├── admin-app/                 # Admin portal
├── dev-app/                   # Developer portal
├── finance-app/               # Finance portal
├── gateway/                   # Zero Trust gateway / enforcement point
├── hr-app/                    # HR portal
├── policy-engine/             # Authorization decision service
├── Dockerfile.mfa             # MFA service container
├── docker-compose.yml         # Keycloak + MFA stack
├── enterprise-zt-realm.json   # Keycloak realm, users, roles, client
├── keycloak_mfa_config.py     # Keycloak OTP setup helper
├── keycloak_setup.py          # Keycloak setup helper
├── login.html                 # Browser login UI
├── login_server.py            # Login UI host
├── mfa_service.py             # Custom MFA/TOTP service
├── security_events_tracking.txt
├── test_auth.py               # Identity/auth tests
└── token_validator.py         # JWT validation helper / contract
```

## Roles and Access Model

|        Role     |                Access             |
|-----------------|-----------------------------------|
| HR              | HR portal only                    |
| Finance         | Finance portal only, MFA required |
| Developer       | Developer portal only             |
| Admin           | All portals, MFA required         |
| SecurityAnalyst | Limited read-style access         |

## Getting Started

### 1) Start Docker services

```bash
docker compose up
```

This starts:
- Keycloak
- MFA service

### 2) Start local Python services

Run each in a separate terminal.

#### Policy Engine
```bash
cd policy-engine
python3 app.py
```

#### Gateway
```bash
cd gateway
python3 app.py
```

#### HR App
```bash
cd hr-app
python3 hr-app.py
```

#### Finance App
```bash
cd finance-app
python3 finance-app.py
```

#### Dev App
```bash
cd dev-app
python3 dev-app.py
```

#### Admin App
```bash
cd admin-app
python3 admin-app.py
```

#### Login UI
```bash
python3 login_server.py
```

### 3) Open the application

- Login UI: `http://localhost:5050`
- Keycloak: `http://localhost:8080`
- Monitoring: `http://localhost:5000/monitoring`

## Demo Accounts

| Username     | Password            | Role       |
|--------------|---------------------|------------|
| `alice_hr`   | `password123`       | HR         |
| `bob_finance`| `password123`       | Finance    |
| `charlie_dev`| `password123`       | Developer  |
| `admin_user` | `admin_secure_pass` | Admin      |

## Authentication and Authorization

### Authentication
- Username/password is validated against **Keycloak**
- Gateway receives a token and extracts user/role context
- MFA is completed through the custom **TOTP MFA service**
- Gateway creates a browser session cookie after successful MFA

### Authorization
- Protected requests are evaluated by the **Policy Engine**
- Policy decisions consider:
  - user role
  - requested resource
  - MFA status
  - client IP
- Gateway enforces the returned allow/deny decision

## Monitoring and Incident Response

### Logged events include
- login success / failure
- MFA success / failure
- access granted / denied
- logout
- incident lockout

### Basic incident response
- repeated failed logins are tracked per IP
- lockout is triggered after threshold failures in a time window
- locked IPs are temporarily blocked
- events are written to `security_events_tracking.txt`

