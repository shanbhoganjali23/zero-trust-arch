# How to Run and Test the Zero Trust Project
## Complete Step-by-Step Guide (No Experience Needed)

---

## PART 1 — Prerequisites (Install Once)

### 1. Install Python
- Download from https://python.org/downloads
- During install, check **"Add Python to PATH"**
- Verify: open a terminal and type `python --version` → should say Python 3.10+

### 2. Install Docker Desktop
- Download from https://www.docker.com/products/docker-desktop
- Install and start it (you need the whale icon running in your taskbar)
- Verify: `docker --version`

### 3. Install Python packages
Open a terminal, go into the project folder, then run:
```
pip install flask requests pyotp python-jose[cryptography] qrcode pillow pytest
```

---

## PART 2 — Start Everything (Do This Every Time)

Open **5 separate terminal windows** (or tabs). Each service runs in its own terminal.

### Terminal 1 — Start Keycloak (Identity Provider)
```
cd zero-trust-fixed
docker compose up
```
Wait until you see a line that says `Keycloak ... started`.
This takes about 60–90 seconds the first time.

### Terminal 2 — Start Policy Engine
```
cd zero-trust-fixed/policy-engine
python app.py
```
You should see: `Running on http://127.0.0.1:5005`

### Terminal 3 — Start the Gateway
```
cd zero-trust-fixed/gateway
python app.py
```
You should see: `Running on http://127.0.0.1:5000`

### Terminal 4 — Start HR Service
```
cd zero-trust-fixed/hr-app
python hr-app.py
```
You should see: `Running on http://127.0.0.1:5001`

### Terminal 5 — Start Finance and Dev services
Open two more tabs or run them one at a time:
```
cd zero-trust-fixed/finance-app
python finance-app.py
```
```
cd zero-trust-fixed/dev-app
python dev-app.py
```

---

## PART 3 — Test Using Your Browser

The gateway runs on port 5000. Open your browser and visit these URLs:

### ✅ Test 1 — HR user accesses HR portal (should SUCCEED)
```
http://localhost:5000/hr-app?user=alice_hr&role=HR&mfa=true
```
Expected result: JSON with `"status": "allowed"`

### ✅ Test 2 — Finance user accesses Finance portal (should SUCCEED)
```
http://localhost:5000/finance-app?user=bob_finance&role=Finance&mfa=true
```
Expected result: JSON with `"status": "allowed"`

### ✅ Test 3 — Developer accesses Dev portal (should SUCCEED)
```
http://localhost:5000/dev-app?user=charlie_dev&role=Developer&mfa=true
```
Expected result: JSON with `"status": "allowed"`

### ❌ Test 4 — Developer tries HR portal (should be DENIED — KO case)
```
http://localhost:5000/hr-app?user=charlie_dev&role=Developer&mfa=true
```
Expected result: `"status": "denied"` with HTTP 403

### ❌ Test 5 — HR user tries Finance portal (should be DENIED)
```
http://localhost:5000/finance-app?user=alice_hr&role=HR&mfa=true
```
Expected result: `"status": "denied"` with HTTP 403

### ❌ Test 6 — Admin without MFA tries to access anything (should be DENIED)
```
http://localhost:5000/hr-app?user=admin_user&role=Admin&mfa=false
```
Expected result: `"status": "denied"`, reason: `"admin access requires MFA"`

### ✅ Test 7 — Admin WITH MFA (should SUCCEED)
```
http://localhost:5000/hr-app?user=admin_user&role=Admin&mfa=true
```
Expected result: `"status": "allowed"`

### ❌ Test 8 — Finance user without MFA tries Finance portal (should be DENIED)
```
http://localhost:5000/finance-app?user=bob_finance&role=Finance&mfa=false
```
Expected result: `"status": "denied"`, reason: `"finance access requires MFA"`

---

## PART 4 — Test Using Command Line (curl)

If you want to test from terminal instead of browser:

```bash
# Test 1: HR user allowed
curl "http://localhost:5000/hr-app?user=alice_hr&role=HR&mfa=true"

# Test 2: Developer denied for HR
curl "http://localhost:5000/hr-app?user=charlie_dev&role=Developer&mfa=true"

# Test 3: Test policy engine directly
curl -X POST http://localhost:5005/evaluate \
  -H "Content-Type: application/json" \
  -d '{"user":"alice","role":"HR","resource":"/hr-app","action":"GET","mfa":true}'

# Test 4: Policy engine deny case
curl -X POST http://localhost:5005/evaluate \
  -H "Content-Type: application/json" \
  -d '{"user":"charlie","role":"Developer","resource":"/hr-app","action":"GET","mfa":true}'
```

**On Windows**, replace the `curl` command with:
```
curl "http://localhost:5000/hr-app?user=alice_hr&role=HR&mfa=true"
```
(Windows curl uses double quotes, not single quotes in the -d argument — use a tool like
Postman if curl is giving you trouble on Windows)

---

## PART 5 — Run Automated Tests

```bash
cd zero-trust-fixed
pip install pytest
pytest test_auth.py -v
```

Note: The Keycloak tests need Docker to be running. The MFA tests need the MFA service
running (starts automatically with docker compose). The token validator negative tests
will always pass since they just check that bad tokens are rejected.

---

## PART 6 — Check the Logs

All access events (allowed and denied) are written to:
```
zero-trust-fixed/security_events_tracking.txt
```
You can open this in any text editor, or run:
```bash
cat zero-trust-fixed/security_events_tracking.txt
```

---

## PART 7 — Stop Everything

In each terminal, press `Ctrl+C` to stop the service.

To stop Keycloak (Docker):
```bash
docker compose down
```

---

## QUICK REFERENCE — Ports

| Service         | Port  | URL                          |
|-----------------|-------|------------------------------|
| Gateway         | 5000  | http://localhost:5000        |
| HR Service      | 5001  | http://localhost:5001/hr-app |
| Finance Service | 5002  | http://localhost:5002/finance-app |
| Dev Service     | 5003  | http://localhost:5003/dev-app |
| Policy Engine   | 5005  | http://localhost:5005/evaluate |
| MFA Service     | 5010  | http://localhost:5010/health |
| Keycloak        | 8080  | http://localhost:8080/admin  |

---

## COMMON ERRORS AND FIXES

**"Address already in use"**
Another program is using that port. Either stop it, or change the port in the `app.run(port=XXXX)` line.

**"ModuleNotFoundError: No module named 'flask'"**
You forgot to install dependencies. Run: `pip install flask requests python-jose[cryptography] pyotp qrcode pillow`

**"Connection refused" when testing the gateway**
The policy engine is not running. Start it first (Terminal 2 above).

**Keycloak takes forever to start**
Normal on first run — wait 2 minutes. If it never starts, run `docker compose logs` to see why.

**"TemplateNotFound" error in HR/Finance/Dev apps**
Make sure you are running the app from inside its own folder (e.g., `cd hr-app` then `python hr-app.py`).
