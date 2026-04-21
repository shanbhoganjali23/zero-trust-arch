# Detailed Demo and Test Cases

## A. Happy path cases

### A1. HR user
- Username: `alice_hr`
- Password: `password123`
- Expected landing page: `/hr-app`
- Why it should work: valid role, valid MFA, trusted device is not mandatory beyond MFA

### A2. Finance user
- Username: `bob_finance`
- Password: `password123`
- Expected landing page: `/finance-app`
- Why it should work: valid role, valid MFA, trusted device required and satisfied on known device

### A3. Developer user
- Username: `charlie_dev`
- Password: `password123`
- Expected landing page: `/dev-app`
- Why it should work: valid role, valid MFA

### A4. Admin user
- Username: `admin_user`
- Password: `admin_secure_pass`
- Expected landing page: `/monitor`
- Why it should work: valid role, valid MFA, trusted device required and satisfied on known device

## B. KO cases

### B1. Wrong password
- Use any valid username with the wrong password
- Expected result: login rejected before MFA starts

### B2. Wrong OTP
- Login correctly, then enter a wrong OTP
- Expected result: MFA rejected, no session cookie issued

### B3. Repeated wrong OTP
- Enter wrong OTP three times
- Expected result: user lockout for 120 seconds, incident logged

### B4. Cross-role access
- Developer -> HR portal
- HR -> Finance portal
- Finance -> Dev portal
- Expected result: access denied by policy engine

### B5. Direct service access
- Visit service ports directly
- Expected result: HTTP 403, because services only accept gateway traffic

### B6. Untrusted device for Finance/Admin
- Reset device identity in the login page
- Login as Finance or Admin
- Expected result: policy denies access because trusted device is required

## C. Monitoring evidence to show in the demo
- Show `security_events_tracking.txt`
- Show `/monitor` dashboard
- Point out:
  - MFA successes and failures
  - denied access attempts
  - incident lockout event
  - device trust values in the logs
