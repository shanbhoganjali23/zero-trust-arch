Gateway:
- Runs on port 5000
- Receives user requests
- Extracts user, role, MFA
- Sends request to policy engine
- Enforces allow/deny

Policy Engine:
- Runs on port 5005
- Evaluates access based on role, resource, and MFA
- Returns decision and reason

Current auth:
- Mocked using headers or browser query params

Next integration needed:
- Member 1: issuer URL, JWKS endpoint, client ID, sample token
- Member 3: HR, Finance, Dev service URLs