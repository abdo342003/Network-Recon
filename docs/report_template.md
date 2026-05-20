# Web Auth Assessment Report

**Title:** Web Authentication Assessment

**Date:** YYYY-MM-DD

**Tester:** Your Name

**Scope & Authorization:**
- Targets: https://svpradius.emsi.ma/login
- Authorized by: [Name/Org]
- Test window: [start - end]
- Techniques allowed: passive/manual, low-rate probes, authorized automated tests

---

## Executive Summary
One-paragraph summary of overall posture, most critical findings, and recommended immediate actions.

## Findings Summary (high-level)
- Total findings: N
- Critical: X, High: Y, Medium: Z, Low: W

---

## Detailed Findings

Each finding should follow this template.

### Finding ID: FIND-001
- **Title:** Short descriptive title
- **Severity:** Critical / High / Medium / Low
- **Affected URL(s):** https://.../login
- **Description:** What was tested, how it behaves, and why this is a problem.
- **Evidence:** (redact secrets)
  - HTTP request/response (sanitized)
  - Screenshot(s) with timestamp
  - Log references (timestamp, logfile, event id)
- **Impact:** Business and technical impact
- **Likelihood:** Low / Medium / High (rationale)
- **Remediation:** Clear, actionable steps to fix
- **Verification Steps:** How to confirm the fix
- **References:** OWASP A2/A3/etc., relevant docs

(Repeat for each finding)

---

### Sample Finding: FIND-002
- **Title:** Session cookie missing SameSite or Secure flags
- **Severity:** Medium
- **Affected URL(s):** https://svpradius.emsi.ma/login
- **Description:** During header inspection of the login response, the session cookie (`sessionid`) was returned without the `SameSite` attribute and without the `Secure` flag in some environments. This increases risk of session cookie leakage via cross-site requests and insecure transport on non-HTTPS connections.
- **Evidence:** (sanitized)
  - Response header excerpt:

```
Set-Cookie: sessionid=abc123; HttpOnly; Path=/
```

  - Screenshot: `evidence/screenshots/login_headers.png` (timestamp: 2026-04-30T10:32:12Z)
  - Log reference: auth.log @ 2026-04-30T10:32:12Z (event id: 42)
- **Impact:** An attacker controlling a cross-site request or on-path observer on non-HTTPS networks could cause cookie disclosure or replay, leading to account takeover of active sessions.
- **Likelihood:** Medium — depends on application deployment and whether HTTPS is enforced for all traffic.
- **Remediation:**
  1. Configure the application or the web server to always set `Secure; HttpOnly; SameSite=Lax` (or `Strict` where compatible) on session cookies.
 2. Enforce HTTPS throughout the site and enable HSTS with an appropriate max-age.
 3. Rotate active session identifiers after configuration change.
- **Verification Steps:**
  1. Re-request the login page and confirm the `Set-Cookie` header includes `Secure; HttpOnly; SameSite=Lax`.
 2. Validate HSTS header is present: `Strict-Transport-Security: max-age=31536000; includeSubDomains`.
- **References:**
  - OWASP Session Management Cheat Sheet: https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html
  - MDN SameSite cookies: https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Set-Cookie

## Remediation Roadmap (prioritized)
- Immediate (within 24-72 hours): fixes for Critical/High
- Short-term: configuration and policy changes
- Long-term: architecture or process changes (MFA rollout, monitoring)

## Test Artifacts
- Attached sanitized request/response captures
- Screenshots folder
- Log snippets with timestamps

## Conclusion
Brief final summary and invitation to schedule re-test.

---

**Distribution & Confidentiality:**
This report is intended for authorized recipients only. Do not share outside scope without approval.
