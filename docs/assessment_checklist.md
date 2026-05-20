# Web Login Assessment Checklist (Authorized Lab)

Purpose: a concise, repeatable checklist for authorized testing of authentication and account flows.

---

## Administrative
- [ ] Written authorization present (scope: domains, IPs, accounts, time window)
- [ ] Point(s) of contact for escalation and outages
- [ ] Test accounts created (normal user, admin, expired, locked)
- [ ] Backup and rollback plan for site-impacting tests

## Scope
- Target URL(s): e.g., https://example/login
- Allowed techniques: passive, manual, low-rate probes, authorized automated tests
- Disallowed techniques: brute-force, exploitation, denial-of-service, social engineering (unless specifically authorized)

## Recon
- [ ] Confirm DNS and certificate (owner, expiry)
- [ ] Identify public assets, subdomains, related auth endpoints (register, reset, verify)
- [ ] Check CDN/WAF presence and note any blockers

## Authentication Surface
- Login page behavior:
  - [ ] HTTP responses and status codes (200/302/401/403)
  - [ ] Error messaging (avoid leaking existence of usernames)
  - [ ] Timing differences (do not use for automated enumeration without approval)
- Account creation:
  - [ ] Password policy enforced client/server-side
  - [ ] Email verification enforced (if applicable)
- Password reset:
  - [ ] Reset request requires only email or more checks?
  - [ ] Reset token length, expiry, single-use
  - [ ] Reset link scope (IP, user agent) and binding
- MFA:
  - [ ] MFA enrollment requires confirmation and secondary channel
  - [ ] Recovery codes and processes tested

## Session Management
- [ ] Cookies: Secure, HttpOnly, SameSite flags
- [ ] Session IDs unguessable and rotated after login
- [ ] Logout invalidates session on server
- [ ] Session timeout/inactivity policies

## Access Control
- [ ] Role separation (normal vs admin)
- [ ] Horizontal privilege checks (user A cannot access user B resources)
- [ ] Vertical checks (non-admin cannot access admin functions)

## Rate-limiting & Brute-force Protections
- [ ] Login attempt thresholds and lockout behavior
- [ ] CAPTCHA or throttling mechanisms
- [ ] Account lockout notifications to user/admin

## Input Handling & CSRF/XSS
- [ ] Auth endpoints protected by CSRF tokens or SameSite cookies
- [ ] Inputs sanitized; login fields do not reflect raw input back

## Logging, Monitoring & Alerting
- [ ] Failed/successful login events are logged with timestamp and source IP
- [ ] Alerts exist for unusual auth activity (mass failures, lockouts)
- [ ] Retention policy for auth logs

## Transport & Deployment
- [ ] TLS present and strong cipher suites + HSTS
- [ ] Secure headers: Content-Security-Policy, X-Frame-Options, X-Content-Type-Options

## Privacy & Data Handling
- [ ] Passwords never returned or emailed in plaintext
- [ ] PII exposure minimized in responses and error messages

## Evidence & Reporting
- For each check, capture:
  - Steps to reproduce (exact UI steps)
  - HTTP request/response (redact sensitive fields)
  - Screenshots with timestamps
  - Relevant server-side log IDs if available

---

Notes:
- Always use test accounts you control. Avoid tests that impact other users.
- If something unexpected or destructive appears, stop and contact the authorizing POC.
