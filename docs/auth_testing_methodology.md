# OWASP-Aligned Authentication Testing Methodology (Safe)

Purpose: a step-by-step, non-destructive process for testing authentication and account flows under authorized, lab-safe conditions.

## Preparations
- Confirm written authorization and allowed techniques.
- Use only test accounts and staging environments when possible.
- Configure an intercepting proxy (Burp or ZAP) and browser dev tools for observation.
- Enable verbose logging on the application or ask the administrator to provide logs for correlation.
- Define evidence handling procedures and redaction rules for sensitive data.

## Test Account Types to Prepare
- Standard user
- Admin user
- Suspended/locked account
- New/unused account

## High-level Steps (Do NOT attempt bypasses)
1. Passive Recon and Baseline
   - Record page flows: GET/POST for login, register, reset, logout, MFA actions.
   - Capture TLS config: `openssl s_client -connect host:443 -servername host` or online TLS checker.
   - Inspect response headers for security flags.

2. Authentication Controls
   - Password policy: test via registration or password change UI to confirm policy enforcement (min length, complexity, blacklist).
   - Login responses: supply correct, wrong password, and observe error messages. Errors should be generic.
   - Session behavior: login, then logout, verify session cookie invalidation.
   - Session fixation: ensure session identifier rotates after login (observe cookie before/after).

3. MFA and Recovery
   - Enroll MFA and verify that the second factor is required to authenticate.
   - Test recovery flow for test account: request reset, verify token appears in email (test inbox), check token expiry and single-use.
   - Ensure recovery flow does not leak account data.

4. Rate Limits and Lockouts (Gentle checks only)
   - Simulate repeated failed logins at low rate to observe rate-limiting behavior and lockout thresholds.
   - Verify account lockouts produce observable notification to owner/admin.
   - Do NOT perform high-volume brute force.

5. Account Enumeration Checks (Non-invasive)
   - Observe differences in time to respond or error message content between existing and non-existing usernames. Use a few gentle probes only.

6. CSRF and State Protection
   - Ensure CSRF tokens (or SameSite cookies) exist for state-changing endpoints.
   - Verify tokens are tied to the user session and cannot be reused across sessions.

7. Input Handling
   - Test for reflected values in the login and error pages (XSS risk) using harmless payloads like `<test>`.
   - Ensure inputs are not reflected back in password fields.

8. Logging and Detection
   - Verify failures and successes produce logs with timestamps and source IPs.
   - Ask whether alerts are triggered for abnormal patterns.

9. Access Control Verification
   - Use separate test accounts to confirm role-based access restrictions.
   - Attempt direct URL access to admin endpoints while authenticated as normal user; expect 403/redirect.

10. Evidence Collection
   - Save request/response pairs with sensitive fields redacted.
   - Screenshots of UI and any relevant admin logs or alerts.
   - Timestamps (UTC) for correlating with server logs.

## Example Tools & Safe Commands
- Browser DevTools — Network tab to observe headers and cookies.
- curl examples (non-destructive):

```bash
# Check headers
curl -I https://svpradius.emsi.ma/login
# Fetch login page to inspect CSRF (do not post credentials via curl unless testing your account)
curl -s https://svpradius.emsi.ma/login | sed -n '1,200p'
```

- OpenSSL TLS check:

```bash
openssl s_client -connect svpradius.emsi.ma:443 -servername svpradius.emsi.ma
```

- Burp or ZAP for intercepting and manual testing (use only with authorization).

## Safety & Ethics
- Never attempt to bypass authentication, escalate privileges, or brute-force without explicit written scope.
- Stop immediately and notify the POC if you detect destructive behavior or instability.
- Maintain an audit trail of every action and keep evidence secure.

## Post-test Actions
- Provide remediation steps and verification steps for fixes.
- Schedule re-test after fixes.
