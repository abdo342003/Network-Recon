# Account Recovery & Troubleshooting Guidance (Authorized)

Purpose: practical steps for safely diagnosing and resolving legitimate account access issues.

## Preliminary checks (user-side)
- Confirm correct username/email and that the account exists.
- Check SPAM/Junk for reset email.
- Verify device time and timezone (token-based MFA depends on clock sync).

## Password Reset Flow Checks (tester/admin)
- Verify reset request flow:
  - Does the app return a generic confirmation ("If an account exists we sent an email")?
  - Is the reset token single-use and time-limited (e.g., 15–60 minutes)?
- Inspect reset email headers and body for:
  - The reset link contains a long unguessable token
  - No plaintext password or PII is included
- Test token behavior:
  - Token invalid after first use
  - Token expired after stated TTL
  - Token bound to account and not reusable across accounts

## MFA Recovery
- Confirm availability of recovery codes and that they are one-time use.
- Verify admin-led recovery path (helpdesk) includes strict identity verification (ID, email, support PIN), logging, and temporary forced password reset.
- Ensure disabling MFA requires strong proof and generates alert to the user.

## Admin Troubleshooting Steps
- Check authentication logs for the user (timestamps, IPs, user-agent).
- Search for recent lockout or failed login spikes.
- If forced reset is required: generate temporary randomized password, require user to change at next login, and notify via out-of-band channel.
- Revoke active sessions after recovery to prevent session reuse.

## Safe Recovery Process (recommended)
1. Validate requester identity via documented steps (POC contact, ticketing).
2. Use admin console to generate a password reset token OR issue a one-time temporary password.
3. Force MFA re-enrollment where applicable.
4. Notify user of account changes and provide guidance for securing their account.
5. Log the incident and upload to ticket with timestamps and actor identity.

## Preventive Controls
- Provide recovery codes on MFA enrollment and instruct users to store them securely.
- Implement rate limiting and fraud detection on reset endpoints.
- Require secondary verification for high-risk resets (e.g., IP change, new device)

## Evidence & Audit
- Retain logs for recovery events, including who performed admin resets and why.
- Attach email headers and token timestamps when investigating lost reset emails.

---

Notes:
- Recovery paths must balance convenience and security — prioritize protecting account integrity.
- Never share reset tokens in chat or insecure channels.
