# Recommended Tools and Safe Practices for Auth Testing

These tools are suggested for authorized, lab-safe testing of authentication flows.

## Interception & Manual Testing
- Burp Suite (Professional or Community) — intercepting proxy, manual request editing. Use only with authorization.
- OWASP ZAP — free alternative for intercept and passive/active scans (be cautious with active scans).
- Browser DevTools — quick inspection of headers, cookies, JS behavior.

## TLS & Header Inspection
- `openssl s_client -connect host:443 -servername host` — TLS negotiation and cert inspection.
- `curl -I https://host` — response headers.

## Email Testing
- Use a test mailbox (MailHog, Mailtrap) for automated test environments; capture reset emails safely.

## Log Analysis & Monitoring
- Access application logs (auth events) with timestamps and IPs.
- SIEM dashboards for aggregated failed/successful auth trends.

## Notes on Rate-Limit & Brute-force Tests
- Avoid automated bruteforce or credential stuffing unless explicitly authorized with limits.
- If testing lockouts, coordinate with POC and perform at low rates to avoid service disruption.

## Evidence Management
- Keep captures in an encrypted archive, redact secrets, and store per the authorization agreement.

## Quick Safe Commands
```bash
# Check headers
curl -I https://svpradius.emsi.ma/login
# TLS check
openssl s_client -connect svpradius.emsi.ma:443 -servername svpradius.emsi.ma
```

---

If you need, I can generate a short `README.md` with exact commands to run these checks and a sample `requests`/`curl` template for evidence capture.
