# Web Application Penetration Testing Checklist

Based on **OWASP WSTG**, **OWASP Top 10:2025**, **OWASP API Security Top 10:2023**, **ASVS 5.0**, **CWE**, **CVSS v4.0**, **NIST SP 800-115** and **PTES**.

## Contents

- [Status markers](#status-markers)
- [References used](#references-used)
- [1. Reconnaissance and information gathering](#1-reconnaissance-and-information-gathering)
- [2. Application mapping](#2-application-mapping)
- [3. Authentication](#3-authentication)
- [4. Authorisation and access control](#4-authorisation-and-access-control)
- [5. Session management](#5-session-management)
- [6. Input validation and injection](#6-input-validation-and-injection)
- [7. Cross-site scripting](#7-cross-site-scripting)
- [8. Cross-site request forgery](#8-cross-site-request-forgery)
- [9. File handling](#9-file-handling)
- [10. Path traversal and file inclusion](#10-path-traversal-and-file-inclusion)
- [11. Server-side request forgery](#11-server-side-request-forgery)
- [12. Business logic](#12-business-logic)
- [13. Race conditions and concurrency](#13-race-conditions-and-concurrency)
- [14. API security](#14-api-security)
- [15. HTTP and transport security](#15-http-and-transport-security)
- [16. Security misconfiguration](#16-security-misconfiguration)
- [17. Client-side security](#17-client-side-security)
- [18. Cryptography and sensitive data](#18-cryptography-and-sensitive-data)
- [19. Error handling and information disclosure](#19-error-handling-and-information-disclosure)
- [20. Third-party and integration security](#20-third-party-and-integration-security)
- [21. Dependency and component security](#21-dependency-and-component-security)
- [22. File and document security](#22-file-and-document-security)
- [23. Reporting and evidence collection](#23-reporting-and-evidence-collection)
- [Important rules](#important-rules)

---

## Status markers

| Marker | Meaning | When to use |
|:---:|---|---|
| `[ ]` | Not Tested | Default. Also used when a test was blocked; record why in Notes. |
| `[x]` | Tested - No Issue | Test performed with evidence that the control works. |
| `[!]` | Potential Finding | Behaviour suggests a weakness but exploitability or impact is not yet confirmed. Never reported as a vulnerability. |
| `[V]` | Validated Finding | Weakness confirmed with evidence. Raise a finding (F-01, F-02, ...) in section 23. |
| `[i]` | Informational | Observation with no direct security impact (e.g. version banner with no applicable CVE). Optional marker. |

## References used

- **WSTG IDs** follow the OWASP WSTG v4.2 stable numbering. IDs marked † exist in the WSTG "latest" branch only.
- **OWASP Top 10:2025** — A01 Broken Access Control · A02 Security Misconfiguration · A03 Software Supply Chain Failures · A04 Cryptographic Failures · A05 Injection · A06 Insecure Design · A07 Authentication Failures · A08 Software or Data Integrity Failures · A09 Security Logging and Alerting Failures · A10 Mishandling of Exceptional Conditions. SSRF is now part of A01.
- **OWASP API Security Top 10:2023** — API1 BOLA · API2 Broken Authentication · API3 BOPLA · API4 Unrestricted Resource Consumption · API5 BFLA · API6 Unrestricted Access to Sensitive Business Flows · API7 SSRF · API8 Security Misconfiguration · API9 Improper Inventory Management · API10 Unsafe Consumption of APIs.
- **OWASP ASVS 5.0** chapters are noted under each section heading for remediation and verification depth.
- **CVSS v4.0** (FIRST), **CWE** (MITRE), **NIST SP 800-115**, **PTES**.

---

## 1. Reconnaissance and information gathering

| ID | Test | Description | Status | Notes |
|---|---|---|:---:|---|
| RECON-01 | Subdomain enumeration | Passive (CT logs, passive DNS, search engines) then active brute force if permitted. Check each result against scope. | [ ] | |
| RECON-02 | Certificate transparency | Query crt.sh / CT logs for hostnames, wildcard certs and internal names. | [ ] | |
| RECON-03 | DNS records | A/AAAA, CNAME, MX, TXT (SPF, DMARC, verification tokens), NS, SRV; attempt zone transfer (AXFR). | [ ] | |
| RECON-04 | Subdomain takeover | Dangling CNAMEs to deprovisioned cloud/SaaS resources. Confirm by fingerprint only; do not claim without authorisation. | [ ] | |
| RECON-05 | Web server identification | Banners, header order, error pages, default files. Record versions as informational. | [ ] | |
| RECON-06 | Framework / CMS identification | Cookies, headers, paths, JS globals, meta generator, favicon hash. | [ ] | |
| RECON-07 | Technology stack and architecture | Identify CDN, WAF, load balancer, reverse proxy, app server, DB hints, cloud provider. | [ ] | |
| RECON-08 | Search-engine reconnaissance | Dorks for `site:`, `filetype:`, `inurl:admin`, error messages, cached docs, paste sites and code repos. | [ ] | |
| RECON-09 | robots.txt | Disallowed paths as leads for hidden content. | [ ] | |
| RECON-10 | sitemap.xml | Enumerate listed URLs, compare against crawled content. | [ ] | |
| RECON-11 | security.txt | `/.well-known/security.txt` present and valid (contact, expiry). Informational. | [ ] | |
| RECON-12 | Other metafiles | `humans.txt`, `/.well-known/*` (openid-configuration, assetlinks, apple-app-site-association). | [ ] | |
| RECON-13 | Applications on the host | Non-standard ports, virtual hosts, path-based apps on the same IP. | [ ] | |
| RECON-14 | JavaScript discovery | Collect all JS (incl. lazy-loaded chunks). Extract endpoints, parameters, feature flags, keys. | [ ] | |
| RECON-15 | Source maps | Check for `*.js.map` files; reconstruct source if exposed. | [ ] | |
| RECON-16 | API endpoint discovery | From JS, mobile apps, docs, proxies: REST, GraphQL, gRPC-web, WebSocket endpoints. | [ ] | |
| RECON-17 | Public directories and files | Content discovery with tuned wordlists at the agreed rate. | [ ] | |
| RECON-18 | Backup files | `.bak`, `.old`, `~`, `.swp`, `.zip`, `.tar.gz`, copies of index/config files. | [ ] | |
| RECON-19 | Configuration files | `.env`, `web.config`, `appsettings.json`, `config.php`, `.htaccess`, `docker-compose.yml`. | [ ] | |
| RECON-20 | Version control exposure | `/.git/`, `/.svn/`, `/.hg/`, `.DS_Store`. | [ ] | |
| RECON-21 | Comments and metadata | HTML/JS comments, hidden fields, debug strings, internal hostnames, developer names. | [ ] | |
| RECON-22 | Public documentation | Swagger/OpenAPI, GraphQL schema, Postman collections, developer portals, help docs. | [ ] | |
| RECON-23 | Email/user enumeration (OSINT) | Email format, staff names, usernames from public sources. Passive only. | [ ] | |
| RECON-24 | Code repository leaks | Public GitHub/GitLab repos, gists, commits containing secrets or internal URLs. | [ ] | |
| RECON-25 | Cloud/service exposure | Public S3/Azure Blob/GCS buckets, Firebase, exposed CI/CD, Kubernetes dashboards. | [ ] | |
| RECON-26 | Third-party integrations | Identify IdP, payment, analytics, email, chat, CDN and tag managers. Feed into section 20. | [ ] | |

---

## 2. Application mapping

Crawl the app as every role (unauthenticated and each authenticated role), then build the inventory below. Every later section tests rows from this inventory.

| ID | Test | Description | Status | Notes |
|---|---|---|:---:|---|
| MAP-01 | Entry points | Every request that accepts input: query, body, headers, cookies, path segments, file uploads, WebSocket frames. | [ ] | |
| MAP-02 | Execution paths | Manual walk-through plus authenticated spidering per role; capture multi-step workflows. | [ ] | |
| MAP-03 | Authentication pages | Login, logout, SSO callbacks, API token issuance, legacy/mobile login endpoints. | [ ] | |
| MAP-04 | Registration | Self-registration, invitations, account provisioning flows. | [ ] | |
| MAP-05 | Password reset | Request, token delivery, token use and password change flows. | [ ] | |
| MAP-06 | MFA | Enrolment, challenge, recovery codes, device trust, disable MFA. | [ ] | |
| MAP-07 | User profile | Profile view/edit, email/phone change, avatar upload, privacy settings. | [ ] | |
| MAP-08 | Administrative functionality | Admin panels, user management, configuration, impersonation, audit logs. | [ ] | |
| MAP-09 | File upload / download | Every upload field, import, attachment and download/export endpoint. | [ ] | |
| MAP-10 | Search | Search boxes, filters, sorting, autocomplete. | [ ] | |
| MAP-11 | API endpoints | Full API inventory with methods, auth type and object IDs. | [ ] | |
| MAP-12 | Webhooks | Outbound webhook configuration and inbound webhook receivers. | [ ] | |
| MAP-13 | Payment functionality | Cart, checkout, payment provider redirect/callback, refunds, credits, subscriptions. | [ ] | |
| MAP-14 | Export / import | CSV/XLSX/PDF export, bulk import, report generation. | [ ] | |
| MAP-15 | Account management | Delete account, change role, team/org management, invitations. | [ ] | |
| MAP-16 | Session-related functionality | Logout, session listing, "sign out everywhere", token refresh. | [ ] | |
| MAP-17 | Hidden / unlinked functionality | Endpoints from JS, old API versions, debug routes, feature-flagged features. | [ ] | |
| MAP-18 | HTTP methods | Allowed methods per endpoint (OPTIONS, PUT, PATCH, DELETE, HEAD, override headers). | [ ] | |
| MAP-19 | Parameters and request bodies | Record type (form, JSON, XML, multipart, GraphQL) and hidden/unused parameters (param mining). | [ ] | |
| MAP-20 | Cookies and tokens | All cookies, bearer tokens, API keys, CSRF tokens and where each is set and used. | [ ] | |
| MAP-21 | Role/permission matrix | For each feature, which roles should have access. Basis for section 4. | [ ] | |

### Endpoint / feature inventory

One row per endpoint and method. Mark the roles that legitimately reach it; tested roles go in Notes.

| # | Feature | Method | Endpoint | Auth required | Roles allowed | Key parameters / object IDs | State-changing | Sensitive (PII, payment, admin) | Notes |
|---|---|---|---|---|---|---|---|---|---|
| 1 | | | | | | | | | |
| 2 | | | | | | | | | |
| 3 | | | | | | | | | |

---

## 3. Authentication

Test every authentication path, including mobile, API and legacy endpoints, not just the main login form. Stay within the agreed lockout and rate limits.

> **ASVS 5.0:** V6 Authentication, V10 OAuth and OIDC · **Top 10:** A07

| ID | Test | Description | Status | Notes |
|---|---|---|:---:|---|
| AUTH-01 | Credentials over encrypted channel | Login, registration and reset submit only over HTTPS; no credentials in URLs. | [ ] | |
| AUTH-02 | Username/email enumeration | Compare responses, status codes, timing and messages across login, registration, reset and MFA for valid vs invalid users. | [ ] | |
| AUTH-03 | Weak username policy | Predictable usernames (sequential, email-based) that ease enumeration. | [ ] | |
| AUTH-04 | Weak password policy | Min length (≥8, ideally ≥15 single-factor), max length allowed ≥64, breached-password check, no forced composition rules. Test server side. | [ ] | |
| AUTH-05 | Default credentials | Admin consoles, CMS, frameworks, third-party components and newly provisioned accounts. | [ ] | |
| AUTH-06 | Brute-force protection | Repeated failed logins against one account trigger throttling, CAPTCHA or lockout. | [ ] | |
| AUTH-07 | Credential stuffing protection | Many accounts from one IP, and one account from rotating IPs/headers (`X-Forwarded-For` spoofing). | [ ] | |
| AUTH-08 | Account lockout | Threshold, duration, unlock mechanism, and whether lockout can be abused to lock out others (DoS). | [ ] | |
| AUTH-09 | Rate limiting on auth endpoints | Login, MFA, reset, registration and OTP verification endpoints, including API equivalents. | [ ] | |
| AUTH-10 | MFA bypass | Skip the MFA step by requesting post-auth pages directly, replaying a pre-MFA session, changing response values, or using alternate endpoints. | [ ] | |
| AUTH-11 | MFA weaknesses | OTP brute force, OTP reuse, long OTP validity, OTP in response, recovery code strength, MFA disable without re-auth. | [ ] | |
| AUTH-12 | Password reset weaknesses | Host header poisoning of reset link, reset link sent to attacker-controlled param, account takeover via email param arrays. | [ ] | |
| AUTH-13 | Reset token predictability | Collect several tokens; check length, entropy, timestamp/sequential patterns. | [ ] | |
| AUTH-14 | Reset token reuse | Token invalidated after use and after a newer token is issued. | [ ] | |
| AUTH-15 | Reset token expiration | Token expires within a short window (e.g. ≤1 hour). | [ ] | |
| AUTH-16 | Token leakage | Reset token not sent in Referer to third parties, not logged in URLs to analytics. | [ ] | |
| AUTH-17 | Password change | Requires current password; invalidates other sessions. | [ ] | |
| AUTH-18 | Security questions | If used: guessable or publicly discoverable answers. | [ ] | |
| AUTH-19 | Authentication bypass | Direct page request, parameter tampering (`authenticated=true`), SQLi in login, response manipulation. | [ ] | |
| AUTH-20 | Alternative authentication paths | Mobile API, older API versions, SOAP, legacy login, and partner portals enforce the same controls. | [ ] | |
| AUTH-21 | OAuth/OIDC weaknesses | `redirect_uri` validation, state/nonce, PKCE, implicit flow use, code reuse, token leakage, scope escalation, account linking. | [ ] | |
| AUTH-22 | SSO / SAML weaknesses | Signature validation (XSW, unsigned assertions), audience/recipient checks, replay, comment injection in NameID. | [ ] | |
| AUTH-23 | Remember-me functionality | Token is random, server-side, revocable, expires, and is not derived from credentials. | [ ] | |
| AUTH-24 | Browser cache of auth pages | Sensitive pages served with `no-store`; back button after logout does not show data. | [ ] | |
| AUTH-25 | Session fixation at login | Session ID rotates on authentication and privilege change. | [ ] | |
| AUTH-26 | Login CSRF | Attacker can log a victim into the attacker's account. | [ ] | |
| AUTH-27 | Authentication state inconsistencies | Partially authenticated states (pending email verification, pending MFA, disabled, locked) cannot reach protected functions. | [ ] | |
| AUTH-28 | Registration abuse | Duplicate accounts with case/unicode variants, email verification bypass, role set at signup. | [ ] | |

---

## 4. Authorisation and access control

Replay every inventory request as each other role and as unauthenticated (Autorize/AuthMatrix-style). Use two accounts per role and two tenants.

> **ASVS 5.0:** V8 Authorization · **Top 10:** A01

| ID | Test | Description | Status | Notes |
|---|---|---|:---:|---|
| AUTHZ-01 | Horizontal privilege escalation | User A reads/modifies/deletes User B's data at the same privilege level. | [ ] | |
| AUTHZ-02 | Vertical privilege escalation | Low-privilege user performs admin or higher-role actions. | [ ] | |
| AUTHZ-03 | IDOR / BOLA | Swap object IDs (numeric, UUID, encoded, composite) in path, query, body and headers for every object type. | [ ] | |
| AUTHZ-04 | Missing function-level access control | Call privileged functions directly without UI exposure. | [ ] | |
| AUTHZ-05 | Forced browsing | Request authenticated/admin URLs while unauthenticated or as a lower role. | [ ] | |
| AUTHZ-06 | Administrative endpoint access | `/admin`, `/manage`, `/internal`, actuator-style endpoints from every role. | [ ] | |
| AUTHZ-07 | Role manipulation | Modify `role`/`isAdmin`/`permissions` fields in requests, profile updates, JWT claims or registration. | [ ] | |
| AUTHZ-08 | Parameter manipulation | Tamper with `accountId`, `orgId`, `userId`, `ownerId` in bodies when the server should derive them from the session. | [ ] | |
| AUTHZ-09 | Access control via HTTP methods | Same endpoint with GET/POST/PUT/DELETE/HEAD and `X-HTTP-Method-Override`. | [ ] | |
| AUTHZ-10 | Access control via APIs | API and GraphQL equivalents of UI functions enforce the same checks (incl. older versions). | [ ] | |
| AUTHZ-11 | Multi-tenant isolation | Cross-tenant reads/writes via IDs, search, exports, reports, file URLs, websockets and caches. | [ ] | |
| AUTHZ-12 | Object ownership validation | Child objects (comments, attachments, line items) validated against the parent owner. | [ ] | |
| AUTHZ-13 | Direct access to restricted resources | Files, exports, signed URLs, static assets of other users; URL predictability and expiry. | [ ] | |
| AUTHZ-14 | Path-based bypass | Case changes, trailing slash, `..;/`, `%2e`, double slashes, path parameters to dodge proxy rules. | [ ] | |
| AUTHZ-15 | Header-based bypass | `X-Original-URL`, `X-Rewrite-URL`, `X-Forwarded-For: 127.0.0.1`, `X-Custom-IP-Authorization`. | [ ] | |
| AUTHZ-16 | Stale permissions | Removed/downgraded user or revoked invitation loses access immediately, including active sessions and tokens. | [ ] | |
| AUTHZ-17 | Impersonation features | Admin "login as" restricted, audited and cannot be triggered by lower roles. | [ ] | |

### Role access matrix

Record the observed result per role: **Allowed** (expected) · **Denied** (expected) · **BYPASS** (finding).

| Feature / endpoint | Unauthenticated | User (tenant A) | User (tenant B) | Manager | Admin | Notes |
|---|---|---|---|---|---|---|
| | | | | | | |
| | | | | | | |
| | | | | | | |

---

## 5. Session management

Covers cookie-based sessions and token-based (JWT, opaque bearer, refresh) sessions.

> **ASVS 5.0:** V7 Session Management, V9 Self-contained Tokens · **Top 10:** A07

| ID | Test | Description | Status | Notes |
|---|---|---|:---:|---|
| SESS-01 | Session mechanism review | Identify session tokens, where issued, transport and storage. | [ ] | |
| SESS-02 | Secure flag | Session and auth cookies set `Secure`. | [ ] | |
| SESS-03 | HttpOnly flag | Session cookies not readable from JavaScript. | [ ] | |
| SESS-04 | SameSite attribute | `Lax` or `Strict` for session cookies; `None` only with justification and `Secure`. | [ ] | |
| SESS-05 | Cookie scope | Domain not overly broad (parent domain); Path appropriate; `__Host-`/`__Secure-` prefixes used. | [ ] | |
| SESS-06 | Session ID entropy | Collect a sample (e.g. Burp Sequencer); ≥128 bits of entropy, no visible structure. | [ ] | |
| SESS-07 | Session fixation | Pre-login session ID is replaced after login and privilege change. | [ ] | |
| SESS-08 | Exposed session variables | Tokens not in URLs, Referer, logs, cacheable responses or GET parameters. | [ ] | |
| SESS-09 | Absolute expiration | Session has a maximum lifetime appropriate to risk. | [ ] | |
| SESS-10 | Idle timeout | Session expires after inactivity; verify server side by replaying an old token. | [ ] | |
| SESS-11 | Logout invalidation | Replay the token after logout; must be rejected server side (incl. JWT/refresh tokens). | [ ] | |
| SESS-12 | Concurrent sessions | Behaviour on multiple logins; user can see and terminate other sessions. | [ ] | |
| SESS-13 | Session revocation | Password change, MFA change, role change and account disable revoke existing sessions. | [ ] | |
| SESS-14 | Session puzzling | Same session variable reused across flows (e.g. reset flow sets identity used elsewhere). | [ ] | |
| SESS-15 | Session hijacking | Token usable from another client/IP; assess exposure paths (XSS, HTTP, logs). | [ ] | |
| SESS-16 | Token reuse | One-time tokens (CSRF, OTP, magic links, invites) cannot be replayed. | [ ] | |
| SESS-17 | JWT implementation | Signature verified; `exp`/`nbf`/`iat`/`iss`/`aud` validated; no sensitive data in payload. | [ ] | |
| SESS-18 | JWT algorithm weaknesses | `alg:none`, RS256→HS256 confusion, weak HMAC secret (offline crack), `kid`/`jku`/`x5u` injection, embedded `jwk`. | [ ] | |
| SESS-19 | JWT claim manipulation | Change `sub`, `role`, `tenant`, `scope`; check acceptance with re-signed or unsigned token. | [ ] | |
| SESS-20 | Token storage (client) | Long-lived tokens in localStorage/sessionStorage exposed to XSS; prefer HttpOnly cookies. | [ ] | |
| SESS-21 | Refresh-token security | Rotation on use, reuse detection, binding to client, expiry, revocation at logout. | [ ] | |

---

## 6. Input validation and injection

Test every entry point from MAP-01 in each input location below. Prefer time-based or boolean confirmation over data extraction; never run stacked or destructive queries (`DROP`, `UPDATE`, `DELETE`) without written approval.

> **ASVS 5.0:** V1 Encoding and Sanitization, V2 Validation · **Top 10:** A05

**Input locations to cover:** GET parameters · POST form fields · JSON (incl. nested keys and type juggling) · XML/SOAP · headers (User-Agent, Referer, X-Forwarded-\*, custom) · cookies · URL path segments · file names and file content · HTTP method · WebSocket messages · GraphQL arguments · second-order inputs (stored then used later).

| ID | Test | Description | Status | Notes |
|---|---|---|:---:|---|
| INJ-01 | SQL injection | Error, boolean, time-based and out-of-band; include `ORDER BY`, `LIMIT`, column names, JSON and second-order. | [ ] | |
| INJ-02 | NoSQL injection | Operator injection (`$ne`, `$gt`, `$regex`, `$where`) in JSON and query strings; JS evaluation. | [ ] | |
| INJ-03 | ORM / HQL injection | Raw query fragments, sort/filter builders. | [ ] | |
| INJ-04 | LDAP injection | Filter metacharacters `* ( ) & \|` in login, search and directory lookups. | [ ] | |
| INJ-05 | XPath injection | XPath-based auth or XML data queries. | [ ] | |
| INJ-06 | XML injection / XXE | Tag/attribute injection; external entities, parameter entities, OOB XXE, XInclude; also via SVG, DOCX, XLSX, SAML. | [ ] | |
| INJ-07 | OS command injection | Separators `;` `\|` `&&` `$()` `` ` ``; blind via time delay or OOB DNS; file conversion and network utilities. | [ ] | |
| INJ-08 | Server-side template injection | `{{7*7}}`, `${7*7}`, `<%= 7*7 %>`; identify engine; confirm with harmless evaluation only. | [ ] | |
| INJ-09 | Expression Language injection | `${...}`, `#{...}`, SpEL/OGNL/MVEL in Java apps. | [ ] | |
| INJ-10 | Code injection | eval-style sinks in PHP/Python/Node/Ruby; deserialisation of untrusted data (Java, .NET, PHP, Python pickle). | [ ] | |
| INJ-11 | HTML injection | Markup rendered unencoded (often a stepping stone to XSS or phishing). | [ ] | |
| INJ-12 | JavaScript injection | Input placed inside script blocks, event handlers or JSONP callbacks. | [ ] | |
| INJ-13 | CRLF / header injection | `%0d%0a` in redirects, cookies and headers; response splitting; log injection. | [ ] | |
| INJ-14 | Host header injection | Password reset poisoning, cache poisoning, routing to internal hosts. | [ ] | |
| INJ-15 | HTTP parameter pollution | Duplicate parameters in query, body and JSON; front-end vs back-end parsing differences. | [ ] | |
| INJ-16 | Mass assignment | Extra fields (`role`, `isAdmin`, `balance`, `ownerId`, `verified`) accepted on create/update. | [ ] | |
| INJ-17 | Format string injection | `%s` `%x` `%n` in inputs reaching native/legacy components or logging. | [ ] | |
| INJ-18 | SSI / ESI injection | `<!--#exec -->`, `<esi:include>` where SSI or edge caching is used. | [ ] | |
| INJ-19 | Email header / IMAP / SMTP injection | CRLF in contact forms, recipient fields, mail commands. | [ ] | |
| INJ-20 | CSV / formula injection | `=`, `+`, `-`, `@` payloads in data later exported to spreadsheets. | [ ] | |
| INJ-21 | Incubated (stored) injection | Payloads stored now and executed later in admin views, reports, emails or batch jobs. | [ ] | |
| INJ-22 | Type and length validation | Arrays instead of strings, large numbers, unicode normalisation, null bytes, overlong input; server-side validation exists. | [ ] | |

---

## 7. Cross-site scripting

Identify the output context (HTML body, attribute, JS, URL, CSS) for each reflection, then test encoding for that context. Use benign proof payloads (e.g. `alert(document.domain)`); do not steal real users' sessions.

> **ASVS 5.0:** V1, V3 Web Frontend Security · **Top 10:** A05

| ID | Test | Description | Status | Notes |
|---|---|---|:---:|---|
| XSS-01 | Reflected XSS | Every reflected parameter, header and path segment, per output context. | [ ] | |
| XSS-02 | Stored XSS | Profile fields, comments, names, tickets, messages; check every view where the data is rendered. | [ ] | |
| XSS-03 | DOM-based XSS | Sources (`location`, `hash`, `postMessage`, storage) flowing into sinks (`innerHTML`, `eval`, `document.write`, jQuery `html()`). | [ ] | |
| XSS-04 | Mutation XSS | Payloads that survive sanitisers (DOMPurify config, custom filters) and mutate on re-parse. | [ ] | |
| XSS-05 | XSS through JSON | JSON served as `text/html`, JSONP callbacks, JSON embedded into HTML without escaping. | [ ] | |
| XSS-06 | XSS through file names | Uploaded file names rendered in listings, admin views and emails. | [ ] | |
| XSS-07 | XSS through uploaded content | HTML, SVG, XML, PDF served inline from the app origin. | [ ] | |
| XSS-08 | XSS in administrative interfaces | Blind XSS via user-supplied data viewed by staff (use an authorised callback host). | [ ] | |
| XSS-09 | XSS in error messages | 404/500 pages, validation messages, search "no results". | [ ] | |
| XSS-10 | XSS in email/notification | HTML emails, in-app notifications, push notifications, PDFs generated from user input. | [ ] | |
| XSS-11 | Output encoding effectiveness | Context-aware encoding consistent across views; framework auto-escaping not bypassed (`dangerouslySetInnerHTML`, `v-html`, `\|safe`). | [ ] | |
| XSS-12 | Content Security Policy effectiveness | No `unsafe-inline`/`unsafe-eval`, no wildcard or JSONP-hosting allowed sources, nonces/hashes, `object-src`/`base-uri` set. Note whether CSP would block a validated XSS. | [ ] | |
| XSS-13 | CSS injection | User-controlled styles enabling data exfiltration or UI redress. | [ ] | |

---

## 8. Cross-site request forgery

List every state-changing request from the inventory and test each without a valid token and cross-origin.

> **ASVS 5.0:** V3 · **Top 10:** A01

| ID | Test | Description | Status | Notes |
|---|---|---|:---:|---|
| CSRF-01 | State-changing requests inventory | Identify all requests that change data, settings, money or permissions. | [ ] | |
| CSRF-02 | Missing CSRF protection | Remove token; submit from a cross-origin PoC page. | [ ] | |
| CSRF-03 | Weak / predictable tokens | Token entropy, static tokens, tokens derived from user ID or time. | [ ] | |
| CSRF-04 | Token reuse | Token tied to the session; another user's token rejected; token from one form accepted elsewhere? | [ ] | |
| CSRF-05 | Token validation | Blank token, removed parameter, removed header, changed case of parameter name. | [ ] | |
| CSRF-06 | SameSite cookie protections | Effectiveness given cookie SameSite values, top-level GET navigation and same-site subdomains. | [ ] | |
| CSRF-07 | Origin / Referer checks | Missing Origin, `null` Origin, suffix/prefix domain bypasses. | [ ] | |
| CSRF-08 | Login and logout CSRF | Forced login into attacker account; forced logout. | [ ] | |
| CSRF-09 | CSRF via alternative methods | POST action accepted as GET; method override parameters. | [ ] | |
| CSRF-10 | JSON-based CSRF | JSON endpoints accepting `text/plain` or form content types; CORS preflight avoidance. | [ ] | |
| CSRF-11 | Clickjacking-assisted actions | Sensitive one-click actions frameable (see HTTP-17). | [ ] | |

---

## 9. File handling

Use harmless proof files (e.g. a script that prints a marker string, EICAR for AV checks). Never upload web shells that persist; delete test files and record what was uploaded where.

> **ASVS 5.0:** V5 File Handling · **Top 10:** A01, A05

| ID | Test | Description | Status | Notes |
|---|---|---|:---:|---|
| FILE-01 | Unrestricted file upload | Any file type accepted; size, count and type limits enforced server side. | [ ] | |
| FILE-02 | Malicious file upload | EICAR / polyglot files; is content scanned or quarantined? | [ ] | |
| FILE-03 | Extension bypass | Case variants (`.pHp`), alternate extensions (`.phtml`, `.php5`, `.aspx`, `.jspx`), trailing dot/space, `::$DATA`. | [ ] | |
| FILE-04 | MIME-type bypass | Changed `Content-Type` header vs actual content. | [ ] | |
| FILE-05 | Content validation | Magic bytes, image re-encoding, polyglot (GIF+PHP, JPEG+HTML). | [ ] | |
| FILE-06 | Double extensions | `file.php.jpg`, `file.jpg.php`; server handler mapping behaviour. | [ ] | |
| FILE-07 | Null-byte techniques | `file.php%00.jpg` on legacy stacks only; record as N/A on modern runtimes with reason. | [ ] | |
| FILE-08 | Path traversal through filenames | `../../` in filename, zip-slip in archives. | [ ] | |
| FILE-09 | Filename manipulation | Unicode, overlong, reserved names (`CON`, `NUL`), special characters, leading dots (`.htaccess`). | [ ] | |
| FILE-10 | SVG-based attacks | Script in SVG, XXE in SVG, SVG served inline from app origin. | [ ] | |
| FILE-11 | HTML file uploads | `.html`/`.htm`/`.xhtml` served from app origin → stored XSS. | [ ] | |
| FILE-12 | Script uploads | Server-side scripts stored in executable web root. | [ ] | |
| FILE-13 | Server-side execution | Confirm with harmless marker output only. | [ ] | |
| FILE-14 | File overwrite | Upload with an existing name overwrites other users' or system files. | [ ] | |
| FILE-15 | Storage location and serving | Uploads stored outside web root or on separate domain; `Content-Disposition: attachment`; `X-Content-Type-Options: nosniff`. | [ ] | |
| FILE-16 | File download authorisation | Download endpoints check ownership; IDs and signed URLs not guessable or reusable indefinitely. | [ ] | |
| FILE-17 | Temporary file exposure | Temp/processing files accessible during or after conversion. | [ ] | |
| FILE-18 | Archive handling | Zip bombs (only with approval), zip-slip, nested archives, symlinks in archives. | [ ] | |
| FILE-19 | Image processing | ImageMagick/Ghostscript/ExifTool-class issues, pixel-flood (with approval). Validate version-specific issues before reporting. | [ ] | |

---

## 10. Path traversal and file inclusion

Target parameters that reference files, templates, languages or pages. Read only harmless proof files (e.g. `/etc/hostname`, `win.ini`).

> **ASVS 5.0:** V5, V15 · **Top 10:** A01

| ID | Test | Description | Status | Notes |
|---|---|---|:---:|---|
| PATH-01 | `../` traversal | Basic relative traversal in file parameters and path segments. | [ ] | |
| PATH-02 | URL-encoded traversal | `%2e%2e%2f`, `..%2f`, `%2e%2e/`. | [ ] | |
| PATH-03 | Double encoding | `%252e%252e%252f`; overlong UTF-8 `%c0%ae`. | [ ] | |
| PATH-04 | Filter bypass | `....//`, `..;/`, mixed separators, prefix requirements (`/var/www/../../etc`). | [ ] | |
| PATH-05 | Windows path traversal | `..\`, `..%5c`, drive letters, UNC paths. | [ ] | |
| PATH-06 | Linux path traversal | `/etc/passwd`, `/proc/self/environ`. | [ ] | |
| PATH-07 | Absolute paths | Absolute path accepted directly in the parameter. | [ ] | |
| PATH-08 | Local File Inclusion | Includes of local files; PHP wrappers (`php://filter`) where relevant. | [ ] | |
| PATH-09 | Remote File Inclusion | Include of an external URL under tester control. | [ ] | |
| PATH-10 | Arbitrary file read | Source code, configs, keys reachable via traversal. Stop at proof; do not exfiltrate secrets. | [ ] | |
| PATH-11 | File disclosure through APIs | File/attachment APIs, export endpoints, template selectors. | [ ] | |

---

## 11. Server-side request forgery

Identify every feature where the server fetches a URL or resource. Use a tester-controlled OOB host. Do not scan internal networks or interact with internal services beyond proof of reach.

> **ASVS 5.0:** V1, V15 · **Top 10:** A01 · **API:** API7

| ID | Test | Description | Status | Notes |
|---|---|---|:---:|---|
| SSRF-01 | Identify SSRF surfaces | URL fetchers, link previews, avatars by URL, imports, webhooks, PDF/HTML renderers, XML parsers, integrations. | [ ] | |
| SSRF-02 | External interaction | Confirm server-side fetch via OOB DNS/HTTP callback. | [ ] | |
| SSRF-03 | localhost access | `127.0.0.1`, `localhost`, `[::1]`, `0.0.0.0`, decimal/octal/hex IP forms. | [ ] | |
| SSRF-04 | Private IP ranges | `10/8`, `172.16/12`, `192.168/16`, link-local; prove reach to one approved host only. | [ ] | |
| SSRF-05 | Cloud metadata endpoints | `169.254.169.254` (AWS IMDSv1/v2, Azure, GCP headers), `fd00:ec2::254`. Stop at proof; do not use retrieved credentials. | [ ] | |
| SSRF-06 | Redirect-based SSRF | External URL that 30x-redirects to an internal target. | [ ] | |
| SSRF-07 | DNS rebinding | Hostname resolving external at validation, internal at fetch (only if allow-list by resolution is used). | [ ] | |
| SSRF-08 | URL parser inconsistencies | `http://allowed@evil`, `evil#allowed`, backslashes, unicode, embedded credentials. | [ ] | |
| SSRF-09 | Protocol restrictions | `file://`, `gopher://`, `dict://`, `ftp://`, `jar://` accepted? | [ ] | |
| SSRF-10 | SSRF through file imports | URL-based imports, XXE in uploaded XML/Office documents. | [ ] | |
| SSRF-11 | SSRF through webhooks | Webhook URLs to internal targets; response or timing differences. | [ ] | |
| SSRF-12 | SSRF through PDF/image processing | HTML-to-PDF renderers (iframes, img, link tags), SVG rasterisers, headless browsers. | [ ] | |
| SSRF-13 | Blind SSRF impact assessment | Timing/error oracles; document reach without exploiting internal services. | [ ] | |

---

## 12. Business logic

Business logic is a primary test area, not an optional one: automated scanners rarely find these issues. For each workflow in the inventory, write down the intended steps and rules, then test what happens when legitimate steps are skipped, reordered, repeated or modified. Use sandbox payment methods only.

> **ASVS 5.0:** V2 Validation and Business Logic · **Top 10:** A06 Insecure Design · **API:** API6

**Per-workflow method:** document the intended sequence and invariants (who, what, how many, in what order, at what price); then for each step try removing it, repeating it, doing it out of order, and changing server-trusted values the client should not control.

| ID | Test | Description | Status | Notes |
|---|---|---|:---:|---|
| BL-01 | Workflow / step sequence bypass | Reach a later step directly, skipping validation or payment steps. | [ ] | |
| BL-02 | State-transition bypass | Force invalid transitions (draft to approved, pending to shipped) by calling the transition endpoint directly. | [ ] | |
| BL-03 | Price manipulation | Alter price, currency, tax, shipping or totals in the request; confirm the server recalculates. | [ ] | |
| BL-04 | Quantity manipulation | Fractional, zero, very large or array quantities; server-side limits and recalculation. | [ ] | |
| BL-05 | Negative values | Negative quantity, amount or balance producing credits or refunds. | [ ] | |
| BL-06 | Integer and rounding issues | Overflow, truncation and rounding in totals, points or balances. | [ ] | |
| BL-07 | Duplicate transactions | Resubmit a completed purchase, transfer or submission. | [ ] | |
| BL-08 | Replay of signed/tokenised requests | Replay a captured signed request or one-time token. | [ ] | |
| BL-09 | Coupon / discount abuse | Stacking, reusing single-use codes, applying after total, case variants. | [ ] | |
| BL-10 | Loyalty / credit abuse | Earn and redeem points or store credit in ways the design did not intend. | [ ] | |
| BL-11 | Account-limit bypass | Exceed per-account caps (seats, API usage, storage) by manipulating requests. | [ ] | |
| BL-12 | Registration-limit bypass | Create more accounts than allowed; bypass one-per-email or one-per-device rules. | [ ] | |
| BL-13 | Invitation / referral abuse | Reuse or forge invitations or referral rewards. | [ ] | |
| BL-14 | Approval bypass | Self-approve, or act on items still awaiting another party. | [ ] | |
| BL-15 | Payment-flow manipulation | Mark an order paid without completing payment; tamper with provider callbacks; confirm server-to-server verification. | [ ] | |
| BL-16 | Refund / cancellation abuse | Refund more than paid; refund and keep goods or access. | [ ] | |
| BL-17 | Missing server-side validation | Rules enforced only in the UI (hidden fields, disabled buttons, client checks) are enforced server side. | [ ] | |
| BL-18 | Trusting client-side controls | Values the client should not set (`role`, `tier`, `verified`, `ownerId`) are ignored server side. | [ ] | |
| BL-19 | Time / sequence assumptions | Manipulate dates, expiry and ordering (back-dating, future-dating, acting after expiry). | [ ] | |
| BL-20 | Unexpected file / data in a flow | Upload or submit data types the workflow does not expect. | [ ] | |

---

## 13. Race conditions and concurrency

Send many copies of the same request in parallel (single-packet / last-byte-sync techniques) to hit the window between check and use. Agree concurrency limits with the client first.

> **Top 10:** A06 · **WSTG:** WSTG-BUSL-04 (behaviour under concurrency)

| ID | Test | Description | Status | Notes |
|---|---|---|:---:|---|
| RACE-01 | Duplicate / parallel submissions | Same state-changing request fired concurrently to bypass once-only checks. | [ ] | |
| RACE-02 | Balance / inventory manipulation | Concurrent withdrawals, purchases or stock decrements exceeding available amount (overdraft, oversell). | [ ] | |
| RACE-03 | Coupon / credit reuse | Redeem a single-use coupon, gift card or credit multiple times in parallel. | [ ] | |
| RACE-04 | Invitation / limit reuse | Exceed per-account or per-code limits via parallel requests. | [ ] | |
| RACE-05 | Password reset / token races | Parallel reset or token-consumption requests causing reuse or takeover. | [ ] | |
| RACE-06 | File operation races | TOCTOU in upload, move, scan-then-serve or conversion steps. | [ ] | |
| RACE-07 | Approval / workflow races | Concurrent approve/act requests that bypass a required gate. | [ ] | |
| RACE-08 | Rate-limit bypass via parallelism | Burst requests arriving together defeat a per-second limit. | [ ] | |

---

## 14. API security

Apply where REST, GraphQL, gRPC-web or WebSocket APIs exist. Each row notes its OWASP API Security Top 10:2023 mapping. Test APIs with each role and across tenants, exactly as in section 4.

| ID | Test | Description | API Top 10 | Status | Notes |
|---|---|---|:---:|:---:|---|
| API-01 | API discovery and inventory | Enumerate endpoints, versions and environments from JS, mobile apps, docs, schemas and proxies. | API9 | [ ] | |
| API-02 | Authentication | Every endpoint requires valid auth; no endpoints silently unauthenticated; token types validated. | API2 | [ ] | |
| API-03 | BOLA / IDOR | Object-level authorisation on every object reference (see AUTHZ-03). | API1 | [ ] | |
| API-04 | Function-level authorisation (BFLA) | Privileged and admin operations enforce role checks; method-based access. | API5 | [ ] | |
| API-05 | Excessive data exposure | Responses return more fields than the client needs (internal flags, PII, other users' data). | API3 | [ ] | |
| API-06 | Mass assignment | Writable properties the client should not set (`role`, `balance`, `verified`, `ownerId`). | API3 | [ ] | |
| API-07 | Improper property-level access | Read or write of restricted object properties. | API3 | [ ] | |
| API-08 | Rate limiting / resource consumption | Per-user and per-endpoint limits; pagination caps; expensive queries. | API4 | [ ] | |
| API-09 | Resource exhaustion | Large page sizes, batch operations, deeply nested payloads, large file refs. | API4 | [ ] | |
| API-10 | Injection | SQL/NoSQL/command/other injection through API parameters and bodies (see section 6). | API8 / A05 | [ ] | |
| API-11 | Security misconfiguration | Verbose errors, permissive CORS, missing headers, debug features (see section 16). | API8 | [ ] | |
| API-12 | Unrestricted access to sensitive business flows | Automatable abuse of flows (bulk purchase, signup, booking) without anti-automation. | API6 | [ ] | |
| API-13 | SSRF via API | URL parameters consumed server side (see section 11). | API7 | [ ] | |
| API-14 | Improper inventory management | Old versions (v1 beside v2), staging/debug hosts, deprecated endpoints still live. | API9 | [ ] | |
| API-15 | Deprecated / debug endpoints | `/debug`, `/test`, `/actuator`, GraphQL introspection and debug flags in production. | API9 / API8 | [ ] | |
| API-16 | Unsafe consumption of upstream APIs | Trusting third-party/integration responses without validation. | API10 | [ ] | |
| API-17 | GraphQL – introspection | Introspection enabled in production; schema exposure. | API8 | [ ] | |
| API-18 | GraphQL – query cost / depth | Deeply nested or recursive queries; batching/aliases to amplify; cost limits. | API4 | [ ] | |
| API-19 | GraphQL – authorisation | Field- and object-level authorisation; mutations enforce access; batching bypass. | API1 / API3 / API5 | [ ] | |
| API-20 | GraphQL – injection / IDOR | Injection and object access through arguments and variables. | API1 | [ ] | |
| API-21 | WebSocket security | Origin check on handshake, auth on connect and per-message, authorisation, injection, CSWSH. | API2 / API5 | [ ] | |
| API-22 | CORS | Reflected/allow-all origins with credentials, `null` origin, trusted-subdomain and suffix bypass. | API8 | [ ] | |
| API-23 | JWT / token handling | See SESS-17 to SESS-21 for algorithm, claim and refresh issues. | API2 | [ ] | |
| API-24 | OAuth / OIDC | See AUTH-21 for `redirect_uri`, PKCE, scope and token-leakage issues. | API2 | [ ] | |
| API-25 | HTTP method handling | Unexpected methods (PUT/DELETE/PATCH) accepted without authorisation. | API5 | [ ] | |

---

## 15. HTTP and transport security

> **ASVS 5.0:** V3 Web Frontend Security, V11 Cryptography, V13 Configuration · **Top 10:** A02

| ID | Test | Description | Status | Notes |
|---|---|---|:---:|---|
| HTTP-01 | HTTPS enforcement | All sensitive pages and APIs served only over HTTPS. | [ ] | |
| HTTP-02 | HTTP-to-HTTPS redirect | Plain HTTP redirects to HTTPS; no sensitive content served on HTTP. | [ ] | |
| HTTP-03 | HSTS | `Strict-Transport-Security` with adequate `max-age`; `includeSubDomains`; `preload` where appropriate. | [ ] | |
| HTTP-04 | TLS configuration | No SSLv3/TLS 1.0/1.1; strong ciphers; valid cert chain; no weak renegotiation. Validate before reporting. | [ ] | |
| HTTP-05 | Mixed content | HTTPS pages do not load active resources over HTTP. | [ ] | |
| HTTP-06 | CORS policy | `Access-Control-Allow-Origin` not reflected or wildcard with credentials; methods/headers scoped. | [ ] | |
| HTTP-07 | Content-Security-Policy | Present and restrictive (see XSS-12). | [ ] | |
| HTTP-08 | X-Content-Type-Options | `nosniff` on responses. | [ ] | |
| HTTP-09 | Referrer-Policy | Set to limit referrer leakage (e.g. `strict-origin-when-cross-origin`). | [ ] | |
| HTTP-10 | Permissions-Policy | Restricts powerful features (camera, geolocation, etc.). | [ ] | |
| HTTP-11 | Cache-Control | Sensitive responses `no-store`/`private`; no auth data cached. | [ ] | |
| HTTP-12 | Cookie security attributes | Secure, HttpOnly, SameSite, scope, prefixes (see SESS-02 to SESS-05). | [ ] | |
| HTTP-13 | Host header handling | Spoofed/duplicate Host, `X-Forwarded-Host` effects on links, resets, routing and cache. | [ ] | |
| HTTP-14 | X-Forwarded-\* handling | Trust of `X-Forwarded-For`/`Proto`/`Host` for access control, rate limiting or logging. | [ ] | |
| HTTP-15 | HTTP request smuggling | CL.TE / TE.CL / TE.TE and CL.0 desync indicators via timing; confirm carefully, do not poison shared infrastructure. | [ ] | |
| HTTP-16 | HTTP methods and TRACE/OPTIONS | Dangerous methods disabled; TRACE off (XST); OPTIONS does not leak. | [ ] | |
| HTTP-17 | Clickjacking protection | `X-Frame-Options` or CSP `frame-ancestors` on sensitive pages; build a framing PoC. | [ ] | |
| HTTP-18 | Open redirect | `redirect`/`return`/`next` parameters allow external destinations (phishing, token theft, OAuth abuse). | [ ] | |

---

## 16. Security misconfiguration

Do not report an old version as vulnerable without validating the specific issue applies.

> **ASVS 5.0:** V13 Configuration · **Top 10:** A02

| ID | Test | Description | Status | Notes |
|---|---|---|:---:|---|
| CONF-01 | Debug mode | Framework debug enabled (Django, Flask, Rails, Symfony, Laravel) exposing config or an interactive console. | [ ] | |
| CONF-02 | Verbose errors / stack traces | Errors reveal stack traces, queries, paths or versions (see section 19). | [ ] | |
| CONF-03 | Directory listing | Indexing enabled on directories. | [ ] | |
| CONF-04 | Default pages / content | Server welcome pages, sample apps, install scripts, setup wizards. | [ ] | |
| CONF-05 | Default credentials | On admin consoles, databases, dashboards and components (see AUTH-05). | [ ] | |
| CONF-06 | Exposed admin interfaces | Admin/management consoles reachable without network restriction. | [ ] | |
| CONF-07 | Development / test endpoints | Debug routes, test harnesses, mock endpoints, feature-flag toggles in production. | [ ] | |
| CONF-08 | Backup and old files | `.bak`, `.old`, archives, editor swap files (see RECON-18). | [ ] | |
| CONF-09 | Configuration / environment files | `.env`, config files, secrets files reachable over HTTP. | [ ] | |
| CONF-10 | Source code exposure | `.git`/`.svn`, source maps, exposed repositories or archives. | [ ] | |
| CONF-11 | Logs exposed | Application, access or error logs reachable over HTTP. | [ ] | |
| CONF-12 | API docs / schema exposure | Swagger/OpenAPI, GraphQL introspection, Postman collections public in production. | [ ] | |
| CONF-13 | Server and framework banners | `Server`, `X-Powered-By`, `X-AspNet-Version`, framework and language versions disclosed. Informational. | [ ] | |
| CONF-14 | Cloud storage misconfiguration | Public buckets, listable containers, writable storage (see RECON-25). | [ ] | |
| CONF-15 | Unused / dangerous features | Unneeded HTTP methods, modules, ports, services enabled. | [ ] | |
| CONF-16 | Security header baseline | Consolidated check that CONF/HTTP headers are consistent across the app. | [ ] | |
| CONF-17 | Subdomain / vhost misrouting | Default vhost, staging content, or a forgotten app on a shared host. | [ ] | |
| CONF-18 | File extension handling | Server reveals source or behaves unexpectedly for odd extensions. | [ ] | |

---

## 17. Client-side security

> **ASVS 5.0:** V3 Web Frontend Security · **Top 10:** A02, A05

| ID | Test | Description | Status | Notes |
|---|---|---|:---:|---|
| CLNT-01 | DOM-based XSS | Source-to-sink analysis in JavaScript (see XSS-03). | [ ] | |
| CLNT-02 | Client-side validation bypass | Submit values the UI blocks directly to the server. | [ ] | |
| CLNT-03 | Secrets in JavaScript | API keys, tokens, credentials, internal URLs hardcoded in JS or config. Verify key is live/sensitive before reporting. | [ ] | |
| CLNT-04 | Source maps in production | `.map` files reconstructing source and comments. | [ ] | |
| CLNT-05 | Dangerous JS functions | `eval`, `Function`, `setTimeout(string)`, `innerHTML`, `document.write` on user data. | [ ] | |
| CLNT-06 | postMessage security | Missing origin checks on message handlers; sensitive data posted to a wildcard target. | [ ] | |
| CLNT-07 | Client-side access control | Routes/UI hidden by JS only; underlying data/API still reachable. | [ ] | |
| CLNT-08 | Browser storage of sensitive data | Tokens, PII or secrets in localStorage/sessionStorage/IndexedDB. | [ ] | |
| CLNT-09 | Web messaging / WebSockets | Origin and data handling for cross-document and socket messages. | [ ] | |
| CLNT-10 | Cross-origin resource sharing (client) | `crossorigin` usage, SRI on third-party scripts. | [ ] | |
| CLNT-11 | Third-party JavaScript | Inventory external scripts; supply-chain exposure, tag managers, excessive trust (see section 21). | [ ] | |
| CLNT-12 | Client-side dependency vulnerabilities | Known-vulnerable frontend libraries; validate the specific issue (see section 21). | [ ] | |
| CLNT-13 | Reverse tabnabbing | `target=_blank` links without `rel=noopener`. | [ ] | |
| CLNT-14 | Clickjacking (client) | Framing of sensitive UI (see HTTP-17). | [ ] | |

---

## 18. Cryptography and sensitive data

Confirm weaknesses by observation; do not attempt to crack production secrets beyond demonstrating feasibility.

> **ASVS 5.0:** V11 Cryptography, V14 Data Protection · **Top 10:** A04

| ID | Test | Description | Status | Notes |
|---|---|---|:---:|---|
| CRYPT-01 | Password storage | Strong, salted, slow hashing (bcrypt/scrypt/argon2). Infer from reset/change behaviour and any disclosed hashes. | [ ] | |
| CRYPT-02 | Sensitive data in transit | All sensitive data over TLS; no credentials or tokens over HTTP (see section 15). | [ ] | |
| CRYPT-03 | Weak algorithms | MD5/SHA1 for signing, DES/RC4, ECB mode, weak key sizes in app features. | [ ] | |
| CRYPT-04 | Weak / predictable randomness | Tokens, IDs, OTPs, reset tokens using non-crypto RNG (see AUTH-13, SESS-06). | [ ] | |
| CRYPT-05 | Hardcoded secrets | Keys, passwords, tokens in JS, source, configs, mobile apps or repos. | [ ] | |
| CRYPT-06 | Sensitive data in URLs | Tokens, session IDs, PII in query strings (logged, cached, in Referer). | [ ] | |
| CRYPT-07 | Sensitive data in responses | Over-disclosure of PII, hashes, internal IDs, other users' data (see API-05). | [ ] | |
| CRYPT-08 | Sensitive data in logs | Secrets or PII in client-visible logs, error output or debug responses. | [ ] | |
| CRYPT-09 | Sensitive data caching | Sensitive responses cacheable by browser or shared caches (see HTTP-11). | [ ] | |
| CRYPT-10 | Encryption implementation | App-level encryption uses authenticated modes; IV/nonce handling; no padding-oracle behaviour. | [ ] | |
| CRYPT-11 | Key and secret exposure | Keys retrievable via traversal, backups, metadata or misconfig (see sections 10, 11, 16). | [ ] | |
| CRYPT-12 | PII minimisation and masking | PII masked where appropriate (card numbers, national IDs); export/print paths considered. | [ ] | |

---

## 19. Error handling and information disclosure

> **ASVS 5.0:** V13, V16 Security Logging and Error Handling · **Top 10:** A02, A10 Mishandling of Exceptional Conditions

| ID | Test | Description | Status | Notes |
|---|---|---|:---:|---|
| ERR-01 | Stack traces | Unhandled exceptions return stack traces to the client. | [ ] | |
| ERR-02 | Database / SQL errors | DB error text disclosed (also an injection oracle). | [ ] | |
| ERR-03 | Internal paths and hostnames | Absolute paths, internal hostnames or IPs in responses. | [ ] | |
| ERR-04 | User / email disclosure | Error, enumeration or export paths reveal usernames or emails (see AUTH-02). | [ ] | |
| ERR-05 | Server / framework / version info | Banners and errors disclose software and versions (see CONF-13). Informational unless a validated CVE applies. | [ ] | |
| ERR-06 | Debug information | Debug flags, trace IDs, verbose JSON errors, dev messages. | [ ] | |
| ERR-07 | Source code disclosure | Code returned instead of executed, or via errors (see CONF-10). | [ ] | |
| ERR-08 | Secrets in errors | API keys or tokens echoed in error messages or responses. | [ ] | |
| ERR-09 | Sensitive response headers | Internal headers (`X-Debug`, `X-Powered-By`, backend IDs) exposed. | [ ] | |
| ERR-10 | Exceptional-condition handling | Behaviour on malformed, oversized or unexpected input: fails safe, does not leak, does not reach an insecure state. | [ ] | |
| ERR-11 | Differential responses | Timing/length/status differences that leak valid data or state. | [ ] | |

---

## 20. Third-party and integration security

> **ASVS 5.0:** V10 OAuth/OIDC, V13 · **Top 10:** A08 Software or Data Integrity Failures · **API:** API10

| ID | Test | Description | Status | Notes |
|---|---|---|:---:|---|
| TP-01 | OAuth / social login providers | `redirect_uri` and account-linking abuse across providers (see AUTH-21). | [ ] | |
| TP-02 | Payment providers | Callback integrity, server-side verification, tampering with return parameters (see BL-15). | [ ] | |
| TP-03 | Email / SMS services | Header injection, spoofing, open relay behaviour, template injection. | [ ] | |
| TP-04 | Cloud storage | Signed URL scope and expiry, bucket permissions, direct-to-storage upload policies. | [ ] | |
| TP-05 | Webhooks (outbound) | SSRF to internal targets, missing signature verification on receipt (see SSRF-11). | [ ] | |
| TP-06 | External APIs consumed | Validation of upstream responses; failure handling; injection via upstream data. | [ ] | |
| TP-07 | SSO / SAML | Assertion signature and audience validation, replay, IdP-initiated flows (see AUTH-22). | [ ] | |
| TP-08 | Analytics / tag managers | Data leakage to third parties; tag manager as an injection vector. | [ ] | |
| TP-09 | Third-party JavaScript | Integrity (SRI), trust level, compromise impact (see CLNT-11). | [ ] | |
| TP-10 | External redirects | Open redirect to third parties (see HTTP-18). | [ ] | |
| TP-11 | Callback / redirect URI validation | Strict allow-list on OAuth and integration callbacks; no wildcard/suffix matches. | [ ] | |
| TP-12 | Integration credentials | API keys/secrets for integrations not exposed client-side; scoped least-privilege. | [ ] | |
| TP-13 | Integration authorisation | Actions via integrations enforce the same access control as the UI. | [ ] | |

---

## 21. Dependency and component security

Identify components, then validate real applicability before reporting. Do not flag a component as exploitable solely because the version is old.

> **ASVS 5.0:** V13 · **Top 10:** A03 Software Supply Chain Failures

| ID | Test | Description | Status | Notes |
|---|---|---|:---:|---|
| DEP-01 | Component inventory | Frontend libraries, backend frameworks, CMS, plugins, server software, JS dependencies and their versions. | [ ] | |
| DEP-02 | Known vulnerabilities | Map identified versions to advisories; confirm the specific CVE affects the deployed configuration and is reachable. | [ ] | |
| DEP-03 | End-of-life components | Unsupported frameworks, runtimes or CMS versions no longer receiving fixes. | [ ] | |
| DEP-04 | Outdated versions | Behind current patch level; note gap, validate exploitability before claiming. | [ ] | |
| DEP-05 | Unnecessary components | Unused plugins, modules, sample apps increasing attack surface. | [ ] | |
| DEP-06 | Exposed component versions | Versions disclosed via banners, paths, static asset fingerprints (see CONF-13). | [ ] | |
| DEP-07 | Vulnerable JS libraries | Client-side libraries with known DOM XSS / prototype pollution issues; confirm reachable sink. | [ ] | |
| DEP-08 | Integrity of delivered code | SRI on third-party scripts; package integrity; no untrusted CDN for critical scripts. | [ ] | |
| DEP-09 | Known CMS/plugin issues | Platform-specific checks (WordPress, Drupal, etc.) validated against the live instance. | [ ] | |

---

## 22. File and document security

Where the application generates, stores or serves documents.

> **ASVS 5.0:** V5, V14

| ID | Test | Description | Status | Notes |
|---|---|---|:---:|---|
| DOC-01 | Metadata exposure | Documents retain metadata (author, software, revision, comments). | [ ] | |
| DOC-02 | EXIF / image metadata | GPS, device, software data in uploaded or served images. | [ ] | |
| DOC-03 | Author / creator info | Internal usernames or names embedded in generated files. | [ ] | |
| DOC-04 | Internal paths in documents | File paths, server names, templates embedded in output. | [ ] | |
| DOC-05 | Embedded active content | Macros or scripts in generated or accepted documents; handling of malicious macros. | [ ] | |
| DOC-06 | File preview / rendering | In-app previewers (XXE, SSRF, XSS via rendered content). | [ ] | |
| DOC-07 | Document conversion | Server-side conversion (HTML-to-PDF SSRF/LFI, Office conversion issues). | [ ] | |
| DOC-08 | Download authorisation | Document downloads enforce ownership (see FILE-16). | [ ] | |
| DOC-09 | Public document exposure | Documents indexed, guessable URLs, or on public storage (see RECON-25). | [ ] | |
| DOC-10 | Generated-file injection | User input in generated PDFs/spreadsheets causing injection (see INJ-20, XSS-10). | [ ] | |

---

## 23. Reporting and evidence collection

Raise a finding (F-01, F-02, ...) only for a **Validated Finding `[V]`**. Potential findings stay in the checklist as `[!]` until confirmed. Capture evidence as you test, not afterwards. Copy the template below per finding.

### Finding template

| Field | Value |
|---|---|
| **ID** | F-01 |
| **Title** | |
| **Severity** | Critical / High / Medium / Low / Info |
| **CVSS v4.0 score** | |
| **CVSS v4.0 vector** | `CVSS:4.0/AV:_/AC:_/AT:_/PR:_/UI:_/VC:_/VI:_/VA:_/SC:_/SI:_/SA:_` |
| **CWE** | CWE-___ |
| **OWASP Top 10:2025** | A__ |
| **OWASP WSTG reference** | WSTG-____-__ |
| **Affected endpoint / functionality** | |
| **Preconditions** | (role, state, prerequisites) |
| **Description** | (what the weakness is, concisely) |
| **Steps to reproduce** | 1. ...<br>2. ...<br>3. ... |
| **Evidence** | (raw request/response, screenshots, command output; secrets and PII redacted) |
| **Security impact** | (technical consequence) |
| **Business impact** | (consequence to the client, where known) |
| **Remediation** | (practical, developer-facing fix) |
| **References** | (WSTG, CWE, vendor advisory) |

> [!IMPORTANT]
> **Evidence rules:** preserve enough raw technical detail (HTTP requests and responses, timestamps, command output) for another tester to reproduce the finding independently. Do not invent evidence, and do not claim exploitability that was not demonstrated.

### Findings summary

| ID | Finding | Severity | CVSS v4.0 | CWE | OWASP Mapping | Status |
|---|---|---|---|---|---|---|
| F-01 | | | | | | |
| F-02 | | | | | | |
| F-03 | | | | | | |

### Testing coverage

Count checklist rows (the ID rows across sections 1–22), not sub-bullets. Fill at the end of testing.

| Metric | Count |
|---|---|
| Total checklist items | |
| Tested - No Issue `[x]` | |
| Not Tested `[ ]` | |
| Potential findings `[!]` | |
| Validated findings `[V]` | |
| Informational `[i]` | |

---

## Important rules

- [ ] Do not blindly mark tests as completed; mark only with evidence the control works.
- [ ] Do not invent evidence.
- [ ] Do not invent vulnerabilities.
- [ ] Do not assume an outdated version is vulnerable without validating the specific issue.
- [ ] Clearly distinguish informational observations from security vulnerabilities.
- [ ] Prioritise practical manual testing over purely theoretical checks.
- [ ] Include both authenticated and unauthenticated testing where applicable.
- [ ] Test every relevant function with multiple user roles.
- [ ] Include API testing when APIs are present.
- [ ] Map findings to the most appropriate CWE and OWASP category.
- [ ] Use CVSS v4.0 for confirmed vulnerabilities.
- [ ] Keep descriptions concise and understandable.
- [ ] Give remediation that is practical for developers.
- [ ] Reference the applicable OWASP WSTG test case wherever possible.
- [ ] Do not perform destructive testing unless explicitly authorised.
- [ ] Do not test systems outside the defined scope.
- [ ] Preserve evidence sufficient for another tester to reproduce the finding.
- [ ] If a test cannot be performed, record why rather than assuming the result.
- [ ] Treat business-logic testing as a major testing area, not an optional item.
- [ ] Keep the checklist practical enough to use during an actual penetration test.
