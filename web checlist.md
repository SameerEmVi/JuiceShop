Web Application Penetration Testing Checklist
Based on OWASP WSTG, OWASP Top 10:2025, OWASP API Security Top 10:2023, ASVS 5.0, CWE, CVSS v4.0, NIST SP 800-115 and PTES.
Status
Marker
Meaning
When to use
[ ]
Not Tested
Default. Also used when a test was blocked; record why in Notes.
[x]
Tested - No Issue
Test performed with evidence that the control works.
[!]
Potential Finding
Behaviour suggests a weakness but exploitability or impact is not yet confirmed. Never reported as a vulnerability.
[i]
Informational
Observation with no direct security impact (e.g. version banner with no applicable CVE). Optional marker.
References used
WSTG IDs follow the OWASP WSTG v4.2 stable numbering. IDs marked † exist in the WSTG "latest" branch only.
OWASP Top 10:2025 — A01 Broken Access Control · A02 Security Misconfiguration · A03 Software Supply Chain Failures · A04 Cryptographic Failures · A05 Injection · A06 Insecure Design · A07 Authentication Failures · A08 Software or Data Integrity Failures · A09 Security Logging and Alerting Failures · A10 Mishandling of Exceptional Conditions. SSRF is now part of A01.
OWASP API Security Top 10:2023 — API1 BOLA · API2 Broken Authentication · API3 BOPLA · API4 Unrestricted Resource Consumption · API5 BFLA · API6 Unrestricted Access to Sensitive Business Flows · API7 SSRF · API8 Security Misconfiguration · API9 Improper Inventory Management · API10 Unsafe Consumption of APIs.
OWASP ASVS 5.0 chapters are noted under each section heading for remediation and verification depth.
CVSS v4.0 (FIRST), CWE (MITRE), NIST SP 800-115, PTES.
1. Reconnaissance and information gathering
Test
Description
Status
Subdomain enumeration
Passive (CT logs, passive DNS, search engines) then active brute force if permitted. Check each result against scope.
[ ]
Certificate transparency
Query crt.sh / CT logs for hostnames, wildcard certs and internal names.
[ ]
DNS records
A/AAAA, CNAME, MX, TXT (SPF, DMARC, verification tokens), NS, SRV; attempt zone transfer (AXFR).
[ ]
Subdomain takeover
Dangling CNAMEs to deprovisioned cloud/SaaS resources. Confirm by fingerprint only; do not claim without authorisation.
[ ]
Web server identification
Banners, header order, error pages, default files. Record versions as informational.
[ ]
Framework / CMS identification
Cookies, headers, paths, JS globals, meta generator, favicon hash.
[ ]
Technology stack and architecture
Identify CDN, WAF, load balancer, reverse proxy, app server, DB hints, cloud provider.
[ ]
Search-engine reconnaissance
Dorks for site:, filetype:, inurl:admin, error messages, cached docs, paste sites and code repos.
[ ]
robots.txt
Disallowed paths as leads for hidden content.
[ ]
sitemap.xml
Enumerate listed URLs, compare against crawled content.
[ ]
security.txt
/.well-known/security.txt present and valid (contact, expiry). Informational.
[ ]
Other metafiles
humans.txt, /.well-known/* (openid-configuration, assetlinks, apple-app-site-association).
[ ]
Applications on the host
Non-standard ports, virtual hosts, path-based apps on the same IP.
[ ]
JavaScript discovery
Collect all JS (incl. lazy-loaded chunks). Extract endpoints, parameters, feature flags, keys.
[ ]
Source maps
Check for *.js.map files; reconstruct source if exposed.
[ ]
API endpoint discovery
From JS, mobile apps, docs, proxies: REST, GraphQL, gRPC-web, WebSocket endpoints.
[ ]
Public directories and files
Content discovery with tuned wordlists at the agreed rate.
[ ]
Backup files
.bak, .old, ~, .swp, .zip, .tar.gz, copies of index/config files.
[ ]
Configuration files
.env, web.config, appsettings.json, config.php, .htaccess, docker-compose.yml.
[ ]
Version control exposure
/.git/, /.svn/, /.hg/, .DS_Store.
[ ]
Comments and metadata
HTML/JS comments, hidden fields, debug strings, internal hostnames, developer names.
[ ]
Public documentation
Swagger/OpenAPI, GraphQL schema, Postman collections, developer portals, help docs.
[ ]
Email/user enumeration (OSINT)
Email format, staff names, usernames from public sources. Passive only.
[ ]
Code repository leaks
Public GitHub/GitLab repos, gists, commits containing secrets or internal URLs.
[ ]
Cloud/service exposure
Public S3/Azure Blob/GCS buckets, Firebase, exposed CI/CD, Kubernetes dashboards.
[ ]
Third-party integrations
Identify IdP, payment, analytics, email, chat, CDN and tag managers. Feed into section 20.
[ ]
2. Application mapping
Crawl the app as every role (unauthenticated and each authenticated role), then build the inventory below. Every later section tests rows from this inventory.
Test
Description
Status
Entry points
Every request that accepts input: query, body, headers, cookies, path segments, file uploads, WebSocket frames.
[ ]
Execution paths
Manual walk-through plus authenticated spidering per role; capture multi-step workflows.
[ ]
Authentication pages
Login, logout, SSO callbacks, API token issuance, legacy/mobile login endpoints.
[ ]
Registration
Self-registration, invitations, account provisioning flows.
[ ]
Password reset
Request, token delivery, token use and password change flows.
[ ]
MFA
Enrolment, challenge, recovery codes, device trust, disable MFA.
[ ]
User profile
Profile view/edit, email/phone change, avatar upload, privacy settings.
[ ]
Administrative functionality
Admin panels, user management, configuration, impersonation, audit logs.
[ ]
File upload / download
Every upload field, import, attachment and download/export endpoint.
[ ]
Search
Search boxes, filters, sorting, autocomplete.
[ ]
API endpoints
Full API inventory with methods, auth type and object IDs.
[ ]
Webhooks
Outbound webhook configuration and inbound webhook receivers.
[ ]
Payment functionality
Cart, checkout, payment provider redirect/callback, refunds, credits, subscriptions.
[ ]
Export / import
CSV/XLSX/PDF export, bulk import, report generation.
[ ]
Account management
Delete account, change role, team/org management, invitations.
[ ]
Session-related functionality
Logout, session listing, "sign out everywhere", token refresh.
[ ]
Hidden / unlinked functionality
Endpoints from JS, old API versions, debug routes, feature-flagged features.
[ ]
HTTP methods
Allowed methods per endpoint (OPTIONS, PUT, PATCH, DELETE, HEAD, override headers).
[ ]
Parameters and request bodies
Record type (form, JSON, XML, multipart, GraphQL) and hidden/unused parameters (param mining).
[ ]
Cookies and tokens
All cookies, bearer tokens, API keys, CSRF tokens and where each is set and used.
[ ]
Role/permission matrix
For each feature, which roles should have access. Basis for section 4.
[ ]
Endpoint / feature inventory
One row per endpoint and method. Mark the roles that legitimately reach it; tested roles go in Notes.
#
Feature
Method
Endpoint
Auth required
Roles allowed
Key parameters / object IDs
State-changing
Sensitive (PII, payment, admin)
Notes
1
2
3
3. Authentication
Test every authentication path, including mobile, API and legacy endpoints, not just the main login form. Stay within the agreed lockout and rate limits. ASVS 5.0: V6 Authentication, V10 OAuth and OIDC. Top 10: A07.
Test
Description
Status
Credentials over encrypted channel
Login, registration and reset submit only over HTTPS; no credentials in URLs.
[  ]
Username/email enumeration
Compare responses, status codes, timing and messages across login, registration, reset and MFA for valid vs invalid users.
[ ]
Weak username policy
Predictable usernames (sequential, email-based) that ease enumeration.
[ ]
Weak password policy
Min length (≥8, ideally ≥15 single-factor), max length allowed ≥64, breached-password check, no forced composition rules. Test server side.
[ ]
Default credentials
Admin consoles, CMS, frameworks, third-party components and newly provisioned accounts.
[ ]
Brute-force protection
Repeated failed logins against one account trigger throttling, CAPTCHA or lockout.
Pending
Credential stuffing protection
Many accounts from one IP, and one account from rotating IPs/headers (X-Forwarded-For spoofing).
[ ]
Account lockout
Threshold, duration, unlock mechanism, and whether lockout can be abused to lock out others (DoS).
[ ]
Rate limiting on auth endpoints
Login, MFA, reset, registration and OTP verification endpoints, including API equivalents.
[ ]
MFA bypass
Skip the MFA step by requesting post-auth pages directly, replaying a pre-MFA session, changing response values, or using alternate endpoints.
[ ]
MFA weaknesses
OTP brute force, OTP reuse, long OTP validity, OTP in response, recovery code strength, MFA disable without re-auth.
[ ]
Password reset weaknesses
Host header poisoning of reset link, reset link sent to attacker-controlled param, account takeover via email param arrays.
[ ]
Reset token predictability
Collect several tokens; check length, entropy, timestamp/sequential patterns.
[ ]
Reset token reuse
Token invalidated after use and after a newer token is issued.
[ ]
Reset token expiration
Token expires within a short window (e.g. ≤1 hour).
[ ]
Token leakage
Reset token not sent in Referer to third parties, not logged in URLs to analytics.
[ ]
Password change
Requires current password; invalidates other sessions.
[ ]
Security questions
If used: guessable or publicly discoverable answers.
[ ]
Authentication bypass
Direct page request, parameter tampering (authenticated=true), SQLi in login, response manipulation.
[ ]
Alternative authentication paths
Mobile API, older API versions, SOAP, legacy login, and partner portals enforce the same controls.
[ ]
OAuth/OIDC weaknesses
redirect_uri validation, state/nonce, PKCE, implicit flow use, code reuse, token leakage, scope escalation, account linking.
[ ]
SSO / SAML weaknesses
Signature validation (XSW, unsigned assertions), audience/recipient checks, replay, comment injection in NameID.
[ ]
Remember-me functionality
Token is random, server-side, revocable, expires, and is not derived from credentials.
[ ]
Browser cache of auth pages
Sensitive pages served with no-store; back button after logout does not show data.
[ ]
Session fixation at login
Session ID rotates on authentication and privilege change.
[ ]
Login CSRF
Attacker can log a victim into the attacker's account.
[ ]
Authentication state inconsistencies
Partially authenticated states (pending email verification, pending MFA, disabled, locked) cannot reach protected functions.
[ ]
Registration abuse
Duplicate accounts with case/unicode variants, email verification bypass, role set at signup.
[ ]
4. Authorisation and access control
Replay every inventory request as each other role and as unauthenticated (Autorize/AuthMatrix-style). Use two accounts per role and two tenants. ASVS 5.0: V8 Authorization. Top 10: A01.
Test
Description
Status
Horizontal privilege escalation
User A reads/modifies/deletes User B's data at the same privilege level.
[ ]
Vertical privilege escalation
Low-privilege user performs admin or higher-role actions.
[ ]
IDOR / BOLA
Swap object IDs (numeric, UUID, encoded, composite) in path, query, body and headers for every object type.
[ ]
Missing function-level access control
Call privileged functions directly without UI exposure.
[ ]
Forced browsing
Request authenticated/admin URLs while unauthenticated or as a lower role.
[ ]
Administrative endpoint access
/admin, /manage, /internal, actuator-style endpoints from every role.
[ ]
Role manipulation
Modify role/isAdmin/permissions fields in requests, profile updates, JWT claims or registration.
[ ]
Parameter manipulation
Tamper with accountId, orgId, userId, ownerId in bodies when the server should derive them from the session.
[ ]
Access control via HTTP methods
Same endpoint with GET/POST/PUT/DELETE/HEAD and X-HTTP-Method-Override.
[ ]
Access control via APIs
API and GraphQL equivalents of UI functions enforce the same checks (incl. older versions).
[ ]
Multi-tenant isolation
Cross-tenant reads/writes via IDs, search, exports, reports, file URLs, websockets and caches.
[ ]
Object ownership validation
Child objects (comments, attachments, line items) validated against the parent owner.
[ ]
Direct access to restricted resources
Files, exports, signed URLs, static assets of other users; URL predictability and expiry.
[ ]
Path-based bypass
Case changes, trailing slash, ..;/, %2e, double slashes, path parameters to dodge proxy rules.
[ ]
Header-based bypass
X-Original-URL, X-Rewrite-URL, X-Forwarded-For: 127.0.0.1, X-Custom-IP-Authorization.
[ ]
Stale permissions
Removed/downgraded user or revoked invitation loses access immediately, including active sessions and tokens.
[ ]
Impersonation features
Admin "login as" restricted, audited and cannot be triggered by lower roles.
[ ]
Role access matrix
Record the observed result per role: Allowed (expected) · Denied (expected) · BYPASS (finding).
Feature / endpoint
Unauthenticated
User (tenant A)
User (tenant B)
Manager
Admin
Notes
5. Session management
Covers cookie-based sessions and token-based (JWT, opaque bearer, refresh) sessions. ASVS 5.0: V7 Session Management, V9 Self-contained Tokens. Top 10: A07.
Test
Description
Status
Session mechanism review
Identify session tokens, where issued, transport and storage.
[ ]
Secure flag
Session and auth cookies set Secure.
[ ]
HttpOnly flag
Session cookies not readable from JavaScript.
[ ]
SameSite attribute
Lax or Strict for session cookies; None only with justification and Secure.
[ ]
Cookie scope
Domain not overly broad (parent domain); Path appropriate; __Host-/__Secure- prefixes used.
[ ]
Session ID entropy
Collect a sample (e.g. Burp Sequencer); ≥128 bits of entropy, no visible structure.
[ ]
Session fixation
Pre-login session ID is replaced after login and privilege change.
[ ]
Exposed session variables
Tokens not in URLs, Referer, logs, cacheable responses or GET parameters.
[ ]
Absolute expiration
Session has a maximum lifetime appropriate to risk.
[ ]
Idle timeout
Session expires after inactivity; verify server side by replaying an old token.
[ ]
Logout invalidation
Replay the token after logout; must be rejected server side (incl. JWT/refresh tokens).
[ ]
Concurrent sessions
Behaviour on multiple logins; user can see and terminate other sessions.
[ ]
Session revocation
Password change, MFA change, role change and account disable revoke existing sessions.
[ ]
Session puzzling
Same session variable reused across flows (e.g. reset flow sets identity used elsewhere).
[ ]
Session hijacking
Token usable from another client/IP; assess exposure paths (XSS, HTTP, logs).
[ ]
Token reuse
One-time tokens (CSRF, OTP, magic links, invites) cannot be replayed.
[ ]
JWT implementation
Signature verified; exp/nbf/iat/iss/aud validated; no sensitive data in payload.
[ ]
JWT algorithm weaknesses
alg:none, RS256→HS256 confusion, weak HMAC secret (offline crack), kid/jku/x5u injection, embedded jwk.
[ ]
JWT claim manipulation
Change sub, role, tenant, scope; check acceptance with re-signed or unsigned token.
[ ]
Token storage (client)
Long-lived tokens in localStorage/sessionStorage exposed to XSS; prefer HttpOnly cookies.
[ ]
Refresh-token security
Rotation on use, reuse detection, binding to client, expiry, revocation at logout.
[ ]
6. Input validation and injection
Test every entry point from MAP-01 in each input location below. Prefer time-based or boolean confirmation over data extraction; never run stacked or destructive queries (DROP, UPDATE, DELETE) without written approval. ASVS 5.0: V1 Encoding and Sanitization, V2 Validation. Top 10: A05.
Input locations to cover: GET parameters · POST form fields · JSON (incl. nested keys and type juggling) · XML/SOAP · headers (User-Agent, Referer, X-Forwarded-*, custom) · cookies · URL path segments · file names and file content · HTTP method · WebSocket messages · GraphQL arguments · second-order inputs (stored then used later).
Test
Description
Status
SQL injection
Error, boolean, time-based and out-of-band; include ORDER BY, LIMIT, column names, JSON and second-order.
[ ]
NoSQL injection
Operator injection ($ne, $gt, $regex, $where) in JSON and query strings; JS evaluation.
[ ]
ORM / HQL injection
Raw query fragments, sort/filter builders.
[ ]
LDAP injection
Filter metacharacters * ( ) & | in login, search and directory lookups.
[ ]
XPath injection
XPath-based auth or XML data queries.
[ ]
XML injection / XXE
Tag/attribute injection; external entities, parameter entities, OOB XXE, XInclude; also via SVG, DOCX, XLSX, SAML.
[ ]
OS command injection
Separators `; | && $() \``, blind via time delay or OOB DNS; file conversion and network utilities.
[ ]
Server-side template injection
{{7*7}}, ${7*7}, <%= 7*7 %>; identify engine; confirm with harmless evaluation only.
[ ]
Expression Language injection
${...}, #{...}, SpEL/OGNL/MVEL in Java apps.
[ ]
Code injection
eval-style sinks in PHP/Python/Node/Ruby; deserialisation of untrusted data (Java, .NET, PHP, Python pickle).
[ ]
HTML injection
Markup rendered unencoded (often a stepping stone to XSS or phishing).
[ ]
JavaScript injection
Input placed inside script blocks, event handlers or JSONP callbacks.
[ ]
CRLF / header injection
%0d%0a in redirects, cookies and headers; response splitting; log injection.
[ ]
Host header injection
Password reset poisoning, cache poisoning, routing to internal hosts.
[ ]
HTTP parameter pollution
Duplicate parameters in query, body and JSON; front-end vs back-end parsing differences.
[ ]
Mass assignment
Extra fields (role, isAdmin, balance, ownerId, verified) accepted on create/update.
[ ]
Format string injection
%s %x %n in inputs reaching native/legacy components or logging.
[ ]
SSI / ESI injection
<!--#exec -->, <esi:include> where SSI or edge caching is used.
[ ]
Email header / IMAP / SMTP injection
CRLF in contact forms, recipient fields, mail commands.
[ ]
CSV / formula injection
=, +, -, @ payloads in data later exported to spreadsheets.
[ ]
Incubated (stored) injection
Payloads stored now and executed later in admin views, reports, emails or batch jobs.
[ ]
Type and length validation
Arrays instead of strings, large numbers, unicode normalisation, null bytes, overlong input; server-side validation exists.
[ ]
7. Cross-site scripting
Identify the output context (HTML body, attribute, JS, URL, CSS) for each reflection, then test encoding for that context. Use benign proof payloads (e.g. alert(document.domain)); do not steal real users' sessions. ASVS 5.0: V1, V3 Web Frontend Security. Top 10: A05.
Test
Description
Status
Reflected XSS
Every reflected parameter, header and path segment, per output context.
[ ]
Stored XSS
Profile fields, comments, names, tickets, messages; check every view where the data is rendered.
[ ]
DOM-based XSS
Sources (location, hash, postMessage, storage) flowing into sinks (innerHTML, eval, document.write, jQuery html()).
[ ]
Mutation XSS
Payloads that survive sanitisers (DOMPurify config, custom filters) and mutate on re-parse.
[ ]
XSS through JSON
JSON served as text/html, JSONP callbacks, JSON embedded into HTML without escaping.
[ ]
XSS through file names
Uploaded file names rendered in listings, admin views and emails.
[ ]
XSS through uploaded content
HTML, SVG, XML, PDF served inline from the app origin.
[ ]
XSS in administrative interfaces
Blind XSS via user-supplied data viewed by staff (use an authorised callback host).
[ ]
XSS in error messages
404/500 pages, validation messages, search "no results".
[ ]
XSS in email/notification
HTML emails, in-app notifications, push notifications, PDFs generated from user input.
[ ]
Output encoding effectiveness
Context-aware encoding consistent across views; framework auto-escaping not bypassed (dangerouslySetInnerHTML, v-html, |safe).
[ ]
Content Security Policy effectiveness
No unsafe-inline/unsafe-eval, no wildcard or JSONP-hosting allowed sources, nonces/hashes, object-src/base-uri set. Note whether CSP would block a validated XSS.
[ ]
CSS injection
User-controlled styles enabling data exfiltration or UI redress.
[ ]
8. Cross-site request forgery
List every state-changing request from the inventory and test each without a valid token and cross-origin. ASVS 5.0: V3. Top 10: A01.
Test
Description
Status
State-changing requests inventory
Identify all requests that change data, settings, money or permissions.
[ ]
Missing CSRF protection
Remove token; submit from a cross-origin PoC page.
[ ]
Weak / predictable tokens
Token entropy, static tokens, tokens derived from user ID or time.
[ ]
Token reuse
Token tied to the session; another user's token rejected; token from one form accepted elsewhere?
[ ]
Token validation
Blank token, removed parameter, removed header, changed case of parameter name.
[ ]
SameSite cookie protections
Effectiveness given cookie SameSite values, top-level GET navigation and same-site subdomains.
[ ]
Origin / Referer checks
Missing Origin, null Origin, suffix/prefix domain bypasses.
[ ]
Login and logout CSRF
Forced login into attacker account; forced logout.
[ ]
CSRF via alternative methods
POST action accepted as GET; method override parameters.
[ ]
JSON-based CSRF
JSON endpoints accepting text/plain or form content types; CORS preflight avoidance.
[ ]
Clickjacking-assisted actions
Sensitive one-click actions frameable (see HTTP-17).
[ ]
9. File handling
Use harmless proof files (e.g. a script that prints a marker string, EICAR for AV checks). Never upload web shells that persist; delete test files and record what was uploaded where. ASVS 5.0: V5 File Handling. Top 10: A01, A05.
Test
Description
Status
Unrestricted file upload
Any file type accepted; size, count and type limits enforced server side.
[ ]
Malicious file upload
EICAR / polyglot files; is content scanned or quarantined?
[ ]
Extension bypass
Case variants (.pHp), alternate extensions (.phtml, .php5, .aspx, .jspx), trailing dot/space, ::$DATA.
[ ]
MIME-type bypass
Changed Content-Type header vs actual content.
[ ]
Content validation
Magic bytes, image re-encoding, polyglot (GIF+PHP, JPEG+HTML).
[ ]
Double extensions
file.php.jpg, file.jpg.php; server handler mapping behaviour.
[ ]
Null-byte techniques
file.php%00.jpg on legacy stacks only; record as N/A on modern runtimes with reason.
[ ]
Path traversal through filenames
../../ in filename, zip-slip in archives.
[ ]
Filename manipulation
Unicode, overlong, reserved names (CON, NUL), special characters, leading dots (.htaccess).
[ ]
SVG-based attacks
Script in SVG, XXE in SVG, SVG served inline from app origin.
[ ]
HTML file uploads
.html/.htm/.xhtml served from app origin → stored XSS.
[ ]
Script uploads
Server-side scripts stored in executable web root.
[ ]
Server-side execution
Confirm with harmless marker output only.
[ ]
File overwrite
Upload with an existing name overwrites other users' or system files.
[ ]
Storage location and serving
Uploads stored outside web root or on separate domain; Content-Disposition: attachment; X-Content-Type-Options: nosniff.
[ ]
File download authorisation
Download endpoints check ownership; IDs and signed URLs not guessable or reusable indefinitely.
[ ]
Temporary file exposure
Temp/processing files accessible during or after conversion.
[ ]
Archive handling
Zip bombs (only with approval), zip-slip, nested archives, symlinks in archives.
[ ]
Image processing
ImageMagick/Ghostscript/ExifTool-class issues, pixel-flood (with approval). Validate version-specific issues before reporting.
[ ]
10. Path traversal and file inclusion
Target parameters that reference files, templates, languages or pages. Read only harmless proof files (e.g. /etc/hostname, win.ini). ASVS 5.0: V5, V15. Top 10: A01.
Test
Description
Status
../ traversal
Basic relative traversal in file parameters and path segments.
[ ]
URL-encoded traversal
%2e%2e%2f, ..%2f, %2e%2e/.
[ ]
Double encoding
%252e%252e%252f; overlong UTF-8 %c0%ae.
[ ]
Filter bypass
....//, ..;/, mixed separators, prefix requirements (/var/www/../../etc).
[ ]
Windows path traversal
..\, ..%5c, drive letters, UNC paths.
[ ]
Linux path traversal
/etc/passwd, /proc/self/environ.
[ ]
Absolute paths
Absolute path accepted directly in the parameter.
[ ]
Local File Inclusion
Includes of local files; PHP wrappers (php://filter) where relevant.
[ ]
Remote File Inclusion
Include of an external URL under tester control.
[ ]
Arbitrary file read
Source code, configs, keys reachable via traversal. Stop at proof; do not exfiltrate secrets.
[ ]
File disclosure through APIs
File/attachment APIs, export endpoints, template selectors.
[ ]
11. Server-side request forgery
Identify every feature where the server fetches a URL or resource. Use a tester-controlled OOB host. Do not scan internal networks or interact with internal services beyond proof of reach. ASVS 5.0: V1, V15. Top 10: A01. API: API7.
Test
Description
Status
Identify SSRF surfaces
URL fetchers, link previews, avatars by URL, imports, webhooks, PDF/HTML renderers, XML parsers, integrations.
[ ]
External interaction
Confirm server-side fetch via OOB DNS/HTTP callback.
[ ]
localhost access
127.0.0.1, localhost, [::1], 0.0.0.0, decimal/octal/hex IP forms.
[ ]
Private IP ranges
10/8, 172.16/12, 192.168/16, link-local; prove reach to one approved host only.
[ ]
Cloud metadata endpoints
169.254.169.254 (AWS IMDSv1/v2, Azure, GCP headers), fd00:ec2::254. Stop at proof; do not use retrieved credentials.
[ ]
Redirect-based SSRF
External URL that 30x-redirects to an internal target.
[ ]
DNS rebinding
Hostname resolving external at validation, internal at fetch (only if allow-list by resolution is used).
[ ]
URL parser inconsistencies
http://allowed@evil, evil#allowed, backslashes, unicode, embedded credentials.
[ ]
Protocol restrictions
file://, gopher://, dict://, ftp://, jar:// accepted?
[ ]
SSRF through file imports
URL-based imports, XXE in uploaded XML/Office documents.
[ ]
SSRF through webhooks
Webhook URLs to internal targets; response or timing differences.
[ ]
SSRF through PDF/image processing
HTML-to-PDF renderers (iframes, img, link tags), SVG rasterisers, headless browsers.
[ ]
Blind SSRF impact assessment
Timing/error oracles; document reach without exploiting internal services.
[ ]
12. Business logic
Business logic is a primary test area, not an optional one: automated scanners rarely find these issues. For each workflow in the inventory, write down the intended steps and rules, then test what happens when legitimate steps are skipped, reordered, repeated or modified. Use sandbox payment methods only. ASVS 5.0: V2 Validation and Business Logic. Top 10: A06 Insecure Design. API: API6.
Per-workflow method: document the intended sequence and invariants (who, what, how many, in what order, at what price); then for each step try removing it, repeating it, doing it out of order, and changing server-trusted values the client should not control.
Test
Description
Status
Workflow / step sequence bypass
Reach a later step directly, skipping validation or payment steps.
[ ]
State-transition bypass
Force invalid transitions (draft to approved, pending to shipped) by calling the transition endpoint directly.
[ ]
Price manipulation
Alter price, currency, tax, shipping or totals in the request; confirm the server recalculates.
[ ]
Quantity manipulation
Fractional, zero, very large or array quantities; server-side limits and recalculation.
[ ]
Negative values
Negative quantity, amount or balance producing credits or refunds.
[ ]
Integer and rounding issues
Overflow, truncation and rounding in totals, points or balances.
[ ]
Duplicate transactions
Resubmit a completed purchase, transfer or submission.
[ ]
Replay of signed/tokenised requests
Replay a captured signed request or one-time token.
[ ]
Coupon / discount abuse
Stacking, reusing single-use codes, applying after total, case variants.
[ ]
Loyalty / credit abuse
Earn and redeem points or store credit in ways the design did not intend.
[ ]
Account-limit bypass
Exceed per-account caps (seats, API usage, storage) by manipulating requests.
[ ]
Registration-limit bypass
Create more accounts than allowed; bypass one-per-email or one-per-device rules.
[ ]
Invitation / referral abuse
Reuse or forge invitations or referral rewards.
[ ]
Approval bypass
Self-approve, or act on items still awaiting another party.
[ ]
Payment-flow manipulation
Mark an order paid without completing payment; tamper with provider callbacks; confirm server-to-server verification.
[ ]
Refund / cancellation abuse
Refund more than paid; refund and keep goods or access.
[ ]
Missing server-side validation
Rules enforced only in the UI (hidden fields, disabled buttons, client checks) are enforced server side.
[ ]
Trusting client-side controls
Values the client should not set (role, tier, verified, ownerId) are ignored server side.
[ ]
Time / sequence assumptions
Manipulate dates, expiry and ordering (back-dating, future-dating, acting after expiry).
[ ]
Unexpected file / data in a flow
Upload or submit data types the workflow does not expect.
[ ]
13. Race conditions and concurrency
Send many copies of the same request in parallel (single-packet / last-byte-sync techniques) to hit the window between check and use. Agree concurrency limits with the client first. Top 10: A06. WSTG: WSTG-BUSL-04 (behaviour under concurrency).
Test
Description
Status
Duplicate / parallel submissions
Same state-changing request fired concurrently to bypass once-only checks.
[ ]
Balance / inventory manipulation
Concurrent withdrawals, purchases or stock decrements exceeding available amount (overdraft, oversell).
[ ]
Coupon / credit reuse
Redeem a single-use coupon, gift card or credit multiple times in parallel.
[ ]
Invitation / limit reuse
Exceed per-account or per-code limits via parallel requests.
[ ]
Password reset / token races
Parallel reset or token-consumption requests causing reuse or takeover.
[ ]
File operation races
TOCTOU in upload, move, scan-then-serve or conversion steps.
[ ]
Approval / workflow races
Concurrent approve/act requests that bypass a required gate.
[ ]
Rate-limit bypass via parallelism
Burst requests arriving together defeat a per-second limit.
[ ]
14. API security
Apply where REST, GraphQL, gRPC-web or WebSocket APIs exist. Each row notes its OWASP API Security Top 10:2023 mapping. Test APIs with each role and across tenants, exactly as in section 4.
Test
Description
Status
API discovery and inventory
Enumerate endpoints, versions and environments from JS, mobile apps, docs, schemas and proxies.
[ ]
Authentication
Every endpoint requires valid auth; no endpoints silently unauthenticated; token types validated.
[ ]
BOLA / IDOR
Object-level authorisation on every object reference (see AUTHZ-03).
[ ]
Function-level authorisation (BFLA)
Privileged and admin operations enforce role checks; method-based access.
[ ]
Excessive data exposure
Responses return more fields than the client needs (internal flags, PII, other users data).
[ ]
Mass assignment
Writable properties the client should not set (role, balance, verified, ownerId).
[ ]
Improper property-level access
Read or write of restricted object properties.
[ ]
Rate limiting / resource consumption
Per-user and per-endpoint limits; pagination caps; expensive queries.
[ ]
Resource exhaustion
Large page sizes, batch operations, deeply nested payloads, large file refs.
[ ]
Injection
SQL/NoSQL/command/other injection through API parameters and bodies (see section 6).
[ ]
Security misconfiguration
Verbose errors, permissive CORS, missing headers, debug features (see section 16).
[ ]
Unrestricted access to sensitive business flows
Automatable abuse of flows (bulk purchase, signup, booking) without anti-automation.
[ ]
SSRF via API
URL parameters consumed server side (see section 11).
[ ]
Improper inventory management
Old versions (v1 beside v2), staging/debug hosts, deprecated endpoints still live.
[ ]
Deprecated / debug endpoints
/debug, /test, /actuator, GraphQL introspection and debug flags in production.
[ ]
Unsafe consumption of upstream APIs
Trusting third-party/integration responses without validation.
[ ]
GraphQL – introspection
Introspection enabled in production; schema exposure.
[ ]
GraphQL – query cost / depth
Deeply nested or recursive queries; batching/aliases to amplify; cost limits.
[ ]
GraphQL – authorisation
Field- and object-level authorisation; mutations enforce access; batching bypass.
[ ]
GraphQL – injection / IDOR
Injection and object access through arguments and variables.
[ ]
WebSocket security
Origin check on handshake, auth on connect and per-message, authorisation, injection, CSWSH.
[ ]
CORS
Reflected/allow-all origins with credentials, null origin, trusted-subdomain and suffix bypass.
[ ]
JWT / token handling
See SESS-17 to SESS-21 for algorithm, claim and refresh issues.
[ ]
OAuth / OIDC
See AUTH-21 for redirect_uri, PKCE, scope and token-leakage issues.
[ ]
HTTP method handling
Unexpected methods (PUT/DELETE/PATCH) accepted without authorisation.
[ ]
15. HTTP and transport security
ASVS 5.0: V3 Web Frontend Security, V11 Cryptography, V13 Configuration. Top 10: A02.
Test
Description
Status
HTTPS enforcement
All sensitive pages and APIs served only over HTTPS.
[ ]
HTTP-to-HTTPS redirect
Plain HTTP redirects to HTTPS; no sensitive content served on HTTP.
[ ]
HSTS
Strict-Transport-Security with adequate max-age; includeSubDomains; preload where appropriate.
[ ]
TLS configuration
No SSLv3/TLS1.0/1.1; strong ciphers; valid cert chain; no weak renegotiation. Validate before reporting.
[ ]
Mixed content
HTTPS pages do not load active resources over HTTP.
[ ]
CORS policy
Access-Control-Allow-Origin not reflected or wildcard with credentials; methods/headers scoped.
[ ]
Content-Security-Policy
Present and restrictive (see XSS-12).
[ ]
X-Content-Type-Options
nosniff on responses.
[ ]
Referrer-Policy
Set to limit referrer leakage (e.g. strict-origin-when-cross-origin).
[ ]
Permissions-Policy
Restricts powerful features (camera, geolocation, etc.).
[ ]
Cache-Control
Sensitive responses no-store/private; no auth data cached.
[ ]
Cookie security attributes
Secure, HttpOnly, SameSite, scope, prefixes (see SESS-02 to SESS-05).
[ ]
Host header handling
Spoofed/duplicate Host, X-Forwarded-Host effects on links, resets, routing and cache.
[ ]
X-Forwarded-* handling
Trust of X-Forwarded-For/Proto/Host for access control, rate limiting or logging.
[ ]
HTTP request smuggling
CL.TE / TE.CL / TE.TE and CL.0 desync indicators via timing; confirm carefully, do not poison shared infrastructure.
[ ]
HTTP methods and TRACE/OPTIONS
Dangerous methods disabled; TRACE off (XST); OPTIONS does not leak.
[ ]
Clickjacking protection
X-Frame-Options or CSP frame-ancestors on sensitive pages; build a framing PoC.
[ ]
Open redirect
redirect/return/next parameters allow external destinations (phishing, token theft, OAuth abuse).
[ ]
16. Security misconfiguration
ASVS 5.0: V13 Configuration. Top 10: A02. Do not report an old version as vulnerable without validating the specific issue applies.
Test
Description
Status
Debug mode
Framework debug enabled (Django, Flask, Rails, Symfony, Laravel) exposing config or an interactive console.
[ ]
Verbose errors / stack traces
Errors reveal stack traces, queries, paths or versions (see section 19).
[ ]
Directory listing
Indexing enabled on directories.
[ ]
Default pages / content
Server welcome pages, sample apps, install scripts, setup wizards.
[ ]
Default credentials
On admin consoles, databases, dashboards and components (see AUTH-05).
[ ]
Exposed admin interfaces
Admin/management consoles reachable without network restriction.
[ ]
Development / test endpoints
Debug routes, test harnesses, mock endpoints, feature-flag toggles in production.
[ ]
Backup and old files
.bak, .old, archives, editor swap files (see RECON-18).
[ ]
Configuration / environment files
.env, config files, secrets files reachable over HTTP.
[ ]
Source code exposure
.git/.svn, source maps, exposed repositories or archives.
[ ]
Logs exposed
Application, access or error logs reachable over HTTP.
[ ]
API docs / schema exposure
Swagger/OpenAPI, GraphQL introspection, Postman collections public in production.
[ ]
Server and framework banners
Server, X-Powered-By, X-AspNet-Version, framework and language versions disclosed. Informational.
[ ]
Cloud storage misconfiguration
Public buckets, listable containers, writable storage (see RECON-25).
[ ]
Unused / dangerous features
Unneeded HTTP methods, modules, ports, services enabled.
[ ]
Security header baseline
Consolidated check that CONF/HTTP headers are consistent across the app.
[ ]
Subdomain / vhost misrouting
Default vhost, staging content, or a forgotten app on a shared host.
[ ]
File extension handling
Server reveals source or behaves unexpectedly for odd extensions.
[ ]
17. Client-side security
ASVS 5.0: V3 Web Frontend Security. Top 10: A02, A05.
Test
Description
Status
DOM-based XSS
Source-to-sink analysis in JavaScript (see XSS-03).
[ ]
Client-side validation bypass
Submit values the UI blocks directly to the server.
[ ]
Secrets in JavaScript
API keys, tokens, credentials, internal URLs hardcoded in JS or config. Verify key is live/sensitive before reporting.
[ ]
Source maps in production
.map files reconstructing source and comments.
[ ]
Dangerous JS functions
eval, Function, setTimeout(string), innerHTML, document.write on user data.
[ ]
postMessage security
Missing origin checks on message handlers; sensitive data posted to a wildcard target.
[ ]
Client-side access control
Routes/UI hidden by JS only; underlying data/API still reachable.
[ ]
Browser storage of sensitive data
Tokens, PII or secrets in localStorage/sessionStorage/IndexedDB.
[ ]
Web messaging / WebSockets
Origin and data handling for cross-document and socket messages.
[ ]
Cross-origin resource sharing (client)
crossorigin usage, SRI on third-party scripts.
[ ]
Third-party JavaScript
Inventory external scripts; supply-chain exposure, tag managers, excessive trust (see section 21).
[ ]
Client-side dependency vulnerabilities
Known-vulnerable frontend libraries; validate the specific issue (see section 21).
[ ]
Reverse tabnabbing
target=_blank links without rel=noopener.
[ ]
Clickjacking (client)
Framing of sensitive UI (see HTTP-17).
[ ]
18. Cryptography and sensitive data
ASVS 5.0: V11 Cryptography, V14 Data Protection. Top 10: A04. Confirm weaknesses by observation; do not attempt to crack production secrets beyond demonstrating feasibility.
Test
Description
Status
Password storage
Strong, salted, slow hashing (bcrypt/scrypt/argon2). Infer from reset/change behaviour and any disclosed hashes.
[ ]
Sensitive data in transit
All sensitive data over TLS; no credentials or tokens over HTTP (see section 15).
[ ]
Weak algorithms
MD5/SHA1 for signing, DES/RC4, ECB mode, weak key sizes in app features.
[ ]
Weak / predictable randomness
Tokens, IDs, OTPs, reset tokens using non-crypto RNG (see AUTH-13, SESS-06).
[ ]
Hardcoded secrets
Keys, passwords, tokens in JS, source, configs, mobile apps or repos.
[ ]
Sensitive data in URLs
Tokens, session IDs, PII in query strings (logged, cached, in Referer).
[ ]
Sensitive data in responses
Over-disclosure of PII, hashes, internal IDs, other users data (see API-05).
[ ]
Sensitive data in logs
Secrets or PII in client-visible logs, error output or debug responses.
[ ]
Sensitive data caching
Sensitive responses cacheable by browser or shared caches (see HTTP-11).
[ ]
Encryption implementation
App-level encryption uses authenticated modes; IV/nonce handling; no padding-oracle behaviour.
[ ]
Key and secret exposure
Keys retrievable via traversal, backups, metadata or misconfig (see sections 10, 11, 16).
[ ]
PII minimisation and masking
PII masked where appropriate (card numbers, national IDs); export/print paths considered.
[ ]
19. Error handling and information disclosure
ASVS 5.0: V13, V16 Security Logging and Error Handling. Top 10: A02, A10 Mishandling of Exceptional Conditions.
Test
Description
Status
Stack traces
Unhandled exceptions return stack traces to the client.
[ ]
Database / SQL errors
DB error text disclosed (also an injection oracle).
[ ]
Internal paths and hostnames
Absolute paths, internal hostnames or IPs in responses.
[ ]
User / email disclosure
Error, enumeration or export paths reveal usernames or emails (see AUTH-02).
[ ]
Server / framework / version info
Banners and errors disclose software and versions (see CONF-13). Informational unless a validated CVE applies.
[ ]
Debug information
Debug flags, trace IDs, verbose JSON errors, dev messages.
[ ]
Source code disclosure
Code returned instead of executed, or via errors (see CONF-10).
[ ]
Secrets in errors
API keys or tokens echoed in error messages or responses.
[ ]
Sensitive response headers
Internal headers (X-Debug, X-Powered-By, backend IDs) exposed.
[ ]
Exceptional-condition handling
Behaviour on malformed, oversized or unexpected input: fails safe, does not leak, does not reach an insecure state.
[ ]
Differential responses
Timing/length/status differences that leak valid data or state.
[ ]
20. Third-party and integration security
ASVS 5.0: V10 OAuth/OIDC, V13. Top 10: A08 Software or Data Integrity Failures. API: API10.
Test
Description
Status
OAuth / social login providers
redirect_uri and account-linking abuse across providers (see AUTH-21).
[ ]
Payment providers
Callback integrity, server-side verification, tampering with return parameters (see BL-15).
[ ]
Email / SMS services
Header injection, spoofing, open relay behaviour, template injection.
[ ]
Cloud storage
Signed URL scope and expiry, bucket permissions, direct-to-storage upload policies.
[ ]
Webhooks (outbound)
SSRF to internal targets, missing signature verification on receipt (see SSRF-11).
[ ]
External APIs consumed
Validation of upstream responses; failure handling; injection via upstream data.
[ ]
SSO / SAML
Assertion signature and audience validation, replay, IdP-initiated flows (see AUTH-22).
[ ]
Analytics / tag managers
Data leakage to third parties; tag manager as an injection vector.
[ ]
Third-party JavaScript
Integrity (SRI), trust level, compromise impact (see CLNT-11).
[ ]
External redirects
Open redirect to third parties (see HTTP-18).
[ ]
Callback / redirect URI validation
Strict allow-list on OAuth and integration callbacks; no wildcard/suffix matches.
[ ]
Integration credentials
API keys/secrets for integrations not exposed client-side; scoped least-privilege.
[ ]
Integration authorisation
Actions via integrations enforce the same access control as the UI.
[ ]
21. Dependency and component security
Identify components, then validate real applicability before reporting. Do not flag a component as exploitable solely because the version is old. ASVS 5.0: V13. Top 10: A03 Software Supply Chain Failures.
Test
Description
Status
Component inventory
Frontend libraries, backend frameworks, CMS, plugins, server software, JS dependencies and their versions.
[ ]
Known vulnerabilities
Map identified versions to advisories; confirm the specific CVE affects the deployed configuration and is reachable.
[ ]
End-of-life components
Unsupported frameworks, runtimes or CMS versions no longer receiving fixes.
[ ]
Outdated versions
Behind current patch level; note gap, validate exploitability before claiming.
[ ]
Unnecessary components
Unused plugins, modules, sample apps increasing attack surface.
[ ]
Exposed component versions
Versions disclosed via banners, paths, static asset fingerprints (see CONF-13).
[ ]
Vulnerable JS libraries
Client-side libraries with known DOM XSS / prototype pollution issues; confirm reachable sink.
[ ]
Integrity of delivered code
SRI on third-party scripts; package integrity; no untrusted CDN for critical scripts.
[ ]
Known CMS/plugin issues
Platform-specific checks (WordPress, Drupal, etc.) validated against the live instance.
[ ]
22. File and document security
Where the application generates, stores or serves documents. ASVS 5.0: V5, V14.
Test
Description
Status
Metadata exposure
Documents retain metadata (author, software, revision, comments).
[ ]
EXIF / image metadata
GPS, device, software data in uploaded or served images.
[ ]
Author / creator info
Internal usernames or names embedded in generated files.
[ ]
Internal paths in documents
File paths, server names, templates embedded in output.
[ ]
Embedded active content
Macros or scripts in generated or accepted documents; handling of malicious macros.
[ ]
File preview / rendering
In-app previewers (XXE, SSRF, XSS via rendered content).
[ ]
Document conversion
Server-side conversion (HTML-to-PDF SSRF/LFI, Office conversion issues).
[ ]
Download authorisation
Document downloads enforce ownership (see FILE-16).
[ ]
Public document exposure
Documents indexed, guessable URLs, or on public storage (see RECON-25).
[ ]
Generated-file injection
User input in generated PDFs/spreadsheets causing injection (see INJ-20, XSS-10).
[ ]
23. Reporting and evidence collection
Raise a finding (F-01, F-02, ...) only for a Validated Finding [V]. Potential findings stay in the checklist as [!] until confirmed. Capture evidence as you test, not afterwards. Copy the template below per finding.
Finding template
Field
Value
ID
F-01
Title
Severity
Critical / High / Medium / Low / Info
CVSS v4.0 score
CVSS v4.0 vector
CVSS:4.0/AV:/AC:/AT:/PR:/UI:/VC:/VI:/VA:/SC:/SI:/SA:_
CWE
CWE-___
OWASP Top 10:2025
A__
OWASP WSTG reference
WSTG-____-__
Affected endpoint / functionality
Preconditions
(role, state, prerequisites)
Description
(what the weakness is, concisely)
Steps to reproduce
1. ... 2. ... 3. ...
Evidence
(raw request/response, screenshots, command output; secrets and PII redacted)
Security impact
(technical consequence)
Business impact
(consequence to the client, where known)
Remediation
(practical, developer-facing fix)
References
(WSTG, CWE, vendor advisory)
Evidence rules: preserve enough raw technical detail (HTTP requests and responses, timestamps, command output) for another tester to reproduce the finding independently. Do not invent evidence, and do not claim exploitability that was not demonstrated.
Findings summary
ID
Finding
Severity
CVSS v4.0
CWE
OWASP Mapping
Status
F-01
F-02
F-03
Testing coverage
Count checklist rows (the ID rows across sections 0–22), not sub-bullets. Fill at the end of testing.
Metric
Count
Total checklist items
Tested - No Issue [x]
Not Tested [ ]
Potential findings [!]
Important rules
Do not blindly mark tests as completed; mark only with evidence the control works.
Do not invent evidence.
Do not invent vulnerabilities.
Do not assume an outdated version is vulnerable without validating the specific issue.
Clearly distinguish informational observations from security vulnerabilities.
Prioritise practical manual testing over purely theoretical checks.
Include both authenticated and unauthenticated testing where applicable.
Test every relevant function with multiple user roles.
Include API testing when APIs are present.
Map findings to the most appropriate CWE and OWASP category.
Use CVSS v4.0 for confirmed vulnerabilities.
Keep descriptions concise and understandable.
Give remediation that is practical for developers.
Reference the applicable OWASP WSTG test case wherever possible.
Do not perform destructive testing unless explicitly authorised.
Do not test systems outside the defined scope.
Preserve evidence sufficient for another tester to reproduce the finding.
If a test cannot be performed, record why rather than assuming the result.
Treat business-logic testing as a major testing area, not an optional item.
Keep the checklist practical enough to use during an actual penetration test.
