import type { Checklist } from '../types'

/**
 * OWASP Top 10:2025 — category ids and titles verified against https://owasp.org/Top10/2025/
 * Review items are written for code / design review of a change or a service.
 */
export const owaspTop10: Checklist = {
  id: 'owasp-top10-2025',
  title: 'OWASP Top 10:2025',
  version: '2025',
  source: 'https://owasp.org/Top10/2025/',
  description:
    'The ten most critical web application security risks (2025 edition). Good default for reviewing a feature or a whole service.',
  categories: [
    {
      id: 'A01',
      title: 'A01:2025 – Broken Access Control',
      description:
        'Users acting outside their intended permissions: IDOR, missing function-level checks, privilege escalation, CORS misconfiguration, SSRF (merged into A01 in 2025).',
      items: [
        {
          id: 'a01-deny-default',
          text: 'Access is denied by default; every new route/handler explicitly declares who may call it.',
          detail:
            'Look for a global auth middleware/filter with an explicit allow-list of public routes. A new endpoint that forgets an annotation (e.g. @PreAuthorize, [Authorize], a route guard) should fail closed, not open.',
          refs: ['CWE-862', 'CWE-285'],
        },
        {
          id: 'a01-object-ownership',
          text: 'Every lookup by a client-supplied id checks that the caller owns or may access that record (no IDOR).',
          detail:
            'Queries should be scoped to the user/tenant, e.g. WHERE id = ? AND owner_id = ?, rather than fetching by id and returning it. Try the request with another user\'s id in a test.',
          refs: ['CWE-639', 'CWE-863'],
        },
        {
          id: 'a01-server-side',
          text: 'Authorization is enforced server-side; hiding a button or route in the UI is never the only control.',
          detail:
            'For every privileged UI action, find the matching server check. Role or "isAdmin" flags must come from the server-side session or a verified token, never from a request body, query string or editable cookie.',
          refs: ['CWE-602', 'CWE-285'],
        },
        {
          id: 'a01-tenant-isolation',
          text: 'Multi-tenant data is isolated: tenant id comes from the authenticated context, not from the request.',
          detail:
            'Check repositories/queries for a mandatory tenant filter (row-level security, a global query filter, or a scoped repository). A tenant id in the URL must be compared against the session, not trusted.',
          refs: ['CWE-639'],
        },
        {
          id: 'a01-cors',
          text: 'CORS only allows an explicit list of trusted origins; credentials are never combined with a reflected or wildcard origin.',
          detail:
            'Reject configs that echo the Origin header back unvalidated, allow "null", or use regexes like .*example.com that also match evil-example.com.',
          stacks: ['web', 'api'],
          refs: ['CWE-942'],
        },
        {
          id: 'a01-ssrf',
          text: 'Server-side requests to user-influenced URLs are restricted to an allow-list of schemes, hosts and ports.',
          detail:
            'Webhooks, URL previews, PDF renderers and image fetchers must block internal ranges (127.0.0.0/8, 10/8, 169.254.169.254 cloud metadata, ::1) after DNS resolution, and should not follow redirects blindly.',
          stacks: ['api', 'infra'],
          refs: ['CWE-918'],
        },
        {
          id: 'a01-csrf',
          text: 'State-changing requests authenticated by cookies are protected against CSRF.',
          detail:
            'Expect SameSite=Lax/Strict session cookies plus a CSRF token or a verified Origin/Sec-Fetch-Site header for POST/PUT/PATCH/DELETE. GET requests must never change state.',
          stacks: ['web'],
          refs: ['CWE-352'],
        },
        {
          id: 'a01-path-traversal',
          text: 'File paths built from user input cannot escape the intended directory.',
          detail:
            'Use generated file names or a lookup table; otherwise canonicalize the path and verify it still starts with the base directory. Test with ../ and URL-encoded variants.',
          refs: ['CWE-22'],
        },
      ],
    },
    {
      id: 'A02',
      title: 'A02:2025 – Security Misconfiguration',
      description:
        'Insecure defaults, verbose errors, unnecessary features, missing hardening headers, open cloud storage, XXE-capable parsers.',
      items: [
        {
          id: 'a02-debug-off',
          text: 'Debug mode, stack traces, admin consoles and sample apps are disabled in production configuration.',
          detail:
            'Check environment-specific config: DEBUG=False (Django), no Werkzeug debugger, Spring Boot actuator endpoints restricted, ASPNETCORE_ENVIRONMENT not Development, no Swagger UI on public prod unless intended.',
          refs: ['CWE-489', 'CWE-215'],
        },
        {
          id: 'a02-headers',
          text: 'Security headers are set: HSTS, Content-Security-Policy, X-Content-Type-Options: nosniff, frame-ancestors / X-Frame-Options, Referrer-Policy.',
          detail:
            'Verify on a real response (curl -I or the Toolbox headers checker). CSP should avoid unsafe-inline/unsafe-eval for scripts; HSTS max-age at least one year.',
          stacks: ['web'],
          refs: ['CWE-1021', 'CWE-693'],
        },
        {
          id: 'a02-xml-parsers',
          text: 'XML parsers disable DTDs / external entity resolution.',
          detail:
            'Java: set disallow-doctype-decl on DocumentBuilderFactory/SAXParserFactory. .NET: DtdProcessing.Prohibit. Python: use defusedxml. Applies to SOAP, SAML, SVG and Office file parsing too.',
          stacks: ['java', 'dotnet', 'python', 'api'],
          refs: ['CWE-611'],
        },
        {
          id: 'a02-cloud-storage',
          text: 'Cloud storage buckets, databases and queues are not publicly accessible and use least-privilege IAM.',
          detail:
            'Review IaC (Terraform, Bicep, CloudFormation) for public ACLs, 0.0.0.0/0 ingress on data stores, and wildcard IAM actions/resources. Run a scanner such as Checkov or tfsec in CI.',
          stacks: ['infra'],
          refs: ['CWE-732'],
        },
        {
          id: 'a02-defaults',
          text: 'No default accounts or passwords, and security-relevant defaults are safe (secure-by-default feature flags).',
          detail:
            'New settings should default to the safe value (e.g. verification on, sharing off). Default credentials in docker-compose or Helm values must not reach shared environments.',
          refs: ['CWE-1188', 'CWE-1392'],
        },
        {
          id: 'a02-cookies',
          text: 'Session cookies are Secure, HttpOnly and have an appropriate SameSite value.',
          detail:
            'Prefer the __Host- prefix for session cookies (requires Secure, Path=/ and no Domain). Check framework defaults, which often differ between dev and prod.',
          stacks: ['web'],
          refs: ['CWE-614', 'CWE-1004', 'CWE-1275'],
        },
        {
          id: 'a02-surface',
          text: 'Unused features, ports, HTTP methods and dependencies are removed; container images are minimal and run as non-root.',
          detail:
            'Dockerfile uses a slim/distroless base and a USER directive; Kubernetes manifests set runAsNonRoot and readOnlyRootFilesystem; no TRACE method or directory listing on the web server.',
          stacks: ['infra'],
          refs: ['CWE-250', 'CWE-548'],
        },
      ],
    },
    {
      id: 'A03',
      title: 'A03:2025 – Software Supply Chain Failures',
      description:
        'Vulnerable, unmaintained or malicious dependencies, and compromised build/CI/CD systems or developer tooling.',
      items: [
        {
          id: 'a03-new-deps',
          text: 'Each newly added dependency is justified, actively maintained, from the official registry, and free of known vulnerabilities.',
          detail:
            'Check OSV.dev / GitHub advisories, last release date, maintainer count, download stats and the licence. Watch for typosquats (e.g. reqeusts vs requests) and install scripts.',
          refs: ['CWE-1104', 'CWE-1395', 'CWE-1357'],
        },
        {
          id: 'a03-lockfile',
          text: 'Dependencies are pinned through a committed lockfile and CI installs from it (npm ci, pip install --require-hashes, dotnet restore --locked-mode).',
          detail:
            'A PR that changes package.json without the lockfile, or adds a git/URL dependency, deserves a closer look. Lockfile diffs should be reviewed, not rubber-stamped.',
          stacks: ['node', 'python', 'java', 'dotnet'],
        },
        {
          id: 'a03-scanning',
          text: 'Automated dependency scanning (Dependabot, Renovate, OSV-Scanner or equivalent) runs on the repository and findings are triaged.',
          detail:
            'There should be a documented SLA for fixing critical/high findings. Ignored advisories need a written justification and an expiry date.',
          refs: ['CWE-1395'],
        },
        {
          id: 'a03-actions-pinned',
          text: 'Third-party CI actions/images are pinned to a full commit SHA or digest, and workflow tokens have minimal permissions.',
          detail:
            'GitHub Actions: uses: owner/action@<40-char sha>, a top-level permissions: block (contents: read by default), and no pull_request_target that checks out untrusted PR code.',
          stacks: ['infra'],
          refs: ['CWE-829'],
        },
        {
          id: 'a03-sbom',
          text: 'An SBOM is produced for release artifacts and the component inventory includes transitive dependencies.',
          detail:
            'CycloneDX or SPDX generated in the build (e.g. cyclonedx-npm, Syft) and stored with the artifact, so you can answer "are we affected?" within hours of a new CVE.',
          stacks: ['infra'],
        },
        {
          id: 'a03-build-integrity',
          text: 'Branch protection requires review before merge, and production deploys only come from CI (no manual uploads).',
          detail:
            'Protected default branch with required reviews and status checks, CODEOWNERS for sensitive paths, deploy credentials only available to the release workflow, MFA on registry and cloud accounts.',
          stacks: ['infra'],
        },
      ],
    },
    {
      id: 'A04',
      title: 'A04:2025 – Cryptographic Failures',
      description:
        'Sensitive data exposed through missing or weak cryptography, bad key management, weak randomness or cleartext transport.',
      items: [
        {
          id: 'a04-tls',
          text: 'All traffic carrying sensitive data uses TLS 1.2+ (including internal service calls), with certificate validation enabled.',
          detail:
            'Search for verify=False, rejectUnauthorized: false, InsecureSkipVerify, custom TrustManagers that accept everything, or http:// URLs to internal services.',
          refs: ['CWE-319', 'CWE-295'],
        },
        {
          id: 'a04-password-hashing',
          text: 'Passwords are stored with a slow, salted password-hashing function (Argon2id, scrypt, bcrypt or PBKDF2 with high iterations).',
          detail:
            'Never MD5/SHA-1/SHA-256 alone, never reversible encryption. Follow the OWASP Password Storage Cheat Sheet parameters (e.g. Argon2id m=19 MiB, t=2, p=1 minimum).',
          stacks: ['api'],
          refs: ['CWE-916', 'CWE-328'],
        },
        {
          id: 'a04-algorithms',
          text: 'Only modern algorithms and modes are used: AES-GCM or ChaCha20-Poly1305, SHA-256+, RSA ≥ 2048 / ECC P-256+. No ECB, DES, RC4, MD5 or SHA-1 for security.',
          detail:
            'Grep for Cipher.getInstance("AES") (defaults to ECB in Java), createCipheriv with ecb, MD5/SHA1 used for signatures or integrity. Nonces/IVs must never repeat for a key.',
          refs: ['CWE-327', 'CWE-326'],
        },
        {
          id: 'a04-randomness',
          text: 'Tokens, ids, reset codes and keys come from a CSPRNG.',
          detail:
            'Good: crypto.randomBytes(32) / crypto.getRandomValues, Python secrets.token_urlsafe, SecureRandom, RandomNumberGenerator. Bad: Math.random, random.random, java.util.Random, timestamps or sequential ids. A UUIDv4 carries only 122 random bits — fine as an id, not ideal as a secret.',
          refs: ['CWE-330', 'CWE-338'],
        },
        {
          id: 'a04-keys',
          text: 'Encryption keys and secrets are not hard-coded; they come from a secret manager/KMS and can be rotated.',
          detail:
            'Look for keys in source, config files, Dockerfiles and test fixtures that are also used in prod. Each environment should have its own keys.',
          refs: ['CWE-321', 'CWE-798'],
        },
        {
          id: 'a04-data-at-rest',
          text: 'Sensitive data is classified and encrypted at rest where required; data not needed is not stored at all.',
          detail:
            'Check new columns/fields holding PII, health, payment or credentials. Prefer not storing (e.g. tokenize card numbers), else database/disk encryption plus field-level encryption for the most sensitive data.',
          refs: ['CWE-311', 'CWE-312'],
        },
      ],
    },
    {
      id: 'A05',
      title: 'A05:2025 – Injection',
      description:
        'Untrusted data interpreted as code or commands: SQL/NoSQL, OS command, LDAP, template injection and cross-site scripting.',
      items: [
        {
          id: 'a05-sql',
          text: 'Database queries use parameterized statements / ORM bindings; no string concatenation or interpolation of user input into queries.',
          detail:
            'Check raw-query escape hatches: f-strings in cursor.execute, template literals in knex.raw / sequelize.query, string concat in JDBC, FromSqlRaw with interpolation. Dynamic ORDER BY / column names must use an allow-list.',
          refs: ['CWE-89'],
        },
        {
          id: 'a05-nosql',
          text: 'NoSQL queries do not accept raw objects or operators from the request.',
          detail:
            'In MongoDB, a body like {"password": {"$ne": null}} bypasses checks. Validate types (string expected → reject objects) and avoid $where / server-side JavaScript.',
          stacks: ['node', 'api'],
          refs: ['CWE-943'],
        },
        {
          id: 'a05-os-command',
          text: 'No shell execution with user input; when a process must be spawned, arguments are passed as an array without a shell.',
          detail:
            'Flag child_process.exec, subprocess with shell=True, Runtime.exec with a single concatenated string, Process.Start with cmd /c. Use execFile/spawn with an args array and validate arguments.',
          refs: ['CWE-78'],
        },
        {
          id: 'a05-xss',
          text: 'Output is encoded for its context; raw-HTML sinks are not fed untrusted data.',
          detail:
            'React/Angular/Vue auto-escape, so look for dangerouslySetInnerHTML, v-html, [innerHTML], bypassSecurityTrust*, innerHTML/outerHTML/document.write, and server templates using |safe or Html.Raw. User-supplied HTML must go through DOMPurify or an equivalent sanitizer.',
          stacks: ['web'],
          refs: ['CWE-79'],
        },
        {
          id: 'a05-url-schemes',
          text: 'User-supplied URLs rendered as links or redirects only allow http(s) (no javascript: or data:).',
          detail:
            'Parse with the URL API and check protocol against an allow-list before using it in href, src or window.location.',
          stacks: ['web'],
          refs: ['CWE-79', 'CWE-601'],
        },
        {
          id: 'a05-template-eval',
          text: 'No eval / dynamic code or template compilation from user input (eval, new Function, SpEL/OGNL, Jinja2 from_string, ERB).',
          detail:
            'Templates must be static files with user data passed as variables. Expression languages must not evaluate request data.',
          refs: ['CWE-94', 'CWE-1336'],
        },
        {
          id: 'a05-ldap-xpath-headers',
          text: 'Other interpreters (LDAP filters, XPath, HTTP headers, email headers, log lines) receive escaped or validated input.',
          detail:
            'Use framework encoders for LDAP filters, reject CR/LF in values placed into headers, and use structured logging rather than concatenated strings.',
          refs: ['CWE-90', 'CWE-113', 'CWE-117'],
        },
      ],
    },
    {
      id: 'A06',
      title: 'A06:2025 – Insecure Design',
      description:
        'Missing or ineffective security controls in the design itself — flaws that perfect implementation cannot fix. Threat model new flows.',
      items: [
        {
          id: 'a06-threat-model',
          text: 'New features that touch authentication, payments, personal data or external integrations have a lightweight threat model.',
          detail:
            'A STRIDE pass on the data-flow diagram is enough for most features. Record the identified threats and which control mitigates each (see the Threat Modeling module).',
        },
        {
          id: 'a06-business-limits',
          text: 'Business limits are enforced server-side (quantities, amounts, number of uses of a coupon, steps of a workflow).',
          detail:
            'Try negative quantities, skipping a step (e.g. calling "confirm" without "pay"), reusing a single-use token, or changing the price in the request.',
          refs: ['CWE-841'],
        },
        {
          id: 'a06-race',
          text: 'Operations that must happen once (redeem, withdraw, book a slot) are safe under concurrent requests.',
          detail:
            'Use database transactions with proper isolation, unique constraints, conditional updates (UPDATE … WHERE balance >= ?) or idempotency keys. Send 20 parallel requests in a test.',
          refs: ['CWE-362'],
        },
        {
          id: 'a06-anti-automation',
          text: 'Abuse-prone flows (signup, login, password reset, SMS/email sending, search, exports) have rate limits or anti-automation.',
          detail:
            'Limits per account, per IP and globally; a cost per SMS/email sent means unlimited sending is a financial risk too.',
          refs: ['CWE-799', 'CWE-770'],
        },
        {
          id: 'a06-trust-boundaries',
          text: 'Trust boundaries are explicit: data from clients, partners and other services is validated where it enters.',
          detail:
            'Data from an internal queue or another microservice can still be attacker-influenced. Each service validates its own inputs instead of assuming upstream did.',
          refs: ['CWE-501'],
        },
        {
          id: 'a06-least-data',
          text: 'The design collects and exposes the minimum data required, with defined retention.',
          detail:
            'For each new field: who needs it, where it is shown, how long it is kept and how it is deleted. Less data stored means less to protect and breach.',
        },
      ],
    },
    {
      id: 'A07',
      title: 'A07:2025 – Authentication Failures',
      description:
        'Weaknesses in confirming identity: credential stuffing, weak passwords, broken session handling, missing MFA, flawed recovery.',
      items: [
        {
          id: 'a07-brute-force',
          text: 'Login, OTP and password-reset endpoints are protected against brute force and credential stuffing.',
          detail:
            'Progressive delays or throttling per account and per IP, breached-password checks, and CAPTCHA or step-up after repeated failures. Avoid hard lockouts that enable account DoS.',
          refs: ['CWE-307'],
        },
        {
          id: 'a07-password-policy',
          text: 'Password policy follows current guidance: minimum 8 (ideally 15) characters, at least 64 allowed, no composition rules, checked against breached lists.',
          detail:
            'No forced periodic rotation, no secret questions, paste and password managers allowed (NIST SP 800-63B, ASVS V6.2).',
          refs: ['CWE-521'],
        },
        {
          id: 'a07-mfa',
          text: 'MFA is available (and required for admin/privileged accounts) and cannot be bypassed via alternative login paths.',
          detail:
            'Check API tokens, "remember me", password reset, SSO fallbacks and mobile endpoints: each must respect MFA. Prefer phishing-resistant factors (WebAuthn/passkeys) for admins.',
          refs: ['CWE-308', 'CWE-287'],
        },
        {
          id: 'a07-session-rotation',
          text: 'Session id is regenerated on login and privilege change; logout and password change invalidate sessions server-side.',
          detail:
            'Prevents session fixation. For JWTs, logout needs short expiry plus a revocation/deny list or refresh-token rotation, since a JWT cannot be "deleted".',
          refs: ['CWE-384', 'CWE-613'],
        },
        {
          id: 'a07-enumeration',
          text: 'Login, registration and reset responses do not reveal whether an account exists.',
          detail:
            'Same message, status code and similar response time for "unknown user" and "wrong password"; reset always answers "if the account exists, an email was sent".',
          refs: ['CWE-204'],
        },
        {
          id: 'a07-reset-flow',
          text: 'Password reset tokens are random, single-use, short-lived and bound to the account; the reset link host is not taken from the Host header.',
          detail:
            'Building the link from the request Host header enables reset-link poisoning. Use a configured base URL. Invalidate other sessions after reset.',
          refs: ['CWE-640'],
        },
        {
          id: 'a07-token-validation',
          text: 'JWT/OIDC tokens are validated fully: signature with a pinned algorithm, iss, aud, exp/nbf.',
          detail:
            'Reject alg "none", do not accept keys from the token header (jku/x5u/jwk) unless allow-listed, and use a vetted library. Paste a token into the Toolbox JWT linter to check claims.',
          stacks: ['api'],
          refs: ['CWE-347', 'CWE-287'],
        },
      ],
    },
    {
      id: 'A08',
      title: 'A08:2025 – Software or Data Integrity Failures',
      description:
        'Trusting code or data without verifying integrity: insecure deserialization, unsigned updates, untrusted CDNs, tampered client data.',
      items: [
        {
          id: 'a08-deserialization',
          text: 'Untrusted data is never deserialized with formats that can instantiate arbitrary types.',
          detail:
            'Flag pickle.loads, yaml.load without SafeLoader, Java ObjectInputStream, BinaryFormatter, Json.NET TypeNameHandling other than None, node-serialize. Prefer plain JSON into explicit DTOs.',
          refs: ['CWE-502'],
        },
        {
          id: 'a08-sri',
          text: 'Third-party scripts loaded from CDNs use Subresource Integrity, or are self-hosted.',
          detail:
            '<script src> from a CDN should carry integrity="sha384-…" and crossorigin. Tag managers and analytics scripts execute with full page privileges — limit them on sensitive pages.',
          stacks: ['web'],
          refs: ['CWE-494', 'CWE-829'],
        },
        {
          id: 'a08-signed-data',
          text: 'Data the client stores and sends back (cookies, hidden fields, JWTs, view state) is signed or validated server-side.',
          detail:
            'Prices, roles, user ids and flags round-tripped through the client must be re-derived or HMAC-verified on the server.',
          refs: ['CWE-345', 'CWE-565'],
        },
        {
          id: 'a08-updates',
          text: 'Software updates, plugins and downloaded artifacts are verified (signature or pinned hash) before use.',
          detail:
            'Applies to curl | bash in Dockerfiles and CI, auto-updaters, and plugin systems. Download over HTTPS and check a checksum or signature (e.g. Sigstore/cosign for images).',
          stacks: ['infra', 'mobile'],
          refs: ['CWE-494'],
        },
        {
          id: 'a08-mass-assignment',
          text: 'Request bodies are bound to explicit DTOs/allow-lists, so clients cannot set fields like role, isAdmin, ownerId or price.',
          detail:
            'Look for binding the whole request into an entity (Object.assign(user, req.body), Model(**data), [Bind] without include). Use separate input models per operation.',
          stacks: ['api'],
          refs: ['CWE-915'],
        },
      ],
    },
    {
      id: 'A09',
      title: 'A09:2025 – Security Logging and Alerting Failures',
      description:
        'Attacks go unnoticed because security events are not logged, logs are not monitored, or alerts do not reach anyone.',
      items: [
        {
          id: 'a09-events',
          text: 'Security-relevant events are logged: login success/failure, MFA changes, password reset, access denied, admin actions, input validation failures.',
          detail:
            'Each entry should include when (UTC), who (user/service id), from where (IP, request id), what and the outcome — enough to reconstruct an incident timeline.',
          refs: ['CWE-778', 'CWE-223'],
        },
        {
          id: 'a09-no-secrets',
          text: 'Logs do not contain passwords, tokens, session ids, API keys, full card numbers or unnecessary personal data.',
          detail:
            'Check request/response logging middleware, exception logging of request bodies, and debug statements. Use a redaction filter for known sensitive field names.',
          refs: ['CWE-532'],
        },
        {
          id: 'a09-injection',
          text: 'Log entries cannot be forged: user input is encoded or logged as structured fields.',
          detail:
            'A username containing a newline must not create a fake log line. Structured JSON logging handles this; plain string formatting usually does not.',
          refs: ['CWE-117'],
        },
        {
          id: 'a09-central',
          text: 'Logs are shipped to a central, access-controlled store with retention, outside the reach of the application itself.',
          detail:
            'An attacker who compromises the app should not be able to delete its audit trail. Verify retention meets legal/incident-response needs.',
        },
        {
          id: 'a09-alerting',
          text: 'Alerts exist for suspicious patterns (spikes in auth failures, access-denied, 5xx, admin actions) and someone is on the receiving end.',
          detail:
            'Name the alert, the threshold, and the team or channel that receives it. An alert nobody reads is equivalent to no alert.',
        },
      ],
    },
    {
      id: 'A10',
      title: 'A10:2025 – Mishandling of Exceptional Conditions',
      description:
        'New in 2025: failing to prevent, detect or respond to errors and abnormal conditions — fail-open logic, unhandled exceptions, leaky errors, resource exhaustion.',
      items: [
        {
          id: 'a10-fail-closed',
          text: 'Security checks fail closed: an exception in an auth, authorization, validation or payment check results in denial, not success.',
          detail:
            'Look for try/catch around a check that logs and continues, default-true flags, or "if (error) return next()" in middleware. Partially completed transactions are rolled back.',
          refs: ['CWE-636', 'CWE-755'],
        },
        {
          id: 'a10-generic-errors',
          text: 'Clients receive generic error messages; stack traces, SQL, file paths and internal hostnames stay in server logs.',
          detail:
            'Check the global exception handler and framework error pages in prod mode. Return a correlation id so support can find the detailed log.',
          refs: ['CWE-209', 'CWE-550'],
        },
        {
          id: 'a10-global-handler',
          text: 'A global exception handler exists as a backstop, and unhandled promise rejections / thread exceptions are caught and logged.',
          detail:
            'Express error middleware, @ControllerAdvice, UseExceptionHandler, Flask errorhandler(Exception). In Node, an unhandled rejection can crash the process — a DoS vector.',
          refs: ['CWE-248', 'CWE-755'],
        },
        {
          id: 'a10-return-values',
          text: 'Return values and error results are checked (no ignored errors, no empty catch blocks).',
          detail:
            'Search for catch {} / except: pass / _ = err. Each swallowed error should be a conscious, commented decision.',
          refs: ['CWE-252', 'CWE-390', 'CWE-391'],
        },
        {
          id: 'a10-resource-limits',
          text: 'Inputs and operations have limits: request body size, pagination maximums, timeouts on outbound calls, regex complexity, decompression size.',
          detail:
            'Unbounded loops over user-controlled sizes, catastrophic-backtracking regexes, and zip/XML bombs cause outages. Every outbound HTTP/DB call needs a timeout.',
          refs: ['CWE-400', 'CWE-770', 'CWE-1333', 'CWE-409'],
        },
        {
          id: 'a10-missing-params',
          text: 'Missing, extra, null or malformed parameters are handled explicitly rather than causing crashes or undefined behavior.',
          detail:
            'Validate request schemas (Zod, Joi, pydantic, Bean Validation, FluentValidation) and reject unknown fields. Add tests for null/empty/oversized values.',
          refs: ['CWE-234', 'CWE-235', 'CWE-476'],
        },
      ],
    },
  ],
}
