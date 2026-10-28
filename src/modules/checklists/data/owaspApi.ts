import type { Checklist } from '../types'

/**
 * OWASP API Security Top 10 – 2023. Titles verified against
 * https://api-security.owasp.org/editions/2023/en/0x11-t10/
 */
export const owaspApi: Checklist = {
  id: 'owasp-api-2023',
  title: 'OWASP API Security Top 10 – 2023',
  version: '2023',
  source: 'https://api-security.owasp.org/editions/2023/en/0x11-t10/',
  description:
    'Risks specific to REST, GraphQL and RPC APIs. Use when reviewing new or changed endpoints, an API gateway, or a partner integration.',
  categories: [
    {
      id: 'API1',
      title: 'API1:2023 – Broken Object Level Authorization',
      description: 'Endpoints that take an object id let callers access objects they do not own.',
      items: [
        {
          id: 'api1-ownership-check',
          text: 'Every endpoint that receives an object id (path, query, body, header) verifies the caller may access that specific object.',
          detail:
            'The check must use the authenticated identity from the token/session, e.g. scope the query by owner or tenant. A test should call the endpoint with user B\'s token on user A\'s object and expect 403/404.',
          refs: ['CWE-639', 'CWE-285'],
        },
        {
          id: 'api1-nested',
          text: 'Nested and bulk resources are checked too (/orders/{id}/invoice, batch endpoints, GraphQL nodes by id, exports).',
          detail:
            'Authorization on the parent does not imply the child belongs to it: verify the child id is linked to the authorized parent. Batch endpoints must check every id in the list.',
          refs: ['CWE-639'],
        },
        {
          id: 'api1-unguessable',
          text: 'Object ids are not relied on for secrecy; random UUIDs are defense in depth, not the authorization control.',
          detail:
            'Sequential ids make BOLA trivially exploitable, but UUIDs leak through URLs, logs and shared links — the ownership check is still required.',
        },
      ],
    },
    {
      id: 'API2',
      title: 'API2:2023 – Broken Authentication',
      description: 'Weak or incorrectly implemented authentication lets attackers assume other identities.',
      items: [
        {
          id: 'api2-all-endpoints',
          text: 'Every non-public endpoint requires authentication, including internal, legacy, health/admin and mobile-specific endpoints.',
          detail:
            'Compare the route list (OpenAPI spec or framework route dump) with the auth middleware configuration. "Internal only" endpoints reachable through the gateway count as public.',
          refs: ['CWE-306'],
        },
        {
          id: 'api2-token-validation',
          text: 'Access tokens are validated for signature (pinned algorithm), issuer, audience, expiry, and token type.',
          detail:
            'An ID token or a token issued for another API must be rejected. Never accept alg "none" or keys supplied in the token header.',
          refs: ['CWE-347', 'CWE-287'],
        },
        {
          id: 'api2-rate-limit-auth',
          text: 'Authentication endpoints (login, token, OTP verification, password reset) are rate-limited per account and per client.',
          detail:
            'Also check GraphQL batching and JSON arrays, which can submit hundreds of password or OTP guesses in a single HTTP request.',
          refs: ['CWE-307'],
        },
        {
          id: 'api2-no-api-keys-for-users',
          text: 'API keys are used only to identify client applications, not to authenticate end users; keys are not sent in URLs.',
          detail:
            'Query strings end up in logs, proxies and browser history. Put credentials in the Authorization header; user identity needs OAuth/OIDC or a session.',
          refs: ['CWE-598'],
        },
        {
          id: 'api2-sensitive-reauth',
          text: 'Sensitive account operations (change email, password, MFA, payout details) require re-authentication.',
          detail:
            'A stolen access token alone should not be enough to take over the account permanently.',
          refs: ['CWE-620'],
        },
      ],
    },
    {
      id: 'API3',
      title: 'API3:2023 – Broken Object Property Level Authorization',
      description: 'Excessive data exposure and mass assignment: callers read or write properties they should not.',
      items: [
        {
          id: 'api3-response-schema',
          text: 'Responses are built from explicit response DTOs/serializers, not by returning ORM entities directly.',
          detail:
            'Look for return user / res.json(entity) / model_to_dict. Hidden fields (password hash, internal flags, other users\' emails) must never leave the server, even if the UI ignores them.',
          refs: ['CWE-213'],
        },
        {
          id: 'api3-mass-assignment',
          text: 'Writable properties are allow-listed per operation; fields like role, isVerified, balance, ownerId cannot be set by clients.',
          detail:
            'Send an extra "role":"admin" in a PATCH body during review/testing and confirm it is ignored or rejected.',
          refs: ['CWE-915'],
        },
        {
          id: 'api3-field-level-authz',
          text: 'Field-level permissions differ by role where needed (e.g. only HR sees salary) and are enforced server-side.',
          detail:
            'GraphQL: field resolvers for sensitive fields need their own authorization, not just the parent query.',
          refs: ['CWE-213'],
        },
      ],
    },
    {
      id: 'API4',
      title: 'API4:2023 – Unrestricted Resource Consumption',
      description: 'No limits on requests, payload size or expensive operations leads to DoS or runaway costs.',
      items: [
        {
          id: 'api4-rate-limits',
          text: 'Rate limits and quotas exist per client/user, with 429 responses.',
          detail:
            'Configured at the gateway or application, per endpoint cost. Check that limits key on the authenticated principal, not only on an IP that can rotate.',
          refs: ['CWE-770', 'CWE-799'],
        },
        {
          id: 'api4-pagination',
          text: 'List endpoints paginate with a server-enforced maximum page size.',
          detail:
            '?limit=1000000 must be capped. Also limit the number of items in batch requests and array inputs.',
          refs: ['CWE-770'],
        },
        {
          id: 'api4-payload-limits',
          text: 'Request body size, upload size, string lengths and decompression ratios are limited.',
          detail:
            'Set body-parser/Kestrel/servlet limits explicitly. Image processing and archive extraction need max dimensions / max uncompressed size.',
          refs: ['CWE-400', 'CWE-409'],
        },
        {
          id: 'api4-graphql-cost',
          text: 'GraphQL APIs limit query depth, complexity/cost and aliases/batching.',
          detail:
            'Use a depth limit and cost analysis (or persisted queries only). A single nested query can otherwise fetch millions of records.',
          refs: ['CWE-400'],
        },
        {
          id: 'api4-paid-actions',
          text: 'Operations with a per-call cost (SMS, email, third-party paid APIs, LLM calls) have spending limits and alerts.',
          detail:
            'Attackers abuse "send OTP" endpoints to run up SMS bills (SMS pumping). Cap per user, per destination and globally.',
          refs: ['CWE-799'],
        },
        {
          id: 'api4-timeouts',
          text: 'Server-side timeouts are set for request handling, DB queries and outbound calls.',
          detail:
            'Without timeouts, a slow dependency or deliberately slow client exhausts the worker pool.',
          refs: ['CWE-400'],
        },
      ],
    },
    {
      id: 'API5',
      title: 'API5:2023 – Broken Function Level Authorization',
      description: 'Regular users can call administrative or privileged functions.',
      items: [
        {
          id: 'api5-admin-endpoints',
          text: 'Administrative and privileged operations check the caller\'s role/permission on the server, for every HTTP method.',
          detail:
            'A common miss: GET /users/{id} is meant for every user, and the UI shows the delete button only to admins, but DELETE /users/{id} accepts any authenticated user. Test each method with a low-privileged token.',
          refs: ['CWE-285', 'CWE-862'],
        },
        {
          id: 'api5-central-policy',
          text: 'Authorization rules live in a central, consistent mechanism (policies, annotations, middleware), deny by default.',
          detail:
            'Scattered if (user.isAdmin) checks are easy to forget. Prefer declarative policies and a test that lists routes lacking a policy.',
          refs: ['CWE-862'],
        },
        {
          id: 'api5-predictable-paths',
          text: 'Hidden or "internal" admin routes are not relied on for protection (/api/admin, /v1/internal).',
          detail:
            'Attackers guess these from the client bundle, OpenAPI docs or by swapping path segments. Network isolation helps but the auth check is still required.',
          refs: ['CWE-425'],
        },
      ],
    },
    {
      id: 'API6',
      title: 'API6:2023 – Unrestricted Access to Sensitive Business Flows',
      description: 'Business flows (buying, booking, posting, referrals) abused at scale by automation.',
      items: [
        {
          id: 'api6-identify-flows',
          text: 'Business flows that would hurt if automated (checkout of limited stock, sign-up bonuses, reservations, comments) are identified.',
          detail:
            'Ask the product owner: "What happens if a bot does this 10,000 times a minute?" Document the flows and the acceptable rate.',
          refs: ['CWE-799'],
        },
        {
          id: 'api6-protections',
          text: 'Identified flows have anti-automation: device fingerprinting, CAPTCHA or proof-of-work, per-user limits, human-pattern checks.',
          detail:
            'Protection must be on the API, not just the web form — bots call the API directly. Consider blocking known hosting/Tor IP ranges for consumer-only flows.',
          refs: ['CWE-799'],
        },
        {
          id: 'api6-business-rules',
          text: 'Business rules are enforced server-side (one coupon per account, max tickets per order, referral self-abuse checks).',
          detail:
            'Rules applied only in the front-end are bypassed by calling the API directly.',
          refs: ['CWE-602'],
        },
      ],
    },
    {
      id: 'API7',
      title: 'API7:2023 – Server Side Request Forgery',
      description: 'The API fetches a remote resource from a user-supplied URL without validation.',
      items: [
        {
          id: 'api7-allowlist',
          text: 'User-supplied URLs (webhooks, imports, avatars, link previews) are validated against an allow-list of schemes, hosts and ports.',
          detail:
            'Only http/https; block file:, gopher:, dict:. Prefer an allow-list of domains over a deny-list.',
          refs: ['CWE-918'],
        },
        {
          id: 'api7-internal-ranges',
          text: 'Resolved IP addresses are checked against private, loopback, link-local and cloud metadata ranges at connection time.',
          detail:
            'Validate after DNS resolution and pin the resolved IP to defeat DNS rebinding. Block 169.254.169.254 and fd00:ec2::254; require IMDSv2 on AWS.',
          stacks: ['api', 'infra'],
          refs: ['CWE-918'],
        },
        {
          id: 'api7-redirects',
          text: 'The HTTP client does not follow redirects (or re-validates each hop), and raw responses are not returned to the caller.',
          detail:
            'An allowed host can redirect to an internal one. Return only the needed, parsed data instead of the full upstream response.',
          refs: ['CWE-918'],
        },
        {
          id: 'api7-egress',
          text: 'The service that fetches URLs runs with restricted network egress.',
          detail:
            'Isolate URL fetching in a separate service or network segment with egress rules that only allow the internet, not internal subnets.',
          stacks: ['infra'],
        },
      ],
    },
    {
      id: 'API8',
      title: 'API8:2023 – Security Misconfiguration',
      description: 'Insecure defaults, missing hardening, permissive CORS, verbose errors, unpatched systems across the API stack.',
      items: [
        {
          id: 'api8-cors',
          text: 'CORS allows only known origins and is not a reflected Origin with Access-Control-Allow-Credentials: true.',
          detail:
            'APIs consumed only server-to-server should not send CORS headers at all.',
          refs: ['CWE-942'],
        },
        {
          id: 'api8-errors',
          text: 'Error responses are generic and consistent; no stack traces, framework versions or SQL fragments.',
          detail:
            'Use a standard error format (e.g. RFC 9457 Problem Details) with a correlation id. Remove X-Powered-By / Server version headers.',
          refs: ['CWE-209'],
        },
        {
          id: 'api8-methods-content-type',
          text: 'Only the expected HTTP methods and content types are accepted; responses set a correct Content-Type and X-Content-Type-Options: nosniff.',
          detail:
            'Reject unexpected Content-Type (e.g. XML on a JSON endpoint, which may enable XXE). Disable TRACE.',
        },
        {
          id: 'api8-transport',
          text: 'TLS is enforced end to end, including between gateway and backend services.',
          detail:
            'Plain HTTP between the load balancer and the service is acceptable only within a trusted, isolated network segment and should be a documented decision.',
          refs: ['CWE-319'],
        },
        {
          id: 'api8-hardening',
          text: 'Framework, server and container configuration is hardened and patched; the same configuration is applied consistently across environments.',
          detail:
            'Automate config via IaC and scan it (Checkov, kube-score). Drift between staging and prod hides misconfigurations.',
          stacks: ['infra'],
        },
      ],
    },
    {
      id: 'API9',
      title: 'API9:2023 – Improper Inventory Management',
      description: 'Forgotten API versions, undocumented endpoints and unknown data flows to third parties.',
      items: [
        {
          id: 'api9-inventory',
          text: 'All API hosts, versions and environments are inventoried, with owner, audience (public/partner/internal) and data sensitivity.',
          detail:
            'An OpenAPI spec generated from code (not hand-written) is the most reliable inventory for a service.',
        },
        {
          id: 'api9-old-versions',
          text: 'Deprecated API versions have a retirement date and receive the same security fixes until removed.',
          detail:
            'Attackers target /v1 when /v2 got the fix. Check that old versions are not still routed in the gateway.',
          refs: ['CWE-1059'],
        },
        {
          id: 'api9-non-prod',
          text: 'Non-production APIs are not publicly reachable and do not use production data.',
          detail:
            'Staging and beta hosts often have weaker auth and debug features enabled. Restrict them to VPN/SSO and use synthetic data.',
          stacks: ['infra'],
        },
        {
          id: 'api9-data-flows',
          text: 'Data flows to third parties are documented: what data is sent, to whom, and under which agreement.',
          detail:
            'Each new integration in the PR should be added to the inventory and, when personal data is involved, to the privacy register.',
        },
      ],
    },
    {
      id: 'API10',
      title: 'API10:2023 – Unsafe Consumption of APIs',
      description: 'Trusting data from third-party APIs more than user input.',
      items: [
        {
          id: 'api10-validate-responses',
          text: 'Responses from third-party and internal APIs are validated and sanitized like user input before use.',
          detail:
            'A compromised or malicious partner can return payloads that become SQL injection, XSS or oversized data in your system. Validate against a schema.',
          refs: ['CWE-20'],
        },
        {
          id: 'api10-tls-redirects',
          text: 'Calls to third-party APIs use TLS with certificate validation and do not blindly follow redirects.',
          detail:
            'Pin to the expected host; a redirect to another host could leak credentials sent in headers.',
          refs: ['CWE-295'],
        },
        {
          id: 'api10-limits',
          text: 'Third-party calls have timeouts, response size limits and circuit breakers.',
          detail:
            'A slow or huge response from a partner should degrade one feature, not take down your service.',
          refs: ['CWE-400'],
        },
        {
          id: 'api10-credentials',
          text: 'Credentials for third-party APIs are stored in a secret manager, scoped to the minimum permissions and rotatable.',
          detail:
            'Use separate keys per environment, and know how to revoke one quickly if the partner is breached.',
          refs: ['CWE-798'],
        },
      ],
    },
  ],
}
