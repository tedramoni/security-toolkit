import type { Checklist } from '../types'

/**
 * Everyday pull-request security review. Distilled from the OWASP Code Review Guide and the
 * OWASP Cheat Sheet Series; each item points at the matching CWE where one applies.
 */
export const prQuick: Checklist = {
  id: 'pr-quick',
  title: 'Pull Request quick review',
  version: '1.0',
  source: 'https://cheatsheetseries.owasp.org/cheatsheets/Secure_Code_Review_Cheat_Sheet.html',
  description:
    'A 10-minute security pass for everyday pull requests. Mark what does not apply as N/A and paste the summary into the PR.',
  categories: [
    {
      id: 'access',
      title: 'Access & identity',
      description: 'New entry points and who can reach them.',
      items: [
        {
          id: 'pr-authn-new-endpoints',
          text: 'New or changed endpoints, handlers, jobs and message consumers require authentication (or are intentionally public and documented).',
          detail:
            'Check the route is covered by the auth middleware / annotation. A "public" endpoint should be called out in the PR description.',
          refs: ['CWE-306'],
        },
        {
          id: 'pr-authz',
          text: 'Authorization is checked for the specific action and object (role/permission and ownership/tenant).',
          detail:
            'Look at how the record is loaded: it should be scoped to the caller (owner, tenant, team). Ask for a test where another user gets 403/404.',
          refs: ['CWE-862', 'CWE-639'],
        },
        {
          id: 'pr-client-trust',
          text: 'No security decision relies on client-controlled data (hidden fields, headers like X-User-Id, role in body, front-end checks).',
          detail:
            'Identity and permissions come from the verified session/token only. Prices and totals are recomputed server-side.',
          refs: ['CWE-602', 'CWE-807'],
        },
      ],
    },
    {
      id: 'input-output',
      title: 'Input & output',
      description: 'Untrusted data entering and leaving the change.',
      items: [
        {
          id: 'pr-input-validation',
          text: 'New inputs are validated server-side for type, length, format and range (schema/DTO validation), and unknown fields are rejected.',
          detail:
            'Look for a schema (Zod, Joi, pydantic, Bean Validation, FluentValidation) on every new request model, query parameter and message payload.',
          refs: ['CWE-20'],
        },
        {
          id: 'pr-sql',
          text: 'Database access uses parameterized queries / ORM bindings — no string concatenation or interpolation with variables.',
          detail:
            'Pay special attention to raw-SQL escape hatches and dynamic ORDER BY / column names, which need an allow-list.',
          refs: ['CWE-89'],
        },
        {
          id: 'pr-output-encoding',
          text: 'Output is encoded for its context; no new raw-HTML sinks with untrusted data (innerHTML, dangerouslySetInnerHTML, v-html, |safe, Html.Raw).',
          detail:
            'If HTML from users is really needed, it goes through a maintained sanitizer such as DOMPurify. Links built from user input allow only http(s).',
          stacks: ['web'],
          refs: ['CWE-79'],
        },
        {
          id: 'pr-commands-files-urls',
          text: 'User input does not reach shell commands, file paths, server-side URL fetches, redirects, eval or deserializers without strict validation.',
          detail:
            'These are the high-impact sinks: command injection, path traversal, SSRF, open redirect, code injection and unsafe deserialization.',
          refs: ['CWE-78', 'CWE-22', 'CWE-918', 'CWE-601', 'CWE-502'],
        },
        {
          id: 'pr-data-exposure',
          text: 'Responses return only the fields the caller needs (explicit DTO/serializer), and writes accept only allow-listed fields.',
          detail:
            'Returning ORM entities leaks internal fields; binding the whole body enables mass assignment (role, ownerId, isAdmin).',
          stacks: ['api'],
          refs: ['CWE-213', 'CWE-915'],
        },
      ],
    },
    {
      id: 'secrets-crypto',
      title: 'Secrets & cryptography',
      description: 'Credentials and crypto choices introduced by the change.',
      items: [
        {
          id: 'pr-no-secrets',
          text: 'No secrets in code, config, tests, fixtures or commit history (API keys, passwords, private keys, connection strings, tokens).',
          detail:
            'Secrets come from environment / secret manager. If a secret was ever committed, rotate it — deleting it in a later commit is not enough. Paste the diff into the Toolbox secrets scanner if in doubt.',
          refs: ['CWE-798'],
        },
        {
          id: 'pr-crypto',
          text: 'Any new crypto uses vetted libraries and modern primitives; random secrets come from a CSPRNG.',
          detail:
            'No home-made crypto, no MD5/SHA-1 for security, no ECB, no Math.random / random.random for tokens. Passwords use Argon2id, scrypt or bcrypt.',
          refs: ['CWE-327', 'CWE-330'],
        },
      ],
    },
    {
      id: 'errors-logging',
      title: 'Errors & logging',
      description: 'What leaks to users and what lands in logs.',
      items: [
        {
          id: 'pr-error-messages',
          text: 'Error responses are generic (no stack traces, SQL, internal paths or hostnames) and do not reveal whether an account exists.',
          detail:
            'Detailed errors go to server logs with a correlation id that is returned to the client.',
          refs: ['CWE-209', 'CWE-204'],
        },
        {
          id: 'pr-fail-closed',
          text: 'Exceptions in security-relevant code fail closed (deny / roll back), and no errors are silently swallowed.',
          detail:
            'Look for empty catch blocks and try/catch around auth or validation checks that continue on error.',
          refs: ['CWE-636', 'CWE-390'],
        },
        {
          id: 'pr-logging-sensitive',
          text: 'Logs do not contain passwords, tokens, session ids, full card numbers or unnecessary personal data.',
          detail:
            'Check new log statements and any request/response logging. Mask or hash where an identifier is needed for correlation.',
          refs: ['CWE-532'],
        },
        {
          id: 'pr-security-events',
          text: 'Security-relevant actions added by the PR (permission changes, exports, admin actions, auth events) are audit-logged.',
          detail:
            'Who did what, on which object, when (UTC), from where, and the outcome — as structured fields.',
          refs: ['CWE-778'],
        },
      ],
    },
    {
      id: 'deps-config',
      title: 'Dependencies & configuration',
      description: 'Third-party code, defaults and deployment settings.',
      items: [
        {
          id: 'pr-new-dependency',
          text: 'Any added or upgraded dependency is needed, maintained, free of known vulnerabilities and has an acceptable licence.',
          detail:
            'Check OSV.dev (or the Dependencies module), the repository activity, typosquatting and install scripts. The lockfile change is part of the review.',
          refs: ['CWE-1395', 'CWE-1104'],
        },
        {
          id: 'pr-secure-defaults',
          text: 'New feature flags and settings default to the secure option, and debug/test switches cannot be enabled in production.',
          detail:
            'A flag that disables a check must default to "check enabled". Test-only backdoors must be compiled out or impossible to reach in prod.',
          refs: ['CWE-1188', 'CWE-489'],
        },
        {
          id: 'pr-ci-iac',
          text: 'Changes to CI workflows, Dockerfiles or IaC keep least privilege (pinned actions, minimal token permissions, non-root containers, no public exposure).',
          detail:
            'GitHub Actions: pin third-party actions to a commit SHA, set permissions explicitly, avoid pull_request_target with checkout of PR code.',
          stacks: ['infra'],
          refs: ['CWE-250', 'CWE-829'],
        },
        {
          id: 'pr-limits',
          text: 'New loops, queries, uploads and outbound calls are bounded (pagination limits, size limits, timeouts, rate limits).',
          detail:
            'User-controlled sizes or counts without a cap become denial-of-service or cost problems.',
          refs: ['CWE-770', 'CWE-400'],
        },
      ],
    },
    {
      id: 'tests',
      title: 'Tests & documentation',
      description: 'Proof that the security behaviour works and stays working.',
      items: [
        {
          id: 'pr-negative-tests',
          text: 'Tests cover the security paths: unauthenticated, wrong user/tenant, wrong role, invalid input — not only the happy path.',
          detail:
            'At minimum one test per new endpoint asserting 401/403 for an unauthorized caller.',
        },
        {
          id: 'pr-threat-model',
          text: 'If the PR changes a trust boundary, data flow or authentication, the threat model / architecture docs are updated.',
          detail:
            'New external integration, new data store, new public endpoint or new type of personal data are typical triggers.',
        },
      ],
    },
  ],
}
