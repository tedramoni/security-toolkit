import { CopyButton } from '../../lib/CopyButton'
import { ACTIONS } from '../deps/ci/versions'
import { BASELINE_FILENAME } from './report'

export const CI_SNIPPET = `# .github/workflows/upload-skill-scan.yml
# The AI Skill Scanner runs only in your browser — there is no CLI to run in CI.
# Workflow: scan the skill in the browser → "Export SARIF" (set the path prefix so paths match the
# repository) → commit it as security/skill-scanner.sarif → this workflow uploads it to
# GitHub code scanning. Re-scan and re-commit whenever the skill changes.
name: Upload AI skill scan
on:
  push:
    branches: [main]
    paths: ['security/skill-scanner.sarif']
  workflow_dispatch:
permissions:
  contents: read
  security-events: write
jobs:
  upload:
    runs-on: ubuntu-latest
    steps:
      - uses: ${ACTIONS.checkout.uses}@${ACTIONS.checkout.ref}
      - uses: ${ACTIONS.uploadSarif.uses}@${ACTIONS.uploadSarif.ref}
        with:
          sarif_file: security/skill-scanner.sarif
          category: ai-skill-scanner
`

export function AboutTab() {
  return (
    <div className="stack">
      <section className="card">
        <h2>What it scans</h2>
        <ul>
          <li>
            <strong>Agent Skills</strong> — <code>SKILL.md</code> (frontmatter: name, description, allowed-tools, hooks) and every bundled script, config and doc.
          </li>
          <li>
            <strong>Agent instruction files</strong> — <code>AGENTS.md</code>, <code>CLAUDE.md</code>, <code>.cursorrules</code>, <code>.cursor/rules/*.mdc</code>, <code>copilot-instructions.md</code>,{' '}
            <code>.claude/agents/*.md</code>, <code>.claude/commands/*.md</code>.
          </li>
          <li>
            <strong>MCP configs</strong> — <code>.mcp.json</code>, <code>mcp.json</code>, <code>.vscode/mcp.json</code>, <code>.cursor/mcp.json</code>, <code>claude_desktop_config.json</code> (unpinned npx/uvx, docker without
            digest, shell launchers, inline secrets, plain-HTTP remotes, poisoned descriptions).
          </li>
          <li>
            <strong>Claude Code settings</strong> — <code>.claude/settings*.json</code>: hooks, <code>permissions.allow</code>, <code>defaultMode</code>, <code>enableAllProjectMcpServers</code>,{' '}
            <code>additionalDirectories</code>, <code>apiKeyHelper</code>.
          </li>
          <li>
            <strong>Hidden content</strong> — Unicode TAG smuggling (decoded), bidi overrides, zero-width characters, variation-selector payloads (decoded), homoglyphs, HTML/link-reference comments,
            whitespace padding, long lines and base64 blobs (decoded preview).
          </li>
        </ul>
        <h2>How it reduces false positives</h2>
        <p>
          Every Markdown line is classified as frontmatter, prose, inline code, fenced code or hidden comment, and scripts distinguish code from comments. Each rule declares where it applies: code-only
          patterns such as <code>eval(</code> are ignored in prose; credential paths in prose only count when the sentence is an instruction; injection phrases count everywhere, including hidden comments.
          Matches in defensive sentences (“never…”, “do not…”, “avoid…”) or lines annotated as bad examples are kept but marked <em>possible false positive</em> and lowered one severity level — except
          for rules whose attack phrasing is itself a negation (“do not tell the user”).
        </p>
        <h2>Limits — read before trusting a PASS</h2>
        <ul>
          <li>Static, pattern-based analysis. It does not execute code, follow imports, resolve variables or fetch remote scripts the skill downloads.</li>
          <li>Obfuscated or novel payloads, and instructions phrased in other languages, can evade the rules. Natural-language intent is judged by heuristics, not by a model.</li>
          <li>Binaries are flagged, not analysed. ZIP64, encrypted and non-deflate archive entries are skipped (and reported).</li>
          <li>A PASS means “no known-bad pattern found”. Review new skills manually and run them with least privilege.</li>
        </ul>
        <h2>Privacy</h2>
        <p>
          Everything runs in your browser. Scanned content stays in memory and is gone when you reload. Only your rule toggles and suppressions (fingerprints, paths, line numbers, reasons) are stored in
          localStorage under <code>scp:skill-scanner</code>. A GitHub token, if you enter one, is kept in memory and sent only to api.github.com.
        </p>
      </section>

      <section className="card stack">
        <h2 style={{ margin: 0 }}>Using results in CI / GitHub code scanning</h2>
        <p>
          This scanner is <strong>browser-only</strong>: there is no command-line version, so it cannot run inside a GitHub Actions job. What you can do is export SARIF 2.1.0 from the Scan tab and let
          GitHub display it as code-scanning alerts with the workflow below. Suppressions can be shared with your team as <code>{BASELINE_FILENAME}</code>. Code scanning on private repositories requires
          GitHub Code Security (Advanced Security).
        </p>
        <pre className="codeblock">{CI_SNIPPET}</pre>
        <div className="row">
          <CopyButton text={CI_SNIPPET} label="Copy workflow" />
          <a className="small" href="https://docs.github.com/en/code-security/code-scanning/integrating-with-code-scanning/sarif-support-for-code-scanning" target="_blank" rel="noopener noreferrer">
            GitHub SARIF support docs
          </a>
        </div>
      </section>

      <section className="card">
        <h2>Credits</h2>
        <p>
          Rule categories inspired by{' '}
          <a href="https://github.com/NVIDIA/SkillSpector" target="_blank" rel="noopener noreferrer">
            NVIDIA SkillSpector
          </a>{' '}
          (Apache-2.0). The rules, context classifier and engine here are an independent implementation. Secret detection reuses the Dev Toolbox secrets ruleset (based on public token
          formats and the gitleaks defaults). Risk references: OWASP Top 10 for LLM Applications 2025, MITRE ATT&amp;CK, CWE, Trojan Source (CVE-2021-42574).
        </p>
      </section>
    </div>
  )
}
