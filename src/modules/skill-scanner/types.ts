/** Shared types for the AI Skill Scanner. */

export type Sev = 'critical' | 'high' | 'medium' | 'low' | 'info'

export const SEVERITIES: readonly Sev[] = ['critical', 'high', 'medium', 'low', 'info']

export function sevRank(s: Sev): number {
  return SEVERITIES.indexOf(s)
}

/** One step less severe (info stays info). */
export function downgrade(s: Sev): Sev {
  return SEVERITIES[Math.min(SEVERITIES.length - 1, sevRank(s) + 1)]
}

/**
 * What a file is, decided from its path (or chosen by the user for pasted text).
 * - skill-md: a SKILL.md (Agent Skills / Claude Code skill)
 * - agent-md: agent instruction files (AGENTS.md, CLAUDE.md, .cursorrules, copilot-instructions.md…)
 * - markdown: any other Markdown / text documentation
 * - script: source code and shell scripts bundled with the skill
 * - json-config: other JSON / YAML / TOML config (package.json…)
 * - mcp-config: MCP server configuration (.mcp.json, claude_desktop_config.json, .vscode/mcp.json…)
 * - claude-settings: Claude Code settings (.claude/settings.json…)
 * - text: plain text of unknown type
 * - binary: not scanned for text (executables are flagged)
 */
export type FileKind =
  | 'skill-md'
  | 'agent-md'
  | 'markdown'
  | 'script'
  | 'json-config'
  | 'mcp-config'
  | 'claude-settings'
  | 'text'
  | 'binary'

export const FILE_KINDS: readonly { id: FileKind; label: string }[] = [
  { id: 'skill-md', label: 'SKILL.md (Agent Skill)' },
  { id: 'agent-md', label: 'Agent instructions (AGENTS.md, CLAUDE.md, .cursorrules…)' },
  { id: 'markdown', label: 'Markdown / documentation' },
  { id: 'script', label: 'Script / source code' },
  { id: 'mcp-config', label: 'MCP config (.mcp.json, claude_desktop_config.json…)' },
  { id: 'claude-settings', label: 'Claude Code settings.json' },
  { id: 'json-config', label: 'Other JSON / YAML config' },
  { id: 'text', label: 'Plain text' },
]

export const MARKDOWN_KINDS: readonly FileKind[] = ['skill-md', 'agent-md', 'markdown']
export const CONFIG_KINDS: readonly FileKind[] = ['json-config', 'mcp-config', 'claude-settings']

/**
 * Where on a line a match sits.
 * - frontmatter: YAML frontmatter of a Markdown file
 * - prose: normal Markdown text (instructions read by the agent)
 * - inline: `inline code` inside prose
 * - code: fenced code block, script, or config file
 * - code-comment: a comment line inside a script
 * - hidden-comment: HTML comment / Markdown link-reference comment (invisible when rendered)
 */
export type Ctx = 'frontmatter' | 'prose' | 'inline' | 'code' | 'code-comment' | 'hidden-comment'

export type Category =
  | 'prompt-injection'
  | 'jailbreak'
  | 'exfiltration'
  | 'credential-access'
  | 'secrets'
  | 'agent-snooping'
  | 'privilege-escalation'
  | 'supply-chain'
  | 'excessive-agency'
  | 'output-handling'
  | 'dynamic-code'
  | 'tool-misuse'
  | 'ssrf'
  | 'deserialization'
  | 'memory-poisoning'
  | 'rogue-agent'
  | 'trigger-abuse'
  | 'permissions'
  | 'mcp'
  | 'lifecycle-hooks'
  | 'hidden-content'
  | 'binary'
  | 'metadata'

export interface CategoryInfo {
  label: string
  /** Reference used as SARIF helpUri for rules of this category. */
  ref: string
}

const OWASP = 'https://genai.owasp.org/llmrisk/'
export const CATEGORIES: Record<Category, CategoryInfo> = {
  'prompt-injection': { label: 'Prompt injection & prompt leakage', ref: `${OWASP}llm01-prompt-injection/` },
  jailbreak: { label: 'Jailbreak / anti-refusal', ref: `${OWASP}llm01-prompt-injection/` },
  exfiltration: { label: 'Data exfiltration', ref: `${OWASP}llm022025-sensitive-information-disclosure/` },
  'credential-access': { label: 'Credential access', ref: 'https://attack.mitre.org/tactics/TA0006/' },
  secrets: { label: 'Hard-coded secrets', ref: 'https://cwe.mitre.org/data/definitions/798.html' },
  'agent-snooping': { label: 'Agent snooping (other agents’ config & history)', ref: `${OWASP}llm022025-sensitive-information-disclosure/` },
  'privilege-escalation': { label: 'Privilege escalation', ref: 'https://attack.mitre.org/tactics/TA0004/' },
  'supply-chain': { label: 'Supply chain', ref: `${OWASP}llm032025-supply-chain/` },
  'excessive-agency': { label: 'Excessive agency / destructive actions', ref: `${OWASP}llm062025-excessive-agency/` },
  'output-handling': { label: 'Improper output handling', ref: `${OWASP}llm052025-improper-output-handling/` },
  'dynamic-code': { label: 'Dynamic code execution', ref: 'https://cwe.mitre.org/data/definitions/95.html' },
  'tool-misuse': { label: 'Tool misuse / insecure defaults', ref: 'https://cwe.mitre.org/data/definitions/78.html' },
  ssrf: { label: 'SSRF / internal network access', ref: 'https://cwe.mitre.org/data/definitions/918.html' },
  deserialization: { label: 'Insecure deserialization', ref: 'https://cwe.mitre.org/data/definitions/502.html' },
  'memory-poisoning': { label: 'Memory / instruction-file poisoning', ref: `${OWASP}llm042025-data-and-model-poisoning/` },
  'rogue-agent': { label: 'Rogue agent (persistence, self-modification)', ref: 'https://attack.mitre.org/tactics/TA0003/' },
  'trigger-abuse': { label: 'Trigger abuse (over-broad skill activation)', ref: `${OWASP}llm062025-excessive-agency/` },
  permissions: { label: 'Wildcard permissions / approval bypass', ref: `${OWASP}llm062025-excessive-agency/` },
  mcp: { label: 'MCP servers & tool poisoning', ref: `${OWASP}llm032025-supply-chain/` },
  'lifecycle-hooks': { label: 'Lifecycle & agent hooks', ref: 'https://cwe.mitre.org/data/definitions/829.html' },
  'hidden-content': { label: 'Hidden content & Unicode deception', ref: 'https://trojansource.codes/' },
  binary: { label: 'Shipped binaries & archives', ref: 'https://cwe.mitre.org/data/definitions/506.html' },
  metadata: { label: 'Skill metadata', ref: 'https://agentskills.io/specification' },
}

/** Metadata common to regex rules and structured checks (used by SARIF, rule toggles, docs). */
export interface RuleMeta {
  id: string
  category: Category
  severity: Sev
  title: string
  description: string
  remediation: string
}

/** A text (or binary placeholder) file to scan. Content stays in memory only. */
export interface ScanFile {
  path: string
  /** Undefined for binaries. */
  content?: string
  size: number
  /** Force a kind (used for pasted text). */
  kind?: FileKind
  /** Set when the file was truncated before scanning. */
  truncated?: boolean
  /** Executable format detected from magic bytes (binary files only). */
  executable?: string
}

export interface Finding {
  ruleId: string
  category: Category
  /** Effective severity (after any false-positive downgrade). */
  severity: Sev
  baseSeverity: Sev
  title: string
  /** Specific detail for this occurrence (may include decoded hidden text, redacted secrets…). */
  message: string
  path: string
  /** 1-based; 0 = whole file. */
  line: number
  /** 1-based column of the match start (UTF-16 units). */
  column: number
  /** Exclusive end column on the same line. */
  endColumn: number
  ctx?: Ctx
  /** Set when the match looks like documentation / defensive phrasing. */
  possibleFalsePositive?: string
  /** Hide the matched span in snippets (secrets). */
  redactMatch?: boolean
  /** Stable identifier: hash(rule + path + normalised line text) + occurrence index. */
  fingerprint: string
}

export interface Suppression {
  fingerprint: string
  ruleId: string
  path: string
  line: number
  reason: string
  createdAt: string
}
