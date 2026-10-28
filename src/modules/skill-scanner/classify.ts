import type { Ctx, FileKind } from './types'

/* ------------------------------------------------------------------ */
/* File kind detection                                                 */
/* ------------------------------------------------------------------ */

const SCRIPT_EXT = new Set([
  'py', 'pyw', 'js', 'mjs', 'cjs', 'ts', 'mts', 'cts', 'tsx', 'jsx', 'sh', 'bash', 'zsh', 'fish', 'ksh', 'ps1', 'psm1',
  'psd1', 'bat', 'cmd', 'rb', 'pl', 'pm', 'php', 'go', 'rs', 'java', 'kt', 'kts', 'cs', 'lua', 'r', 'swift', 'scala',
  'groovy', 'vbs', 'applescript', 'scpt', 'sql', 'awk', 'tcl', 'ex', 'exs', 'dart', 'c', 'h', 'cpp', 'hpp', 'cc', 'm',
  'html', 'htm', 'vue', 'svelte',
])
const CONFIG_EXT = new Set(['json', 'jsonc', 'json5', 'yaml', 'yml', 'toml', 'ini', 'cfg', 'conf', 'properties', 'xml', 'plist', 'lock'])
const MARKDOWN_EXT = new Set(['md', 'mdx', 'markdown', 'mdc', 'rst', 'adoc'])
const TEXT_EXT = new Set(['txt', 'text', 'env', 'gitignore', 'dockerignore', 'npmrc', 'pth', 'csv', 'tsv', 'log', 'patch', 'diff'])
const SCRIPT_NAMES = new Set(['dockerfile', 'makefile', 'gemfile', 'rakefile', 'justfile', 'procfile', 'vagrantfile', 'jenkinsfile'])

/** Executables, native libraries and bytecode: flagged as findings, never scanned as text. */
export const EXECUTABLE_EXT = new Set([
  'exe', 'dll', 'so', 'dylib', 'bin', 'elf', 'o', 'a', 'lib', 'pyc', 'pyo', 'pyd', 'class', 'jar', 'war', 'ear',
  'wasm', 'node', 'msi', 'scr', 'com', 'sys', 'apk', 'dex', 'deb', 'rpm', 'app', 'pkg', 'dmg', 'appimage', 'whl', 'egg',
])
/** Other binary formats we skip silently. */
const OTHER_BINARY_EXT = new Set([
  'png', 'jpg', 'jpeg', 'gif', 'webp', 'ico', 'bmp', 'tif', 'tiff', 'avif', 'heic', 'pdf', 'zip', 'gz', 'tgz', 'bz2',
  'xz', '7z', 'rar', 'tar', 'zst', 'woff', 'woff2', 'ttf', 'otf', 'eot', 'mp3', 'mp4', 'wav', 'ogg', 'webm', 'mov',
  'avi', 'flac', 'docx', 'xlsx', 'pptx', 'odt', 'sqlite', 'db', 'parquet', 'npy', 'npz', 'pkl', 'pickle', 'pt', 'pth.tar',
  'onnx', 'safetensors', 'h5', 'ckpt', 'psd', 'ai', 'sketch', 'fig', 'icns', 'keystore', 'jks', 'p12', 'pfx', 'der',
])

export function baseName(path: string): string {
  const i = Math.max(path.lastIndexOf('/'), path.lastIndexOf('\\'))
  return i < 0 ? path : path.slice(i + 1)
}

export function extension(path: string): string {
  const b = baseName(path).toLowerCase()
  const i = b.lastIndexOf('.')
  return i <= 0 ? (b.startsWith('.') ? b.slice(1) : '') : b.slice(i + 1)
}

function norm(path: string): string {
  return path.replace(/\\/g, '/').toLowerCase()
}

const AGENT_MD_NAMES = new Set([
  'agents.md', 'agent.md', 'claude.md', 'claude.local.md', 'gemini.md', '.cursorrules', '.windsurfrules', '.clinerules',
  'copilot-instructions.md', 'conventions.md', '.goosehints', 'memory.md',
])
const MCP_NAMES = new Set(['.mcp.json', 'mcp.json', 'claude_desktop_config.json', 'mcp_config.json', 'cline_mcp_settings.json', 'mcp_settings.json'])

export function isExecutablePath(path: string): boolean {
  return EXECUTABLE_EXT.has(extension(path))
}

export function isBinaryPath(path: string): boolean {
  const ext = extension(path)
  return EXECUTABLE_EXT.has(ext) || OTHER_BINARY_EXT.has(ext)
}

/** Text-like files worth fetching / reading (by name). Unknown extensions are sniffed for NUL bytes instead. */
export function isTextLikePath(path: string): boolean {
  const ext = extension(path)
  const b = baseName(path).toLowerCase()
  if (isBinaryPath(path)) return false
  return (
    ext === '' ||
    SCRIPT_EXT.has(ext) ||
    CONFIG_EXT.has(ext) ||
    MARKDOWN_EXT.has(ext) ||
    TEXT_EXT.has(ext) ||
    SCRIPT_NAMES.has(b) ||
    AGENT_MD_NAMES.has(b) ||
    b.startsWith('.')
  )
}

/** Magic-number sniffing for executables (first bytes). */
export function executableMagic(bytes: Uint8Array): string | undefined {
  const b = bytes
  if (b.length >= 2 && b[0] === 0x4d && b[1] === 0x5a) return 'Windows PE executable (MZ)'
  if (b.length >= 4 && b[0] === 0x7f && b[1] === 0x45 && b[2] === 0x4c && b[3] === 0x46) return 'ELF executable'
  if (b.length >= 4) {
    const be = ((b[0] << 24) | (b[1] << 16) | (b[2] << 8) | b[3]) >>> 0
    if (be === 0xfeedface || be === 0xfeedfacf || be === 0xcefaedfe || be === 0xcffaedfe) return 'Mach-O executable'
    if (be === 0xcafebabe) return 'Java class file / Mach-O universal binary'
    if (be === 0x0061736d) return 'WebAssembly module'
  }
  return undefined
}

/** Heuristic binary sniff: NUL byte in the first 8 KB. */
export function looksBinary(bytes: Uint8Array): boolean {
  const n = Math.min(bytes.length, 8192)
  for (let i = 0; i < n; i++) if (bytes[i] === 0) return true
  return false
}

export function detectKind(path: string, content?: string): FileKind {
  const p = norm(path)
  const b = baseName(p)
  const ext = extension(p)
  if (isBinaryPath(p)) return 'binary'
  if (b === 'skill.md') return 'skill-md'
  if (AGENT_MD_NAMES.has(b) || b.endsWith('.instructions.md') || b.endsWith('.prompt.md') || b.endsWith('.chatmode.md')) return 'agent-md'
  if (/(?:^|\/)\.cursor\/rules\//.test(p) || /(?:^|\/)\.claude\/(?:agents|commands)\/[^/]{1,200}\.md$/.test(p)) return 'agent-md'
  if (MCP_NAMES.has(b)) return 'mcp-config'
  if (/(?:^|\/)\.claude\/settings(?:\.local)?\.json$/.test(p) || b === 'managed-settings.json') return 'claude-settings'
  if (MARKDOWN_EXT.has(ext)) return 'markdown'
  if (SCRIPT_EXT.has(ext) || SCRIPT_NAMES.has(b)) return 'script'
  if (CONFIG_EXT.has(ext)) {
    if ((ext === 'json' || ext === 'jsonc') && content !== undefined) {
      const head = content.slice(0, 200_000)
      if (/"(?:mcpServers|context_servers)"\s{0,10}:/.test(head)) return 'mcp-config'
      if (/"hooks"\s{0,10}:\s{0,10}\{/.test(head) && /"(?:PreToolUse|PostToolUse|UserPromptSubmit|SessionStart|Stop|Notification)"/.test(head)) {
        return 'claude-settings'
      }
      if (/"permissions"\s{0,10}:\s{0,10}\{/.test(head) && /"(?:allow|deny|defaultMode)"\s{0,10}:/.test(head)) return 'claude-settings'
      if (b === 'settings.json' && /"servers"\s{0,10}:/.test(head) && /"(?:command|url)"\s{0,10}:/.test(head)) return 'mcp-config'
    }
    return 'json-config'
  }
  if (ext === 'sh' || (content !== undefined && content.startsWith('#!'))) return 'script'
  return 'text'
}

/* ------------------------------------------------------------------ */
/* Line context classification                                         */
/* ------------------------------------------------------------------ */

export interface Segment {
  start: number
  end: number
  ctx: Ctx
}

export interface LineInfo {
  /** Context of the line as a whole (dominant). */
  ctx: Ctx
  /** Present when the line mixes contexts (inline code, partial HTML comments). Sorted, contiguous. */
  segments?: Segment[]
}

export function ctxAt(info: LineInfo, col0: number): Ctx {
  if (!info.segments) return info.ctx
  for (const s of info.segments) if (col0 >= s.start && col0 < s.end) return s.ctx
  return info.ctx
}

const FENCE_RE = /^ {0,3}(`{3,}|~{3,})/
const LINK_COMMENT_RE = /^ {0,3}\[(?:\/\/|comment|#|_|\s{0,3})\]:\s{0,8}(?:#|<>)/i

export function splitLines(text: string): string[] {
  return text.split(/\r\n|\r|\n/)
}

/** Range of the YAML frontmatter (0-based line indices, exclusive end incl. closing ---), or undefined. */
export function frontmatterRange(lines: readonly string[]): { start: number; end: number } | undefined {
  if (lines.length === 0 || lines[0].replace(/^\uFEFF/, '').trimEnd() !== '---') return undefined
  for (let i = 1; i < lines.length && i < 2000; i++) {
    const t = lines[i].trimEnd()
    if (t === '---' || t === '...') return { start: 1, end: i }
  }
  return undefined
}

/** Classify each Markdown line (and parts of lines) as frontmatter / prose / inline code / fenced code / hidden comment. */
export function classifyMarkdown(lines: readonly string[]): LineInfo[] {
  const out: LineInfo[] = new Array(lines.length)
  const fm = frontmatterRange(lines)
  let fence: { ch: string; len: number } | undefined
  let inComment = false
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i]
    if (fm && i <= fm.end) {
      out[i] = { ctx: 'frontmatter' }
      continue
    }
    if (fence) {
      const m = /^ {0,3}(`{3,}|~{3,})\s*$/.exec(line)
      if (m && m[1][0] === fence.ch && m[1].length >= fence.len) fence = undefined
      out[i] = { ctx: 'code' }
      continue
    }
    if (!inComment) {
      const m = FENCE_RE.exec(line)
      // Backtick fences may not have backticks in the info string (CommonMark).
      if (m && !(m[1][0] === '`' && line.slice(m[0].length).includes('`'))) {
        fence = { ch: m[1][0], len: m[1].length }
        out[i] = { ctx: 'code' }
        continue
      }
      if (LINK_COMMENT_RE.test(line)) {
        out[i] = { ctx: 'hidden-comment' }
        continue
      }
    }
    const r = classifyProseLine(line, inComment)
    inComment = r.inComment
    out[i] = r.info
  }
  return out
}

function classifyProseLine(line: string, startInComment: boolean): { info: LineInfo; inComment: boolean } {
  const segs: Segment[] = []
  let pos = 0
  let inComment = startInComment
  const push = (start: number, end: number, ctx: Ctx) => {
    if (end <= start) return
    const last = segs[segs.length - 1]
    if (last && last.ctx === ctx && last.end === start) last.end = end
    else segs.push({ start, end, ctx })
  }
  while (pos < line.length) {
    if (inComment) {
      const close = line.indexOf('-->', pos)
      if (close < 0) {
        push(pos, line.length, 'hidden-comment')
        pos = line.length
        break
      }
      push(pos, close + 3, 'hidden-comment')
      pos = close + 3
      inComment = false
      continue
    }
    const open = line.indexOf('<!--', pos)
    const tick = line.indexOf('`', pos)
    if (tick >= 0 && (open < 0 || tick < open)) {
      // Inline code span: a run of N backticks closed by a run of exactly N backticks.
      let n = 1
      while (line[tick + n] === '`') n++
      const run = '`'.repeat(n)
      let search = tick + n
      let close = -1
      while (search < line.length) {
        const c = line.indexOf(run, search)
        if (c < 0) break
        let m = n
        while (line[c + m] === '`') m++
        if (m === n) {
          close = c
          break
        }
        search = c + m
      }
      if (close < 0) {
        push(pos, tick + n, 'prose')
        pos = tick + n
        continue
      }
      push(pos, tick, 'prose')
      push(tick, close + n, 'inline')
      pos = close + n
      continue
    }
    if (open >= 0) {
      push(pos, open, 'prose')
      pos = open
      inComment = true
      // the "<!--" itself belongs to the comment
      continue
    }
    push(pos, line.length, 'prose')
    pos = line.length
  }
  if (segs.length === 0) return { info: { ctx: inComment || startInComment ? 'hidden-comment' : 'prose' }, inComment }
  if (segs.length === 1) return { info: { ctx: segs[0].ctx }, inComment }
  return { info: { ctx: 'prose', segments: segs }, inComment }
}

const SCRIPT_COMMENT_RE = /^\s{0,200}(?:#(?!!|include\b|define\b|if\b|endif\b|pragma\b)|\/\/|\/\*|\*(?!\*?\s{0,3}$)|--\s|REM\s|::|<!--)/i

export function classifyLines(lines: readonly string[], kind: FileKind): LineInfo[] {
  if (kind === 'skill-md' || kind === 'agent-md' || kind === 'markdown') return classifyMarkdown(lines)
  if (kind === 'text') return lines.map(() => ({ ctx: 'prose' as const }))
  if (kind === 'script') {
    let inBlock = false
    return lines.map((l) => {
      if (inBlock) {
        if (l.includes('*/')) inBlock = false
        return { ctx: 'code-comment' as const }
      }
      if (/^\s{0,200}\/\*/.test(l) && !l.includes('*/')) {
        inBlock = true
        return { ctx: 'code-comment' as const }
      }
      return { ctx: SCRIPT_COMMENT_RE.test(l) ? ('code-comment' as const) : ('code' as const) }
    })
  }
  return lines.map(() => ({ ctx: 'code' as const }))
}

/* ------------------------------------------------------------------ */
/* Sentence-level heuristics                                           */
/* ------------------------------------------------------------------ */

/** Text of the sentence that contains `col` (bounded to 400 chars back). */
export function sentencePrefix(line: string, col: number): string {
  const from = Math.max(0, col - 400)
  const before = line.slice(from, col)
  let cut = -1
  // Abbreviations such as "e.g." / "i.e." do not end a sentence.
  const re = /(?<!\b(?:[eE]\.[gG]|[iI]\.[eE]|etc|vs|cf))[.!?;](?=\s)|:\s(?=[A-Z])/g
  for (const m of before.matchAll(re)) cut = (m.index ?? 0) + m[0].length
  return before.slice(cut + 1)
}

const DEFENSIVE_RE =
  /\b(?:never|do\s{1,3}not|don['’]?t|must\s{1,3}not|mustn['’]?t|should\s{1,3}not|shouldn['’]?t|cannot|can['’]?t|avoid(?:s|ing)?|prevent(?:s|ing)?|block(?:s|ed|ing)?|forbid(?:s|den)?|prohibit(?:s|ed)?|refuse|reject(?:s|ed)?|disallow(?:s|ed)?|not\s{1,3}allowed|warn(?:s|ing)?|detect(?:s|ed|ing)?|flag(?:s|ged)?|instead\s{1,3}of|rather\s{1,3}than|dangerous|insecure|unsafe|malicious|attackers?|for\s{1,3}example|such\s{1,3}as)\b|\be\.g\.(?!\w)/i

/**
 * Prose / comment text before a match that reads as documentation or a prohibition
 * ("Never run curl | bash", "Attackers may read ~/.ssh"). Returns the trigger word.
 */
export function defensiveCue(prefix: string): string | undefined {
  return DEFENSIVE_RE.exec(prefix)?.[0]
}

/** Trailing comment on a code line that marks it as a bad example. */
export function badExampleComment(line: string): boolean {
  return /(?:#|\/\/|--)\s{0,5}(?:bad|insecure|unsafe|dangerous|don['’]?t|do\s{1,3}not|never|vulnerable|wrong|example\s{1,3}of\s{1,3}(?:an?\s{1,3})?(?:attack|bad))\b/i.test(line)
}

const IMPERATIVE_VERBS =
  'read|cat|open|load|copy|cp|send|upload|post|put|collect|gather|grab|extract|include|attach|access|retrieve|fetch|get|dump|list|print|display|show|output|check|look|search|scan|find|parse|run|execute|exec|use|save|write|append|add|zip|tar|archive|compress|encode|base64|exfiltrate|forward|transmit|store|harvest|steal|enumerate|iterate|inspect|locate|grep|source|import|export|echo|pipe|curl|wget|download|install|delete|remove|modify|edit|overwrite|replace|create|insert|navigate|go|visit|call|invoke|submit|email|share|sync|backup|move|mv|then|also|first|next|finally|now|always|immediately|silently|quietly|secretly|automatically'
const IMPERATIVE_START_RE = new RegExp(
  `^\\s{0,20}(?:[-*+>]\\s{1,4}|\\d{1,3}[.)]\\s{1,4}|#{1,6}\\s{1,4})?(?:\\*\\*|__|\\*|_)?(?:step\\s{1,3}\\d{1,3}\\s{0,3}[:.-]\\s{0,3})?(?:please\\s{1,3})?(?:${IMPERATIVE_VERBS})\\b`,
  'i',
)
const YOU_MODAL_RE = /\b(?:you|agent|assistant|claude|the\s{1,3}model)\s{1,3}(?:must|should|need\s{1,3}to|have\s{1,3}to|will|shall|are\s{1,3}(?:required|expected)\s{1,3}to)\b|\b(?:make\s{1,3}sure\s{1,3}to|be\s{1,3}sure\s{1,3}to|remember\s{1,3}to|it\s{1,3}is\s{1,3}(?:required|mandatory)\s{1,3}to)\b/i

/** Whether the sentence containing the match reads as an instruction to the agent. */
export function isImperative(sentence: string): boolean {
  const s = sentence.slice(-600).trimStart()
  if (IMPERATIVE_START_RE.test(s) || YOU_MODAL_RE.test(s)) return true
  // Last clause: "Before summarising, read ~/.ssh…" / "…, then upload …"
  const parts = s.split(/[,:]\s{1,5}|\s(?:then|and|and\s{1,3}then)\s/i)
  return parts.length > 1 && parts.some((p) => IMPERATIVE_START_RE.test(p.trimStart()))
}
