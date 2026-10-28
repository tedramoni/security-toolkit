import { isPlaceholder, scanSecrets } from '../toolbox/secrets'
import { ctxAt } from './classify'
import type { FileScan } from './collector'
import { MAX_FINDINGS_PER_RULE_PER_FILE, addFinding, hasFindingAt } from './collector'
import type { Frontmatter } from './frontmatter'
import { fmString, parseFrontmatter, splitToolList } from './frontmatter'
import { REGEX_RULES, runnerPackage, runnerPinned } from './rules'
import { MARKDOWN_KINDS } from './types'
import {
  BIDI_RE,
  TAG_RUN_RE,
  VS_RUN_RE,
  ZERO_WIDTH_RE,
  bytesPreview,
  charName,
  decodeTags,
  decodeVariationSelectors,
  findMixedScriptWords,
  visibleEscape,
} from './unicode'

const isMd = (s: FileScan) => MARKDOWN_KINDS.includes(s.kind)

/**
 * Structured checks locate each entry with findLine() (a scan of the file), so the number of entries examined
 * is capped to keep huge generated configs from going quadratic (8,500 servers took ~30 s).
 */
export const MAX_CONFIG_ENTRIES = 300

/* ------------------------------------------------------------------ */
/* Unicode & hidden content                                            */
/* ------------------------------------------------------------------ */

const EMOJI_RE = /\p{Extended_Pictographic}/u
const NON_LATIN_LETTER_RE = /[\p{Script=Arabic}\p{Script=Hebrew}\p{Script=Devanagari}\p{Script=Bengali}\p{Script=Gurmukhi}\p{Script=Gujarati}\p{Script=Oriya}\p{Script=Tamil}\p{Script=Telugu}\p{Script=Kannada}\p{Script=Malayalam}\p{Script=Sinhala}\p{Script=Thai}\p{Script=Khmer}\p{Script=Syriac}\p{Script=Mongolian}]/u
const RTL_RE = /[\p{Script=Arabic}\p{Script=Hebrew}\p{Script=Syriac}\p{Script=Thaana}]/u

export function checkUnicode(s: FileScan): void {
  for (let i = 0; i < s.lines.length; i++) {
    const line = s.lines[i]
    // Fast path: pure ASCII lines cannot contain any of these.
    // eslint-disable-next-line no-control-regex
    if (!/[^\u0000-\u007F]/.test(line)) continue

    for (const m of line.matchAll(TAG_RUN_RE)) {
      const decoded = decodeTags(m[0])
      addFinding(s, 'SS-UC-001', {
        line: i,
        col: m.index,
        len: m[0].length,
        ctx: ctxAt(s.infos[i], m.index ?? 0),
        message: `${[...m[0]].length} invisible TAG characters. Hidden text: "${visibleEscape(decoded).slice(0, 500)}"${decoded.length > 500 ? '…' : ''}`,
      })
    }
    for (const m of line.matchAll(VS_RUN_RE)) {
      const bytes = decodeVariationSelectors(m[0])
      addFinding(s, 'SS-UC-004', {
        line: i,
        col: m.index,
        len: m[0].length,
        message: `${bytes.length} consecutive variation selectors encode hidden bytes: "${bytesPreview(bytes)}"`,
      })
    }
    const bidi = [...line.matchAll(BIDI_RE)]
    if (bidi.length > 0) {
      const names = [...new Set(bidi.map((m) => charName(m[0])))].join(', ')
      addFinding(s, 'SS-UC-002', {
        line: i,
        col: bidi[0].index,
        len: 1,
        message: `${bidi.length} bidi control character(s): ${names}.`,
        possibleFalsePositive: RTL_RE.test(line) && isMd(s) ? 'Line contains right-to-left script text, where bidi controls can be legitimate.' : undefined,
      })
    }
    const zw: { index: number; ch: string }[] = []
    for (const m of line.matchAll(ZERO_WIDTH_RE)) {
      const idx = m.index ?? 0
      const ch = m[0]
      const cp = ch.charCodeAt(0)
      if (cp === 0xfeff && i === 0 && idx === 0) continue // byte-order mark
      const prev = line.slice(Math.max(0, idx - 2), idx)
      const next = line.slice(idx + 1, idx + 3)
      // ZWJ inside emoji sequences, ZWNJ/ZWJ inside Indic/Arabic words are legitimate.
      if (cp === 0x200d && (EMOJI_RE.test(prev) || EMOJI_RE.test(next))) continue
      if ((cp === 0x200c || cp === 0x200d) && (NON_LATIN_LETTER_RE.test(prev) || NON_LATIN_LETTER_RE.test(next))) continue
      zw.push({ index: idx, ch })
    }
    if (zw.length > 0) {
      const names = [...new Set(zw.map((z) => charName(z.ch)))].join(', ')
      const onlySoftHyphen = zw.every((z) => z.ch === '\u00AD')
      addFinding(s, 'SS-UC-003', {
        line: i,
        col: zw[0].index,
        len: 1,
        message: `${zw.length} invisible character(s): ${names}.`,
        possibleFalsePositive: onlySoftHyphen ? 'Soft hyphens are sometimes used for hyphenation hints.' : undefined,
      })
    }
    for (const w of findMixedScriptWords(line)) {
      addFinding(s, 'SS-UC-005', {
        line: i,
        col: w.index,
        len: w.word.length,
        message: `"${w.word}" mixes Latin and look-alike letters (reads as "${w.skeleton}"; non-Latin: ${[...new Set([...w.word].filter((ch) => !/\p{Script=Latin}/u.test(ch)))]
          .map((ch) => `${ch} U+${(ch.codePointAt(0) ?? 0).toString(16).toUpperCase().padStart(4, '0')}`)
          .join(', ')}).`,
      })
    }
  }
}

const PAD_RE = /(?<![ \t\u00A0\u2000-\u200A\u3000])[ \t\u00A0\u2000-\u200A\u3000]{80,}(?=\S)/g
const B64_RE = /(?<![A-Za-z0-9+/=_-])[A-Za-z0-9+/]{60,20000}={0,2}(?![A-Za-z0-9+/=_-])/g
const SUSPICIOUS_DECODED_RE =
  /\b(?:curl|wget|bash|sh\s+-c|powershell|iex|eval|exec|import\s+os|subprocess|rm\s+-rf|ignore\s+(?:all\s+|previous\s+|prior\s+)|system\s+prompt|instructions?|https?:\/\/|\.ssh|\.aws|token|password|api[_-]?key)\b/i

function decodeBase64Text(b64: string): { text: string; printable: boolean } | undefined {
  try {
    const bin = atob(b64.length % 4 === 0 ? b64 : b64 + '='.repeat(4 - (b64.length % 4)))
    const bytes = Uint8Array.from(bin, (c) => c.charCodeAt(0))
    const text = new TextDecoder('utf-8', { fatal: false }).decode(bytes)
    let ok = 0
    for (const ch of text) if (/[\p{L}\p{N}\p{P}\p{S}\s]/u.test(ch) && ch !== '\uFFFD') ok++
    return { text, printable: text.length > 0 && ok / [...text].length >= 0.9 }
  } catch {
    return undefined
  }
}

const HIDDEN_STRONG_RE =
  /\b(?:ignore\s{1,3}(?:all|any|previous|prior|the)|you\s{1,3}(?:must|should|will|are)|assistant|AI|LLM|claude|agent|model|do\s{1,3}not\s{1,3}(?:tell|mention|reveal|inform)|system\s{1,3}prompt|instructions?)\b/i
const HIDDEN_WEAK_RE = /\b(?:execute|run|curl|wget|send|upload|fetch|read|post|install|download|delete|token|password|secret|key|always|never|important)\b/gi

export function checkHiddenContent(s: FileScan): void {
  const md = isMd(s)
  // Hidden comment blocks (Markdown only): collect consecutive hidden-comment text.
  if (md) {
    let block: { start: number; text: string } | undefined
    const flush = () => {
      if (!block) return
      const t = block.text
      const strong = HIDDEN_STRONG_RE.exec(t)
      const weak = new Set((t.match(HIDDEN_WEAK_RE) ?? []).map((w) => w.toLowerCase()))
      if (strong || weak.size >= 2) {
        addFinding(s, 'SS-HC-004', {
          line: block.start,
          ctx: 'hidden-comment',
          message: `Hidden comment (not shown when rendered) contains instruction-like text: "${visibleEscape(t.trim()).slice(0, 240)}${t.length > 240 ? '…' : ''}"`,
        })
      }
      block = undefined
    }
    for (let i = 0; i < s.lines.length; i++) {
      const info = s.infos[i]
      const segs = info.segments ?? [{ start: 0, end: s.lines[i].length, ctx: info.ctx }]
      const hidden = segs.filter((g) => g.ctx === 'hidden-comment')
      if (hidden.length === 0) {
        flush()
        continue
      }
      const text = hidden.map((g) => s.lines[i].slice(g.start, g.end)).join(' ')
      if (!block) block = { start: i, text }
      else block.text += ' ' + text
      // A comment closing mid-line ends the block.
      if (info.segments && hidden[hidden.length - 1].end < s.lines[i].length) flush()
      if (block && block.text.length > 20_000) flush()
    }
    flush()
  }

  for (let i = 0; i < s.lines.length; i++) {
    const line = s.lines[i]
    if (line.length >= 80) {
      for (const m of line.matchAll(PAD_RE)) {
        const idx = m.index ?? 0
        const leading = line.slice(0, idx).trim() === ''
        if (!md && leading) continue
        addFinding(s, 'SS-HC-002', {
          line: i,
          col: idx,
          len: m[0].length,
          severity: md ? 'medium' : 'low',
          message: `${m[0].length} whitespace characters push "${visibleEscape(line.slice(idx + m[0].length, idx + m[0].length + 120))}" off-screen.`,
        })
        break
      }
    }
    if (md && line.length > 1500 && s.infos[i].ctx !== 'code') {
      addFinding(s, 'SS-HC-003', { line: i, message: `Line is ${line.length.toLocaleString('en-US')} characters long; content past the visible width is easy to miss.` })
    }
    if ((md || s.kind === 'text' || s.kind === 'script') && line.length >= 60) {
      for (const m of line.matchAll(B64_RE)) {
        const blob = m[0]
        const idx = m.index ?? 0
        if (/base64,\s{0,3}$/.test(line.slice(Math.max(0, idx - 40), idx)) && /data:(?:image|font|audio|video)\//.test(line.slice(Math.max(0, idx - 80), idx))) continue
        if (/^[0-9a-fA-F]+$/.test(blob) || !/[A-Z]/.test(blob) || !/[a-z]/.test(blob) || !/[0-9+/]/.test(blob)) continue
        const dec = decodeBase64Text(blob.replace(/=+$/, ''))
        if (!dec) continue
        const suspicious = dec.printable && SUSPICIOUS_DECODED_RE.test(dec.text)
        if (s.kind === 'script' && !suspicious) continue
        if (!dec.printable && !md) continue
        addFinding(s, 'SS-HC-005', {
          line: i,
          col: idx,
          len: blob.length,
          severity: suspicious ? 'high' : 'low',
          message: dec.printable
            ? `Base64 (${blob.length} chars) decodes to text${suspicious ? ' with suspicious content' : ''}: "${visibleEscape(dec.text).slice(0, 200)}${dec.text.length > 200 ? '…' : ''}"`
            : `Base64 blob (${blob.length} chars) decodes to binary data.`,
        })
      }
    }
  }
}

/* ------------------------------------------------------------------ */
/* Secrets                                                             */
/* ------------------------------------------------------------------ */

export function checkSecrets(s: FileScan, text: string): void {
  for (const f of scanSecrets(text)) {
    const line = s.lines[f.line - 1] ?? ''
    const col = f.column - 1
    const tok = /^[^\s"'`,;)]{1,500}/.exec(line.slice(col))?.[0] ?? ''
    addFinding(s, 'SS-SE-001', {
      line: f.line - 1,
      col,
      len: tok.length,
      severity: f.severity === 'pass' ? 'info' : f.severity,
      message: `${f.ruleName}: ${f.redacted}`,
      redactMatch: true,
    })
  }
}

/* ------------------------------------------------------------------ */
/* Skill / agent frontmatter                                           */
/* ------------------------------------------------------------------ */

const NAME_RE = /^[a-z0-9](?:[a-z0-9]|-(?=[a-z0-9])){0,63}$/
const TRIGGER_HIJACK_RE =
  /\b(?:use|invoke|trigger|activate|load|run|apply|select)\s{1,3}(?:this\s{1,3}(?:skill|agent|tool)\s{1,3}|me\s{1,3}|it\s{1,3})?(?:for|on|with|in|during|before)\s{1,3}(?:any|every|all|each)\s{1,3}(?:(?:user|incoming|single|other|kind\s{1,3}of|type\s{1,3}of)\s{1,3})?(?:requests?|tasks?|prompts?|messages?|questions?|conversations?|queries|query|inputs?|turns?|interactions?|actions?|tool\s{1,3}calls?)\b|\balways\s{1,3}(?:use|invoke|activate|load|run|trigger|apply|call|consult|select)\s{1,3}(?:this|me|it)\b|\b(?:before|instead\s{1,3}of|over|prefer(?:red)?\s{1,3}(?:to|over))\s{1,3}(?:any|every|all)\s{1,3}other\s{1,3}(?:skills?|tools?|agents?)\b|\bregardless\s{1,3}of\s{1,3}(?:the\s{1,3}|what\s{1,3}the\s{1,3})?(?:request|task|topic|context|user\s{1,3}asks?|question)\b|\b(?:highest|top|maximum)\s{1,3}priority\b|\bmust\s{1,3}(?:always\s{1,3})?be\s{1,3}(?:used|loaded|invoked|activated)\b|\b(?:use|invoke)\s{1,3}(?:this\s{1,3}skill\s{1,3})?(?:always|for\s{1,3}everything)\b/i
const GENERIC_DESC_RE = /^(?:a\s+)?(?:helper|helps?|utility|utilities|tools?|assistant|misc(?:ellaneous)?|general(?:\s+purpose)?|does\s+stuff|various\s+things|useful\s+skill|skill)\.?$/i

export function checkFrontmatter(s: FileScan, text: string): Frontmatter | undefined {
  const fm = parseFrontmatter(text)
  if (s.kind === 'skill-md' && !fm) {
    addFinding(s, 'SS-SK-001', { line: 0, message: 'No YAML frontmatter found: the skill has no name/description for the agent to decide when to load it.' })
    return undefined
  }
  if (!fm) return undefined
  const lineOf = (k: string) => (fm.lines[k] ?? 1) - 1
  const skill = s.kind === 'skill-md'

  const name = fmString(fm.data.name)
  if (skill) {
    if (name === undefined || name.trim() === '') addFinding(s, 'SS-SK-002', { line: 0, message: 'No name in frontmatter (Claude Code falls back to the directory name; the Agent Skills spec requires one).' })
    else if (!NAME_RE.test(name)) addFinding(s, 'SS-SK-002', { line: lineOf('name'), message: `Name "${visibleEscape(name).slice(0, 80)}" violates the Agent Skills spec (1–64 chars: a-z, 0-9, single hyphens, no leading/trailing hyphen).` })
  }
  if (name && /anthropic|claude/i.test(name)) {
    addFinding(s, 'SS-SK-004', { line: lineOf('name'), message: `Name "${visibleEscape(name).slice(0, 80)}" contains a reserved vendor word (the Anthropic Skills API rejects "anthropic" and "claude" in names; Claude Code reserves "anthropic-skills").` })
  }

  const description = fmString(fm.data.description)
  const whenToUse = fmString(fm.data.when_to_use)
  if (skill) {
    if (description === undefined || description.trim() === '') addFinding(s, 'SS-SK-003', { line: 0, message: 'No description: the agent cannot tell when to use this skill (Claude Code falls back to the first body line).' })
    else if (description.length > 1024) addFinding(s, 'SS-SK-003', { line: lineOf('description'), severity: 'low', message: `Description is ${description.length} characters (Agent Skills spec maximum: 1024).` })
  }
  for (const [key, value] of [['description', description], ['when_to_use', whenToUse]] as const) {
    if (!value) continue
    const tag = /<\/?[A-Za-z][\w:-]{0,40}(?:\s[^<>]{0,200})?\/?>/.exec(value)
    if (tag) addFinding(s, 'SS-SK-005', { line: lineOf(key), message: `The ${key} contains markup: ${visibleEscape(tag[0]).slice(0, 80)}` })
    const hijack = TRIGGER_HIJACK_RE.exec(value)
    if (hijack) addFinding(s, 'SS-TR-001', { line: lineOf(key), ctx: 'frontmatter', message: `The ${key} tries to broaden activation: "${hijack[0]}".` })
  }
  if (skill && description && description.trim().length > 0 && (description.trim().length < 25 || GENERIC_DESC_RE.test(description.trim()))) {
    addFinding(s, 'SS-TR-002', { line: lineOf('description'), message: `Description "${visibleEscape(description.trim()).slice(0, 80)}" is too short or generic to scope activation.` })
  }

  for (const key of ['allowed-tools', 'tools']) {
    if (fm.data[key] === undefined) continue
    if (key === 'tools' && s.kind !== 'agent-md') continue
    checkToolGrants(s, splitToolList(fm.data[key]), lineOf(key), key)
  }
  if (fm.data.hooks !== undefined) {
    addFinding(s, 'SS-CS-003', { line: lineOf('hooks'), message: 'The frontmatter registers hooks: they stay active for the rest of the session after the skill is invoked. Review every hook command.' })
  }
  return fm
}

const BROAD_PREFIX_RE = /^(?:curl|wget|sh|bash|zsh|fish|dash|python[\d.]{0,4}|py|node|deno|bun|perl|ruby|php|eval|exec|sudo|su|rm|nc|ncat|netcat|socat|ssh|scp|rsync|powershell|pwsh|cmd|npx|uvx|pipx|pip[\d.]{0,4}|npm|yarn|pnpm|docker|kubectl|git\s{1,3}push|chmod|chown|dd|env|xargs|find|awk|sed|osascript|open|start|iex|Invoke-Expression|Invoke-WebRequest|Invoke-RestMethod)$/i

/** Classify tool permission entries (allowed-tools, permissions.allow). */
export function classifyToolGrant(entry: string): 'unrestricted' | 'broad' | undefined {
  const e = entry.trim()
  if (e === '*' || /^Bash$/i.test(e) || /^(?:Bash|Shell|PowerShell)\(\s{0,3}\*?\s{0,3}(?::\s{0,3}\*)?\s{0,3}\)$/i.test(e)) return 'unrestricted'
  const m = /^(?:Bash|Shell|PowerShell)\((.{1,300})\)$/i.exec(e)
  if (!m) return undefined
  const inner = m[1].trim()
  // Wildcard prefix rule: "cmd *", "cmd:*", "cmd*"
  const pm = /^(.{1,100}?)\s{0,3}(?::\s{0,3}\*|\s\*|\*)$/.exec(inner)
  if (pm && BROAD_PREFIX_RE.test(pm[1].trim())) return 'broad'
  return undefined
}

function checkToolGrants(s: FileScan, entries: readonly string[], line0: number, source: string): void {
  for (const e of entries) {
    const c = classifyToolGrant(e)
    if (c === 'unrestricted') addFinding(s, 'SS-PM-001', { line: line0, message: `${source} grants "${e}" — any command runs without a permission prompt.` })
    else if (c === 'broad') addFinding(s, 'SS-PM-002', { line: line0, message: `${source} pre-approves "${e}", effectively arbitrary code execution or network access.` })
  }
}

/* ------------------------------------------------------------------ */
/* JSON configs                                                        */
/* ------------------------------------------------------------------ */

/** Strip // and /* *\/ comments and trailing commas (JSONC), respecting strings. */
export function stripJsonc(text: string): string {
  let out = ''
  let i = 0
  const n = text.length
  while (i < n) {
    const c = text[i]
    if (c === '"') {
      let j = i + 1
      while (j < n && text[j] !== '"') j += text[j] === '\\' ? 2 : 1
      out += text.slice(i, j + 1)
      i = j + 1
    } else if (c === '/' && text[i + 1] === '/') {
      while (i < n && text[i] !== '\n') i++
    } else if (c === '/' && text[i + 1] === '*') {
      const end = text.indexOf('*/', i + 2)
      i = end < 0 ? n : end + 2
    } else {
      out += c
      i++
    }
  }
  return out.replace(/,(\s{0,1000}[}\]])/g, '$1')
}

export function parseJsonLoose(text: string): unknown {
  return JSON.parse(stripJsonc(text.replace(/^\uFEFF/, '')))
}

type Obj = Record<string, unknown>
const isObj = (v: unknown): v is Obj => typeof v === 'object' && v !== null && !Array.isArray(v)
const strArr = (v: unknown): string[] => (Array.isArray(v) ? v.filter((x): x is string => typeof x === 'string') : [])

/** 0-based line of the first line containing `needle` (JSON-encoded string form tried first), searching from `from`. */
export function findLine(lines: readonly string[], needle: string, from = 0): number {
  const enc = JSON.stringify(needle).slice(1, -1)
  for (const n of [enc.slice(0, 200), needle.slice(0, 200)]) {
    if (n === '') continue
    for (let i = Math.max(0, from); i < lines.length; i++) if (lines[i].includes(n)) return i
  }
  return Math.max(0, Math.min(from, lines.length - 1))
}

const NETWORK_CMD_RE = /\b(?:curl|wget|nc|ncat|netcat|socat|ssh|scp|rsync|ftp|telnet|Invoke-WebRequest|Invoke-RestMethod|iwr|irm|Net\.WebClient|requests\.(?:get|post)|urllib|fetch\(|http\.client|nslookup|dig)\b|https?:\/\//i

export function checkClaudeSettings(s: FileScan, data: unknown): void {
  if (!isObj(data)) return
  const lines = s.lines
  const perms = isObj(data.permissions) ? data.permissions : undefined
  if (perms?.defaultMode === 'bypassPermissions') {
    addFinding(s, 'SS-CS-001', { line: findLine(lines, '"defaultMode"'), message: 'permissions.defaultMode is "bypassPermissions": every tool call runs without approval.' })
  }
  if (perms) {
    for (const e of strArr(perms.allow).slice(0, MAX_CONFIG_ENTRIES)) {
      const c = classifyToolGrant(e)
      const line = findLine(lines, e)
      if (c === 'unrestricted') addFinding(s, 'SS-PM-001', { line, message: `permissions.allow contains "${e}" — any shell command runs without a prompt.` })
      else if (c === 'broad') addFinding(s, 'SS-PM-002', { line, message: `permissions.allow contains "${e}", effectively arbitrary code execution / network access.` })
    }
    for (const d of strArr(perms.additionalDirectories).slice(0, MAX_CONFIG_ENTRIES)) {
      const t = d.trim().replace(/[\\/]+$/, '')
      if (t === '' || t === '~' || t === '$HOME' || t === '/' || /^[A-Za-z]:$/.test(t) || /^(?:\/home|\/Users|\/root|\/etc|C:\\Users)$/i.test(t)) {
        addFinding(s, 'SS-CS-005', { line: findLine(lines, d), message: `additionalDirectories includes "${d}".` })
      }
    }
  }
  if (data.enableAllProjectMcpServers === true) {
    addFinding(s, 'SS-CS-002', { line: findLine(lines, '"enableAllProjectMcpServers"') })
  }
  if (typeof data.apiKeyHelper === 'string') {
    addFinding(s, 'SS-CS-006', { line: findLine(lines, '"apiKeyHelper"'), message: `apiKeyHelper runs: ${data.apiKeyHelper.slice(0, 200)}` })
  }
  if (isObj(data.hooks)) checkHooks(s, data.hooks)
  checkMcpConfig(s, data, true)
}

function checkHooks(s: FileScan, hooks: Obj): void {
  let from = 0
  for (const [event, groups] of Object.entries(hooks)) {
    if (!Array.isArray(groups)) continue
    for (const g of groups) {
      if (!isObj(g)) continue
      const matcher = typeof g.matcher === 'string' ? g.matcher : ''
      for (const h of Array.isArray(g.hooks) ? g.hooks : []) {
        if (!isObj(h)) continue
        const cmd = typeof h.command === 'string' ? h.command : undefined
        const url = typeof h.url === 'string' ? h.url : undefined
        const what = cmd ?? url
        if (!what) continue
        const line = findLine(s.lines, what, from)
        from = line
        const where = `${event}${matcher && matcher !== '*' ? ` (matcher "${matcher}")` : ' (every invocation)'}`
        if (url || NETWORK_CMD_RE.test(cmd ?? '')) {
          addFinding(s, 'SS-CS-004', { line, message: `${where} hook ${url ? 'posts event data to' : 'runs a network command:'} ${what.slice(0, 200)}` })
        } else {
          addFinding(s, 'SS-CS-003', { line, message: `${where} hook runs: ${what.slice(0, 200)}` })
        }
      }
    }
  }
}

const SECRET_KEY_RE = /(?:TOKEN|SECRET|PASSWORD|PASSWD|API_?KEY|ACCESS_?KEY|PRIVATE_?KEY|CREDENTIAL|AUTH)/i
const SECRET_ARG_RE = /^--?(?:api[-_]?key|token|access[-_]?token|auth[-_]?token|secret|password|client[-_]?secret)(?:=(.{1,500}))?$/i

function isReference(v: string): boolean {
  const t = v.trim()
  return t === '' || /^\$\{[^}]{1,200}\}$|^\$[A-Z_][A-Z0-9_]{0,100}$|^%[A-Z_][A-Z0-9_]{0,100}%$|^<[^>]{0,200}>$/i.test(t) || /\$\{(?:env|input):/.test(t) || isPlaceholder(t) || /^(?:Bearer\s{1,3})?\$\{/.test(t)
}

function literalSecret(value: string): boolean {
  const v = value.replace(/^Bearer\s{1,3}/i, '').trim()
  return v.length >= 8 && !isReference(v) && !/\s/.test(v) && !/^(?:true|false|\d{1,10})$/i.test(v)
}

const PI_RULE_IDS = new Set(['SS-PI-001', 'SS-PI-002', 'SS-PI-003', 'SS-PI-004', 'SS-PI-005', 'SS-PI-006', 'SS-PI-007', 'SS-PI-008', 'SS-JB-001', 'SS-JB-002', 'SS-JB-003', 'SS-EX-009', 'SS-EA-001', 'SS-MP-002'])
const PI_RULES = REGEX_RULES.filter((r) => PI_RULE_IDS.has(r.id))

function injectionIn(text: string): string | undefined {
  for (const r of PI_RULES) {
    for (const p of r.patterns) {
      const m = p.exec(text)
      if (m) return `${r.title}: "${visibleEscape(m[0]).slice(0, 120)}"`
    }
  }
  return undefined
}

const SHELLS = new Set(['sh', 'bash', 'zsh', 'dash', 'ksh', 'fish', 'cmd', 'cmd.exe', 'powershell', 'powershell.exe', 'pwsh', 'pwsh.exe'])
const DOCKER_FLAGS_WITH_ARG = new Set(['-e', '--env', '-v', '--volume', '--name', '--network', '--net', '-p', '--publish', '--mount', '--env-file', '-w', '--workdir', '--entrypoint', '-u', '--user', '--platform', '--pull', '-l', '--label', '--add-host', '--cap-add', '--cap-drop', '-m', '--memory', '--cpus', '--security-opt', '--device', '--hostname', '-h', '--user-ns', '--ipc', '--pid', '--tmpfs', '--log-driver', '--restart', '--runtime', '--gpus'])

function exeName(cmd: string): string {
  return cmd.replace(/\\/g, '/').split('/').pop()?.toLowerCase() ?? ''
}

/** MCP server definitions from Claude/Cursor (mcpServers), VS Code (servers / mcp.servers), Zed (context_servers). */
export function mcpServers(data: unknown): [string, Obj][] {
  if (!isObj(data)) return []
  const out: [string, Obj][] = []
  const containers = [data.mcpServers, data.servers, isObj(data.mcp) ? data.mcp.servers : undefined, data.context_servers]
  for (const c of containers) {
    if (!isObj(c)) continue
    for (const [name, def] of Object.entries(c)) if (isObj(def)) out.push([name, def])
  }
  // claude.json style: projects.<path>.mcpServers
  if (isObj(data.projects)) for (const p of Object.values(data.projects)) out.push(...mcpServers(isObj(p) ? { mcpServers: p.mcpServers } : undefined))
  return out
}

export function checkMcpConfig(s: FileScan, data: unknown, nested = false): void {
  const servers = mcpServers(data)
  if (servers.length === 0 && !nested) return
  for (const [name, srv] of servers.slice(0, MAX_CONFIG_ENTRIES)) {
    const nameLine = findLine(s.lines, `"${name}"`)
    let command = typeof srv.command === 'string' ? srv.command : isObj(srv.command) && typeof srv.command.path === 'string' ? srv.command.path : ''
    let args = strArr(srv.args ?? (isObj(srv.command) ? srv.command.args : undefined))
    const lineFor = (needle: string) => findLine(s.lines, needle, nameLine)
    // Unwrap Windows "cmd /c npx …"
    if (/^cmd(?:\.exe)?$/.test(exeName(command)) && /^\/[cCkK]$/.test(args[0] ?? '') && args.length > 1 && !/[|&<>]/.test(args.slice(1).join(' '))) {
      command = args[1]
      args = args.slice(2)
    }
    const exe = exeName(command)
    const joined = [command, ...args].join(' ')

    if (SHELLS.has(exe) && args.some((a) => /^(?:-c|\/c|\/k|-Command|-command|-EncodedCommand|-e|-enc)$/.test(a))) {
      const network = NETWORK_CMD_RE.test(joined)
      addFinding(s, 'SS-MC-003', {
        line: lineFor(command),
        severity: network ? 'high' : 'medium',
        message: `Server "${name}" is started through ${exe}: ${joined.slice(0, 200)}`,
      })
    }

    let runner: string | undefined
    let runnerArgs = args
    if (/^(?:npx|bunx|uvx)(?:\.cmd|\.exe)?$/.test(exe)) runner = exe.replace(/\.(?:cmd|exe)$/, '')
    else if (/^(?:pnpm|yarn)(?:\.cmd)?$/.test(exe) && args[0] === 'dlx') {
      runner = `${exe.replace(/\.cmd$/, '')} dlx`
      runnerArgs = args.slice(1)
    } else if (/^pipx(?:\.exe)?$/.test(exe) && args[0] === 'run') {
      runner = 'pipx run'
      runnerArgs = args.slice(1)
    } else if (/^uv(?:\.exe)?$/.test(exe) && args[0] === 'tool' && args[1] === 'run') {
      runner = 'uvx'
      runnerArgs = args.slice(2)
    }
    if (runner) {
      const pkg = runnerPackage(runner, runnerArgs.map((a) => (/\s/.test(a) ? `"${a}"` : a)).join(' '))
      if (pkg && !runnerPinned(runner, pkg)) {
        addFinding(s, 'SS-MC-001', { line: lineFor(pkg), message: `Server "${name}" runs ${runner} ${pkg} — not pinned to an exact version.` })
      }
    }
    if (/^(?:docker|podman)(?:\.exe)?$/.test(exe) && args.includes('run')) {
      const rest = args.slice(args.indexOf('run') + 1)
      let image: string | undefined
      for (let i = 0; i < rest.length; i++) {
        const a = rest[i]
        if (a.startsWith('-')) {
          if (!a.includes('=') && DOCKER_FLAGS_WITH_ARG.has(a)) i++
          continue
        }
        image = a
        break
      }
      if (image && !/@sha256:[0-9a-f]{64}\b/.test(image)) {
        const tag = /:([\w][\w.-]{0,127})$/.exec(image.split('/').pop() ?? '')?.[1]
        const floating = !tag || tag === 'latest' || tag === 'main' || tag === 'master' || tag === 'edge'
        addFinding(s, 'SS-MC-002', {
          line: lineFor(image),
          severity: floating ? 'medium' : 'low',
          message: `Server "${name}" runs image ${image}${floating ? ' (floating tag)' : ''} without an @sha256 digest.`,
        })
      }
    }

    // Secrets inline
    const secretValues: [string, string][] = []
    if (isObj(srv.env)) for (const [k, v] of Object.entries(srv.env)) if (typeof v === 'string') secretValues.push([k, v])
    if (isObj(srv.headers)) for (const [k, v] of Object.entries(srv.headers)) if (typeof v === 'string') secretValues.push([k, v])
    for (let i = 0; i < args.length; i++) {
      const m = SECRET_ARG_RE.exec(args[i])
      if (m) secretValues.push([args[i].split('=')[0], m[1] ?? args[i + 1] ?? ''])
    }
    for (const [k, v] of secretValues) {
      if (!v) continue
      const named = SECRET_KEY_RE.test(k) || /^authorization$/i.test(k)
      const known = scanSecrets(v).length > 0
      if ((named && literalSecret(v)) || known) {
        const line = lineFor(v)
        if (hasFindingAt(s, line, (id) => id === 'SS-SE-001')) continue
        // Locate the value so snippets/viewer redact it (col/len 0 would leave it visible).
        const enc = JSON.stringify(v).slice(1, -1)
        const lineText = s.lines[line] ?? ''
        const at = lineText.indexOf(enc)
        addFinding(s, 'SS-MC-004', {
          line,
          col: at >= 0 ? at : 0,
          len: at >= 0 ? enc.length : lineText.length,
          message: `Server "${name}": ${k} holds a literal value (${v.slice(0, 4)}****).`,
          redactMatch: true,
        })
      }
    }

    for (const key of ['url', 'serverUrl', 'httpUrl', 'endpoint']) {
      const u = srv[key]
      if (typeof u !== 'string') continue
      if (/^(?:http|ws):\/\//i.test(u) && !/^(?:http|ws):\/\/(?:localhost|127\.\d{1,3}\.\d{1,3}\.\d{1,3}|\[::1\]|0\.0\.0\.0|host\.docker\.internal)(?::\d{1,5})?(?:\/|$)/i.test(u)) {
        addFinding(s, 'SS-MC-005', { line: lineFor(u), message: `Server "${name}" uses ${u.slice(0, 200)}` })
      }
    }
  }

  // Tool poisoning: description-like fields anywhere in the config (decoded, so \u-escapes cannot hide text).
  let poisoned = 0
  const walk = (v: unknown, depth: number) => {
    if (depth > 12 || poisoned >= MAX_FINDINGS_PER_RULE_PER_FILE) return
    if (Array.isArray(v)) v.forEach((x) => walk(x, depth + 1))
    else if (isObj(v)) {
      for (const [k, x] of Object.entries(v)) {
        if (typeof x === 'string' && /^(?:description|instructions|prompt|systemPrompt|title)$/i.test(k)) {
          const hit = injectionIn(x)
          if (!hit) continue
          poisoned++
          const line = findLine(s.lines, x.slice(0, 60))
          if (hasFindingAt(s, line, (id) => PI_RULE_IDS.has(id))) continue
          addFinding(s, 'SS-MC-006', { line, message: `"${k}" field: ${hit}` })
        } else walk(x, depth + 1)
      }
    }
  }
  walk(data, 0)
}

export function checkJsonConfig(s: FileScan, text: string): void {
  let data: unknown
  try {
    data = parseJsonLoose(text)
  } catch (e) {
    if (s.kind === 'mcp-config' || s.kind === 'claude-settings' || /\.json$/i.test(s.path)) {
      addFinding(s, 'SS-MC-007', { line: 0, message: `JSON parse error: ${(e as Error).message.slice(0, 200)}` })
    }
    return
  }
  if (s.kind === 'claude-settings') checkClaudeSettings(s, data)
  else checkMcpConfig(s, data, s.kind === 'mcp-config')
}

