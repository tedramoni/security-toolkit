import type { Ctx, FileKind, RuleMeta } from './types'

/*
 * Regex ruleset. Original rules written for this tool; the category list is inspired by NVIDIA SkillSpector
 * (https://github.com/NVIDIA/SkillSpector, Apache-2.0). Every pattern runs on ONE line at a time and must stay linear-time:
 * bounded quantifiers only, no nested quantifiers over overlapping character classes.
 * Patterns are written WITHOUT the g flag; the engine adds it.
 */

export interface RegexRule extends RuleMeta {
  appliesTo: readonly FileKind[] | 'any'
  patterns: readonly RegExp[]
  /** Contexts where the rule applies (default: all). */
  contexts?: readonly Ctx[]
  /** In prose / hidden comments, only report when the sentence reads as an instruction to the agent. */
  proseImperative?: boolean
  /** The phrasing is itself a negation ("do not tell the user") — never downgrade as defensive text. */
  noDowngrade?: boolean
  /** Only files whose base name matches. */
  fileName?: RegExp
  /** Extra check on the match / whole line. */
  accept?: (m: RegExpExecArray, line: string) => boolean
  /** Occurrence-specific message (default: rule description). */
  message?: (m: RegExpExecArray) => string
}

const CODE: readonly Ctx[] = ['code', 'inline', 'code-comment']
const CODE_STRICT: readonly Ctx[] = ['code', 'code-comment']
const MD: readonly FileKind[] = ['skill-md', 'agent-md', 'markdown']
const NOT_BINARY = 'any' as const

/* ---------- helpers for package pinning ---------- */

function tokens(args: string): string[] {
  return args
    .trim()
    .split(/\s+/)
    .map((t) => t.replace(/^["']|["']$/g, ''))
    .filter((t) => t !== '')
}

function isPlaceholderToken(t: string): boolean {
  return /^[<{[$%]/.test(t) || /^(?:package|pkg|name|module|\.\.\.)$/i.test(t)
}

const PIP_FLAGS_WITH_ARG = new Set(['-r', '--requirement', '-c', '--constraint', '-e', '--editable', '-i', '--index-url', '--extra-index-url', '-t', '--target', '--prefix', '--root', '-f', '--find-links', '--python', '-p'])

/** Unpinned packages in a `pip install …` argument string. */
export function unpinnedPip(args: string): string[] {
  const t = tokens(args)
  const out: string[] = []
  for (let i = 0; i < t.length; i++) {
    const tok = t[i]
    if (tok.startsWith('-')) {
      if (PIP_FLAGS_WITH_ARG.has(tok)) i++
      continue
    }
    if (isPlaceholderToken(tok) || /^(?:\.|\/|~|git\+|https?:)/.test(tok) || /\.(?:whl|tar\.gz|zip|txt)$/i.test(tok)) continue
    if (/===?/.test(tok) || /\s@\s/.test(tok) || / @ /.test(tok)) continue
    out.push(tok)
  }
  return out
}

/** npm-style spec: pinned when name@<exact semver>. */
export function npmSpecPinned(spec: string): boolean {
  const at = spec.lastIndexOf('@')
  if (at <= 0) return false
  return /^v?\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.-]{1,64})?$/.test(spec.slice(at + 1))
}

const NPM_FLAGS_WITH_ARG = new Set(['--registry', '--prefix', '-w', '--workspace', '--filter', '--cwd', '--tag'])

export function unpinnedNpm(args: string): string[] {
  const out: string[] = []
  const t = tokens(args)
  for (let i = 0; i < t.length; i++) {
    const tok = t[i]
    if (tok.startsWith('-')) {
      if (NPM_FLAGS_WITH_ARG.has(tok)) i++
      continue
    }
    if (isPlaceholderToken(tok) || /^(?:\.|\/|~|file:|git\+|https?:|github:)/.test(tok)) continue
    if (!npmSpecPinned(tok)) out.push(tok)
  }
  return out
}

/** Package launched by npx/bunx/pnpm dlx/uvx/pipx run (first positional or --package/--from value). */
export function runnerPackage(_runner: string, args: string): string | undefined {
  const t = tokens(args)
  for (let i = 0; i < t.length; i++) {
    const tok = t[i]
    if (tok === '-p' || tok === '--package' || tok === '--from' || tok === '--spec') return t[i + 1]
    if (/^--(?:package|from|spec)=/.test(tok)) return tok.slice(tok.indexOf('=') + 1)
    if (tok.startsWith('-')) {
      if (tok === '--python' || tok === '--with' || tok === '--index-url' || tok === '--registry') i++
      continue
    }

    return tok
  }
  return undefined
}

export function runnerPinned(runner: string, spec: string): boolean {
  if (/^(?:uvx|pipx|uv)/.test(runner)) return /==\s{0,3}\d|@\s{0,3}v?\d+\.\d+/.test(spec)
  return npmSpecPinned(spec)
}

/* ---------- write detection used by several rules ---------- */

const WRITE_OP_RE =
  /(?:(?:^|[\s)"'`\d&])>>?(?!=)|\btee\b|\bwrite(?:_text|_bytes|File(?:Sync)?|lines)?\s{0,3}\(|\bappend(?:File(?:Sync)?)?\s{0,3}\(|\bopen\s{0,3}\([^\n)]{0,200}["'](?:[aw]\+?|[aw]b|r\+)["']|\bSet-Content\b|\bAdd-Content\b|\bOut-File\b|\bsed\s{1,3}-i|\bcp\s|\bmv\s|\bln\s{1,3}-s|\bcopyFile|\bshutil\.(?:copy|move)|\bfs\.(?:write|append|copy|rename))/i

export function hasWriteOp(line: string): boolean {
  return WRITE_OP_RE.test(line)
}

const PRIVATE_IP_RE = /^(?:127\.|10\.|192\.168\.|172\.(?:1[6-9]|2\d|3[01])\.|169\.254\.|0\.|100\.(?:6[4-9]|[7-9]\d|1[01]\d|12[0-7])\.)/

/* ------------------------------------------------------------------ */

export const REGEX_RULES: readonly RegexRule[] = [
  /* ===== Prompt injection & leakage ===== */
  {
    id: 'SS-PI-001',
    category: 'prompt-injection',
    severity: 'critical',
    title: 'Instruction override ("ignore previous instructions")',
    description: 'Text tells the model to ignore, forget or override its existing instructions — the classic prompt-injection payload.',
    remediation: 'Remove the text. A legitimate skill never needs to override the system prompt or prior instructions.',
    appliesTo: NOT_BINARY,
    patterns: [
      /\b(?:ignore|disregard|forget|override|bypass|skip)\s{1,5}(?:(?:all|any|the|your|my|these|those|previous|prior|above|earlier|preceding|existing|original|other)\s{1,5}){1,3}(?:instructions?|prompts?|rules|guidelines|directives|system\s{1,5}(?:prompt|message)|guardrails|constraints)\b/i,
    ],
  },
  {
    id: 'SS-PI-002',
    category: 'prompt-injection',
    severity: 'high',
    title: 'Role / persona reassignment',
    description: 'Text tries to redefine what the model is ("you are now…", "new system prompt") so that earlier safety instructions no longer apply.',
    remediation: 'Remove the persona switch. Describe the task instead of redefining the assistant.',
    appliesTo: NOT_BINARY,
    patterns: [
      /\byou\s{1,3}are\s{1,3}now\s{1,3}(?:an?\s{1,3})?(?:unrestricted|unfiltered|uncensored|jailbroken|evil|in\s{1,3}(?:developer|god|admin|debug)\s{1,3}mode|no\s{1,3}longer|free\s{1,3}(?:from|of)|DAN)\b/i,
      /\b(?:new|updated|real|actual|true)\s{1,3}system\s{1,3}(?:prompt|instructions?)\s{0,3}[:=-]/i,
      /\bfrom\s{1,3}now\s{1,3}on,?\s{1,3}you\s{1,3}(?:will|must|are)\s{1,3}(?:ignore|obey\s{1,3}only|no\s{1,3}longer|act\s{1,3}as)\b/i,
    ],
  },
  {
    id: 'SS-PI-003',
    category: 'prompt-injection',
    severity: 'high',
    title: 'Fake chat-template / system tokens',
    description: 'Special tokens or tags used by model chat templates (<|im_start|>, [INST], <<SYS>>, </system>) appear in content. They are used to forge system or assistant turns.',
    remediation: 'Remove chat-template control tokens from skill content.',
    appliesTo: NOT_BINARY,
    patterns: [
      /<\|(?:im_start|im_end|im_sep|system|user|assistant|endoftext|eot_id|start_header_id|end_header_id|begin_of_text)\|>|\[\/?INST\]|<<\/?SYS>>|<\/?(?:system|system_prompt|sys)>|\bBEGIN\s{1,3}SYSTEM\s{1,3}PROMPT\b/i,
    ],
  },
  {
    id: 'SS-PI-004',
    category: 'prompt-injection',
    severity: 'high',
    title: 'System-prompt leakage request',
    description: 'Asks the model to reveal, print or send its system prompt / hidden instructions (OWASP LLM07).',
    remediation: 'Remove the request. Skills should not need the host system prompt.',
    appliesTo: NOT_BINARY,
    patterns: [
      /\b(?:reveal|print|output|show|repeat|dump|leak|disclose|return|send|copy|write\s{1,3}out)\s{1,3}(?:(?:me|us|all|the|your|its|full|entire|complete|exact|original|verbatim)\s{1,3}){0,4}(?:system\s{1,3}(?:prompt|message|instructions)|initial\s{1,3}(?:prompt|instructions)|hidden\s{1,3}(?:prompt|instructions)|developer\s{1,3}(?:message|prompt|instructions)|pre-?prompt)\b/i,
    ],
  },
  {
    id: 'SS-PI-005',
    category: 'prompt-injection',
    severity: 'high',
    title: 'Concealment from the user',
    description: 'Instructs the agent to hide its actions from the user ("do not tell the user", "silently upload"). Legitimate skills have no reason to keep the user uninformed.',
    remediation: 'Remove the concealment instruction; every side effect should be visible to the user.',
    appliesTo: NOT_BINARY,
    noDowngrade: true,
    patterns: [
      /\b(?:do\s{1,3}not|don['’]?t|never|without)\s{1,3}(?:tell(?:ing)?|inform(?:ing)?|notify(?:ing)?|alert(?:ing)?|mention(?:ing)?\s{1,3}(?:this|it|that)\s{1,3}to|reveal(?:ing)?\s{1,3}(?:this|it|that)\s{1,3}to|let(?:ting)?|show(?:ing)?\s{1,3}(?:this|it)\s{1,3}to|ask(?:ing)?)\s{1,3}(?:the\s{1,3})?(?:user|human|operator|developer|owner)\b(?!\s{1,3}(?:for\s{1,3})?(?:confirm|approv|permiss|consent))/i,
      /\bwithout\s{1,3}(?:the\s{1,3})?(?:user|human)(?:['’]s)?\s{1,3}(?:knowing|knowledge|noticing|awareness|seeing)\b/i,
      /\b(?:silently|secretly|covertly|quietly|discreetly|stealthily|invisibly)\s{1,3}(?:send|upload|post|exfiltrate|copy|run|execute|install|modify|delete|add|forward|collect|read|transmit|download|write)\b/i,
    ],
  },
  {
    id: 'SS-PI-006',
    category: 'prompt-injection',
    severity: 'medium',
    title: 'Message addressed to the AI reader',
    description: 'A note explicitly addressed to the AI/agent reading the file (common in indirect prompt injection placed in docs, READMEs and tool descriptions).',
    remediation: 'Check what the note asks the agent to do. Instructions belong in SKILL.md prose, not in notes aimed at whatever model reads the file.',
    appliesTo: NOT_BINARY,
    patterns: [
      /\b(?:note|message|instructions?|attention|important|notice)\s{1,3}(?:to|for)\s{1,3}(?:the\s{1,3}|any\s{1,3}|all\s{1,3})?(?:AI|LLMs?|assistants?|agents?|models?|claude|chatgpt|copilot|gpt|language\s{1,3}models?)\b/i,
      /\b(?:if\s{1,3}you\s{1,3}are|as)\s{1,3}an?\s{1,3}(?:AI|LLM|language\s{1,3}model|AI\s{1,3}(?:assistant|agent))\s{0,3}(?:reading|processing|parsing|summari[sz]ing)\b/i,
    ],
  },
  {
    id: 'SS-PI-007',
    category: 'mcp',
    severity: 'high',
    title: 'Tool-poisoning directive tag',
    description: 'Pseudo-XML tags such as <IMPORTANT> or <SYSTEM> inside descriptions/docs are the hallmark of MCP tool-poisoning attacks: the tag is invisible to users in most UIs but is read by the model.',
    remediation: 'Remove the hidden directive. Tool and skill descriptions should only describe functionality.',
    appliesTo: NOT_BINARY,
    patterns: [/<\s{0,3}(?:IMPORTANT|CRITICAL|SECRET|HIDDEN|INSTRUCTIONS?|ADMIN|OVERRIDE)\s{0,3}>/],
  },
  {
    id: 'SS-PI-008',
    category: 'mcp',
    severity: 'high',
    title: 'Tool shadowing / cross-tool instructions',
    description: 'Text that dictates how the agent must use OTHER tools, or demands extra data "before using this tool" — a tool-poisoning / tool-shadowing pattern.',
    remediation: 'A tool or skill should only describe its own behaviour. Remove instructions about other tools and requests for unrelated data.',
    appliesTo: NOT_BINARY,
    patterns: [
      /\b(?:before|prior\s{1,3}to|when)\s{1,3}(?:using|calling|invoking|running)\s{1,3}(?:this|any|the|every)\s{1,3}(?:other\s{1,3})?tools?\b[^\n]{0,160}?\b(?:read|pass|include|send|provide|attach|append|add)\b[^\n]{0,80}?\b(?:file|content|key|token|secret|password|credentials?|config|\.ssh|\.env|history|conversation)/i,
      /\b(?:instead\s{1,3}of\s{1,3}(?:using\s{1,3})?|do\s{1,3}not\s{1,3}use|never\s{1,3}use)\s{1,3}(?:the\s{1,3})?(?:other|original|built-?in|default|real|official)\s{1,3}(?:[\w-]{1,30}\s{1,3})?tools?\b/i,
      /\bwhen\s{1,3}(?:the\s{1,3})?[\w-]{1,40}\s{1,3}tool\s{1,3}is\s{1,3}(?:called|used|invoked)\b[^\n]{0,120}?\b(?:also|instead|first|always)\b/i,
    ],
  },

  /* ===== Jailbreak ===== */
  {
    id: 'SS-JB-001',
    category: 'jailbreak',
    severity: 'high',
    title: 'Anti-refusal instruction',
    description: 'Tells the model never to refuse, apologise or add warnings, or to ignore ethics/safety — classic jailbreak phrasing.',
    remediation: 'Remove anti-refusal language. Skills must work within the model’s safety policies.',
    appliesTo: NOT_BINARY,
    noDowngrade: true,
    patterns: [
      /\b(?:never|do\s{1,3}not|don['’]?t)\s{1,3}(?:ever\s{1,3})?(?:refuse|decline|say\s{1,3}(?:no|you\s{1,3}can['’]?t)|apologi[sz]e|add\s{1,3}(?:any\s{1,3})?(?:warnings|disclaimers|caveats)|mention\s{1,3}(?:ethics|safety|legality))\b/i,
      /\b(?:no|without\s{1,3}any|ignore\s{1,3}(?:all\s{1,3})?)\s{1,3}(?:ethical|moral|safety|content)\s{1,3}(?:guidelines|restrictions|filters|limits|policies|considerations)\b/i,
      /\bregardless\s{1,3}of\s{1,3}(?:ethics|morality|safety|legality|(?:any\s{1,3})?(?:content\s{1,3})?polic(?:y|ies)|the\s{1,3}law)\b/i,
    ],
  },
  {
    id: 'SS-JB-002',
    category: 'jailbreak',
    severity: 'high',
    title: 'Known jailbreak persona / mode',
    description: 'References a known jailbreak persona or "mode" (DAN, developer mode, god mode…).',
    remediation: 'Remove the jailbreak text.',
    appliesTo: NOT_BINARY,
    patterns: [
      /\b(?:DAN\s{1,3}(?:mode|prompt)|do\s{1,3}anything\s{1,3}now|developer\s{1,3}mode\s{1,3}(?:enabled|on|activated)|jailbr(?:eak|oken)\s{1,3}mode|god\s{1,3}mode\s{1,3}(?:enabled|on|activated)|unfiltered\s{1,3}mode|evil\s{1,3}confidant|AIM\s{1,3}\(?always\s{1,3}intelligent)/i,
    ],
  },
  {
    id: 'SS-JB-003',
    category: 'jailbreak',
    severity: 'high',
    title: 'False authorisation / safety-disabled claim',
    description: 'Claims safety filters are disabled or that the model has been "authorised" to bypass its rules.',
    remediation: 'Remove the claim. Authorisation cannot be granted by content the model reads.',
    appliesTo: NOT_BINARY,
    patterns: [
      /\b(?:safety|content|ethical)\s{1,3}(?:filters?|polic(?:y|ies)|guardrails?|restrictions?)\s{1,3}(?:are|is|have\s{1,3}been|has\s{1,3}been)\s{1,3}(?:now\s{1,3})?(?:disabled|off|removed|lifted|suspended|turned\s{1,3}off)\b/i,
      /\byou\s{1,3}(?:have\s{1,3}been|are)\s{1,3}(?:now\s{1,3})?(?:authori[sz]ed|permitted|cleared|allowed)\s{1,3}to\s{1,3}(?:ignore|bypass|override|disregard)\b/i,
    ],
  },

  /* ===== Exfiltration ===== */
  {
    id: 'SS-EX-001',
    category: 'exfiltration',
    severity: 'high',
    title: 'Webhook catcher / paste site / tunnel / OAST domain',
    description: 'References a service commonly used to receive exfiltrated data or to tunnel into a machine (webhook.site, requestbin, pipedream, ngrok, interact.sh, Burp Collaborator, paste sites, Discord/Telegram bot webhooks…).',
    remediation: 'Remove the endpoint, or justify it and send only data the user explicitly approved.',
    appliesTo: NOT_BINARY,
    patterns: [
      /\b(?:webhook\.site|requestbin\.(?:net|com)|pipedream\.net|ngrok(?:-free)?\.(?:io|app|dev)|interact\.sh|interactsh\.com|oast\.(?:fun|live|me|online|pro|site)|burpcollaborator\.net|oastify\.com|canarytokens\.(?:com|org)|requestcatcher\.com|beeceptor\.com|hookbin\.com|requestinspector\.com|webhook\.cool|postb\.in|pastebin\.com|paste\.ee|hastebin\.com|ghostbin\.\w{2,6}|transfer\.sh|0x0\.st|termbin\.com|file\.io|trycloudflare\.com|serveo\.net|localtunnel\.me|loca\.lt|pinggy\.io|discord(?:app)?\.com\/api\/webhooks|api\.telegram\.org\/bot)/i,
    ],
    message: (m) => `References ${m[0]} — a service commonly used to receive exfiltrated data or expose local services.`,
  },
  {
    id: 'SS-EX-002',
    category: 'exfiltration',
    severity: 'high',
    title: 'Local file uploaded with curl/wget',
    description: 'curl/wget sends the content of a local file (-d @file, -F field=@file, -T, --post-file).',
    remediation: 'Make sure the uploaded file and destination are expected; never upload credentials or user files without explicit consent.',
    appliesTo: NOT_BINARY,
    contexts: CODE,
    patterns: [
      /\bcurl\b[^\n]{0,200}?\s(?:-d|--data(?:-binary|-raw|-urlencode)?|-F|--form|-T|--upload-file)\s{0,3}=?\s{0,3}["']?(?:[\w.-]{1,40}=)?@\s{0,2}["']?[~$/.\w-]/,
      /\bwget\b[^\n]{0,200}?\s--(?:post|body)-file\s{0,3}=?\s{0,3}\S/,
      /\bInvoke-(?:WebRequest|RestMethod)\b[^\n]{0,200}?-InFile\b/i,
    ],
  },
  {
    id: 'SS-EX-003',
    category: 'exfiltration',
    severity: 'high',
    title: 'Secrets / environment sent over the network',
    description: 'A network call on the same line references secret-looking environment variables or dumps the environment.',
    remediation: 'Do not transmit tokens or the environment. Pass only the specific credential an API needs, to that API’s official host.',
    appliesTo: NOT_BINARY,
    contexts: CODE,
    patterns: [
      /\b(?:curl|wget|requests\.(?:post|get|put)|httpx\.(?:post|get|put)|axios(?:\.post|\.get|\.put)?|fetch|http\.request|urlopen|Invoke-WebRequest|Invoke-RestMethod|iwr|irm|nc)\b[^\n]{0,200}?(?:\$\{?[A-Z_]{0,30}(?:TOKEN|SECRET|PASSWORD|PASSWD|API_KEY|APIKEY|CREDENTIALS?|PRIVATE_KEY|ACCESS_KEY)\b|process\.env(?![.[]\w{0,40}(?:URL|HOST|PORT))|os\.environ(?!\.get\(\s{0,3}["'](?:\w{0,40}(?:URL|HOST|PORT))["'])|\$\(\s{0,3}(?:env|printenv|cat\s{1,3}[^)\n]{0,60}(?:\.env|\.ssh|\.aws|credentials))\b|\$env:\w{0,30}(?:TOKEN|SECRET|KEY|PASSWORD))/i,
    ],
  },
  {
    id: 'SS-EX-004',
    category: 'exfiltration',
    severity: 'medium',
    title: 'Whole environment dumped',
    description: 'Dumps all environment variables (printenv, env |, os.environ.copy(), JSON.stringify(process.env)). The environment often holds API keys and tokens.',
    remediation: 'Read only the specific variables you need.',
    appliesTo: NOT_BINARY,
    contexts: CODE,
    patterns: [
      /(?:^|[\s;&|(`$])(?:printenv|env|set)\s{0,3}(?:\||>)/,
      /\b(?:dict\(\s{0,3}os\.environ\s{0,3}\)|os\.environ\.(?:copy|items)\(\)|json\.dumps\(\s{0,3}(?:dict\()?os\.environ|JSON\.stringify\(\s{0,3}process\.env\s{0,3}[,)]|Object\.(?:entries|keys|values)\(\s{0,3}process\.env\s{0,3}\)|Get-ChildItem\s{1,3}env:|gci\s{1,3}env:|\[Environment\]::GetEnvironmentVariables\(\))/i,
    ],
  },
  {
    id: 'SS-EX-005',
    category: 'exfiltration',
    severity: 'high',
    title: 'DNS exfiltration pattern',
    description: 'A DNS lookup / ping whose host name is built from command output or variables — a common way to smuggle data out through DNS.',
    remediation: 'Remove dynamic DNS lookups; there is no legitimate reason for a skill to encode data into host names.',
    appliesTo: NOT_BINARY,
    contexts: CODE,
    patterns: [
      /\b(?:nslookup|dig|host|ping|Resolve-DnsName)\s{1,5}(?:-[\w-]{1,10}\s{1,5}(?:\d{1,4}\s{1,5})?){0,3}["']?[\w.-]{0,100}(?:\$\(|`|\$\{?[A-Za-z_])/,
      /\b(?:socket\.gethostbyname|dns\.resolve\w{0,10}|dns\.lookup|getaddrinfo)\s{0,3}\(\s{0,3}(?:f["']|["'`][^"'`\n]{0,100}["'`]\s{0,3}\+|`[^`\n]{0,100}\$\{)/,
    ],
  },
  {
    id: 'SS-EX-006',
    category: 'exfiltration',
    severity: 'critical',
    title: 'Reverse shell',
    description: 'Classic reverse-shell construction (bash -i >& /dev/tcp, nc -e, socat exec, mkfifo + nc, PowerShell TCPClient).',
    remediation: 'Remove it. There is no legitimate use of a reverse shell in an agent skill.',
    appliesTo: NOT_BINARY,
    patterns: [
      /\/dev\/(?:tcp|udp)\/[\w.-]{1,253}\/\d{1,5}/,
      /\bn(?:c|cat|etcat)\s{1,5}(?:-[a-z]{1,5}\s{1,5}(?:[\w.-]{1,64}\s{1,5})?){0,4}-[a-z]{0,4}[ec]\s{1,3}(?:\/bin\/)?(?:ba|z)?sh\b/i,
      /\bsocat\b[^\n]{0,200}\bexec:/i,
      /\bmkfifo\s{1,3}\S{1,100}[^\n]{0,100}\bn(?:c|cat)\s/,
      /New-Object\s{1,3}(?:System\.)?Net\.Sockets\.TCPClient\s{0,3}\(/i,
      /\bpty\.spawn\s{0,3}\(\s{0,3}["'](?:\/bin\/)?(?:ba)?sh/,
    ],
  },
  {
    id: 'SS-EX-007',
    category: 'exfiltration',
    severity: 'medium',
    title: 'URL with a raw public IP address',
    description: 'A URL pointing at a hard-coded public IP address rather than a domain — typical of command-and-control or drop servers.',
    remediation: 'Use a well-known, documented domain name, or explain why a raw IP is needed.',
    appliesTo: NOT_BINARY,
    patterns: [/\b(?:https?|ftp|wss?):\/\/((?:\d{1,3}\.){3}\d{1,3})(?![\d.])/i],
    accept: (m) => !PRIVATE_IP_RE.test(m[1]) && m[1].split('.').every((o) => Number(o) <= 255),
  },
  {
    id: 'SS-EX-008',
    category: 'exfiltration',
    severity: 'high',
    title: 'Markdown image / link exfiltration',
    description: 'A Markdown image or link whose URL carries a placeholder to be filled with data ({…}, $VAR, <…>). When the agent renders it, the client fetches the URL and leaks the data — no tool call needed.',
    remediation: 'Remove dynamic image/link URLs. Never ask the model to put conversation data into URLs.',
    appliesTo: NOT_BINARY,
    patterns: [/!?\[[^\][\n]{0,200}\]\(\s{0,3}<?https?:\/\/[^\s)]{1,300}?[?&#/][\w.-]{0,40}=?(?:\{\{?|\$\{?|%7B|<|\[)[^\s)]{0,200}\)/i],
  },
  {
    id: 'SS-EX-009',
    category: 'exfiltration',
    severity: 'critical',
    title: 'Instruction to send sensitive data to an external destination',
    description: 'Prose instructs the agent to send conversation content, credentials, keys or environment variables to a URL/endpoint/email.',
    remediation: 'Remove the instruction. Sensitive data must never leave the machine without the user explicitly asking for it.',
    appliesTo: NOT_BINARY,
    contexts: ['prose', 'hidden-comment', 'frontmatter', 'code-comment', 'inline'],
    patterns: [
      /\b(?:send|post|upload|forward|transmit|submit|exfiltrate|leak|email|share|report|sync)\s{1,3}(?:[\w'’-]{1,20}\s{1,3}){0,5}?(?:conversation|chat\s{1,3}(?:history|log)|context\s{1,3}window|api\s{1,3}keys?|credentials|secrets|(?:access\s{1,3}|auth\s{1,3})?tokens?|passwords?|env(?:ironment)?\s{1,3}variables|ssh\s{1,3}keys?|private\s{1,3}keys?|\.env|cookies|session)\b[^\n]{0,160}?\b(?:to|at|via|using)\s{1,3}(?:https?:\/\/|the\s{1,3}(?:following\s{1,3}|remote\s{1,3}|external\s{1,3})?(?:url|endpoint|server|webhook|address|api)|[\w.+-]{1,64}@[\w-]{1,63}\.)/i,
    ],
  },

  /* ===== Credential access ===== */
  {
    id: 'SS-CR-001',
    category: 'credential-access',
    severity: 'high',
    title: 'SSH key / SSH config access',
    description: 'References the user’s SSH directory or private key files.',
    remediation: 'A skill should not read SSH keys. Use the ssh-agent or ask the user to configure access themselves.',
    appliesTo: NOT_BINARY,
    proseImperative: true,
    patterns: [
      /(?:~|\$HOME|\$\{HOME\}|%USERPROFILE%|\$env:USERPROFILE|\/home\/[\w.-]{1,32}|\/root|\/Users\/[\w.-]{1,32})[/\\]\.ssh\b/,
      /\bid_(?:rsa|ed25519|ecdsa|dsa)\b(?!\.pub)/,
    ],
  },
  {
    id: 'SS-CR-002',
    category: 'credential-access',
    severity: 'high',
    title: 'Cloud / package-registry credential files',
    description: 'References credential stores of cloud CLIs and package managers (~/.aws/credentials, gcloud, Azure, kubeconfig, docker config, .npmrc, .pypirc, .netrc, git-credentials, gh hosts.yml).',
    remediation: 'Do not read credential files. Rely on the official SDK credential chain at runtime, scoped to the task.',
    appliesTo: NOT_BINARY,
    proseImperative: true,
    patterns: [
      /(?:~|\$HOME|\$\{HOME\}|%USERPROFILE%|%APPDATA%|\$env:USERPROFILE)[/\\]\.?(?:aws[/\\](?:credentials|config)|config[/\\]gcloud|azure[/\\]|kube[/\\]config|docker[/\\]config\.json|npmrc|pypirc|netrc|git-credentials|config[/\\]gh[/\\]hosts\.yml|gnupg|terraform\.d[/\\]credentials)/i,
      /\b(?:application_default_credentials|credentials\.db|access_tokens\.db)\.json\b|\bcredentials\.db\b|\baccess_tokens\.db\b/,
    ],
  },
  {
    id: 'SS-CR-003',
    category: 'credential-access',
    severity: 'critical',
    title: 'Browser cookie / password store access',
    description: 'References browser profile databases that hold cookies and saved passwords (Chrome "Login Data", Firefox logins.json / key4.db, Safari Cookies.binarycookies).',
    remediation: 'Remove it. Reading browser credential stores is info-stealer behaviour.',
    appliesTo: NOT_BINARY,
    patterns: [
      /\bLogin\s{1,3}Data\b|\bCookies\.binarycookies\b|\bcookies\.sqlite\b|\blogins\.json\b|\bkey[34]\.db\b/,
      /(?:Google[/\\]Chrome|Chromium|BraveSoftware[/\\]Brave-Browser|Microsoft[/\\]Edge|Mozilla[/\\]Firefox|Library[/\\]Safari)[/\\](?:User\s{1,3}Data|Profiles|Default)\b/i,
    ],
  },
  {
    id: 'SS-CR-004',
    category: 'credential-access',
    severity: 'high',
    title: 'OS keychain / credential manager dump',
    description: 'Reads secrets from the OS keychain or credential manager, or references credential-dumping tools.',
    remediation: 'Remove it unless the skill only reads its OWN entry and the user has been told.',
    appliesTo: NOT_BINARY,
    contexts: CODE_STRICT,
    patterns: [
      /\bsecurity\s{1,3}(?:find-generic-password|find-internet-password|dump-keychain)\b|\bcmdkey\s{1,3}\/list\b|\bvaultcmd\b|\bsecret-tool\s{1,3}(?:lookup|search)\b|\bCredRead[AW]?\b|\bLaZagne\b|\bmimikatz\b|\bsekurlsa::|\bGet-StoredCredential\b/i,
    ],
  },
  {
    id: 'SS-CR-005',
    category: 'credential-access',
    severity: 'medium',
    title: '.env file read',
    description: 'Reads a .env file, which typically contains API keys and database passwords.',
    remediation: 'Read only the variables the skill needs from the environment; do not read or transmit whole .env files.',
    appliesTo: NOT_BINARY,
    contexts: CODE,
    patterns: [
      /(?:\b(?:cat|less|more|head|tail|type|bat|Get-Content|gc)\s{1,3}|\bopen\s{0,3}\(\s{0,3}|\bread(?:File(?:Sync)?|_text)\s{0,3}\(\s{0,3}|\bsource\s{1,3}|^\.\s{1,3})["'`]?[\w./~$\\-]{0,100}(?<![\w-])\.env(?:\.(?!example|sample|template|dist)[\w-]{1,20})?(?![\w.-])/,
    ],
  },
  {
    id: 'SS-CR-006',
    category: 'credential-access',
    severity: 'high',
    title: 'Crypto-wallet files',
    description: 'References cryptocurrency wallet files or extension data.',
    remediation: 'Remove it; wallet access is a hallmark of info-stealers.',
    appliesTo: NOT_BINARY,
    proseImperative: true,
    patterns: [/\bwallet\.dat\b|\.bitcoin[/\\]|\.ethereum[/\\]keystore|\bexodus\.wallet\b|\belectrum[/\\]wallets\b|solana[/\\]id\.json|\bnkbihfbeogaeaoehlefnkodbefgpgknn\b/i],
  },
  {
    id: 'SS-CR-007',
    category: 'credential-access',
    severity: 'high',
    title: 'System password database',
    description: 'References /etc/shadow, sudoers or the Windows SAM/SECURITY hives.',
    remediation: 'Remove it.',
    appliesTo: NOT_BINARY,
    proseImperative: true,
    patterns: [/\/etc\/(?:shadow|gshadow|master\.passwd)\b|\breg(?:\.exe)?\s{1,3}save\s{1,3}hklm\\(?:sam|security|system)\b|\\config\\SAM\b/i],
  },
  {
    id: 'SS-CR-008',
    category: 'credential-access',
    severity: 'low',
    title: 'Secret-named environment variable read',
    description: 'Code reads an environment variable whose name looks like a secret. Usually legitimate (the skill’s own API key) — check where the value goes.',
    remediation: 'Make sure the value is only sent to the API it belongs to and never logged.',
    appliesTo: ['script', 'skill-md', 'agent-md', 'markdown'],
    contexts: CODE_STRICT,
    patterns: [
      /\b(?:process\.env|os\.environ|os\.getenv|getenv|System\.getenv|Deno\.env\.get|\$env:|ENV\[)\s{0,3}[[.(]?\s{0,3}["']?[A-Z0-9_]{0,40}(?:TOKEN|SECRET|PASSWORD|PASSWD|API_KEY|APIKEY|PRIVATE_KEY|ACCESS_KEY|CREDENTIALS)[A-Z0-9_]{0,40}/,
    ],
  },

  /* ===== Agent snooping ===== */
  {
    id: 'SS-AS-001',
    category: 'agent-snooping',
    severity: 'medium',
    title: 'Reads other agents’ configuration / skills',
    description: 'References configuration, skills or MCP settings of coding agents (~/.claude, ~/.codex, ~/.cursor, claude_desktop_config.json…). These contain tokens, server lists and other skills.',
    remediation: 'A skill should only touch its own directory and the project it works on.',
    appliesTo: NOT_BINARY,
    contexts: ['code', 'code-comment', 'prose', 'hidden-comment'],
    proseImperative: true,
    patterns: [
      /(?:~|\$HOME|\$\{HOME\}|%USERPROFILE%|%APPDATA%|\$env:USERPROFILE)[/\\]\.(?:claude(?:\.json)?|codex|cursor|gemini|continue|aider[\w.-]{0,20}|codeium|windsurf|copilot|kiro|roo|cline)\b/i,
      /\bclaude_desktop_config\.json\b|\.claude[/\\](?:settings(?:\.local)?\.json|skills[/\\]|agents[/\\]|commands[/\\])|\.config[/\\](?:github-copilot|claude)\b|\bcline_mcp_settings\.json\b/i,
    ],
  },
  {
    id: 'SS-AS-002',
    category: 'agent-snooping',
    severity: 'critical',
    title: 'Agent credential files',
    description: 'References files holding coding-agent / CLI login tokens (~/.claude/.credentials.json, ~/.codex/auth.json, gh hosts.yml, Copilot apps.json).',
    remediation: 'Remove it. Reading another tool’s auth token is credential theft.',
    appliesTo: NOT_BINARY,
    proseImperative: true,
    patterns: [/\.claude[/\\]\.credentials\.json|\.codex[/\\]auth\.json|github-copilot[/\\](?:apps|hosts)\.json|\.gemini[/\\]oauth_creds\.json/i],
  },
  {
    id: 'SS-AS-003',
    category: 'agent-snooping',
    severity: 'high',
    title: 'Agent conversation history access',
    description: 'References stored agent transcripts / session history (e.g. ~/.claude/projects/*.jsonl, ~/.codex/sessions, history.jsonl).',
    remediation: 'Remove it. Transcripts contain everything the user and other tools said, including secrets.',
    appliesTo: NOT_BINARY,
    proseImperative: true,
    patterns: [/\.claude[/\\]projects[/\\]|\.codex[/\\]sessions\b|\bhistory\.jsonl\b|\.cursor[/\\]chats\b|workspaceStorage[/\\][^\s]{0,100}state\.vscdb/i],
  },

  /* ===== Privilege escalation ===== */
  {
    id: 'SS-PE-001',
    category: 'privilege-escalation',
    severity: 'medium',
    title: 'sudo usage',
    description: 'Runs a command with sudo. Agent skills should not need root; sudo in an unattended agent run is a red flag.',
    remediation: 'Remove sudo, or document exactly why root is needed and require the user to run it themselves.',
    appliesTo: NOT_BINARY,
    contexts: CODE,
    patterns: [/(?:^|[;&|`(]|\$\()\s{0,3}sudo\s{1,3}(?!-[lkKvV]\b)[\w"'/-]/],
    message: () => 'Command executed with sudo.',
  },
  {
    id: 'SS-PE-002',
    category: 'privilege-escalation',
    severity: 'high',
    title: 'World-writable or setuid permissions',
    description: 'chmod 777 / a+rwx makes files writable by everyone; setuid/setgid bits (+s, 4755, 2755) let anyone run the file with its owner’s privileges.',
    remediation: 'Use the narrowest permissions (e.g. 755 for scripts, 600 for secrets). Never set setuid.',
    appliesTo: NOT_BINARY,
    contexts: CODE,
    patterns: [/\bchmod\s{1,3}(?:-[Rcfv]{1,4}\s{1,3})?(?:0?777|[0-7]?[246][0-7]{3}|a\+rwx|[ugoa]{0,3}\+[rwx]{0,3}s[rwx]{0,3}|o\+w)(?![\w])/],
  },
  {
    id: 'SS-PE-003',
    category: 'privilege-escalation',
    severity: 'critical',
    title: 'sudoers / admin-group modification',
    description: 'Adds NOPASSWD sudo rules, edits sudoers or adds a user to sudo/wheel/docker/Administrators.',
    remediation: 'Remove it. A skill must never change system privilege configuration.',
    appliesTo: NOT_BINARY,
    patterns: [/\bNOPASSWD\s{0,3}:|\/etc\/sudoers(?:\.d)?\b|\bvisudo\b|\busermod\s{1,3}-a?G\s{1,3}(?:sudo|wheel|docker|admin|root)\b|\bnet\s{1,3}localgroup\s{1,3}administrators\b[^\n]{0,100}\/add\b|\bAdd-LocalGroupMember\b[^\n]{0,100}Administrators/i],
  },
  {
    id: 'SS-PE-004',
    category: 'privilege-escalation',
    severity: 'high',
    title: 'Windows elevation / execution-policy bypass',
    description: 'Elevates with -Verb RunAs, bypasses the PowerShell execution policy, or disables Microsoft Defender.',
    remediation: 'Remove elevation and policy bypasses; sign scripts instead of bypassing policy.',
    appliesTo: NOT_BINARY,
    contexts: CODE,
    patterns: [
      /\bStart-Process\b[^\n]{0,200}-Verb\s{1,3}RunAs\b|\bSet-ExecutionPolicy\s{1,3}(?:-ExecutionPolicy\s{1,3})?(?:Bypass|Unrestricted)\b|-(?:ExecutionPolicy|ep|exec)\s{1,3}Bypass\b/i,
      /\bSet-MpPreference\b[^\n]{0,200}-Disable\w{1,40}\s{1,3}\$?true|\bAdd-MpPreference\b[^\n]{0,100}-ExclusionPath\b/i,
    ],
  },
  {
    id: 'SS-PE-005',
    category: 'privilege-escalation',
    severity: 'high',
    title: 'Security controls disabled',
    description: 'Disables SELinux, firewalls, macOS Gatekeeper/SIP, or strips the quarantine attribute from downloaded files.',
    remediation: 'Remove it. A skill must not weaken host security controls.',
    appliesTo: NOT_BINARY,
    contexts: CODE,
    patterns: [/\bsetenforce\s{1,3}0\b|\bufw\s{1,3}disable\b|\biptables\s{1,3}-F\b|\bspctl\s{1,3}--master-disable\b|\bcsrutil\s{1,3}disable\b|\bxattr\s{1,3}(?:-[a-z]{1,3}\s{1,3}){0,2}-d\s{1,3}com\.apple\.quarantine|\bxattr\s{1,3}-[a-z]{0,2}c[a-z]{0,2}\s|\bnetsh\s{1,3}advfirewall\s{1,3}set\s{1,3}\w{1,20}\s{1,3}state\s{1,3}off\b/i],
  },

  /* ===== Supply chain ===== */
  {
    id: 'SS-SC-001',
    category: 'supply-chain',
    severity: 'high',
    title: 'Remote script piped to a shell (curl | bash)',
    description: 'Downloads code and executes it immediately (curl … | sh, iwr … | iex, bash <(curl …)). Whatever the server returns — today or after a compromise — runs with the user’s privileges.',
    remediation: 'Download to a file, verify a pinned checksum/signature, then run it. Prefer a package manager with pinned versions.',
    appliesTo: NOT_BINARY,
    patterns: [
      /\b(?:curl|wget|fetch)\b[^\n|]{0,200}\|\s{0,3}(?:sudo\s{1,3}(?:-[\w-]{1,10}\s{1,3}){0,3})?(?:env\s{1,3})?(?:ba|z|da|k|fi)?sh\b/i,
      /\b(?:curl|wget)\b[^\n|]{0,200}\|\s{0,3}(?:sudo\s{1,3})?(?:python[23]?|node|perl|ruby|php|deno\s{1,3}run)\b/i,
      /\b(?:iwr|irm|Invoke-WebRequest|Invoke-RestMethod|DownloadString|curl)\b[^\n|]{0,200}\|\s{0,3}(?:iex|Invoke-Expression)\b/i,
      /\b(?:ba|z)?sh\s{1,3}(?:-c\s{1,3})?["']?\$\(\s{0,3}(?:curl|wget)\b|\b(?:source|\.|(?:ba|z)?sh)\s{1,3}<\(\s{0,3}(?:curl|wget)\b/,
      /\biex\s{0,3}\(\s{0,3}(?:New-Object\s{1,3}(?:System\.)?Net\.WebClient|iwr|irm|Invoke-WebRequest|Invoke-RestMethod)/i,
    ],
  },
  {
    id: 'SS-SC-002',
    category: 'supply-chain',
    severity: 'critical',
    title: 'Obfuscated payload executed (base64 → shell / exec)',
    description: 'Decodes an encoded blob and executes it (base64 -d | sh, exec(b64decode(…)), eval(atob(…)), powershell -EncodedCommand). Obfuscation hides what actually runs.',
    remediation: 'Ship readable source. Never execute decoded blobs.',
    appliesTo: NOT_BINARY,
    patterns: [
      /\bbase64\s{1,3}(?:-d|--decode|-D)\b[^\n]{0,120}\|\s{0,3}(?:sudo\s{1,3})?(?:ba|z|da)?sh\b/,
      /\b(?:exec|eval)\s{0,3}\(\s{0,3}(?:(?:base64\.)?b64decode|base64\.(?:b64|b32|b16|a85|b85)decode|codecs\.decode|zlib\.decompress|marshal\.loads|bytes\.fromhex|atob|Buffer\.from)\s{0,3}\(/,
      /\bFromBase64String\b[^\n]{0,200}(?:\biex\b|Invoke-Expression)|(?:\biex\b|Invoke-Expression)[^\n]{0,200}FromBase64String/i,
      /\b(?:powershell|pwsh)(?:\.exe)?\b[^\n]{0,100}?\s-(?:e|ec|en|enc|enco|encodedcommand)\s{1,3}[A-Za-z0-9+/=]{20,10000}/i,
    ],
  },
  {
    id: 'SS-SC-003',
    category: 'supply-chain',
    severity: 'low',
    title: 'Unpinned pip install',
    description: 'pip installs packages without an exact version (==). A future or hijacked release (typosquat, account takeover) is installed silently.',
    remediation: 'Pin exact versions (pkg==1.2.3), ideally with hashes (--require-hashes) in a requirements file.',
    appliesTo: NOT_BINARY,
    contexts: ['code', 'inline'],
    patterns: [/\b(?:pip[23]?(?:\.\d{1,2})?|python[23]?(?:\.\d{1,2})?\s{1,3}-m\s{1,3}pip|uv\s{1,3}pip)\s{1,3}install\b([^\n;&|#`]{0,300})/],
    accept: (m) => unpinnedPip(m[1] ?? '').length > 0,
    message: (m) => `Unpinned: ${unpinnedPip(m[1] ?? '').slice(0, 5).join(', ')}`,
  },
  {
    id: 'SS-SC-004',
    category: 'supply-chain',
    severity: 'low',
    title: 'Unpinned npm/yarn/pnpm package install',
    description: 'Installs npm packages without an exact version. Global installs (-g) of floating versions are especially risky.',
    remediation: 'Pin exact versions (pkg@1.2.3) and commit a lockfile; prefer `npm ci`.',
    appliesTo: NOT_BINARY,
    contexts: ['code', 'inline'],
    patterns: [/\b(?:npm\s{1,3}(?:install|i|add)|yarn\s{1,3}(?:global\s{1,3})?add|pnpm\s{1,3}(?:add|install|i)|bun\s{1,3}(?:add|install|i))\b([^\n;&|#`]{0,300})/],
    accept: (m) => unpinnedNpm(m[1] ?? '').length > 0,
    message: (m) => `Unpinned: ${unpinnedNpm(m[1] ?? '').slice(0, 5).join(', ')}`,
  },
  {
    id: 'SS-SC-005',
    category: 'supply-chain',
    severity: 'medium',
    title: 'Unpinned package runner (npx / uvx / pipx run / dlx)',
    description: 'npx, bunx, pnpm dlx, uvx and pipx run download and execute the LATEST version of a package on every run.',
    remediation: 'Pin the version: npx pkg@1.2.3, uvx pkg==1.2.3 (or uvx pkg@1.2.3).',
    appliesTo: NOT_BINARY,
    contexts: ['code', 'inline'],
    patterns: [/\b(npx|bunx|pnpm\s{1,3}dlx|yarn\s{1,3}dlx|uvx|pipx\s{1,3}run)\s{1,3}([^\n;&|#`]{1,300})/],
    accept: (m) => {
      const pkg = runnerPackage(m[1], m[2])
      return pkg !== undefined && !isPlaceholderToken(pkg) && !/^(?:\.|\/)/.test(pkg) && !runnerPinned(m[1], pkg)
    },
    message: (m) => `${m[1]} runs "${runnerPackage(m[1], m[2]) ?? '?'}" without a pinned version.`,
  },
  {
    id: 'SS-SC-006',
    category: 'supply-chain',
    severity: 'medium',
    title: 'Package installed from URL / git / custom index',
    description: 'Installs from a git URL, tarball URL or non-default package index — bypasses registry provenance and is a dependency-confusion vector.',
    remediation: 'Install from the official registry with a pinned version, or pin the git dependency to a full commit SHA.',
    appliesTo: NOT_BINARY,
    contexts: ['code', 'inline'],
    patterns: [
      /\b(?:pip[23]?|uv\s{1,3}pip|npm|yarn|pnpm|gem|cargo)\s{1,3}(?:install|i|add)\b[^\n]{0,200}?(?:git\+(?:https?|ssh):\/\/|\bhttps?:\/\/\S{1,300}\.(?:tar\.gz|tgz|whl|zip|gem)\b|--(?:extra-)?index-url\b|--registry\b|--source\b)/i,
    ],
    accept: (_m, line) => !/git\+[^\s@]{1,300}@[0-9a-f]{40}\b/.test(line),
  },
  {
    id: 'SS-SC-007',
    category: 'supply-chain',
    severity: 'high',
    title: 'Binary downloaded then made executable',
    description: 'Downloads a file and immediately marks it executable / runs it, without checksum verification.',
    remediation: 'Verify a pinned SHA-256 (sha256sum -c) or signature before executing downloaded binaries.',
    appliesTo: NOT_BINARY,
    contexts: CODE,
    patterns: [/\b(?:curl|wget|Invoke-WebRequest|iwr)\b[^\n]{0,200}?(?:&&|;|\|\|)\s{0,3}(?:sudo\s{1,3})?chmod\s{1,3}(?:[ugoa]{0,3}\+x|[0-7]{3,4})\b/i],
    accept: (_m, line) => !/\bsha(?:256|512)sum\b|\bshasum\b|Get-FileHash|gpg\s{1,3}--verify|cosign\s{1,3}verify/i.test(line),
  },

  /* ===== Excessive agency ===== */
  {
    id: 'SS-EA-001',
    category: 'excessive-agency',
    severity: 'high',
    title: 'Human-in-the-loop removed',
    description: 'Tells the agent to act without asking for confirmation / approval, or to auto-approve everything.',
    remediation: 'Keep the user in the loop for side effects (writes, network, deletes, purchases, messages).',
    appliesTo: NOT_BINARY,
    noDowngrade: true,
    patterns: [
      /\bwithout\s{1,3}(?:asking|prompting|confirming|confirmation|approval|permission|consent|checking\s{1,3}with|(?:the\s{1,3})?user['’]?s?\s{1,3}(?:approval|permission|consent|confirmation|input))\b/i,
      /\b(?:do\s{1,3}not|don['’]?t|never|no\s{1,3}need\s{1,3}to)\s{1,3}(?:ask|wait|prompt|check)\s{1,3}(?:the\s{1,3}user\s{1,3}|with\s{1,3}the\s{1,3}user\s{1,3})?(?:for\s{1,3})?(?:confirmation|approval|permission|consent|before)\b/i,
      /\bauto-?(?:approve|confirm|accept)\s{1,3}(?:all|every|any)\b|\b(?:skip|bypass)\s{1,3}(?:all\s{1,3})?(?:confirmations?|approvals?|permission\s{1,3}(?:checks|prompts|dialogs))\b/i,
    ],
  },
  {
    id: 'SS-EA-002',
    category: 'excessive-agency',
    severity: 'high',
    title: 'Recursive delete of a broad path',
    description: 'rm -rf (or Remove-Item -Recurse) on /, ~, $HOME, *, . or an unchecked variable. An empty or wrong variable wipes the wrong tree.',
    remediation: 'Delete specific paths; guard variables (${VAR:?}); prefer moving to a temp/trash directory; ask the user first.',
    appliesTo: NOT_BINARY,
    contexts: CODE,
    patterns: [
      /\brm\s{1,3}(?:-{1,2}[\w-]{1,20}\s{1,3}){1,4}["']?(?:\/|~|\$HOME|\$\{HOME\}|\*|\.{1,2}|\$\{?[A-Za-z_]\w{0,40}\}?)["']?\/?\*?(?=\s|$|;|&|\||\))/,
      /\b(?:Remove-Item|rm|ri|del)\b[^\n]{0,100}-Recurse\b[^\n]{0,100}(?:\s(?:[A-Z]:\\?|~|\$HOME|\$env:USERPROFILE|\$env:HOMEPATH|\*)["']?(?=\s|$)|-Path\s{1,3}["']?(?:[A-Z]:\\?|~|\$HOME|\$env:USERPROFILE)["']?(?=\s|$))/i,
      /\brd\s{1,3}\/s\s{1,3}\/q\s{1,3}(?:[A-Z]:\\|%USERPROFILE%|%HOMEPATH%)/i,
    ],
    accept: (m) => !/^rm/.test(m[0]) || /\s-{1,2}(?:[a-zA-Z]{0,5}[rR][a-zA-Z]{0,5}|recursive)\b/.test(m[0]),
  },
  {
    id: 'SS-EA-003',
    category: 'excessive-agency',
    severity: 'critical',
    title: 'Disk / filesystem wipe',
    description: 'Formats or overwrites disks (mkfs, dd to a block device, format C:, diskpart clean, shred of a device).',
    remediation: 'Remove it.',
    appliesTo: NOT_BINARY,
    contexts: CODE,
    patterns: [/\bmkfs(?:\.\w{1,10})?\s{1,3}\/dev\/|\bdd\b[^\n]{0,100}\bof=\/dev\/(?:sd|hd|nvme|disk|xvd|vd|mmcblk)|\bformat(?:\.com)?\s{1,3}[A-Z]:(?:\s|$)|\bdiskpart\b[^\n]{0,100}\bclean\b|\bshred\b[^\n]{0,100}\/dev\/|\bwipefs\s{1,3}-a\b|>\s{0,3}\/dev\/(?:sd[a-z]|nvme\d)/i],
  },
  {
    id: 'SS-EA-004',
    category: 'excessive-agency',
    severity: 'medium',
    title: 'Git history destruction / force push',
    description: 'Force-pushes, hard-resets, cleans untracked files or rewrites history — work can be lost for the user and collaborators.',
    remediation: 'Use --force-with-lease, create a backup branch, and ask the user before rewriting history.',
    appliesTo: NOT_BINARY,
    contexts: CODE,
    patterns: [/\bgit\s{1,3}push\b[^\n]{0,200}?(?:\s--force(?![\w-])|\s-f\b|\s\+[\w/.-]{1,100}(?::|\s|$))|\bgit\s{1,3}reset\s{1,3}--hard\b|\bgit\s{1,3}clean\s{1,3}-[a-z]{0,4}[fdx][a-z]{0,4}[fdx]|\bgit\s{1,3}filter-(?:branch|repo)\b|\bgit\s{1,3}branch\s{1,3}-D\s{1,3}(?:main|master|develop|release)\b/],
  },
  {
    id: 'SS-EA-005',
    category: 'excessive-agency',
    severity: 'medium',
    title: 'Destructive database statement',
    description: 'DROP / TRUNCATE or an unbounded DELETE. Executed by an agent, this is irreversible data loss.',
    remediation: 'Require explicit user confirmation, use transactions and backups, scope DELETEs with WHERE.',
    appliesTo: NOT_BINARY,
    contexts: CODE_STRICT,
    patterns: [/\b(?:DROP\s{1,3}(?:DATABASE|SCHEMA|TABLE)(?!\s{1,3}IF\s{1,3}EXISTS\s{1,3}(?:tmp|temp)_)|TRUNCATE\s{1,3}TABLE|DELETE\s{1,3}FROM\s{1,3}[\w."`[\]]{1,128}\s{0,3}(?:;|["'`)]|$))/i],
  },
  {
    id: 'SS-EA-006',
    category: 'permissions',
    severity: 'high',
    title: 'Agent approval bypass flag',
    description: 'Starts an agent with every approval disabled (--dangerously-skip-permissions, --dangerously-bypass-approvals-and-sandbox, --yolo, --allow-all-tools, --full-auto, --trust-all-tools).',
    remediation: 'Run agents with explicit, narrow allow-lists; use bypass modes only inside disposable sandboxes without credentials.',
    appliesTo: NOT_BINARY,
    patterns: [/--(?:dangerously-skip-permissions|dangerously-bypass-approvals-and-sandbox|yolo|allow-all-tools|full-auto|trust-all-tools|permission-mode[ =]bypassPermissions)\b/],
  },
  {
    id: 'SS-EA-007',
    category: 'excessive-agency',
    severity: 'medium',
    title: 'Irreversible publish / infrastructure command',
    description: 'Publishes packages or destroys cloud infrastructure (npm publish, twine upload, terraform destroy, kubectl delete, aws s3 rm --recursive, gh repo delete).',
    remediation: 'Keep these behind explicit user confirmation; never run them autonomously.',
    appliesTo: NOT_BINARY,
    contexts: CODE,
    patterns: [/\b(?:npm\s{1,3}publish|yarn\s{1,3}publish|pnpm\s{1,3}publish|twine\s{1,3}upload|cargo\s{1,3}publish|gem\s{1,3}push|terraform\s{1,3}destroy|kubectl\s{1,3}delete\s{1,3}(?:ns|namespace|all|--all)|aws\s{1,3}s3\s{1,3}(?:rm|rb)\b[^\n]{0,200}--(?:recursive|force)|gh\s{1,3}repo\s{1,3}delete|gcloud\s{1,3}projects\s{1,3}delete|az\s{1,3}group\s{1,3}delete)\b/],
  },

  /* ===== Output handling ===== */
  {
    id: 'SS-OH-001',
    category: 'output-handling',
    severity: 'medium',
    title: 'Unsafe HTML sink',
    description: 'Writes HTML with innerHTML / outerHTML / document.write / insertAdjacentHTML / dangerouslySetInnerHTML / v-html. If model output or fetched data reaches it, this is XSS.',
    remediation: 'Use textContent or a vetted sanitizer (DOMPurify) and a strict CSP.',
    appliesTo: NOT_BINARY,
    contexts: CODE_STRICT,
    patterns: [/\.(?:innerHTML|outerHTML)\s{0,3}\+?=(?!=)|\bdocument\.write(?:ln)?\s{0,3}\(|\binsertAdjacentHTML\s{0,3}\(|\bdangerouslySetInnerHTML\b|\bv-html\s{0,3}=|\|\s{0,3}safe\b(?=\s{0,3}\}\})|\bMarkup\s{0,3}\(/],
  },
  {
    id: 'SS-OH-002',
    category: 'output-handling',
    severity: 'high',
    title: 'Model / tool output executed',
    description: 'Passes a model response or tool result straight into eval/exec/a shell. Anyone who can influence the model (prompt injection) gets code execution.',
    remediation: 'Never execute model output. Parse it into a fixed set of allowed actions, or require user review.',
    appliesTo: NOT_BINARY,
    contexts: CODE_STRICT,
    patterns: [/\b(?:eval|exec|os\.system|os\.popen|subprocess\.\w{1,20}|child_process\.\w{1,10}|execSync|spawnSync|spawn|Invoke-Expression|iex)\s{0,3}\(\s{0,3}[^\n)]{0,80}?\b(?:response|completion|llm_?(?:output|response|result)|model_?(?:output|response)|output_text|choices\[0\]|message\.content|result\.text|generated(?:_code|Code)?|ai_?(?:output|response)|tool_?(?:output|result))\b/i],
  },
  {
    id: 'SS-OH-003',
    category: 'output-handling',
    severity: 'medium',
    title: 'SQL built by string formatting',
    description: 'A SQL statement is assembled with f-strings, concatenation, % or template literals before execution — SQL injection if any part comes from input or the model.',
    remediation: 'Use parameterised queries / placeholders.',
    appliesTo: NOT_BINARY,
    contexts: CODE_STRICT,
    patterns: [/\b(?:execute|executemany|query|raw|exec)\s{0,3}\(\s{0,3}(?:f["'][^\n]{0,200}\{|["'][^"'\n]{0,200}["']\s{0,3}(?:\+|%\s{0,3}[(\w])|`[^`\n]{0,200}\$\{|["'][^"'\n]{0,200}["']\.format\()/],
    accept: (m) => /\b(?:SELECT|INSERT|UPDATE|DELETE|DROP|CREATE|ALTER|WHERE)\b/i.test(m[0]),
  },

  /* ===== Dynamic code ===== */
  {
    id: 'SS-DC-001',
    category: 'dynamic-code',
    severity: 'medium',
    title: 'eval / exec of a dynamic string',
    description: 'eval() / exec() runs arbitrary code built at runtime.',
    remediation: 'Replace with explicit logic (json.loads, ast.literal_eval, a dispatch table).',
    appliesTo: NOT_BINARY,
    contexts: CODE_STRICT,
    patterns: [/(?<![\w.$>-])(?:eval|exec)\s{0,3}\((?!\s{0,3}\))/],
    accept: (_m, line) => !/\b(?:def|function)\s{1,3}(?:eval|exec)\b/.test(line),
  },
  {
    id: 'SS-DC-002',
    category: 'dynamic-code',
    severity: 'medium',
    title: 'Dynamic code construction (Function, vm, compile, import)',
    description: 'new Function(), vm.runIn*Context, compile(), __import__ / importlib with a variable, or setTimeout with a string evaluates code assembled at runtime.',
    remediation: 'Use static imports and explicit logic.',
    appliesTo: NOT_BINARY,
    contexts: CODE_STRICT,
    patterns: [/\bnew\s{1,3}Function\s{0,3}\(|\bvm\.runIn(?:New|This)?Context\s{0,3}\(|\bvm\.Script\s{0,3}\(|(?<![\w.])compile\s{0,3}\([^\n)]{0,100}["'](?:exec|eval)["']|\b__import__\s{0,3}\(\s{0,3}[a-zA-Z_]|\bimportlib\.import_module\s{0,3}\(\s{0,3}[a-zA-Z_]|\bset(?:Timeout|Interval)\s{0,3}\(\s{0,3}["'`]/],
  },
  {
    id: 'SS-DC-003',
    category: 'dynamic-code',
    severity: 'medium',
    title: 'PowerShell Invoke-Expression',
    description: 'Invoke-Expression / iex executes a string as code.',
    remediation: 'Call commands directly with argument arrays (& $cmd @args).',
    appliesTo: NOT_BINARY,
    contexts: CODE,
    patterns: [/\bInvoke-Expression\b|(?:^|[|;(]\s{0,3})iex\s{0,3}(?:\(|\$|["'])/i],
  },

  /* ===== Tool misuse ===== */
  {
    id: 'SS-TM-001',
    category: 'tool-misuse',
    severity: 'medium',
    title: 'Shell invoked with shell=True / os.system',
    description: 'Commands run through a shell interpreter; any interpolated value becomes command injection.',
    remediation: 'Pass an argument list without a shell (subprocess.run([...]), execFile).',
    appliesTo: NOT_BINARY,
    contexts: CODE_STRICT,
    patterns: [/\bshell\s{0,3}=\s{0,3}True\b|\bos\.(?:system|popen)\s{0,3}\(|\bsubprocess\.getoutput\s{0,3}\(|\bshell:\s{0,3}true\b/],
  },
  {
    id: 'SS-TM-002',
    category: 'tool-misuse',
    severity: 'high',
    title: 'Command string built from variables',
    description: 'A shell command is assembled with f-strings, concatenation or template literals and executed — command injection.',
    remediation: 'Use argument arrays and never interpolate untrusted values (including model output) into commands.',
    appliesTo: NOT_BINARY,
    contexts: CODE_STRICT,
    patterns: [/\b(?:os\.system|os\.popen|subprocess\.(?:call|run|Popen|check_output|check_call|getoutput)|child_process\.exec(?:Sync)?|execSync|exec)\s{0,3}\(\s{0,3}(?:f["'][^\n]{0,200}\{|`[^`\n]{0,200}\$\{|["'][^"'\n]{0,200}["']\s{0,3}(?:\+|%\s{0,3}[(\w]|\.format\())/],
  },
  {
    id: 'SS-TM-003',
    category: 'tool-misuse',
    severity: 'high',
    title: 'TLS certificate verification disabled',
    description: 'Disables HTTPS certificate checks (verify=False, NODE_TLS_REJECT_UNAUTHORIZED=0, curl -k, --no-check-certificate, --trusted-host…), enabling man-in-the-middle attacks.',
    remediation: 'Keep verification on; add a custom CA bundle if you need an internal CA.',
    appliesTo: NOT_BINARY,
    contexts: ['code', 'inline', 'code-comment'],
    patterns: [
      /\bverify\s{0,3}=\s{0,3}False\b|NODE_TLS_REJECT_UNAUTHORIZED["']?\s{0,3}[=:]\s{0,3}["']?0\b|\brejectUnauthorized["']?\s{0,3}:\s{0,3}false\b|\bInsecureSkipVerify\s{0,3}:\s{0,3}true\b|\bssl\._create_unverified_context\b|\bCERT_NONE\b|\bcheck_hostname\s{0,3}=\s{0,3}False\b/,
      /\bcurl\b[^\n]{0,200}?\s(?:-k|--insecure)(?![\w-])|\bwget\b[^\n]{0,200}?--no-check-certificate\b|--trusted-host\b|\bstrict-ssl\s{1,3}false\b|\bGIT_SSL_NO_VERIFY\b|\bhttp\.sslVerify\s{1,3}false\b|-SkipCertificateCheck\b|ServerCertificateValidationCallback\s{0,3}=\s{0,3}\{\s{0,3}\$?true/i,
    ],
  },
  {
    id: 'SS-TM-004',
    category: 'tool-misuse',
    severity: 'high',
    title: 'Privileged container / host escape',
    description: 'Runs containers privileged, with host namespaces, all capabilities, the host root filesystem or the Docker socket — equivalent to root on the host.',
    remediation: 'Drop privileges: no --privileged, no host namespaces, mount only what is needed read-only, never mount docker.sock.',
    appliesTo: NOT_BINARY,
    contexts: ['code', 'inline', 'code-comment'],
    patterns: [/--privileged\b|--cap-add[= ](?:ALL|SYS_ADMIN|SYS_PTRACE)\b|--(?:pid|net|network|ipc|uts)[= ]host\b|\s-v\s{1,3}["']?\/:\/|\/var\/run\/docker\.sock|\bprivileged["']?\s{0,3}:\s{0,3}true\b|\bhost(?:PID|Network|IPC)["']?\s{0,3}:\s{0,3}true\b|--security-opt[= ]["']?(?:seccomp|apparmor)[=:]unconfined/],
  },
  {
    id: 'SS-TM-005',
    category: 'tool-misuse',
    severity: 'low',
    title: 'Network listener exposed on all interfaces',
    description: 'Starts a server bound to 0.0.0.0 or a netcat listener — local files or tools become reachable from the network.',
    remediation: 'Bind to 127.0.0.1 unless remote access is required, and add authentication.',
    appliesTo: NOT_BINARY,
    contexts: CODE_STRICT,
    patterns: [/\b(?:python[23]?\s{1,3}-m\s{1,3}http\.server|SimpleHTTPServer)\b(?![^\n]{0,100}--bind\s{1,3}127\.)|\bn(?:c|cat)\s{1,3}(?:-[a-z]{0,4}l[a-z]{0,4})\b|(?:host|bind|listen)["']?\s{0,3}[=:(]\s{0,3}["']0\.0\.0\.0["']/],
  },

  /* ===== SSRF ===== */
  {
    id: 'SS-SR-001',
    category: 'ssrf',
    severity: 'critical',
    title: 'Cloud metadata endpoint',
    description: 'Accesses the cloud instance metadata service (169.254.169.254, metadata.google.internal, Azure IMDS, ECS task metadata, Alibaba 100.100.100.200), which hands out temporary cloud credentials.',
    remediation: 'Remove it. Skills have no reason to query instance metadata.',
    appliesTo: NOT_BINARY,
    patterns: [/\b169\.254\.169\.254\b|\b169\.254\.170\.2\b|\bmetadata\.google\.internal\b|\bmetadata\.azure\.com\b|\b100\.100\.100\.200\b|\bfd00:ec2::254\b|\/latest\/meta-data\b|\/computeMetadata\/v1\b|\/metadata\/identity\/oauth2\/token\b/i],
  },
  {
    id: 'SS-SR-002',
    category: 'ssrf',
    severity: 'medium',
    title: 'Internal network address',
    description: 'URL to a private network range or internal host name (10.x, 192.168.x, 172.16–31.x, *.internal, *.corp, *.lan). Localhost is not flagged.',
    remediation: 'Confirm the skill is meant to reach internal services; never let model output pick internal URLs.',
    appliesTo: NOT_BINARY,
    patterns: [/\b(?:https?|wss?|ftp):\/\/(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}|[\w-]{1,63}(?:\.[\w-]{1,63}){0,5}\.(?:internal|intranet|corp|lan|home\.arpa))(?![\w.-])/i],
  },
  {
    id: 'SS-SR-003',
    category: 'ssrf',
    severity: 'medium',
    title: 'Dangerous URL scheme',
    description: 'gopher://, dict://, ldap://, tftp:// or file:// URLs to system paths — classic SSRF / local file read vectors.',
    remediation: 'Restrict fetches to https:// and an allow-list of hosts.',
    appliesTo: NOT_BINARY,
    patterns: [/\b(?:gopher|dict|ldap|tftp|jar|netdoc):\/\/|\bfile:\/\/\/?(?:etc|proc|root|home|Users|var|[A-Z]:)/i],
  },

  /* ===== Deserialization ===== */
  {
    id: 'SS-DS-001',
    category: 'deserialization',
    severity: 'high',
    title: 'Pickle / marshal deserialization',
    description: 'pickle, dill, joblib, marshal, shelve and torch.load (without weights_only=True) execute code embedded in the data they load.',
    remediation: 'Load data with JSON / safetensors, or torch.load(..., weights_only=True). Never unpickle untrusted data.',
    appliesTo: NOT_BINARY,
    contexts: CODE_STRICT,
    patterns: [/\b(?:pickle|cPickle|_pickle|dill|cloudpickle)\.(?:loads?|Unpickler)\s{0,3}\(|\bmarshal\.loads?\s{0,3}\(|\bshelve\.open\s{0,3}\(|\bjoblib\.load\s{0,3}\(|\bpandas\.read_pickle\s{0,3}\(|\bpd\.read_pickle\s{0,3}\(|\btorch\.load\s{0,3}\((?![^\n]{0,200}weights_only\s{0,3}=\s{0,3}True)/],
  },
  {
    id: 'SS-DS-002',
    category: 'deserialization',
    severity: 'high',
    title: 'Unsafe YAML load',
    description: 'yaml.load without SafeLoader (or unsafe_load / full_load / Loader=yaml.Loader) can construct arbitrary Python objects.',
    remediation: 'Use yaml.safe_load().',
    appliesTo: NOT_BINARY,
    contexts: CODE_STRICT,
    patterns: [/\byaml\.(?:load|load_all)\s{0,3}\((?![^\n]{0,200}Loader\s{0,3}=\s{0,3}(?:yaml\.)?C?(?:Safe|Base)Loader)|\byaml\.(?:unsafe_load|unsafe_load_all|full_load)\s{0,3}\(|\bLoader\s{0,3}=\s{0,3}(?:yaml\.)?(?:Unsafe|Full)?Loader\b/],
  },
  {
    id: 'SS-DS-003',
    category: 'deserialization',
    severity: 'high',
    title: 'Unsafe object deserialization (PHP / Java / .NET / Ruby / Node)',
    description: 'unserialize(), ObjectInputStream, BinaryFormatter, Marshal.load, node-serialize, jsonpickle.decode can instantiate attacker-chosen objects.',
    remediation: 'Use a data-only format (JSON) with schema validation.',
    appliesTo: NOT_BINARY,
    contexts: CODE_STRICT,
    patterns: [/\bunserialize\s{0,3}\(|\bObjectInputStream\b|\bBinaryFormatter\b|\bNetDataContractSerializer\b|\bLosFormatter\b|\bMarshal\.load\b|\brequire\(\s{0,3}["']node-serialize["']\s{0,3}\)|\bjsonpickle\.decode\s{0,3}\(|\bYAML\.unsafe_load\b|\bTypeNameHandling\s{0,3}=\s{0,3}TypeNameHandling\.(?:All|Auto|Objects)/],
  },

  /* ===== Memory poisoning ===== */
  {
    id: 'SS-MP-001',
    category: 'memory-poisoning',
    severity: 'high',
    title: 'Writes to agent instruction / memory files',
    description: 'Code writes to CLAUDE.md, AGENTS.md, .cursorrules, copilot-instructions.md or agent memory. Anything written there becomes persistent instructions for future sessions.',
    remediation: 'Skills should not modify agent instruction files. If they must, show the diff and ask the user.',
    appliesTo: NOT_BINARY,
    contexts: CODE,
    patterns: [/\b(?:CLAUDE|AGENTS|GEMINI|MEMORY)\.md\b|\.(?:cursorrules|windsurfrules|clinerules|goosehints)\b|\bcopilot-instructions\.md\b|\.claude[/\\]memory\b|\.cursor[/\\]rules\b/],
    accept: (_m, line) => hasWriteOp(line),
  },
  {
    id: 'SS-MP-002',
    category: 'memory-poisoning',
    severity: 'medium',
    title: 'Instruction to persist instructions in agent memory',
    description: 'Prose tells the agent to store something in its memory / CLAUDE.md / system prompt, or to “remember this for all future sessions”.',
    remediation: 'Persistent memory should only be changed by the user. Remove the instruction.',
    appliesTo: NOT_BINARY,
    contexts: ['prose', 'hidden-comment', 'frontmatter', 'inline', 'code-comment'],
    patterns: [
      /\b(?:add|append|write|save|insert|store|put|persist)\s{1,3}(?:[\w'’"-]{1,20}\s{1,3}){0,6}?(?:to|in|into)\s{1,3}(?:your\s{1,3}|the\s{1,3})?(?:CLAUDE\.md|AGENTS\.md|GEMINI\.md|\.cursorrules|long-?term\s{1,3}memory|persistent\s{1,3}memory|memory\s{1,3}file|system\s{1,3}prompt|global\s{1,3}instructions|user\s{1,3}instructions|custom\s{1,3}instructions)\b/i,
      /\b(?:remember|memori[sz]e|retain)\b[^\n]{0,80}?\b(?:for\s{1,3}(?:all\s{1,3})?future\s{1,3}(?:sessions|conversations|chats|requests)|in\s{1,3}(?:every|all)\s{1,3}(?:future\s{1,3})?(?:sessions?|conversations?)|permanently|forever)\b/i,
    ],
  },

  /* ===== Rogue agent ===== */
  {
    id: 'SS-RA-001',
    category: 'rogue-agent',
    severity: 'high',
    title: 'Self-modification of skills / agent configuration',
    description: 'Code writes to SKILL.md, .claude/skills, .claude/settings*.json, hooks or MCP config — the skill can rewrite itself or grant itself permissions.',
    remediation: 'Skills must not modify their own definition or agent settings.',
    appliesTo: NOT_BINARY,
    contexts: CODE,
    patterns: [/\bSKILL\.md\b|\.claude[/\\](?:skills|agents|commands|hooks)\b|\.claude[/\\]settings(?:\.local)?\.json|\.mcp\.json\b|\bclaude_desktop_config\.json\b|\.cursor[/\\]mcp\.json|\.vscode[/\\](?:mcp|settings)\.json/],
    accept: (_m, line) => hasWriteOp(line),
  },
  {
    id: 'SS-RA-002',
    category: 'rogue-agent',
    severity: 'high',
    title: 'Persistence mechanism (cron, systemd, launchd, Run keys)',
    description: 'Installs a cron job, systemd/launchd unit, scheduled task or Run-key so code keeps running after the session ends.',
    remediation: 'Remove it. Skills must not install persistence.',
    appliesTo: NOT_BINARY,
    contexts: CODE,
    patterns: [
      /\bcrontab\s{1,3}(?:-e\b|-r\b|-u\s{1,3}\w{1,32}\s{1,3}-e\b|-\s{0,3}(?:$|[;&|<)])|[^\s-])|\/etc\/cron(?:tab|\.d|\.daily|\.hourly|\.weekly)\b|@reboot\b/,
      /\bsystemctl\s{1,3}(?:--user\s{1,3})?(?:enable|link)\b|\/etc\/systemd\/system\/|\.config\/systemd\/user\/|\blaunchctl\s{1,3}(?:load|bootstrap|submit|enable)\b|\bLaunch(?:Agents|Daemons)\b|\/etc\/rc\.local\b|\/etc\/init\.d\//,
      /\bschtasks(?:\.exe)?\s{1,3}\/create\b|\bRegister-ScheduledTask\b|\bNew-ScheduledTask(?:Action|Trigger)?\b|\\CurrentVersion\\Run(?:Once)?\b|\\Start\s{1,3}Menu\\Programs\\Startup\b|\bNew-Service\b|\bsc(?:\.exe)?\s{1,3}create\b/i,
    ],
  },
  {
    id: 'SS-RA-003',
    category: 'rogue-agent',
    severity: 'high',
    title: 'Shell profile modification',
    description: 'Appends to ~/.bashrc, ~/.zshrc, ~/.profile or the PowerShell $PROFILE — code (aliases, PATH hijacks) then runs in every new shell.',
    remediation: 'Do not modify shell startup files; print instructions for the user instead.',
    appliesTo: NOT_BINARY,
    contexts: CODE,
    patterns: [/(?:>>?|\btee\s{1,3}(?:-a\s{1,3})?|\bsed\s{1,3}-i\S{0,10}\s[^\n]{0,100}?)\s{0,3}["']?(?:~|\$HOME|\$\{HOME\})\/\.(?:bashrc|bash_profile|bash_login|zshrc|zprofile|zshenv|zlogin|profile|kshrc|config\/fish\/config\.fish)\b|(?:Add-Content|Set-Content|Out-File)\b[^\n]{0,100}\$PROFILE\b|\$PROFILE\b[^\n]{0,20}(?:>>|\|\s{0,3}(?:Add|Set)-Content)/],
  },
  {
    id: 'SS-RA-004',
    category: 'rogue-agent',
    severity: 'high',
    title: 'Git hook or authorized_keys installation',
    description: 'Writes git hooks (code that runs on every commit/checkout) or adds SSH authorized_keys (persistent remote access).',
    remediation: 'Remove it, or let the user install hooks via a reviewed tool (pre-commit, husky) explicitly.',
    appliesTo: NOT_BINARY,
    contexts: CODE,
    patterns: [/(?:>>?|\btee\b|\bcp\b|\bmv\b|\bln\s{1,3}-s|\bwrite\w{0,10}\s{0,3}\(|\bcopy\w{0,10}\s{0,3}\()[^\n]{0,150}?\.git[/\\]hooks[/\\]|\bgit\s{1,3}config\b[^\n]{0,50}core\.hooksPath\b|(?:>>|\btee\s{1,3}-a)[^\n]{0,100}?\bauthorized_keys\b/],
  },
  {
    id: 'SS-RA-005',
    category: 'rogue-agent',
    severity: 'medium',
    title: 'Detached / hidden background process',
    description: 'Launches a process that survives the session or hides its window (nohup … &, disown, setsid, -WindowStyle Hidden, pythonw).',
    remediation: 'Run commands in the foreground so the user and agent can see and stop them.',
    appliesTo: NOT_BINARY,
    contexts: CODE,
    patterns: [/\bnohup\b[^\n]{0,200}&\s{0,3}(?:$|;|disown)|\bdisown\b|\bsetsid\s{1,3}\S|-WindowStyle\s{1,3}Hidden\b|\bpythonw(?:\.exe)?\s|\bstart\s{1,3}\/b\s|\bCreateNoWindow\s{0,3}=\s{0,3}true\b/i],
  },
  {
    id: 'SS-RA-006',
    category: 'rogue-agent',
    severity: 'high',
    title: 'Anti-forensics (history / log wiping)',
    description: 'Clears shell history or system logs to hide activity.',
    remediation: 'Remove it.',
    appliesTo: NOT_BINARY,
    contexts: CODE,
    patterns: [/\bhistory\s{1,3}-c\b|\bunset\s{1,3}HISTFILE\b|HISTFILE=\/dev\/null|\bexport\s{1,3}HISTSIZE=0\b|(?:rm|shred|truncate)\b[^\n]{0,50}(?:\.bash_history|\.zsh_history|\/var\/log\/)|\bClear-History\b|\bwevtutil(?:\.exe)?\s{1,3}cl\b|\bClear-EventLog\b|\bjournalctl\s{1,3}--vacuum/i],
  },

  /* ===== Lifecycle hooks ===== */
  {
    id: 'SS-LH-001',
    category: 'lifecycle-hooks',
    severity: 'medium',
    title: 'npm install-time script',
    description: 'package.json declares preinstall/install/postinstall/prepare scripts, which run automatically on npm install.',
    remediation: 'Avoid install scripts; if required, keep them minimal and review what they execute (users can install with --ignore-scripts).',
    appliesTo: ['json-config'],
    fileName: /^package\.json$/i,
    patterns: [/"(?:preinstall|install|postinstall|prepare|prepublish)"\s{0,3}:\s{0,3}"([^"\n]{0,500})"/],
    accept: (m) => !/^(?:husky(?:\s{1,3}install)?|tsc|npm\s{1,3}run\s{1,3}build|node-gyp\s{1,3}rebuild)$/.test((m[1] ?? '').trim()),
    message: (m) => `Runs automatically on install: ${(m[1] ?? '').slice(0, 120)}`,
  },
  {
    id: 'SS-LH-002',
    category: 'lifecycle-hooks',
    severity: 'medium',
    title: 'Custom Python install command (setup.py cmdclass)',
    description: 'setup.py overrides install/develop/egg_info commands — arbitrary code runs at pip install time.',
    remediation: 'Use a declarative pyproject.toml build without custom install hooks.',
    appliesTo: ['script'],
    fileName: /^setup\.py$/i,
    patterns: [/\bcmdclass\s{0,3}=|\bclass\s{1,5}\w{1,60}\s{0,3}\(\s{0,3}(?:install|develop|egg_info|build_py|sdist)\s{0,3}\)/],
  },
  {
    id: 'SS-LH-003',
    category: 'lifecycle-hooks',
    severity: 'high',
    title: 'Executable .pth file',
    description: 'A .pth file line starting with "import" is executed by every Python interpreter start-up — a stealthy persistence trick.',
    remediation: 'Remove executable lines from .pth files.',
    appliesTo: 'any',
    fileName: /\.pth$/i,
    patterns: [/^\s{0,3}import\s/],
  },

  /* ===== Hidden content (lexical part) ===== */
  {
    id: 'SS-HC-001',
    category: 'hidden-content',
    severity: 'medium',
    title: 'CSS-hidden HTML content',
    description: 'HTML with display:none, visibility:hidden, zero font-size/opacity or white/transparent text — invisible when rendered but read by the model.',
    remediation: 'Remove hidden markup; everything the model reads should be visible to reviewers.',
    appliesTo: MD,
    patterns: [
      /<[a-z][a-z0-9]{0,9}\b[^<>\n]{0,300}\bstyle\s{0,3}=\s{0,3}["'][^"'\n]{0,200}(?:display\s{0,3}:\s{0,3}none|visibility\s{0,3}:\s{0,3}hidden|font-size\s{0,3}:\s{0,3}0(?![.\d])|opacity\s{0,3}:\s{0,3}0(?![.\d])|color\s{0,3}:\s{0,3}(?:white|#fff(?:fff)?|transparent)\b)/i,
      /<[a-z][a-z0-9]{0,9}\s[^>\n]{0,200}\bhidden(?:\s{0,3}=\s{0,3}["']?(?:hidden|true)?["']?)?\s{0,3}\/?>/i,
    ],
  },
]

/* ------------------------------------------------------------------ */
/* Structured (non-regex) checks — metadata only; logic in checks.ts   */
/* ------------------------------------------------------------------ */

export const STRUCTURED_RULES: readonly RuleMeta[] = [
  // Hidden content / Unicode
  { id: 'SS-UC-001', category: 'hidden-content', severity: 'critical', title: 'Unicode TAG characters (ASCII smuggling)', description: 'Invisible Unicode TAG characters (U+E0000–U+E007F) encode ASCII text that humans cannot see but models read. The hidden text is decoded in the finding.', remediation: 'Remove all TAG characters. There is no legitimate use in skill content.' },
  { id: 'SS-UC-002', category: 'hidden-content', severity: 'high', title: 'Bidirectional control characters (Trojan Source)', description: 'Bidi overrides/isolates (U+202A–U+202E, U+2066–U+2069) reorder how text is displayed so reviewers see something different from what is executed or read (CVE-2021-42574).', remediation: 'Remove bidi control characters from code and instructions.' },
  { id: 'SS-UC-003', category: 'hidden-content', severity: 'medium', title: 'Zero-width / invisible characters', description: 'Zero-width spaces/joiners, word joiners, soft hyphens, Hangul fillers or similar invisible characters inside text — used to hide or split keywords and evade review.', remediation: 'Remove invisible characters (the file viewer shows them as ⟦U+…⟧).' },
  { id: 'SS-UC-004', category: 'hidden-content', severity: 'high', title: 'Variation-selector smuggling', description: 'Runs of Unicode variation selectors (U+FE00–FE0F, U+E0100–E01EF) can encode arbitrary bytes invisibly after a visible character. The decoded bytes are shown.', remediation: 'Remove the variation-selector run.' },
  { id: 'SS-UC-005', category: 'hidden-content', severity: 'medium', title: 'Mixed-script word (homoglyph)', description: 'A word mixes Latin letters with look-alike Cyrillic/Greek letters (e.g. “pаypal” with a Cyrillic а). Used to spoof names, commands and domains or to evade keyword filters.', remediation: 'Replace look-alike letters with their ASCII equivalents.' },
  { id: 'SS-HC-002', category: 'hidden-content', severity: 'medium', title: 'Whitespace padding hides content', description: 'A long run of spaces/tabs pushes the rest of the line off-screen in editors and diffs.', remediation: 'Remove the padding and review the hidden text.' },
  { id: 'SS-HC-003', category: 'hidden-content', severity: 'low', title: 'Extremely long line', description: 'A very long line in Markdown hides content from reviewers who do not scroll horizontally.', remediation: 'Wrap long lines so reviewers can read everything.' },
  { id: 'SS-HC-004', category: 'hidden-content', severity: 'medium', title: 'Hidden comment with instructions', description: 'An HTML comment or Markdown link-reference comment contains instruction-like text. Comments are invisible in rendered Markdown but fully visible to the model.', remediation: 'Move legitimate notes into visible text, or delete the comment.' },
  { id: 'SS-HC-005', category: 'hidden-content', severity: 'low', title: 'Encoded blob in documentation', description: 'A long base64 blob in Markdown/text. Encoded payloads hide instructions or code from reviewers; the decoded preview is shown.', remediation: 'Replace encoded blobs with readable content or a reference to a reviewed file.' },
  // Secrets
  { id: 'SS-SE-001', category: 'secrets', severity: 'high', title: 'Hard-coded secret', description: 'A credential (API key, token, private key, password) appears in the file. Detected with the Dev Toolbox secrets ruleset; values are redacted.', remediation: 'Remove the secret, rotate it, and load it from the environment or a secret manager.' },
  // Skill metadata / trigger abuse
  { id: 'SS-SK-001', category: 'metadata', severity: 'medium', title: 'SKILL.md without frontmatter', description: 'A SKILL.md must start with YAML frontmatter (--- … ---) containing at least name and description.', remediation: 'Add frontmatter with name and description.' },
  { id: 'SS-SK-002', category: 'metadata', severity: 'low', title: 'Missing or invalid skill name', description: 'The Agent Skills spec requires name: 1–64 chars, lowercase letters, digits and single hyphens, not starting/ending with a hyphen.', remediation: 'Set a valid kebab-case name matching the skill folder.' },
  { id: 'SS-SK-003', category: 'metadata', severity: 'medium', title: 'Missing or invalid skill description', description: 'The description decides when the skill is loaded. The Agent Skills spec requires 1–1024 characters.', remediation: 'Write a specific description: what the skill does and when to use it.' },
  { id: 'SS-SK-004', category: 'metadata', severity: 'medium', title: 'Impersonating / reserved skill name', description: 'Name mimics a vendor or a built-in (anthropic, claude, openai, system, official…). Claude Code reserves the anthropic-skills namespace.', remediation: 'Use a name that describes the skill without implying it is official.' },
  { id: 'SS-SK-005', category: 'prompt-injection', severity: 'medium', title: 'Markup in skill description', description: 'XML/HTML tags in the description are inserted into the system prompt’s skill list and can break out of it.', remediation: 'Use plain text in the description.' },
  { id: 'SS-TR-001', category: 'trigger-abuse', severity: 'high', title: 'Trigger hijacking description', description: 'The description tries to make the skill load for every request, take precedence over other skills/tools, or run regardless of the task.', remediation: 'Describe the specific task and trigger conditions only.' },
  { id: 'SS-TR-002', category: 'trigger-abuse', severity: 'low', title: 'Vague skill description', description: 'A very short or generic description causes the skill to be selected unpredictably.', remediation: 'Explain what the skill does and when it should be used (≥ 40 characters, specific keywords).' },
  { id: 'SS-PM-001', category: 'permissions', severity: 'high', title: 'Unrestricted tool pre-approval', description: 'allowed-tools / permissions.allow grants unrestricted Bash or all tools (Bash, Bash(*), *). Any command the model decides to run executes without a prompt.', remediation: 'List specific commands: Bash(git status *), Bash(npm test *).' },
  { id: 'SS-PM-002', category: 'permissions', severity: 'medium', title: 'Broad interpreter / network tool pre-approval', description: 'Pre-approves an interpreter or network tool by prefix (Bash(curl *), Bash(python *), Bash(sh *), Bash(rm *)…), which is effectively arbitrary code execution or exfiltration.', remediation: 'Pre-approve concrete scripts/commands instead of whole interpreters.' },
  // Claude settings
  { id: 'SS-CS-001', category: 'permissions', severity: 'critical', title: 'Permission prompts bypassed (defaultMode)', description: 'permissions.defaultMode is bypassPermissions (every tool call runs without approval). Since Claude Code v2.1.257 this only takes effect from user/managed settings, but older versions honour it from project files.', remediation: 'Use "default" or "plan"; reserve bypass mode for isolated sandboxes.' },
  { id: 'SS-CS-002', category: 'mcp', severity: 'medium', title: 'All project MCP servers auto-enabled', description: 'enableAllProjectMcpServers: true starts every server in the repository’s .mcp.json without individual approval — a cloned repo can launch arbitrary programs.', remediation: 'Remove it; approve project MCP servers individually (enabledMcpjsonServers).' },
  { id: 'SS-CS-003', category: 'lifecycle-hooks', severity: 'low', title: 'Agent hook runs a shell command', description: 'A Claude Code hook executes a shell command automatically on an agent event. Hooks run with the user’s full privileges, without a permission prompt.', remediation: 'Review every hook command; keep hooks in the repository minimal and auditable.' },
  { id: 'SS-CS-004', category: 'lifecycle-hooks', severity: 'high', title: 'Agent hook makes network calls / runs remote code', description: 'A hook command contacts the network (curl, wget, nc, Invoke-WebRequest…). Hooks see tool inputs/outputs (via stdin) and can exfiltrate them on every event.', remediation: 'Hooks should not reach the network. If they must, pin the endpoint and document what is sent.' },
  { id: 'SS-CS-005', category: 'permissions', severity: 'medium', title: 'Over-broad additional directories', description: 'permissions.additionalDirectories grants access to the home directory or filesystem root.', remediation: 'Add only the specific directories the project needs.' },
  { id: 'SS-CS-006', category: 'permissions', severity: 'low', title: 'apiKeyHelper script', description: 'apiKeyHelper runs a script to produce API credentials. In a shared project file, it lets the repository decide what executes to obtain your key.', remediation: 'Keep apiKeyHelper in user settings only, pointing to a script you control.' },
  // MCP
  { id: 'SS-MC-001', category: 'mcp', severity: 'medium', title: 'MCP server package not pinned', description: 'The server is launched with npx/uvx/pipx/bunx/dlx without an exact version, so every start downloads whatever the latest release is.', remediation: 'Pin the version (pkg@1.2.3 / pkg==1.2.3) and review updates.' },
  { id: 'SS-MC-002', category: 'mcp', severity: 'medium', title: 'MCP Docker image not pinned by digest', description: 'docker run uses a tag (or no tag) instead of an immutable @sha256 digest.', remediation: 'Reference the image by digest: image@sha256:…' },
  { id: 'SS-MC-003', category: 'mcp', severity: 'high', title: 'MCP server launched through a shell', description: 'The server command is a shell (sh -c, bash -c, cmd /c, powershell -Command) — arbitrary command lines, often curl | sh.', remediation: 'Launch the server binary directly with an argument list.' },
  { id: 'SS-MC-004', category: 'secrets', severity: 'high', title: 'Secret inline in MCP config', description: 'An API key/token is written literally in the server env, args or headers. MCP configs are often committed or shared.', remediation: 'Reference environment variables or input prompts (${env:VAR}, ${input:…}) instead of literal secrets.' },
  { id: 'SS-MC-005', category: 'mcp', severity: 'high', title: 'Remote MCP server over plain HTTP', description: 'A remote server URL uses http:// or ws:// — tokens and tool traffic travel unencrypted.', remediation: 'Use https:// (localhost is fine for local development).' },
  { id: 'SS-MC-006', category: 'mcp', severity: 'high', title: 'MCP description with injection phrasing (tool poisoning)', description: 'A server/tool description or instructions field contains prompt-injection phrasing. Descriptions are fed to the model verbatim.', remediation: 'Descriptions must only describe functionality.' },
  { id: 'SS-MC-007', category: 'metadata', severity: 'info', title: 'Config could not be parsed', description: 'The JSON configuration could not be parsed, so structured checks were skipped (regex rules still ran).', remediation: 'Fix the JSON syntax.' },
  // Binaries & archives
  { id: 'SS-BN-001', category: 'binary', severity: 'high', title: 'Shipped executable / bytecode', description: 'The skill ships compiled code (executables, native libraries, .pyc bytecode, .jar, .wasm). It cannot be reviewed as source and may differ from any source shown.', remediation: 'Ship source and build from it; remove binaries and bytecode.' },
  { id: 'SS-BN-002', category: 'binary', severity: 'high', title: 'Archive entry with path traversal', description: 'A ZIP entry name is absolute or contains ../ — extracting it would write outside the target folder (Zip Slip).', remediation: 'Rebuild the archive with relative paths only.' },
  { id: 'SS-BN-003', category: 'binary', severity: 'high', title: 'Symbolic link in archive', description: 'A ZIP entry is a symlink; on extraction it can point at ~/.ssh or other sensitive paths that the skill then reads or overwrites.', remediation: 'Remove symlinks from the archive.' },
  { id: 'SS-BN-004', category: 'binary', severity: 'medium', title: 'Archive limits exceeded / unreadable entries', description: 'Some entries were skipped (encrypted, unsupported compression, over the size/ratio limits — possible zip bomb).', remediation: 'Inspect the skipped entries manually.' },
]

export const ALL_RULES: readonly RuleMeta[] = [...REGEX_RULES, ...STRUCTURED_RULES]

export const RULES_BY_ID: ReadonlyMap<string, RuleMeta> = new Map(ALL_RULES.map((r) => [r.id, r]))
