import { executableMagic, extension, isBinaryPath, isExecutablePath, looksBinary } from './classify'
import type { ArchiveIssue } from './engine'
import type { ScanFile } from './types'
import { DEFAULT_ZIP_LIMITS, readZip } from './zip'

export const UPLOAD_LIMITS = {
  maxFiles: 2000,
  maxTotalBytes: 60 * 1024 * 1024,
  maxTextBytes: 2 * 1024 * 1024,
  /** Uncompressed bytes extracted from ALL archives together (each archive is also capped by DEFAULT_ZIP_LIMITS). */
  maxExtractedBytes: 100 * 1024 * 1024,
}

export interface IngestResult {
  files: ScanFile[]
  issues: ArchiveIssue[]
  warnings: string[]
}

/** Turn raw bytes into a ScanFile (text, flagged executable) or undefined for other binaries. */
export function bytesToScanFile(path: string, bytes: Uint8Array): ScanFile | undefined {
  const magic = executableMagic(bytes)
  if (magic || isExecutablePath(path)) return { path, size: bytes.length, executable: magic }
  if (isBinaryPath(path) || looksBinary(bytes)) return undefined
  const truncated = bytes.length > UPLOAD_LIMITS.maxTextBytes
  const content = new TextDecoder('utf-8', { fatal: false }).decode(truncated ? bytes.subarray(0, UPLOAD_LIMITS.maxTextBytes) : bytes)
  return { path, size: bytes.length, content, truncated }
}

export interface InputFile {
  path: string
  size: number
  bytes: () => Promise<Uint8Array>
}

export function fromBrowserFiles(list: Iterable<File>): InputFile[] {
  return [...list].map((f) => ({
    path: (f as File & { webkitRelativePath?: string }).webkitRelativePath || f.name,
    size: f.size,
    bytes: async () => new Uint8Array(await f.arrayBuffer()),
  }))
}

// dist/ and build/ are deliberately NOT ignored: MCP servers ship dist/index.js and a payload could hide there.
const IGNORED_DIR_RE = /(?:^|\/)(?:node_modules|\.git|__pycache__|\.venv|venv)\//

/** Read uploaded files and ZIP archives into scan inputs, with limits. */
export async function ingest(inputs: readonly InputFile[]): Promise<IngestResult> {
  const files: ScanFile[] = []
  const issues: ArchiveIssue[] = []
  const warnings: string[] = []
  let total = 0
  let ignored = 0
  let skippedBinary = 0
  let extracted = 0
  let fileCapHit = false
  const multiple = inputs.length > 1
  for (const input of inputs) {
    if (files.length >= UPLOAD_LIMITS.maxFiles) {
      warnings.push(`Stopped at ${UPLOAD_LIMITS.maxFiles} files.`)
      break
    }
    const path = input.path.replace(/\\/g, '/')
    if (IGNORED_DIR_RE.test(path) && !/__pycache__\/[^/]{1,200}\.pyc$/.test(path)) {
      ignored++
      continue
    }
    if (total + input.size > UPLOAD_LIMITS.maxTotalBytes) {
      warnings.push(`Total upload limit (${UPLOAD_LIMITS.maxTotalBytes / 1024 / 1024} MB) reached; remaining files skipped.`)
      break
    }
    total += input.size
    const bytes = await input.bytes()
    if (extension(path) === 'zip' || (bytes[0] === 0x50 && bytes[1] === 0x4b && bytes[2] === 0x03 && bytes[3] === 0x04 && /\.(?:zip|skill)$/i.test(path))) {
      try {
        const remaining = UPLOAD_LIMITS.maxExtractedBytes - extracted
        if (remaining <= 0) {
          warnings.push(`${path}: not extracted — the ${UPLOAD_LIMITS.maxExtractedBytes / 1024 / 1024} MB limit for all archives together was reached.`)
          continue
        }
        const z = await readZip(bytes, { ...DEFAULT_ZIP_LIMITS, maxTotalBytes: Math.min(DEFAULT_ZIP_LIMITS.maxTotalBytes, remaining) })
        const prefix = multiple ? `${path}/` : ''
        for (const i of z.issues) issues.push({ archive: path, entry: i.entry, kind: i.kind, detail: i.detail })
        for (const e of z.entries) {
          if (e.data) extracted += e.data.length
          if (files.length >= UPLOAD_LIMITS.maxFiles) {
            fileCapHit = true
            continue
          }
          if (IGNORED_DIR_RE.test(e.name) && !/\.pyc$/.test(e.name)) {
            ignored++
            continue
          }
          if (!e.data) {
            if (isExecutablePath(e.name)) files.push({ path: prefix + e.name, size: e.size })
            continue
          }
          const f = bytesToScanFile(prefix + e.name, e.data)
          if (f) files.push(f)
          else skippedBinary++
        }
      } catch (err) {
        warnings.push(`${path}: ${(err as Error).message}`)
      }
      continue
    }
    const f = bytesToScanFile(path, bytes)
    if (f) files.push(f)
    else skippedBinary++
  }
  if (fileCapHit) warnings.push(`Stopped at ${UPLOAD_LIMITS.maxFiles} files; remaining archive entries were not scanned.`)
  if (ignored) warnings.push(`${ignored} file(s) in node_modules, .git, __pycache__ or virtualenv folders ignored.`)
  if (skippedBinary) warnings.push(`${skippedBinary} non-text file(s) skipped (images, fonts, archives…).`)
  return { files, issues, warnings }
}
