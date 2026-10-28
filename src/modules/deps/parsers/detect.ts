import type { LockfileFormat, ParseResult } from '../types.ts'
import { parseGoMod, parseGoSum } from './go.ts'
import { parsePom } from './maven.ts'
import { parsePackageLock } from './npm.ts'
import { parseCargoLock, parseComposerLock, parsePoetryLock } from './other.ts'
import { parsePipfileLock, parseRequirements } from './pypi.ts'
import { parseGemfileLock } from './ruby.ts'
import { parseYarnLock } from './yarn.ts'

export const FORMAT_LABELS: Record<LockfileFormat, string> = {
  'package-lock': 'package-lock.json (npm)',
  'yarn-lock': 'yarn.lock (npm)',
  requirements: 'requirements.txt (PyPI)',
  'pipfile-lock': 'Pipfile.lock (PyPI)',
  'poetry-lock': 'poetry.lock (PyPI)',
  pom: 'pom.xml (Maven)',
  'go-mod': 'go.mod (Go)',
  'go-sum': 'go.sum (Go)',
  'gemfile-lock': 'Gemfile.lock (RubyGems)',
  'composer-lock': 'composer.lock (Packagist)',
  'cargo-lock': 'Cargo.lock (crates.io)',
}

const PARSERS: Record<LockfileFormat, (text: string) => ParseResult> = {
  'package-lock': parsePackageLock,
  'yarn-lock': parseYarnLock,
  requirements: parseRequirements,
  'pipfile-lock': parsePipfileLock,
  'poetry-lock': parsePoetryLock,
  pom: parsePom,
  'go-mod': parseGoMod,
  'go-sum': parseGoSum,
  'gemfile-lock': parseGemfileLock,
  'composer-lock': parseComposerLock,
  'cargo-lock': parseCargoLock,
}

/** Detect by file name (basename, case-insensitive). */
export function detectByFilename(filename: string): LockfileFormat | null {
  const base = filename.split(/[\\/]/).pop()?.toLowerCase() ?? ''
  if (base === 'package-lock.json' || base === 'npm-shrinkwrap.json') return 'package-lock'
  if (base === 'yarn.lock') return 'yarn-lock'
  if (base === 'pipfile.lock') return 'pipfile-lock'
  if (base === 'poetry.lock') return 'poetry-lock'
  if (base === 'pom.xml' || base.endsWith('.pom')) return 'pom'
  if (base === 'go.mod') return 'go-mod'
  if (base === 'go.sum') return 'go-sum'
  if (base === 'gemfile.lock' || base === 'gems.locked') return 'gemfile-lock'
  if (base === 'composer.lock') return 'composer-lock'
  if (base === 'cargo.lock') return 'cargo-lock'
  if (/requirements.*\.txt$/.test(base) || /^constraints.*\.txt$/.test(base)) return 'requirements'
  return null
}

/** Detect by content when there is no (useful) file name, e.g. pasted text. */
export function detectByContent(text: string): LockfileFormat | null {
  const t = text.trimStart()
  if (t.startsWith('{')) {
    if (/"lockfileVersion"\s*:/.test(t)) return 'package-lock'
    if (/"content-hash"\s*:/.test(t) && /"packages"\s*:/.test(t)) return 'composer-lock'
    if (/"_meta"\s*:/.test(t) && /"default"\s*:/.test(t)) return 'pipfile-lock'
    return null
  }
  if (t.startsWith('<') && /<project[\s>]/.test(t)) return 'pom'
  if (/^# yarn lockfile v1/m.test(t) || /^__metadata:/m.test(t)) return 'yarn-lock'
  if (/^GEM\s*$/m.test(t) && /^ {2}specs:/m.test(t)) return 'gemfile-lock'
  if (/^\[\[package\]\]/m.test(t)) {
    if (/^source = "(registry|git)\+/m.test(t) || /^checksum = "/m.test(t) || /^version = \d+\s*$/m.test(t)) return 'cargo-lock'
    return 'poetry-lock'
  }
  if (/^module\s+\S+/m.test(t) || /^require\s*\(/m.test(t)) return 'go-mod'
  if (/^\S+\s+v\S+\s+h1:\S+=\s*$/m.test(t)) return 'go-sum'
  if (/^[A-Za-z0-9][A-Za-z0-9._-]*\s*(\[[^\]]*\])?\s*(==|>=|<=|~=|!=|>|<|===)/m.test(t)) return 'requirements'
  return null
}

export function detectFormat(filename: string | undefined, text: string): LockfileFormat | null {
  return (filename ? detectByFilename(filename) : null) ?? detectByContent(text)
}

export function parseLockfile(format: LockfileFormat, text: string): ParseResult {
  return PARSERS[format](text)
}
