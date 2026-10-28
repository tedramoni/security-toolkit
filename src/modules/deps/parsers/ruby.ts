import type { Dependency, ParseResult, SkippedEntry } from '../types.ts'

/**
 * Parse Gemfile.lock. Only gems from "GEM" sections (rubygems.org or another gem server) are
 * checked; "GIT" and "PATH" sections are reported as skipped. Spec lines are indented exactly
 * 4 spaces ("    rails (7.1.3)"); their own dependencies are indented 6 and ignored.
 */
export function parseGemfileLock(text: string): ParseResult {
  const deps: Dependency[] = []
  const skipped: SkippedEntry[] = []
  let section = ''
  let inSpecs = false
  let sawSection = false

  for (const raw of text.split(/\r?\n/)) {
    if (raw.trim() === '') {
      inSpecs = false
      continue
    }
    if (!raw.startsWith(' ')) {
      section = raw.trim()
      sawSection = true
      inSpecs = false
      continue
    }
    if (raw.trim() === 'specs:') {
      inSpecs = true
      continue
    }
    if (!inSpecs) continue
    const m = /^ {4}(\S+) \(([^)]+)\)$/.exec(raw)
    if (!m) continue
    const name = m[1]
    // platform-specific gems: "nokogiri (1.16.2-x86_64-linux)" — the version is before the first "-"
    const version = m[2].split('-')[0]
    if (section === 'GEM') deps.push({ name, version, ecosystem: 'RubyGems' })
    else skipped.push({ entry: `${name} (${m[2]})`, reason: `from a ${section} source, not a gem server` })
  }
  if (!sawSection) throw new Error('No GEM section found — is this a Gemfile.lock?')
  return { deps, skipped }
}
