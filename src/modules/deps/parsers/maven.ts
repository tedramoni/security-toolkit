import type { Dependency, ParseResult, SkippedEntry } from '../types.ts'

function childrenByName(el: Element, name: string): Element[] {
  return Array.from(el.children).filter((c) => c.localName === name)
}

function childText(el: Element, name: string): string | undefined {
  const c = childrenByName(el, name)[0]
  const t = c?.textContent?.trim()
  return t ? t : undefined
}

const PROP = /\$\{([^}]+)\}/g

/** Resolve ${prop} references (recursively, with a depth limit). Returns undefined if anything stays unresolved. */
export function resolveProps(value: string, props: Map<string, string>, depth = 0): string | undefined {
  if (!value.includes('${')) return value
  if (depth > 10) return undefined
  let unresolved = false
  const out = value.replace(PROP, (_m, key: string) => {
    const v = props.get(key)
    if (v === undefined) {
      unresolved = true
      return ''
    }
    return v
  })
  if (unresolved) return undefined
  return resolveProps(out, props, depth + 1)
}

/**
 * Parse a Maven pom.xml. Only dependencies with an explicit (or property-resolved) version are
 * checked: versions inherited from a parent POM or BOM cannot be resolved without Maven itself.
 */
export function parsePom(text: string): ParseResult {
  const doc = new DOMParser().parseFromString(text, 'application/xml')
  if (doc.getElementsByTagName('parsererror').length > 0) throw new Error('pom.xml is not well-formed XML')
  const project = doc.documentElement
  if (!project || project.localName !== 'project') throw new Error('Root element is not <project> — is this a pom.xml?')

  const props = new Map<string, string>()
  const parent = childrenByName(project, 'parent')[0]
  const projectVersion = childText(project, 'version') ?? (parent && childText(parent, 'version'))
  const projectGroup = childText(project, 'groupId') ?? (parent && childText(parent, 'groupId'))
  if (projectVersion) {
    props.set('project.version', projectVersion)
    props.set('pom.version', projectVersion)
    props.set('version', projectVersion)
  }
  if (projectGroup) {
    props.set('project.groupId', projectGroup)
    props.set('pom.groupId', projectGroup)
  }
  if (parent) {
    const pv = childText(parent, 'version')
    if (pv) props.set('project.parent.version', pv)
  }
  for (const propsEl of childrenByName(project, 'properties')) {
    for (const p of Array.from(propsEl.children)) {
      const v = p.textContent?.trim()
      if (v) props.set(p.localName, v)
    }
  }

  const deps: Dependency[] = []
  const skipped: SkippedEntry[] = []
  const all = Array.from(doc.getElementsByTagNameNS('*', 'dependency')).filter(
    // only <dependencies><dependency>, and skip build plugin dependencies (not shipped)
    (dep) => dep.parentElement?.localName === 'dependencies' && dep.parentElement.parentElement?.localName !== 'plugin',
  )
  const isManaged = (dep: Element) => dep.parentElement?.parentElement?.localName === 'dependencyManagement'

  // Versions declared in this POM's own <dependencyManagement> apply to version-less dependencies.
  const managed = new Map<string, string>()
  for (const dep of all) {
    if (!isManaged(dep)) continue
    const g = childText(dep, 'groupId')
    const a = childText(dep, 'artifactId')
    const v = childText(dep, 'version')
    if (g && a && v) managed.set(`${g}:${a}`, v)
  }

  for (const dep of all) {
    const rawGroup = childText(dep, 'groupId')
    const rawArtifact = childText(dep, 'artifactId')
    const scope = childText(dep, 'scope')
    const label = `${rawGroup ?? '?'}:${rawArtifact ?? '?'}`
    if (!rawGroup || !rawArtifact) {
      skipped.push({ entry: label, reason: 'missing groupId or artifactId' })
      continue
    }
    if (scope === 'import') {
      // a BOM: its own coordinates are not a library that ships with the application
      skipped.push({ entry: label, reason: 'imported BOM (scope import) — the versions it manages cannot be resolved here' })
      continue
    }
    const rawVersion = childText(dep, 'version') ?? (isManaged(dep) ? undefined : managed.get(label))
    if (!rawVersion) {
      skipped.push({ entry: label, reason: 'version managed by a parent POM or BOM — not resolvable here' })
      continue
    }
    const groupId = resolveProps(rawGroup, props)
    const artifactId = resolveProps(rawArtifact, props)
    const version = resolveProps(rawVersion, props)
    if (!groupId || !artifactId || !version) {
      skipped.push({ entry: `${label}:${rawVersion}`, reason: 'unresolvable ${property} (defined in a parent POM?)' })
      continue
    }
    if (/^[[(]/.test(version) || version.includes(',')) {
      skipped.push({ entry: `${groupId}:${artifactId}:${version}`, reason: 'version range, not a pinned version' })
      continue
    }
    deps.push({ name: `${groupId}:${artifactId}`, version, ecosystem: 'Maven', dev: scope === 'test' })
  }
  return { deps, skipped }
}
