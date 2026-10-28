/**
 * Threat model data types, factories, import validation and cascade helpers.
 * Everything here is pure (no React, no storage) so it can be unit-tested.
 */

export const SCHEMA_VERSION = 1

export const ELEMENT_TYPES = ['process', 'datastore', 'external', 'dataflow'] as const
export type ElementType = (typeof ELEMENT_TYPES)[number]

export const NODE_TYPES = ['process', 'datastore', 'external'] as const
export type NodeType = (typeof NODE_TYPES)[number]

export const DATA_CLASSIFICATIONS = ['public', 'internal', 'confidential', 'secret'] as const
export type DataClassification = (typeof DATA_CLASSIFICATIONS)[number]

export const STRIDE = ['S', 'T', 'R', 'I', 'D', 'E'] as const
export type StrideCategory = (typeof STRIDE)[number]

export const STRIDE_NAMES: Record<StrideCategory, string> = {
  S: 'Spoofing',
  T: 'Tampering',
  R: 'Repudiation',
  I: 'Information disclosure',
  D: 'Denial of service',
  E: 'Elevation of privilege',
}

/** Security property violated by each STRIDE category. */
export const STRIDE_PROPERTY: Record<StrideCategory, string> = {
  S: 'Authentication',
  T: 'Integrity',
  R: 'Non-repudiation',
  I: 'Confidentiality',
  D: 'Availability',
  E: 'Authorization',
}

export const THREAT_STATUSES = ['open', 'mitigated', 'accepted', 'transferred', 'not-applicable'] as const
export type ThreatStatus = (typeof THREAT_STATUSES)[number]

export const STATUS_LABELS: Record<ThreatStatus, string> = {
  open: 'Open',
  mitigated: 'Mitigated',
  accepted: 'Risk accepted',
  transferred: 'Transferred',
  'not-applicable': 'Not applicable',
}

export const ELEMENT_TYPE_LABELS: Record<ElementType, string> = {
  process: 'Process',
  datastore: 'Data store',
  external: 'External entity',
  dataflow: 'Data flow',
}

export interface TagDef {
  id: string
  label: string
  hint: string
  types: NodeType[]
}

/** Tags drive the rule engine. Keep ids stable: they are persisted. */
export const TAGS: TagDef[] = [
  { id: 'internet-facing', label: 'Internet-facing', hint: 'Reachable from the public internet', types: ['process'] },
  { id: 'handles-auth', label: 'Handles authentication', hint: 'Logs users in, issues or validates sessions/tokens', types: ['process'] },
  { id: 'admin', label: 'Admin functions', hint: 'Exposes administrative or back-office operations', types: ['process', 'external'] },
  { id: 'processes-payments', label: 'Processes payments', hint: 'Moves money or handles card data', types: ['process'] },
  { id: 'stores-pii', label: 'Stores personal data', hint: 'Holds personal data (GDPR scope)', types: ['process', 'datastore'] },
  { id: 'stores-credentials', label: 'Stores credentials', hint: 'Passwords, API keys, tokens or private keys', types: ['datastore'] },
  { id: 'logs', label: 'Log / audit store', hint: 'Holds audit or security logs (adds Repudiation)', types: ['datastore'] },
  { id: 'third-party', label: 'Third party', hint: 'Operated by a vendor / outside your control', types: ['process', 'datastore', 'external'] },
  { id: 'human', label: 'Human user', hint: 'A person (browser, mobile app user, operator)', types: ['external'] },
]

export interface ModelElement {
  id: string
  name: string
  type: ElementType
  description: string
  /** Processes, data stores and external entities. Empty for flows. */
  tags: string[]
  // Data-flow only:
  fromId?: string
  toId?: string
  protocol?: string
  crossesTrustBoundary?: boolean
  dataClassification?: DataClassification
}

export interface Threat {
  id: string
  elementId: string
  category: StrideCategory
  title: string
  description: string
  likelihood: number
  impact: number
  status: ThreatStatus
  mitigation: string
  owner?: string
  ticket?: string
  generated: boolean
  ruleId?: string
  /** Generated threat whose rule no longer applies after the last refresh. Kept, never auto-deleted. */
  stale?: boolean
  /** Controls proposed by the rule engine (refreshed on every regeneration). */
  suggestedMitigations?: string[]
  /** Reference URLs backing the rule. */
  references?: string[]
  /**
   * Likelihood / impact the rule produced at the last refresh. When the current score still equals these
   * defaults the user has not overridden it, so a refresh may move it (e.g. after a flow becomes "secret").
   */
  ruleLikelihood?: number
  ruleImpact?: number
}

export interface ThreatModel {
  schemaVersion: 1
  id: string
  name: string
  description: string
  owner: string
  createdAt: string
  updatedAt: string
  assumptions: string[]
  elements: ModelElement[]
  threats: Threat[]
}

// ---------------------------------------------------------------------------
// Factories
// ---------------------------------------------------------------------------

export function createModel(id: string, name: string, now: string = new Date().toISOString()): ThreatModel {
  return {
    schemaVersion: SCHEMA_VERSION,
    id,
    name,
    description: '',
    owner: '',
    createdAt: now,
    updatedAt: now,
    assumptions: [],
    elements: [],
    threats: [],
  }
}

export function createNode(id: string, type: NodeType, name: string, tags: string[] = [], description = ''): ModelElement {
  return { id, name, type, description, tags: [...tags] }
}

export function createFlow(
  id: string,
  fromId: string,
  toId: string,
  opts: Partial<Pick<ModelElement, 'name' | 'description' | 'protocol' | 'crossesTrustBoundary' | 'dataClassification'>> = {},
): ModelElement {
  return {
    id,
    name: opts.name ?? '',
    type: 'dataflow',
    description: opts.description ?? '',
    tags: [],
    fromId,
    toId,
    protocol: opts.protocol ?? '',
    crossesTrustBoundary: opts.crossesTrustBoundary ?? false,
    dataClassification: opts.dataClassification ?? 'internal',
  }
}

/** Tags that make sense for an element type. */
export function tagsForType(type: ElementType): TagDef[] {
  return TAGS.filter((t) => (t.types as string[]).includes(type))
}

export function isFlow(el: ModelElement): boolean {
  return el.type === 'dataflow'
}

export function nodesOf(model: ThreatModel): ModelElement[] {
  return model.elements.filter((e) => e.type !== 'dataflow')
}

export function flowsOf(model: ThreatModel): ModelElement[] {
  return model.elements.filter((e) => e.type === 'dataflow')
}

/** Human-readable name of an element; flows without a name are described by their endpoints. */
export function displayName(model: ThreatModel, el: ModelElement): string {
  if (el.name.trim()) return el.name.trim()
  if (el.type === 'dataflow') {
    const from = model.elements.find((e) => e.id === el.fromId)
    const to = model.elements.find((e) => e.id === el.toId)
    return `${from?.name.trim() || '?'} → ${to?.name.trim() || '?'}`
  }
  return '(unnamed)'
}

/** Return a copy with updatedAt bumped. */
export function touch(model: ThreatModel, now: string = new Date().toISOString()): ThreatModel {
  return { ...model, updatedAt: now }
}

/** Deep copy under a new id. Element and threat ids are model-local and are kept. */
export function duplicateModel(model: ThreatModel, newModelId: string, now: string = new Date().toISOString()): ThreatModel {
  const copy = structuredClone(model)
  return { ...copy, id: newModelId, name: `Copy of ${model.name}`, createdAt: now, updatedAt: now }
}

// ---------------------------------------------------------------------------
// Cascade delete
// ---------------------------------------------------------------------------

export interface RemovalImpact {
  /** The element itself plus every flow attached to it. */
  elementIds: string[]
  flows: ModelElement[]
  threatCount: number
}

export function removalImpact(model: ThreatModel, elementId: string): RemovalImpact {
  const flows =
    model.elements.find((e) => e.id === elementId)?.type === 'dataflow'
      ? []
      : model.elements.filter((e) => e.type === 'dataflow' && (e.fromId === elementId || e.toId === elementId))
  const elementIds = [elementId, ...flows.map((f) => f.id)]
  const threatCount = model.threats.filter((t) => elementIds.includes(t.elementId)).length
  return { elementIds, flows, threatCount }
}

/** Remove an element, every data flow attached to it, and every threat on any of those. */
export function removeElement(model: ThreatModel, elementId: string): ThreatModel {
  const { elementIds } = removalImpact(model, elementId)
  const gone = new Set(elementIds)
  return {
    ...model,
    elements: model.elements.filter((e) => !gone.has(e.id)),
    threats: model.threats.filter((t) => !gone.has(t.elementId)),
  }
}

/** Insert or replace an element by id. */
export function upsertElement(model: ThreatModel, el: ModelElement): ThreatModel {
  const exists = model.elements.some((e) => e.id === el.id)
  return {
    ...model,
    elements: exists ? model.elements.map((e) => (e.id === el.id ? el : e)) : [...model.elements, el],
  }
}

/** Apply a partial update to one threat. */
export function updateThreat(model: ThreatModel, threatId: string, patch: Partial<Threat>): ThreatModel {
  return { ...model, threats: model.threats.map((t) => (t.id === threatId ? { ...t, ...patch, id: t.id } : t)) }
}

// ---------------------------------------------------------------------------
// Validation of untrusted JSON (imports, localStorage)
// ---------------------------------------------------------------------------

export const LIMITS = {
  text: 20_000,
  elements: 2_000,
  threats: 10_000,
  assumptions: 500,
  tags: 50,
  models: 500,
}

export type ValidationResult = { ok: true; model: ThreatModel } | { ok: false; errors: string[] }

const isObj = (v: unknown): v is Record<string, unknown> => typeof v === 'object' && v !== null && !Array.isArray(v)

class Collector {
  errors: string[] = []
  add(path: string, msg: string) {
    if (this.errors.length < 50) this.errors.push(`${path}: ${msg}`)
  }
  str(o: Record<string, unknown>, key: string, path: string, opts: { required?: boolean; nonEmpty?: boolean } = {}): string {
    const v = o[key]
    if (v === undefined || v === null) {
      if (opts.required) this.add(`${path}.${key}`, 'is required')
      return ''
    }
    if (typeof v !== 'string') {
      this.add(`${path}.${key}`, 'must be a string')
      return ''
    }
    if (v.length > LIMITS.text) this.add(`${path}.${key}`, `is longer than ${LIMITS.text} characters`)
    if (opts.nonEmpty && !v.trim()) this.add(`${path}.${key}`, 'must not be empty')
    return v
  }
  optStr(o: Record<string, unknown>, key: string, path: string): string | undefined {
    if (o[key] === undefined || o[key] === null) return undefined
    return this.str(o, key, path)
  }
  strArray(o: Record<string, unknown>, key: string, path: string, max: number): string[] {
    const v = o[key]
    if (v === undefined || v === null) return []
    if (!Array.isArray(v)) {
      this.add(`${path}.${key}`, 'must be an array of strings')
      return []
    }
    if (v.length > max) this.add(`${path}.${key}`, `has more than ${max} entries`)
    const out: string[] = []
    v.forEach((s, i) => {
      if (typeof s !== 'string') this.add(`${path}.${key}[${i}]`, 'must be a string')
      else if (s.length > LIMITS.text) this.add(`${path}.${key}[${i}]`, 'is too long')
      else out.push(s)
    })
    return out
  }
  oneOf<T extends string>(o: Record<string, unknown>, key: string, path: string, allowed: readonly T[]): T {
    const v = o[key]
    if (typeof v !== 'string' || !(allowed as readonly string[]).includes(v)) {
      this.add(`${path}.${key}`, `must be one of ${allowed.join(', ')}`)
      return allowed[0]
    }
    return v as T
  }
  score(o: Record<string, unknown>, key: string, path: string): number {
    const v = o[key]
    if (typeof v !== 'number' || !Number.isInteger(v) || v < 1 || v > 3) {
      this.add(`${path}.${key}`, 'must be an integer from 1 to 3')
      return 1
    }
    return v
  }
  /** Optional ISO-8601 timestamp, normalised with toISOString(); '' when absent. */
  date(o: Record<string, unknown>, key: string, path: string): string {
    const v = this.str(o, key, path)
    if (!v) return ''
    const ms = v.length <= 40 ? Date.parse(v) : NaN
    if (!/^\d{4}-\d{2}-\d{2}/.test(v) || Number.isNaN(ms)) {
      this.add(`${path}.${key}`, 'must be an ISO 8601 date (e.g. 2026-01-31T12:00:00.000Z)')
      return ''
    }
    return new Date(ms).toISOString()
  }
  bool(o: Record<string, unknown>, key: string, path: string, fallback: boolean): boolean {
    const v = o[key]
    if (v === undefined) return fallback
    if (typeof v !== 'boolean') {
      this.add(`${path}.${key}`, 'must be true or false')
      return fallback
    }
    return v
  }
}

/**
 * Validate an untrusted value and return a normalized ThreatModel built from scratch
 * (unknown keys are dropped, so nothing like __proto__ is carried over).
 */
export function validateModel(raw: unknown, path = 'model'): ValidationResult {
  const c = new Collector()
  if (!isObj(raw)) return { ok: false, errors: [`${path}: must be a JSON object`] }
  if (raw.schemaVersion !== SCHEMA_VERSION) {
    const got = (JSON.stringify(raw.schemaVersion) ?? 'nothing').slice(0, 40)
    return { ok: false, errors: [`${path}.schemaVersion: expected ${SCHEMA_VERSION}, got ${got} — is this a threat model export?`] }
  }
  const id = c.str(raw, 'id', path, { required: true, nonEmpty: true })
  const name = c.str(raw, 'name', path, { required: true })
  const description = c.str(raw, 'description', path)
  const owner = c.str(raw, 'owner', path)
  const createdAt = c.date(raw, 'createdAt', path) || new Date(0).toISOString()
  const updatedAt = c.date(raw, 'updatedAt', path) || createdAt
  const assumptions = c.strArray(raw, 'assumptions', path, LIMITS.assumptions)

  const elements: ModelElement[] = []
  if (!Array.isArray(raw.elements)) c.add(`${path}.elements`, 'must be an array')
  else if (raw.elements.length > LIMITS.elements) c.add(`${path}.elements`, `has more than ${LIMITS.elements} entries`)
  else {
    raw.elements.forEach((e, i) => {
      const p = `${path}.elements[${i}]`
      if (!isObj(e)) return c.add(p, 'must be an object')
      const type = c.oneOf(e, 'type', p, ELEMENT_TYPES)
      const el: ModelElement = {
        id: c.str(e, 'id', p, { required: true, nonEmpty: true }),
        name: c.str(e, 'name', p),
        type,
        description: c.str(e, 'description', p),
        tags: type === 'dataflow' ? [] : c.strArray(e, 'tags', p, LIMITS.tags),
      }
      if (type === 'dataflow') {
        el.fromId = c.str(e, 'fromId', p, { required: true, nonEmpty: true })
        el.toId = c.str(e, 'toId', p, { required: true, nonEmpty: true })
        el.protocol = c.str(e, 'protocol', p)
        el.crossesTrustBoundary = c.bool(e, 'crossesTrustBoundary', p, false)
        el.dataClassification =
          e.dataClassification === undefined ? 'internal' : c.oneOf(e, 'dataClassification', p, DATA_CLASSIFICATIONS)
      }
      elements.push(el)
    })
  }

  const byId = new Map<string, ModelElement>()
  elements.forEach((el, i) => {
    if (!el.id) return
    if (byId.has(el.id)) c.add(`${path}.elements[${i}].id`, `duplicate id "${el.id}"`)
    byId.set(el.id, el)
  })
  elements.forEach((el, i) => {
    if (el.type !== 'dataflow') return
    for (const key of ['fromId', 'toId'] as const) {
      const ref = el[key]
      if (!ref) continue
      const target = byId.get(ref)
      if (!target) c.add(`${path}.elements[${i}].${key}`, `references unknown element "${ref}"`)
      else if (target.type === 'dataflow') c.add(`${path}.elements[${i}].${key}`, 'must reference a process, data store or external entity, not a data flow')
    }
  })

  const threats: Threat[] = []
  if (raw.threats !== undefined && !Array.isArray(raw.threats)) c.add(`${path}.threats`, 'must be an array')
  else if (Array.isArray(raw.threats)) {
    if (raw.threats.length > LIMITS.threats) c.add(`${path}.threats`, `has more than ${LIMITS.threats} entries`)
    else {
      const seen = new Set<string>()
      raw.threats.forEach((t, i) => {
        const p = `${path}.threats[${i}]`
        if (!isObj(t)) return c.add(p, 'must be an object')
        const th: Threat = {
          id: c.str(t, 'id', p, { required: true, nonEmpty: true }),
          elementId: c.str(t, 'elementId', p, { required: true, nonEmpty: true }),
          category: c.oneOf(t, 'category', p, STRIDE),
          title: c.str(t, 'title', p, { required: true }),
          description: c.str(t, 'description', p),
          likelihood: c.score(t, 'likelihood', p),
          impact: c.score(t, 'impact', p),
          status: c.oneOf(t, 'status', p, THREAT_STATUSES),
          mitigation: c.str(t, 'mitigation', p),
          generated: c.bool(t, 'generated', p, false),
        }
        const owner = c.optStr(t, 'owner', p)
        if (owner !== undefined) th.owner = owner
        const ticket = c.optStr(t, 'ticket', p)
        if (ticket !== undefined) th.ticket = ticket
        const ruleId = c.optStr(t, 'ruleId', p)
        if (ruleId !== undefined) th.ruleId = ruleId
        if (t.stale !== undefined) th.stale = c.bool(t, 'stale', p, false)
        if (t.suggestedMitigations !== undefined) th.suggestedMitigations = c.strArray(t, 'suggestedMitigations', p, 100)
        if (t.references !== undefined) th.references = c.strArray(t, 'references', p, 100)
        if (t.ruleLikelihood !== undefined) th.ruleLikelihood = c.score(t, 'ruleLikelihood', p)
        if (t.ruleImpact !== undefined) th.ruleImpact = c.score(t, 'ruleImpact', p)
        if (th.id && seen.has(th.id)) c.add(`${p}.id`, `duplicate id "${th.id}"`)
        seen.add(th.id)
        if (th.elementId && !byId.has(th.elementId)) c.add(`${p}.elementId`, `references unknown element "${th.elementId}"`)
        threats.push(th)
      })
    }
  }

  if (c.errors.length) return { ok: false, errors: c.errors }
  return {
    ok: true,
    model: { schemaVersion: SCHEMA_VERSION, id, name, description, owner, createdAt, updatedAt, assumptions, elements, threats },
  }
}

/** Model ids appear in URLs: imported ids outside this alphabet are replaced. */
export const SAFE_ID = /^[A-Za-z0-9_-]{1,100}$/

export type ImportResult = { ok: true; models: ThreatModel[] } | { ok: false; errors: string[] }

/**
 * Parse an import file. Accepts a single model or an array of models.
 * Models whose id collides with an existing one (or another imported one), or is not URL-safe, get a fresh id.
 * All-or-nothing: any invalid model rejects the whole import.
 */
export function parseImport(text: string, existingIds: Iterable<string>, makeId: () => string): ImportResult {
  let data: unknown
  try {
    data = JSON.parse(text)
  } catch (e) {
    return { ok: false, errors: [`Not valid JSON: ${e instanceof Error ? e.message : String(e)}`] }
  }
  const list = Array.isArray(data) ? data : [data]
  if (list.length === 0) return { ok: false, errors: ['The file contains an empty list — nothing to import.'] }
  if (list.length > LIMITS.models) return { ok: false, errors: [`Too many models (max ${LIMITS.models}).`] }
  const taken = new Set(existingIds)
  const models: ThreatModel[] = []
  const errors: string[] = []
  list.forEach((raw, i) => {
    const res = validateModel(raw, Array.isArray(data) ? `[${i}]` : 'model')
    if (!res.ok) {
      errors.push(...res.errors)
      return
    }
    const m = res.model
    if (taken.has(m.id) || !SAFE_ID.test(m.id)) m.id = makeId()
    taken.add(m.id)
    models.push(m)
  })
  if (errors.length) return { ok: false, errors: errors.slice(0, 50) }
  return { ok: true, models }
}

export interface StoredPartition {
  models: ThreatModel[]
  /**
   * Persisted entries that failed validation (or repeat an id already loaded). They are not shown,
   * but they are written back untouched so that one corrupt entry never silently destroys user data.
   */
  invalid: unknown[]
}

/** Split a persisted value (localStorage may hold anything) into valid models and unreadable entries. */
export function partitionStored(raw: unknown): StoredPartition {
  if (raw === null || raw === undefined) return { models: [], invalid: [] }
  if (!Array.isArray(raw)) return { models: [], invalid: [raw] }
  const models: ThreatModel[] = []
  const invalid: unknown[] = []
  const seen = new Set<string>()
  for (const item of raw) {
    const res = validateModel(item)
    if (res.ok && !seen.has(res.model.id)) {
      seen.add(res.model.id)
      models.push(res.model)
    } else invalid.push(item)
  }
  return { models, invalid }
}

/** Keep only valid models from a persisted value. */
export function sanitizeStored(raw: unknown): ThreatModel[] {
  return partitionStored(raw).models
}
