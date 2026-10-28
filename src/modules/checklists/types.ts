/** Technology stacks an item can be scoped to. Items without `stacks` apply everywhere. */
export const STACKS = ['web', 'api', 'node', 'java', 'python', 'dotnet', 'mobile', 'infra'] as const
export type Stack = (typeof STACKS)[number]

export const STACK_LABELS: Record<Stack, string> = {
  web: 'Web front-end',
  api: 'API / backend',
  node: 'Node.js',
  java: 'Java',
  python: 'Python',
  dotnet: '.NET',
  mobile: 'Mobile',
  infra: 'Infra / CI',
}

export interface ChecklistItem {
  /** Unique within its checklist. Never rename once shipped: saved reviews key results by this id. */
  id: string
  /** The question / control, phrased so that "pass" means "good". */
  text: string
  /** How to check it and what good looks like (1-3 sentences). */
  detail: string
  stacks?: Stack[]
  /** ASVS verification level, when the item comes from ASVS. */
  level?: 1 | 2 | 3
  /** CWE ids ("CWE-89") or ASVS 5.0 ids ("ASVS v5.0.0-1.2.4"). */
  refs?: string[]
}

export interface ChecklistCategory {
  id: string
  title: string
  description: string
  items: ChecklistItem[]
}

export interface Checklist {
  id: string
  title: string
  version: string
  source: string
  description: string
  categories: ChecklistCategory[]
}

export const ITEM_STATUSES = ['unchecked', 'pass', 'fail', 'na'] as const
export type ItemStatus = (typeof ITEM_STATUSES)[number]

export const STATUS_LABELS: Record<ItemStatus, string> = {
  unchecked: 'Not reviewed',
  pass: 'Pass',
  fail: 'Fail',
  na: 'N/A',
}

export interface ItemResult {
  status: ItemStatus
  note: string
}

export const REVIEW_SCHEMA_VERSION = 1

/** A saved review. Plain JSON — persisted in localStorage and exportable. */
export interface Review {
  schemaVersion: typeof REVIEW_SCHEMA_VERSION
  id: string
  name: string
  link: string
  checklistId: string
  /** Checklist version at creation time, to explain drift if the data changes later. */
  checklistVersion: string
  /** Stack filter. Empty = show every item. */
  stacks: Stack[]
  /** Keyed by ChecklistItem.id. Missing entry = unchecked with no note. */
  results: Record<string, ItemResult>
  createdAt: string
  updatedAt: string
}
