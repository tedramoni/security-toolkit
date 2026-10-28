import type { OpDef } from '../engine/types'
import { CATEGORIES } from '../engine/types'
import { cryptoOps } from './crypto'
import { encodingOps } from './encoding'
import { extractOps } from './extract'
import { formatOps } from './formats'
import { hashingOps } from './hashing'
import { textOps } from './text'

export const OPERATIONS: readonly OpDef[] = [...encodingOps, ...cryptoOps, ...hashingOps, ...textOps, ...extractOps, ...formatOps].sort(
  (a, b) => CATEGORIES.indexOf(a.category) - CATEGORIES.indexOf(b.category),
)

export const OPS_BY_ID: ReadonlyMap<string, OpDef> = new Map(OPERATIONS.map((o) => [o.id, o]))

export function getOp(id: string): OpDef | undefined {
  return OPS_BY_ID.get(id)
}
