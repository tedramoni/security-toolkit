import type { Checklist } from '../types'
import { asvs } from './asvs'
import { owaspApi } from './owaspApi'
import { owaspTop10 } from './owaspTop10'
import { prQuick } from './prQuick'

/** Display order on the start page. */
export const CHECKLISTS: Checklist[] = [prQuick, owaspTop10, owaspApi, asvs]

export function getChecklist(id: string): Checklist | undefined {
  return CHECKLISTS.find((c) => c.id === id)
}
