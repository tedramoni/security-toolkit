import { mdTable } from '../../lib/markdown'
import { applicableItems, computeProgress, getResult } from './logic'
import type { ItemRef } from './logic'
import type { Checklist, ItemStatus, Review } from './types'
import { STACK_LABELS } from './types'

/**
 * Neutralise user text for GitHub-flavoured Markdown: HTML special characters become entities
 * (so no raw HTML or fake <details> blocks can be injected) and line breaks are flattened.
 */
export function escapeHtmlText(s: string): string {
  return s.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
}

/** Inline (single-line) user text: entities + Markdown emphasis/link/code characters escaped. */
export function mdInline(s: string): string {
  return escapeHtmlText(s)
    .replace(/([\\`*_[\]|])/g, '\\$1')
    .replace(/\s*\r?\n\s*/g, ' ')
    .trim()
}

/** Table cell holding user text: entities, pipes and newlines handled. */
export function mdUserCell(s: string): string {
  return escapeHtmlText(s.trim())
}

/** Only http(s) links are rendered; anything else (javascript:, data:, garbage) is dropped. */
export function safeHttpUrl(raw: string): string | null {
  const trimmed = raw.trim()
  if (!trimmed) return null
  try {
    const url = new URL(trimmed)
    if (url.protocol !== 'http:' && url.protocol !== 'https:') return null
    return url.href
  } catch {
    return null
  }
}

function itemLabel(ref: ItemRef): string {
  return ref.item.text
}

function refsText(ref: ItemRef): string {
  return ref.item.refs?.length ? ref.item.refs.join(', ') : ''
}

export interface ReportOptions {
  /** Defaults to true: passed items in a collapsed <details> block. */
  includePassed?: boolean
}

/** Markdown summary suitable for a GitHub/GitLab PR comment. */
export function reviewToMarkdown(review: Review, checklist: Checklist, opts: ReportOptions = {}): string {
  const includePassed = opts.includePassed ?? true
  const progress = computeProgress(checklist, review)
  const items = applicableItems(checklist, review.stacks)
  const byStatus = (s: ItemStatus) => items.filter((r) => getResult(review, r.item.id).status === s)
  const failed = byStatus('fail')
  const na = byStatus('na')
  const passed = byStatus('pass')

  const lines: string[] = []
  lines.push(`## Security review: ${mdInline(review.name)}`)
  lines.push('')

  const meta: string[] = [`**Checklist:** [${mdInline(checklist.title)}](${checklist.source})`]
  const link = safeHttpUrl(review.link)
  if (link) meta.push(`**Link:** <${link}>`)
  else if (review.link.trim()) meta.push(`**Ref:** ${mdInline(review.link)}`)
  if (review.stacks.length) meta.push(`**Scope:** ${review.stacks.map((s) => STACK_LABELS[s]).join(', ')}`)
  lines.push(meta.join('  \n'))
  lines.push('')

  const verdict = progress.fail > 0 ? `**${progress.fail} failed**` : '0 failed'
  lines.push(
    `**Progress:** ${progress.answered}/${progress.total} reviewed (${progress.percent}%) — ${verdict} · ${progress.pass} passed · ${progress.na} N/A · ${progress.unchecked} not reviewed`,
  )
  lines.push('')

  if (failed.length) {
    lines.push(`### Failed (${failed.length})`)
    lines.push('')
    // mdTable runs mdCell (pipes, backslashes, newlines) — we pre-escape HTML in user notes.
    lines.push(
      mdTable(
        ['Category', 'Item', 'Note', 'Refs'],
        failed.map((r) => [
          mdUserCell(r.category.title),
          mdUserCell(itemLabel(r)),
          mdUserCell(getResult(review, r.item.id).note) || '—',
          refsText(r),
        ]),
      ),
    )
    lines.push('')
  } else {
    lines.push('### Failed (0)')
    lines.push('')
    lines.push('_No failed items._')
    lines.push('')
  }

  if (na.length) {
    lines.push(`### Not applicable (${na.length})`)
    lines.push('')
    for (const r of na) {
      const note = getResult(review, r.item.id).note.trim()
      lines.push(`- ${mdInline(itemLabel(r))}${note ? ` — _${mdInline(note)}_` : ''}`)
    }
    lines.push('')
  }

  if (includePassed && passed.length) {
    lines.push('<details>')
    lines.push(`<summary>Passed (${passed.length})</summary>`)
    lines.push('')
    for (const r of passed) {
      const note = getResult(review, r.item.id).note.trim()
      lines.push(`- ${mdInline(itemLabel(r))}${note ? ` — _${mdInline(note)}_` : ''}`)
    }
    lines.push('')
    lines.push('</details>')
    lines.push('')
  }

  lines.push(`<sub>Generated with Security Champion Toolkit · ${mdInline(checklist.title)} v${mdInline(checklist.version)}</sub>`)
  return lines.join('\n')
}
