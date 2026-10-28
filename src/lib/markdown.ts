/**
 * Escape a value for use inside a Markdown table cell (table structure only).
 * Does NOT neutralise HTML or link syntax: callers entity-encode untrusted text first.
 */
export function mdCell(value: string): string {
  return value.replace(/\\/g, '\\\\').replace(/\|/g, '\\|').replace(/\r?\n/g, '<br>')
}

export function mdTable(headers: string[], rows: string[][]): string {
  const head = `| ${headers.map(mdCell).join(' | ')} |`
  const sep = `| ${headers.map(() => '---').join(' | ')} |`
  const body = rows.map((r) => `| ${r.map(mdCell).join(' | ')} |`)
  return [head, sep, ...body].join('\n')
}
