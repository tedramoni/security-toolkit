/** Display formatting helpers. */

export function fmtDate(iso: string | undefined): string | undefined {
  if (!iso) return undefined
  const t = Date.parse(iso)
  return Number.isNaN(t) ? iso : new Date(t).toISOString().slice(0, 10)
}

export function fmtTtl(s: number): string {
  if (s >= 86400 && s % 3600 === 0) return `${s} s (${(s / 86400).toFixed(s % 86400 === 0 ? 0 : 1)} d)`
  if (s >= 3600) return `${s} s (${(s / 3600).toFixed(s % 3600 === 0 ? 0 : 1)} h)`
  if (s >= 60) return `${s} s (${Math.round(s / 60)} min)`
  return `${s} s`
}
