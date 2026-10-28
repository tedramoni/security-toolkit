/** Dashboard tiles for every check. Each check is split into several compact tiles (see tiles.ts for the routing). */
import type { ReactNode } from 'react'
import { useEffect, useRef, useState } from 'react'
import { CopyButton } from '../../lib/CopyButton'
import { downloadText, slugify } from '../../lib/download'
import { DNSSEC_ALGS } from './dns'
import type { DnsResult } from './doh'
import { createResolver } from './doh'
import type { SpfNode } from './email'
import { fmtDate, fmtTtl } from './format'
import { isAbortError } from './net'
import { SOURCES } from './report'
import type { ResolvedHost } from './subdomains'
import { RESOLVE_CAP, RESOLVE_CONCURRENCY, resolveHosts, resolvedFindings } from './subdomains'
import type { TileId } from './tiles'
import { splitFindings, tileStatus } from './tiles'
import type { CheckId, Finding } from './types'
import type { TileMore, TileProps } from './ui'
import { ExtLink, Tile } from './ui'
import type { CheckDataMap, CheckState, Checks } from './useRecon'

type Common = Pick<TileProps, 'status' | 'source' | 'findings' | 'onRerun' | 'message'>

const EMPTY: Finding[] = []

/** Props shared by every tile of a check: status from the check + the findings routed to this tile. */
function common(check: CheckId, st: CheckState, byTile: Map<TileId, Finding[]> | undefined, tile: TileId, onRerun?: () => void): Common {
  const findings = byTile?.get(tile) ?? EMPTY
  return {
    status: tileStatus(st.status, findings),
    source: SOURCES[check],
    findings,
    onRerun,
    message: st.status === 'error' ? <>Failed: {st.error}. Other tiles are not affected.</> : st.note && st.note !== 'needs-proxy' ? st.note : undefined,
  }
}

const single = (st: CheckState, tile: TileId) => (st.status === 'done' ? new Map<TileId, Finding[]>([[tile, st.findings]]) : undefined)

function Table({ head, rows }: { head: string[]; rows: ReactNode[][] }) {
  return (
    <table className="table recon-table">
      <thead>
        <tr>
          {head.map((h) => (
            <th key={h} scope="col">
              {h}
            </th>
          ))}
        </tr>
      </thead>
      <tbody>
        {rows.map((r, i) => (
          <tr key={i}>
            {r.map((c, j) => (
              <td key={j} className="recon-break">
                {c}
              </td>
            ))}
          </tr>
        ))}
      </tbody>
    </table>
  )
}

/** Table row helper (call arguments, not an array literal, so React keys are positional by design). */
const cells = (...c: ReactNode[]): ReactNode[] => c

const count = (n: number, one: string, many = `${one}s`) => `${n} ${n === 1 ? one : many}`

/* ---------------------------------------------------------------- DNS */

function dnsTiles(st: CheckState<CheckDataMap['dns']>, onRerun: () => void): ReactNode[] {
  const d = st.data
  const by = st.status === 'done' ? splitFindings('dns', st.findings) : undefined
  const ok = (r: DnsResult | { error: string } | undefined): r is DnsResult => r !== undefined && !('error' in r)
  const recs = (t: string) => {
    const r = d?.results[t]
    return ok(r) ? r.records : []
  }
  const rows: { type: string; name: string; ttl: number; value: string }[] = []
  const failed: string[] = []
  if (d) {
    for (const [type, r] of Object.entries(d.results)) {
      if (!ok(r)) {
        failed.push(`${type}: ${r.error}`)
        continue
      }
      for (const rec of r.records) rows.push({ type, name: rec.name, ttl: rec.ttl, value: rec.data })
    }
    rows.sort((a, b) => a.type.localeCompare(b.type))
  }
  const a = d?.results.A
  const cnames = ok(a) ? a.cnames : []
  const list = (t: string, max = 3) => {
    const v = recs(t).map((r) => r.data)
    return v.length === 0 ? undefined : `${v.slice(0, max).join(', ')}${v.length > max ? ` +${v.length - max}` : ''}`
  }
  return [
    <Tile
      key="dns-records"
      id="dns-records"
      icon="🌐"
      title="DNS records"
      wide
      {...common('dns', st, by, 'dns-records', onRerun)}
      facts={
        d && {
          A: list('A') ?? 'none',
          AAAA: list('AAAA') ?? 'none',
          'CNAME chain': cnames.length > 0 ? cnames.join(' → ') : undefined,
          MX:
            d.mx.length > 0
              ? `${d.mx
                  .slice(0, 3)
                  .map((m) => `${m.priority} ${m.exchange}`)
                  .join(', ')}${d.mx.length > 3 ? ` +${d.mx.length - 3}` : ''}`
              : 'none',
          TXT: `${count(recs('TXT').length, 'record')}${d.services.length > 0 ? ` — ${d.services.slice(0, 4).join(', ')}${d.services.length > 4 ? '…' : ''}` : ''}`,
          HTTPS: list('HTTPS', 1),
          Resolver: d.resolvers.join(', '),
        }
      }
      more={
        d
          ? [
              {
                label: `All records (${rows.length})`,
                render: () => (
                  <>
                    <Table
                      head={['Type', 'Name', 'TTL', 'Value']}
                      rows={rows.map((r) =>
                        cells(<code>{r.type}</code>, r.name, <span className="small recon-nowrap">{fmtTtl(r.ttl)}</span>, <code>{r.value}</code>),
                      )}
                    />
                    {failed.length > 0 && <p className="small muted">Queries that failed: {failed.join('; ')}</p>}
                  </>
                ),
              },
            ]
          : []
      }
      raw={d}
    />,
    <Tile
      key="dns-dnssec"
      id="dns-dnssec"
      icon="🔏"
      title="DNSSEC"
      {...common('dns', st, by, 'dns-dnssec')}
      facts={
        d && {
          Status: {
            validated: 'Signed and validated (AD flag)',
            unsigned: 'Not signed',
            'ds-present-not-validated': 'DS present, answers NOT validated',
            unknown: 'Unknown',
          }[d.dnssec],
          'DS records': d.ds.length > 0 ? d.ds.map((x) => `tag ${x.keyTag}, ${DNSSEC_ALGS[x.algorithm] ?? `alg ${x.algorithm}`}`).join('; ') : 'none',
          DNSKEY: count(recs('DNSKEY').length, 'key'),
        }
      }
    />,
    <Tile
      key="dns-caa"
      id="dns-caa"
      icon="🏷️"
      title="CAA (allowed CAs)"
      {...common('dns', st, by, 'dns-caa')}
      facts={
        d && {
          Issue:
            d.caa
              .filter((c) => c.tag === 'issue')
              .map((c) => c.value || ';')
              .join(', ') || (d.caa.length === 0 ? 'any CA' : undefined),
          'Issue wildcard':
            d.caa
              .filter((c) => c.tag === 'issuewild')
              .map((c) => c.value || ';')
              .join(', ') || undefined,
          'Reports (iodef)':
            d.caa
              .filter((c) => c.tag === 'iodef')
              .map((c) => c.value)
              .join(', ') || undefined,
          'Found at': d.caa.length > 0 ? (d.caaFrom ?? d.host) : undefined,
        }
      }
    />,
    <Tile
      key="dns-ns"
      id="dns-ns"
      icon="🗂️"
      title="Name servers & SOA"
      {...common('dns', st, by, 'dns-ns')}
      facts={
        d && {
          NS: list('NS', 2) ?? 'none',
          'SOA primary': d.soa?.mname,
          'SOA contact': d.soa?.rname,
          Serial: d.soa ? String(d.soa.serial) : undefined,
          Wildcard: d.wildcard === undefined ? undefined : d.wildcard ? `yes (*.${d.host} resolves)` : 'no',
        }
      }
    />,
  ]
}

/* ---------------------------------------------------------------- Email */

function SpfTree({ node }: { node: SpfNode }) {
  return (
    <li>
      <code>{node.domain}</code>
      {node.via !== 'root' && <span className="muted small"> ({node.via})</span>}
      {node.lookups > 0 && <span className="small"> — {count(node.lookups, 'lookup')}</span>}
      {node.loop && <span className="badge sev-high"> loop</span>}
      {node.error && <span className="small sev-high"> — {node.error}</span>}
      {node.notExpanded && <span className="small muted"> — not expanded: {node.notExpanded}</span>}
      {node.children.length > 0 && (
        <ul className="recon-tree">
          {node.children.map((c, i) => (
            <SpfTree key={`${c.domain}-${i}`} node={c} />
          ))}
        </ul>
      )}
    </li>
  )
}

function emailTiles(st: CheckState<CheckDataMap['email']>, onRerun: () => void): ReactNode[] {
  const d = st.data
  const by = st.status === 'done' ? splitFindings('email', st.findings) : undefined
  const spf = d?.spf
  const dm = d?.dmarc?.parsed
  const all = spf?.root.parsed?.all
  const mxText = (n: number) =>
    d
      ? d.nullMx
        ? 'Null MX (no mail)'
        : d.mx.length > 0
          ? `${d.mx
              .slice(0, n)
              .map((m) => `${m.priority} ${m.exchange}`)
              .join(', ')}${d.mx.length > n ? ` +${d.mx.length - n}` : ''}`
          : 'none'
      : undefined
  return [
    <Tile
      key="email-spf"
      id="email-spf"
      icon="✉️"
      title="Mail servers & SPF"
      {...common('email', st, by, 'email-spf', onRerun)}
      facts={
        d && {
          MX: mxText(2),
          SPF: spf?.records[0] ? <code className="recon-clamp">{spf.records[0]}</code> : 'none',
          Lookups: spf?.records.length ? `${spf.totalLookups} / 10${spf.capped ? ' (capped)' : ''}` : undefined,
          Policy: all ? `${all}all` : spf?.root.parsed?.redirect ? `redirect=${spf.root.parsed.redirect}` : undefined,
        }
      }
      more={
        spf && spf.root.children.length > 0
          ? [
              {
                label: 'Include tree',
                render: () => (
                  <ul className="recon-tree">
                    <SpfTree node={spf.root} />
                  </ul>
                ),
              },
            ]
          : []
      }
      raw={d}
    />,
    <Tile
      key="email-dmarc"
      id="email-dmarc"
      icon="🛡️"
      title="DMARC"
      {...common('email', st, by, 'email-dmarc')}
      facts={
        d && {
          Policy: dm
            ? `p=${dm.p ?? '?'}${dm.sp ? `, sp=${dm.sp}` : ''}${dm.pct < 100 ? `, pct=${dm.pct}` : ''}`
            : (d.dmarc?.records.length ?? 0) > 1
              ? 'several records (ignored)'
              : 'no record',
          Alignment: dm ? `DKIM ${dm.adkim === 's' ? 'strict' : 'relaxed'}, SPF ${dm.aspf === 's' ? 'strict' : 'relaxed'}` : undefined,
          Reports: dm ? [...dm.rua.map((x) => `rua ${x}`), ...dm.ruf.map((x) => `ruf ${x}`)].join(', ') || 'none' : undefined,
          Record: d.dmarc?.records[0] ? <code className="recon-clamp">{d.dmarc.records[0]}</code> : undefined,
          From: d.dmarc?.fallback ? d.dmarc.name : undefined,
        }
      }
    />,
    <Tile
      key="email-dkim"
      id="email-dkim"
      icon="🔑"
      title="DKIM"
      {...common('email', st, by, 'email-dkim')}
      facts={
        d && {
          'Keys found': d.dkim.length > 0 ? d.dkim.map((k) => k.selector).join(', ') : `none on ${d.dkimProbed.length} common selectors`,
          Strength:
            d.dkim.length > 0
              ? d.dkim
                  .slice(0, 3)
                  .map((k) =>
                    k.revoked ? `${k.selector}: revoked` : k.error ? `${k.selector}: unreadable` : `${k.selector}: ${k.keyType.toUpperCase()} ${k.bits ?? '?'}`,
                  )
                  .join(', ')
              : undefined,
        }
      }
      more={
        d
          ? [
              {
                label: d.dkim.length > 0 ? `Keys (${d.dkim.length})` : 'Selectors probed',
                render: () =>
                  d.dkim.length > 0 ? (
                    <Table
                      head={['Selector', 'Key', 'Notes']}
                      rows={d.dkim.map((k) =>
                        cells(
                          <code>{k.selector}._domainkey</code>,
                          k.revoked ? 'revoked (empty p=)' : (k.error ?? `${k.keyType.toUpperCase()} ${k.bits ?? '?'} bit`),
                          k.testing ? 'testing (t=y)' : '',
                        ),
                      )}
                    />
                  ) : (
                    <p className="small muted">
                      {d.dkimProbed.join(', ')}. Selectors cannot be listed through DNS; check the s= tag of a received email's DKIM-Signature.
                    </p>
                  ),
              },
            ]
          : []
      }
    />,
    <Tile
      key="email-transport"
      id="email-transport"
      icon="📬"
      title="MTA-STS, TLS-RPT & BIMI"
      {...common('email', st, by, 'email-transport')}
      facts={
        d && {
          'MTA-STS': d.mtaSts?.record ? (d.mtaSts.policy ? `mode ${d.mtaSts.policy.mode ?? '?'}` : 'record present') : 'none',
          'STS MX': d.mtaSts?.policy && d.mtaSts.policy.mx.length > 0 ? d.mtaSts.policy.mx.join(', ') : undefined,
          'TLS-RPT': d.tlsRpt?.record ? d.tlsRpt.rua.join(', ') || 'record present' : 'none',
          BIMI: d.bimi?.record ? d.bimi.logo ? <ExtLink href={d.bimi.logo}>logo</ExtLink> : 'record present' : 'none',
        }
      }
    />,
  ]
}

/* ---------------------------------------------------------------- Certificate transparency */

function CtHostsTile({ st, onRerun }: { st: CheckState<CheckDataMap['ct']>; onRerun: () => void }) {
  const data = st.data
  const [filter, setFilter] = useState('')
  // Resolution results belong to one CT data object: a new scan / re-run shows none without a reset effect.
  const [res, setRes] = useState<{ for: unknown; rows?: ResolvedHost[]; error?: string }>({ for: undefined })
  const resolved = res.for === data ? res.rows : undefined
  const resolveError = res.for === data ? res.error : undefined
  const [progress, setProgress] = useState<{ done: number; total: number } | undefined>()
  const ctrl = useRef<AbortController | null>(null)
  // New scan / re-run / unmount: stop resolving the previous target's names.
  useEffect(() => () => ctrl.current?.abort(), [data])

  const by = st.status === 'done' ? splitFindings('ct', st.findings) : undefined
  const subs = data?.summary.subdomains ?? []
  const list = subs.join('\n')
  const q = filter.trim().toLowerCase()
  const shown = q ? subs.filter((h) => h.includes(q)) : subs

  const runResolve = async () => {
    ctrl.current?.abort()
    const c = new AbortController()
    ctrl.current = c
    // Own resolver bound to this run: works even after the scan itself was cancelled.
    const resolve = createResolver({ signal: c.signal })
    const forData = data
    setRes({ for: forData })
    setProgress({ done: 0, total: Math.min(subs.length, RESOLVE_CAP) })
    try {
      const rows = await resolveHosts(subs, resolve, {
        signal: c.signal,
        onProgress: (done, total) => setProgress({ done, total }),
      })
      if (!c.signal.aborted) setRes({ for: forData, rows })
    } catch (e) {
      setRes({ for: forData, error: isAbortError(e) || c.signal.aborted ? 'Cancelled.' : e instanceof Error ? e.message : String(e) })
    } finally {
      if (ctrl.current === c) setProgress(undefined)
    }
  }
  const resolvedF = resolved ? resolvedFindings(resolved) : []
  const findings = [...(by?.get('ct-hosts') ?? []), ...resolvedF]
  const takeovers = resolved?.filter((r) => r.takeover.verdict === 'possible-takeover').length ?? 0

  const more: TileMore[] = data
    ? [
        {
          label: `All host names (${subs.length})`,
          render: () => (
            <div className="stack">
              <div className="row">
                <label>
                  <span className="sr-only">Filter host names</span>
                  <input type="search" value={filter} onChange={(e) => setFilter(e.target.value)} placeholder="Filter: dev, admin, api…" />
                </label>
                <CopyButton text={list} label="Copy" />
                <button type="button" className="btn btn-sm" onClick={() => downloadText(`${slugify(data.domain)}-subdomains.txt`, list + '\n')}>
                  Export .txt
                </button>
              </div>
              <ul className="recon-hosts" aria-label="Discovered host names">
                {shown.slice(0, 1000).map((h) => (
                  <li key={h}>
                    <code>{h}</code>
                  </li>
                ))}
              </ul>
              {shown.length > 1000 && <p className="small muted">Showing 1000 of {shown.length}; use Copy/Export for the full list.</p>}
            </div>
          ),
        },
      ]
    : []
  if (resolved) {
    more.push({
      label: `Resolution (${resolved.length})`,
      render: () => (
        <Table
          head={['Host', 'Status', 'CNAME', 'Addresses', 'Takeover']}
          rows={resolved.map((r) =>
            cells(
              <code>{r.host}</code>,
              r.error ? 'error' : r.status,
              <span className="small">{r.cnames.join(' → ')}</span>,
              <span className="small">{`${r.addresses.slice(0, 3).join(', ')}${r.addresses.length > 3 ? '…' : ''}`}</span>,
              r.takeover.verdict === 'possible-takeover' ? (
                <span className={`badge sev-${r.takeover.severity}`}>verify: {r.takeover.service}</span>
              ) : r.takeover.verdict === 'dangling-cname' ? (
                <span className="badge sev-low">dangling</span>
              ) : r.takeover.verdict === 'review' ? (
                <span className="muted small">{r.takeover.service}</span>
              ) : (
                ''
              ),
            ),
          )}
        />
      ),
    })
  }

  return (
    <Tile
      id="ct-hosts"
      icon="🔎"
      title="Subdomains (certificate transparency)"
      wide
      {...common('ct', st, by, 'ct-hosts', onRerun)}
      findings={findings}
      status={tileStatus(st.status, findings)}
      facts={
        data && {
          'Domain queried': data.domain,
          'Host names': `${subs.length}${data.unexpiredOnly ? ' (unexpired certificates only)' : ''}`,
          Wildcards: data.summary.wildcards.slice(0, 4).join(', ') || undefined,
          Takeover: resolved ? (takeovers > 0 ? `${takeovers} candidate(s) — verify manually` : 'no candidate found') : undefined,
        }
      }
      more={more}
      raw={data}
    >
      {data && subs.length > 0 && (
        <>
          <p className="recon-preview small">
            {subs.slice(0, 12).map((h) => (
              <code key={h}>{h}</code>
            ))}
            {subs.length > 12 && <span className="muted">+{subs.length - 12} more</span>}
          </p>
          <div className="row recon-actions">
            <button type="button" className="btn btn-sm btn-primary" onClick={runResolve} disabled={progress !== undefined}>
              Resolve host names
            </button>
            {progress && (
              <button type="button" className="btn btn-sm" onClick={() => ctrl.current?.abort()}>
                Cancel
              </button>
            )}
            <span className="small muted">
              DoH, {RESOLVE_CONCURRENCY} at a time, first {RESOLVE_CAP}; flags dangling CNAMEs (possible takeovers)
            </span>
          </div>
          {progress && (
            <div
              className="progress"
              role="progressbar"
              aria-label="Resolving host names"
              aria-valuemin={0}
              aria-valuemax={progress.total}
              aria-valuenow={progress.done}
            >
              <span
                style={{
                  width: `${progress.total ? (progress.done / progress.total) * 100 : 0}%`,
                }}
              />
            </div>
          )}
          {resolveError && <div className="recon-msg small">{resolveError}</div>}
        </>
      )}
    </Tile>
  )
}

function ctCertsTile(st: CheckState<CheckDataMap['ct']>): ReactNode {
  const data = st.data
  const by = st.status === 'done' ? splitFindings('ct', st.findings) : undefined
  const s = data?.summary
  const valid = s ? s.certs.filter((c) => !c.expired) : []
  const soon = valid.filter((c) => c.daysLeft <= 14).length
  return (
    <Tile
      key="ct-certs"
      id="ct-certs"
      icon="📜"
      title="Certificates"
      {...common('ct', st, by, 'ct-certs')}
      facts={
        s && {
          'Log entries': String(s.totalEntries),
          Certificates: `${s.certs.length} unique, ${valid.length} valid`,
          'Expiring ≤ 14 d': String(soon),
          Issuers:
            s.issuers
              .slice(0, 3)
              .map((i) => `${i.issuer} (${i.count})`)
              .join(', ') || undefined,
          'crt.sh': data && <ExtLink href={`https://crt.sh/?q=${encodeURIComponent(data.domain)}`}>open search</ExtLink>,
        }
      }
      more={
        s && s.certs.length > 0
          ? [
              {
                label: `Recent certificates (${Math.min(100, s.certs.length)} of ${s.certs.length})`,
                render: () => (
                  <Table
                    head={['Common name', 'Issuer', 'Valid', 'SANs']}
                    rows={s.certs.slice(0, 100).map((c) =>
                      cells(
                        <ExtLink href={`https://crt.sh/?id=${c.id}`}>{c.commonName || '(none)'}</ExtLink>,
                        <span className="small">{c.issuer}</span>,
                        <span className="small recon-nowrap">
                          {fmtDate(`${c.notBefore}Z`)} → {fmtDate(`${c.notAfter}Z`)}
                          {c.expired ? ' (expired)' : c.daysLeft <= 14 ? ` (${c.daysLeft} d left)` : ''}
                        </span>,
                        <span className="small">{`${c.names.slice(0, 6).join(', ')}${c.names.length > 6 ? ` +${c.names.length - 6}` : ''}`}</span>,
                      ),
                    )}
                  />
                ),
              },
            ]
          : []
      }
    />
  )
}

/* ---------------------------------------------------------------- RDAP / IP / Wayback */

function rdapTile(st: CheckState<CheckDataMap['rdap']>, onRerun: () => void): ReactNode {
  const r = st.data
  const d = r?.kind === 'ok' ? r.domain : undefined
  const locks = d ? d.status.filter((s) => s.code.endsWith('Prohibited')).length : 0
  return (
    <Tile
      key="rdap"
      id="rdap"
      icon="📇"
      title="Registration (RDAP)"
      {...common('rdap', st, single(st, 'rdap'), 'rdap', onRerun)}
      facts={
        r?.kind === 'unavailable'
          ? { Queried: r.queried.join(', ') }
          : d && {
              Registrar: d.registrar ? d.registrar.url ? <ExtLink href={d.registrar.url}>{d.registrar.name}</ExtLink> : d.registrar.name : undefined,
              Registered: fmtDate(d.registration),
              Expires: fmtDate(d.expiration),
              'Last changed': fmtDate(d.lastChanged),
              Locks: locks > 0 ? count(locks, 'lock') : 'none',
              'DNSSEC (registry)': d.delegationSigned === undefined ? undefined : d.delegationSigned ? 'signed' : 'not signed',
            }
      }
      more={
        d
          ? [
              {
                label: `Status & contacts (${d.status.length})`,
                render: () => (
                  <div className="stack">
                    <ul className="recon-list">
                      {d.status.map((s) => (
                        <li key={s.code}>
                          <code>{s.code}</code>
                          {s.help && <span className="small muted"> — {s.help}</span>}
                        </li>
                      ))}
                    </ul>
                    <p className="small">
                      Name servers: {d.nameservers.join(', ') || 'none'}
                      <br />
                      Abuse contact: {d.abuse ? [d.abuse.email, d.abuse.phone].filter(Boolean).join(' · ') : 'n/a'}
                      <br />
                      Registry server: {r?.kind === 'ok' ? r.server : ''} {d.self && <ExtLink href={d.self}>(RDAP record)</ExtLink>}
                    </p>
                  </div>
                ),
              },
            ]
          : []
      }
      raw={r?.kind === 'ok' ? r.raw : r}
    />
  )
}

function ipTile(st: CheckState<CheckDataMap['ip']>, onRerun: () => void): ReactNode {
  const d = st.data
  const n = d?.rdap
  return (
    <Tile
      key="ip"
      id="ip"
      icon="📍"
      title="IP address & network"
      {...common('ip', st, single(st, 'ip'), 'ip', onRerun)}
      facts={
        d && {
          Address: d.ip ? `${d.ip}${d.addresses.length > 1 ? ` (+${d.addresses.length - 1} more)` : ''}` : 'none',
          PTR: d.ptr.join(', ') || (d.ip ? 'none' : undefined),
          Network: n ? [n.org ?? n.name, n.cidrs[0] ?? n.startAddress].filter(Boolean).join(' — ') : undefined,
          Country: n?.country,
          'Origin AS': n && n.asns.length > 0 ? n.asns.join(', ') : undefined,
          Abuse: n?.abuse?.email,
        }
      }
      raw={d?.raw ?? d}
    />
  )
}

function waybackTile(st: CheckState<CheckDataMap['wayback']>, onRerun: () => void): ReactNode {
  const d = st.data
  return (
    <Tile
      key="wayback"
      id="wayback"
      icon="🕰️"
      title="Web archive"
      {...common('wayback', st, single(st, 'wayback'), 'wayback', onRerun)}
      facts={
        d && {
          'First capture': d.first ? <ExtLink href={d.first.url}>{fmtDate(d.first.date)}</ExtLink> : 'unknown',
          'Latest capture': d.latest ? <ExtLink href={d.latest.url}>{fmtDate(d.latest.date)}</ExtLink> : 'unknown',
          'All captures': <ExtLink href={d.calendarUrl}>calendar</ExtLink>,
        }
      }
    >
      {d && <p className="small muted">Capture counts need the CDX API, which does not allow browser (CORS) requests.</p>}
    </Tile>
  )
}

/* ---------------------------------------------------------------- Website (proxy) */

function webTiles(st: CheckState<CheckDataMap['web']>, onRerun: (() => void) | undefined, onConfigure: () => void): ReactNode[] {
  if (st.status === 'needs-proxy') {
    return [
      <Tile
        key="web-https"
        id="web-https"
        icon="🧩"
        title="Website checks"
        status="needs-proxy"
        source={SOURCES.web}
        onRerun={onRerun}
        message={
          <>
            Security headers, redirects, robots.txt, sitemap, security.txt, the MTA-STS policy and HSTS preload need the target site itself, which browsers
            cannot read (CORS). These checks were not run.{' '}
            <button type="button" className="btn btn-sm" onClick={onConfigure}>
              Set up a proxy
            </button>
          </>
        }
      />,
    ]
  }
  const d = st.data
  const by = st.status === 'done' ? splitFindings('web', st.findings) : undefined
  const h = d?.headers
  const sec = d?.securityTxt?.parsed
  const robots = d?.robots
  return [
    <Tile
      key="web-https"
      id="web-https"
      icon="🔀"
      title="HTTPS & redirects"
      {...common('web', st, by, 'web-https', onRerun)}
      facts={
        d && {
          'Final URL': d.https ? <ExtLink href={d.https.finalUrl} /> : 'unreachable',
          Redirects: String(d.redirects.length),
          'http → https': d.httpsUpgrade === undefined ? undefined : d.httpsUpgrade ? 'yes' : 'no',
          'HSTS preload': d.preload?.status,
          Tech:
            d.tech
              .slice(0, 4)
              .map((t) => t.name)
              .join(', ') || undefined,
        }
      }
      more={
        d && d.redirects.length > 0
          ? [
              {
                label: `Redirect chain (${d.redirects.length})`,
                render: () => <Table head={['Status', 'From', 'To']} rows={d.redirects.map((r) => cells(String(r.status), r.url, r.location ?? '?'))} />,
              },
            ]
          : []
      }
      raw={d}
    />,
    <Tile
      key="web-headers"
      id="web-headers"
      icon="🧾"
      title="Security headers"
      {...common('web', st, by, 'web-headers')}
      facts={
        d && {
          Grade: h ? (
            <>
              <strong>{h.grade}</strong> — {h.score}/100
            </>
          ) : (
            'unavailable'
          ),
          'HTTP status': d.https ? String(d.https.status) : undefined,
          Cookies: h ? String(h.cookies.length) : undefined,
        }
      }
      more={
        h && h.parsed.headers.size > 0
          ? [
              {
                label: `Response headers (${h.parsed.headers.size})`,
                render: () => (
                  <Table
                    head={['Header', 'Value']}
                    rows={[...h.parsed.headers.entries()].flatMap(([name, vals]) => vals.map((v) => cells(<strong>{name}</strong>, <code>{v}</code>)))}
                  />
                ),
              },
            ]
          : []
      }
    />,
    <Tile
      key="web-robots"
      id="web-robots"
      icon="🤖"
      title="robots.txt & sitemap"
      {...common('web', st, by, 'web-robots')}
      facts={
        d && {
          'robots.txt': robots ? count(robots.disallow.length, 'disallowed path') : d.robotsStatus ? `HTTP ${d.robotsStatus}` : 'not found',
          Sensitive: robots && robots.interesting.length > 0 ? robots.interesting.slice(0, 4).join(', ') : undefined,
          Sitemap: d.sitemap ? `${d.sitemap.isIndex ? 'index, ' : ''}${d.sitemap.urls} URL(s)${d.sitemap.truncated ? ' (truncated)' : ''}` : 'not found',
        }
      }
      more={
        robots && robots.disallow.length > 0
          ? [
              {
                label: `Disallowed paths (${robots.disallow.length})`,
                render: () => (
                  <ul className="recon-hosts">
                    {robots.disallow.slice(0, 500).map((p) => (
                      <li key={p}>
                        <code>{p}</code>
                      </li>
                    ))}
                  </ul>
                ),
              },
            ]
          : []
      }
    />,
    <Tile
      key="web-securitytxt"
      id="web-securitytxt"
      icon="📮"
      title="security.txt"
      {...common('web', st, by, 'web-securitytxt')}
      facts={
        d && {
          File: d.securityTxt ? <ExtLink href={d.securityTxt.url} /> : 'not found',
          Contact: sec?.contact.slice(0, 2).join(', '),
          Expires: sec?.expires[0],
          Signed: sec ? (sec.signed ? 'PGP (not verified)' : 'no') : undefined,
        }
      }
      more={
        sec
          ? [
              {
                label: 'All fields',
                render: () => (
                  <Table
                    head={['Field', 'Value']}
                    rows={(
                      [
                        ['Contact', sec.contact],
                        ['Expires', sec.expires],
                        ['Encryption', sec.encryption],
                        ['Policy', sec.policy],
                        ['Canonical', sec.canonical],
                        ['Preferred-Languages', sec.preferredLanguages],
                        ['Acknowledgments', sec.acknowledgments],
                        ['Hiring', sec.hiring],
                      ] as [string, string[]][]
                    )
                      .filter(([, v]) => v.length > 0)
                      .map(([k, v]) => cells(k, v.join(', ')))}
                  />
                ),
              },
            ]
          : []
      }
    />,
  ]
}

/* ---------------------------------------------------------------- all tiles */

export interface TilesProps {
  checks: Checks
  onRerun: (id: CheckId) => void
  hasProxy: boolean
  onConfigureProxy: () => void
}

/** Every tile in dashboard order. IP targets only get the IP tile (the other checks are not applicable). */
export function ReconTiles({ checks, onRerun, hasProxy, onConfigureProxy }: TilesProps) {
  const r = (id: CheckId) => () => onRerun(id)
  if (checks.dns.status === 'skipped') return <>{ipTile(checks.ip, r('ip'))}</>
  return (
    <>
      {dnsTiles(checks.dns, r('dns'))}
      {emailTiles(checks.email, r('email'))}
      <CtHostsTile key="ct-hosts" st={checks.ct} onRerun={r('ct')} />
      {ctCertsTile(checks.ct)}
      {rdapTile(checks.rdap, r('rdap'))}
      {ipTile(checks.ip, r('ip'))}
      {waybackTile(checks.wayback, r('wayback'))}
      {webTiles(checks.web, hasProxy ? r('web') : undefined, onConfigureProxy)}
    </>
  )
}
