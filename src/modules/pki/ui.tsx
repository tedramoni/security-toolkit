/** Shared UI pieces for the PKI tabs. */
import type { ReactNode } from 'react'
import { useId, useMemo, useRef, useState } from 'react'
import { useNow } from './hooks'
import { CopyButton } from '../../lib/CopyButton'
import type { Finding, Severity } from '../toolbox/types'
import { SEVERITY_ORDER, countBySeverity, findingsToMarkdown, sortFindings } from '../toolbox/types'
import type { AsnNode } from './der'
import { describeValue, parseDer, tagName } from './der'
import type { DecodedExtension, ExtensionInfo, GeneralNameInfo } from './extensions'
import { toHex } from './bytes'
import { oidName } from './oids'

/** Only http(s) URLs become links; anything else is shown as text. */
export function SafeLink({ href, children }: { href: string; children?: ReactNode }) {
  let ok = false
  try {
    const u = new URL(href)
    ok = u.protocol === 'http:' || u.protocol === 'https:'
  } catch {
    ok = false
  }
  if (!ok) return <code className="pki-break">{href}</code>
  return (
    <a href={href} target="_blank" rel="noopener noreferrer nofollow" className="pki-break">
      {children ?? href}
    </a>
  )
}

export function SeverityBadge({ severity }: { severity: Severity }) {
  return <span className={`badge sev-${severity}`}>{severity.toUpperCase()}</span>
}

export function PkiFindingList({ findings, reportTitle }: { findings: readonly Finding[]; reportTitle: string }) {
  const counts = countBySeverity(findings)
  const shown = sortFindings(findings)
  return (
    <div className="stack">
      <div className="row">
        <div className="row small" aria-label="Findings by severity">
          {SEVERITY_ORDER.filter((s) => counts[s] > 0).map((s) => (
            <span key={s} className={`badge sev-${s}`}>
              {counts[s]} {s}
            </span>
          ))}
        </div>
        <span className="spacer" />
        {findings.length > 0 && <CopyButton text={findingsToMarkdown(reportTitle, findings)} label="Copy findings as Markdown" />}
      </div>
      <ul className="pki-findings">
        {shown.map((f, i) => (
          <li key={`${f.title}-${i}`} className={`pki-finding sev-${f.severity}`}>
            <div className="pki-finding-title">
              <SeverityBadge severity={f.severity} />
              <span>{f.title}</span>
            </div>
            <p>{f.detail}</p>
            {f.fix && (
              <p className="pki-fix">
                <strong>Fix:</strong> {f.fix}
              </p>
            )}
            {f.ref && (
              <p className="small">
                <SafeLink href={f.ref}>Reference</SafeLink>
              </p>
            )}
          </li>
        ))}
      </ul>
    </div>
  )
}

/** Textarea + file upload + sample/clear buttons. Files are read locally (never uploaded). */
export function PemInput({
  label,
  value,
  onChange,
  onFile,
  accept = '.pem,.crt,.cer,.der,.p7b,.p7c,.csr,.req,.key,.pub,.crl,.txt',
  placeholder,
  rows = 8,
  extraButtons,
}: {
  label: string
  value: string
  onChange: (v: string) => void
  onFile?: (bytes: Uint8Array, name: string) => void
  accept?: string
  placeholder?: string
  rows?: number
  extraButtons?: ReactNode
}) {
  const id = useId()
  const fileRef = useRef<HTMLInputElement>(null)
  const [fileErr, setFileErr] = useState<string>()
  return (
    <div className="stack pki-input">
      <label htmlFor={id}>{label}</label>
      <textarea id={id} value={value} onChange={(e) => onChange(e.target.value)} placeholder={placeholder} rows={rows} spellCheck={false} autoComplete="off" />
      <div className="row">
        {onFile && (
          <>
            <input
              ref={fileRef}
              type="file"
              accept={accept}
              className="sr-only"
              aria-label={`${label}: choose a file`}
              tabIndex={-1}
              onChange={async (e) => {
                const f = e.target.files?.[0]
                e.target.value = ''
                if (!f) return
                if (f.size > 50 * 1024 * 1024) {
                  setFileErr('File larger than 50 MB — refusing to load it in the browser.')
                  return
                }
                setFileErr(undefined)
                onFile(new Uint8Array(await f.arrayBuffer()), f.name)
              }}
            />
            <button type="button" className="btn btn-sm" onClick={() => fileRef.current?.click()}>
              Open file…
            </button>
          </>
        )}
        {extraButtons}
        <button type="button" className="btn btn-sm" onClick={() => onChange('')} disabled={value === ''}>
          Clear
        </button>
      </div>
      {fileErr && (
        <div className="callout error" role="alert">
          {fileErr}
        </div>
      )}
    </div>
  )
}

export function KV({ rows }: { rows: [string, ReactNode][] }) {
  return (
    <dl className="pki-kv">
      {rows.map(([k, v]) => (
        <div key={k} className="pki-kv-row">
          <dt>{k}</dt>
          <dd>{v}</dd>
        </div>
      ))}
    </dl>
  )
}

export function GeneralNames({ names }: { names: GeneralNameInfo[] }) {
  if (names.length === 0) return <span className="muted">—</span>
  return (
    <ul className="pki-list">
      {names.map((n, i) => (
        <li key={i}>
          <span className="badge sev-info">{n.type}</span> {n.type === 'URI' ? <SafeLink href={n.value} /> : <code className="pki-break">{n.value}</code>}
        </li>
      ))}
    </ul>
  )
}

function DecodedView({ d }: { d: DecodedExtension }) {
  switch (d.kind) {
    case 'names':
      return <GeneralNames names={d.names} />
    case 'ku':
      return <span>{d.usages.join(', ') || '(none)'}</span>
    case 'eku':
      return (
        <ul className="pki-list">
          {d.usages.map((u, i) => (
            <li key={i}>
              {u.name ?? 'Unknown purpose'} <code className="muted small">{u.oid}</code>
            </li>
          ))}
        </ul>
      )
    case 'bc':
      return (
        <span>
          CA: <strong>{d.ca ? 'TRUE' : 'FALSE'}</strong>
          {d.pathLen !== undefined && <> · pathLenConstraint: {d.pathLen}</>}
        </span>
      )
    case 'keyId':
      return <code className="pki-break">{d.keyId}</code>
    case 'aki':
      return (
        <div>
          {d.keyId && (
            <div>
              keyIdentifier: <code className="pki-break">{d.keyId}</code>
            </div>
          )}
          {d.issuer && <GeneralNames names={d.issuer} />}
          {d.serial && (
            <div>
              serial: <code>{d.serial}</code>
            </div>
          )}
        </div>
      )
    case 'access':
      return (
        <ul className="pki-list">
          {d.items.map((it, i) => (
            <li key={i}>
              <strong>{it.methodName ?? it.method}</strong>: {it.location.type === 'URI' ? <SafeLink href={it.location.value} /> : <code>{it.location.value}</code>}
            </li>
          ))}
        </ul>
      )
    case 'crldp':
      return (
        <div>
          {d.points.map((p, i) => (
            <div key={i}>
              <GeneralNames names={p.names} />
              {p.reasons && <div className="small muted">reasons: {p.reasons.join(', ')}</div>}
              {p.crlIssuer && (
                <div className="small muted">
                  CRL issuer: {p.crlIssuer.map((n) => n.value).join(', ')}
                </div>
              )}
            </div>
          ))}
        </div>
      )
    case 'policies':
      return (
        <ul className="pki-list">
          {d.policies.map((p, i) => (
            <li key={i}>
              <code>{p.oid}</code> {p.name && <strong>{p.name}</strong>}
              {p.cps.map((u, j) => (
                <div key={j} className="small">
                  CPS: <SafeLink href={u} />
                </div>
              ))}
              {p.notices.map((n, j) => (
                <div key={j} className="small">
                  Notice: {n}
                </div>
              ))}
            </li>
          ))}
        </ul>
      )
    case 'sct':
      return (
        <div>
          <div>
            {d.scts.length} SCT{d.scts.length === 1 ? '' : 's'} embedded (Certificate Transparency)
          </div>
          <ul className="pki-list small">
            {d.scts.map((s, i) => (
              <li key={i}>
                log ID <code className="pki-break">{s.logIdBase64}</code> · {s.timestamp.toISOString()}
              </li>
            ))}
          </ul>
        </div>
      )
    case 'nc':
      return (
        <div>
          <div>Permitted:</div>
          <GeneralNames names={d.permitted} />
          <div>Excluded:</div>
          <GeneralNames names={d.excluded} />
        </div>
      )
    case 'tlsFeature':
      return <span>{d.features.map((f) => (f === 5 ? 'status_request (OCSP Must-Staple)' : f === 17 ? 'status_request_v2' : String(f))).join(', ')}</span>
    case 'integer':
      return <code>{d.value}</code>
    case 'reason':
      return <span>{d.name}</span>
    case 'time':
      return <span>{d.date.toISOString()}</span>
    case 'idp':
      return (
        <div>
          <GeneralNames names={d.names} />
          <div className="small muted">
            {[d.onlyUser && 'only user certs', d.onlyCA && 'only CA certs', d.indirect && 'indirect CRL'].filter(Boolean).join(', ') || 'full CRL'}
          </div>
        </div>
      )
    case 'flag':
    case 'text':
      return <span>{d.text}</span>
  }
}

export function ExtensionsTable({ extensions }: { extensions: ExtensionInfo[] }) {
  if (extensions.length === 0) return <p className="muted">No extensions.</p>
  return (
    <div className="pki-table-wrap">
      <table className="table">
        <thead>
          <tr>
            <th scope="col">Extension</th>
            <th scope="col">Critical</th>
            <th scope="col">Value</th>
          </tr>
        </thead>
        <tbody>
          {extensions.map((e, i) => (
            <tr key={`${e.oid}-${i}`}>
              <td>
                <div>{e.name ?? <em>Unknown extension</em>}</div>
                <code className="small muted">{e.oid}</code>
              </td>
              <td>{e.critical ? <span className="badge sev-medium">critical</span> : <span className="muted">no</span>}</td>
              <td>
                {e.decoded ? (
                  <DecodedView d={e.decoded} />
                ) : e.error ? (
                  <span className="pki-err">{e.error}</span>
                ) : (
                  <code className="pki-break small">{toHex(e.value.subarray(0, 64), ' ')}{e.value.length > 64 ? ' …' : ''}</code>
                )}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  )
}

// ------------------------------------------------------------------------------------------------ ASN.1 tree

const TREE_LIMIT = 400

function TreeNode({ b, n, depth, order, limit }: { b: Uint8Array; n: AsnNode; depth: number; order: WeakMap<AsnNode, number>; limit: number }) {
  if ((order.get(n) ?? Infinity) >= limit) return null
  const label = (
    <>
      <span className="pki-asn-meta">
        {n.offset}+{n.headerLength}+{n.length}
        {n.indefinite ? ' (indef)' : ''}
      </span>{' '}
      <span className="pki-asn-tag">{tagName(n)}</span> <span className="pki-asn-val">{describeValue(b, n, oidName)}</span>
      {n.error && <span className="pki-err"> ⚠ {n.error}</span>}
    </>
  )
  if (!n.children || n.children.length === 0) return <li className="pki-asn-leaf">{label}</li>
  return (
    <li>
      <details open={depth < 3}>
        <summary>{label}</summary>
        <ul>
          {n.children.map((c, i) => (
            <TreeNode key={i} b={b} n={c} depth={depth + 1} order={order} limit={limit} />
          ))}
        </ul>
      </details>
    </li>
  )
}

export function AsnTree({ der }: { der: Uint8Array }) {
  const [limit, setLimit] = useState(TREE_LIMIT)
  const parsed = useMemo(() => parseDer(der, { maxNodes: 20000 }), [der])
  // Depth-first index of every node, so only the first `limit` nodes are rendered.
  const order = useMemo(() => {
    const m = new WeakMap<AsnNode, number>()
    let i = 0
    const walk = (ns: AsnNode[]) => {
      for (const n of ns) {
        m.set(n, i++)
        if (n.children) walk(n.children)
      }
    }
    walk(parsed.nodes)
    return m
  }, [parsed])
  return (
    <div className="stack">
      <p className="small muted">
        offset+header+length · {parsed.nodeCount} nodes{parsed.truncated ? ' (truncated at the node limit)' : ''}. OCTET/BIT STRINGs that contain valid DER are expanded.
      </p>
      {parsed.errors.map((e, i) => (
        <div key={i} className="callout warn small">
          {e}
        </div>
      ))}
      <ul className="pki-asn">
        {parsed.nodes.map((n, i) => (
          <TreeNode key={i} b={der} n={n} depth={0} order={order} limit={limit} />
        ))}
      </ul>
      {parsed.nodeCount > limit && (
        <button type="button" className="btn btn-sm" onClick={() => setLimit((l) => l + 2000)}>
          Show more nodes ({parsed.nodeCount - limit} hidden)
        </button>
      )}
    </div>
  )
}

export function PrivacyNote() {
  return (
    <div className="callout small">
      Everything runs locally in your browser with WebCrypto — nothing is uploaded or logged.
    </div>
  )
}

export function DaysBadge({ notBefore, notAfter }: { notBefore: Date; notAfter: Date }) {
  const now = useNow()
  if (now < notBefore) return <span className="badge sev-medium">not yet valid</span>
  if (now > notAfter) return <span className="badge sev-critical">expired {Math.floor((now.getTime() - notAfter.getTime()) / 86_400_000)} d ago</span>
  const left = Math.floor((notAfter.getTime() - now.getTime()) / 86_400_000)
  return <span className={`badge ${left <= 30 ? 'sev-low' : 'sev-ok'}`}>{left} days left</span>
}
