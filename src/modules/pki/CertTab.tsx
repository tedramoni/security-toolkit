import { useMemo, useState } from 'react'
import { CopyButton } from '../../lib/CopyButton'
import type { CertInfo, Fingerprints } from './cert'
import { decodeCertificate, fingerprints, isSelfIssued, serialDisplay } from './cert'
import { certsFromText } from './certInput'
import { lintCertificate, validityDays } from './lint'
import { toPem } from './pem'
import { ISRG_ROOT_X1_PEM, LE_R12_PEM } from './publicCerts'
import { getSamplePki } from './samples'
import { AsnTree, DaysBadge, ExtensionsTable, KV, PemInput, PkiFindingList, PrivacyNote } from './ui'
import { downloadBytes, useAsync, useDebounced } from './hooks'
import { bytesToInputText } from './fileInput'
import { verifyCertSignature } from './verify'
import { formatName } from './names'

interface Decoded {
  info?: CertInfo
  error?: string
  fp?: Fingerprints
  selfSigned?: boolean
}

const PAGE = 10

async function decodeAll(ders: Uint8Array[]): Promise<Decoded[]> {
  return Promise.all(
    ders.map(async (d) => {
      try {
        const info = decodeCertificate(d)
        const [fp, ss] = await Promise.all([fingerprints(info), isSelfIssued(info) ? verifyCertSignature(info.der, info.der) : Promise.resolve({ ok: false })])
        return { info, fp, selfSigned: ss.ok }
      } catch (e) {
        return { error: (e as Error).message }
      }
    }),
  )
}

export function CertTab() {
  const [text, setText] = useState('')
  const [shown, setShown] = useState(PAGE)
  const debounced = useDebounced(text, 250)
  const input = useMemo(() => certsFromText(debounced), [debounced])
  const { data, loading } = useAsync(input.certs, decodeAll)

  const loadSample = async (which: 'leaf' | 'bad' | 'le') => {
    if (which === 'le') return setText(`${LE_R12_PEM}${ISRG_ROOT_X1_PEM}`)
    const pki = await getSamplePki()
    setText(which === 'leaf' ? pki.pem.leaf : pki.pem.badLeaf)
  }

  return (
    <div className="stack">
      <PrivacyNote />
      <PemInput
        label="Certificate(s): PEM (one or many, surrounding text is ignored), base64/hex DER, or a .pem/.crt/.cer/.der/.p7b file"
        value={text}
        onChange={(v) => {
          setText(v)
          setShown(PAGE)
        }}
        onFile={(bytes) => setText(bytesToInputText(bytes, 'CERTIFICATE'))}
        placeholder="-----BEGIN CERTIFICATE-----"
        extraButtons={
          <>
            <button type="button" className="btn btn-sm" onClick={() => loadSample('leaf')}>
              Sample: generated TLS leaf
            </button>
            <button type="button" className="btn btn-sm" onClick={() => loadSample('bad')}>
              Sample: badly issued cert
            </button>
            <button type="button" className="btn btn-sm" onClick={() => loadSample('le')}>
              Sample: Let’s Encrypt R12 + ISRG Root X1
            </button>
          </>
        }
      />
      {input.warnings.map((w, i) => (
        <div key={i} className="callout warn small" role="status">
          {w}
        </div>
      ))}
      {input.skipped.length > 0 && <p className="small muted">Skipped non-certificate blocks: {input.skipped.join(', ')}.</p>}
      {loading && input.certs.length > 0 && !data && <p className="muted">Decoding…</p>}
      {data && data.length > 1 && <p className="small muted">{data.length} certificates found.</p>}
      {data?.slice(0, shown).map((d, i) => (
        <CertCard key={i} index={i} d={d} total={data.length} />
      ))}
      {data && data.length > shown && (
        <button type="button" className="btn" onClick={() => setShown((s) => s + PAGE)}>
          Show {Math.min(PAGE, data.length - shown)} more ({data.length - shown} hidden)
        </button>
      )}
    </div>
  )
}

function CertCard({ d, index, total }: { d: Decoded; index: number; total: number }) {
  if (!d.info) {
    return (
      <div className="callout error" role="alert">
        Certificate #{index + 1}: {d.error}
      </div>
    )
  }
  const c = d.info
  const findings = lintCertificate(c, { selfSigned: d.selfSigned })
  const cn = c.subject.flatMap((r) => r.filter((a) => a.short === 'CN').map((a) => a.value))[0]
  const pem = toPem(c.der, 'CERTIFICATE')
  return (
    <section className="card stack" aria-label={`Certificate ${index + 1}`}>
      <div className="row">
        <h2 className="pki-h">
          {total > 1 && <span className="muted">#{index + 1} </span>}
          {cn ?? (c.subjectString || '(empty subject)')}
        </h2>
        <DaysBadge notBefore={c.notBefore} notAfter={c.notAfter} />
        {d.selfSigned && <span className="badge sev-info">self-signed</span>}
        <span className="spacer" />
        <CopyButton text={pem} label="Copy PEM" />
        <button type="button" className="btn" onClick={() => downloadBytes(`${(cn ?? 'certificate').replace(/[^A-Za-z0-9.-]+/g, '_')}.der`, c.der, 'application/pkix-cert')}>
          Download DER
        </button>
      </div>
      <KV
        rows={[
          ['Subject', <RdnList key="s" rdns={c.subject} />],
          ['Issuer', <RdnList key="i" rdns={c.issuer} />],
          ['Serial', <code key="sn" className="pki-break">{serialDisplay(c)}</code>],
          ['Version', `v${c.version}`],
          [
            'Validity',
            <span key="v">
              {c.notBefore.toISOString()} → {c.notAfter.toISOString()} <span className="muted">({Math.round(validityDays(c))} days)</span>
            </span>,
          ],
          ['Signature', c.signatureAlg.name],
          ['Public key', c.publicKey.summary],
          ['SHA-256', <code key="f2" className="pki-break">{d.fp?.sha256 ?? '…'}</code>],
          ['SHA-1', <code key="f1" className="pki-break">{d.fp?.sha1 ?? '…'}</code>],
          ['SPKI SHA-256', <code key="f3" className="pki-break">{d.fp?.spkiSha256 ?? '…'}</code>],
        ]}
      />
      <h3>Extensions</h3>
      <ExtensionsTable extensions={c.extensions} />
      <h3>Lint</h3>
      <PkiFindingList findings={findings} reportTitle={`Certificate lint: ${cn ?? formatName(c.subject)}`} />
      <details className="pki-details">
        <summary>Raw ASN.1 structure</summary>
        <AsnTree der={c.der} />
      </details>
    </section>
  )
}

export function RdnList({ rdns }: { rdns: CertInfo['subject'] }) {
  if (rdns.length === 0) return <span className="muted">(empty)</span>
  return (
    <span className="pki-rdns">
      {rdns.map((r, i) => (
        <span key={i} className="pki-rdn">
          {r.map((a, j) => (
            <span key={j} title={a.oid}>
              {j > 0 && ' + '}
              <span className="muted">{a.short}=</span>
              {a.value}
            </span>
          ))}
        </span>
      ))}
    </span>
  )
}
