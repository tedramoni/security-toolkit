import { useId, useMemo, useState } from 'react'
import { CopyButton } from '../../../lib/CopyButton'
import { detectFileType, detectType, printableRatio, shannonEntropy } from '../engine/analysis'
import { isValidUtf8, utf8Decode } from '../engine/bytes'
import type { Bytes } from '../engine/types'
import { hexdump } from '../ops/formats'
import { downloadBytes, formatBytes } from './format'

const TEXT_CAP = 512 * 1024
const HEX_CAP = 64 * 1024

interface Props {
  bytes: Bytes
  title: string
  onReplaceInput(): void
}

type View = 'auto' | 'text' | 'hex'

export function OutputPanel({ bytes, title, onReplaceInput }: Props) {
  const [view, setView] = useState<View>('auto')
  // "Show more" multiplier, reset whenever a new output arrives.
  const [capState, setCapState] = useState<{ bytes: Bytes; cap: number }>({ bytes, cap: 1 })
  const cap = capState.bytes === bytes ? capState.cap : 1
  const setCap = (f: (c: number) => number) => setCapState({ bytes, cap: f(cap) })
  const outId = useId()

  const info = useMemo(() => {
    const sample = bytes.subarray(0, 1024 * 1024)
    const utf8 = isValidUtf8(bytes.length <= 8 * 1024 * 1024 ? bytes : sample)
    const looksText = utf8 && printableRatio(sample) > 0.9
    return { utf8, looksText, entropy: shannonEntropy(sample), type: detectType(sample) }
  }, [bytes])

  const effective: 'text' | 'hex' = view === 'auto' ? (info.looksText || bytes.length === 0 ? 'text' : 'hex') : view
  const limit = (effective === 'text' ? TEXT_CAP : HEX_CAP) * cap
  const truncated = bytes.length > limit
  const shown = useMemo(() => {
    const slice = bytes.subarray(0, limit)
    return effective === 'text' ? utf8Decode(slice) : hexdump(slice, 16)
  }, [bytes, limit, effective])
  const copyText = useMemo(() => (effective === 'text' && truncated ? utf8Decode(bytes.subarray(0, 64 * 1024 * 1024)) : shown), [bytes, effective, truncated, shown])
  const lines = useMemo(() => (shown === '' ? 0 : (shown.match(/\n/g)?.length ?? 0) + (shown.endsWith('\n') ? 0 : 1)), [shown])

  const download = () => {
    const sig = detectFileType(bytes)
    const ext = sig?.ext ?? (info.utf8 ? 'txt' : 'bin')
    downloadBytes(`data-lab-output.${ext}`, bytes, sig?.mime ?? (info.utf8 ? 'text/plain' : 'application/octet-stream'))
  }

  return (
    <section className="card data-lab-io" aria-labelledby={`${outId}-h`}>
      <div className="row data-lab-io-head">
        <h2 id={`${outId}-h`}>{title}</h2>
        <span className="spacer" />
        <div className="row" role="group" aria-label="Output view">
          {(['auto', 'text', 'hex'] as const).map((v) => (
            <button key={v} type="button" className="btn btn-sm" aria-pressed={view === v} onClick={() => setView(v)}>
              {v === 'auto' ? 'Auto' : v === 'text' ? 'Text' : 'Hex'}
            </button>
          ))}
        </div>
      </div>
      <p className="small muted data-lab-stats" aria-live="polite">
        {formatBytes(bytes.length)} · {bytes.length.toLocaleString('en-US')} bytes{effective === 'text' ? ` · ${lines.toLocaleString('en-US')} line${lines === 1 ? '' : 's'}` : ''} ·
        entropy {info.entropy.toFixed(2)} bits/byte · {info.type}
        {!info.utf8 && effective === 'text' ? ' · not valid UTF-8 (invalid sequences shown as �)' : ''}
      </p>
      <label htmlFor={outId} className="sr-only">
        Output
      </label>
      <textarea id={outId} className="data-lab-output" readOnly value={shown} spellCheck={false} wrap={effective === 'hex' ? 'off' : 'soft'} rows={14} />
      {truncated && (
        <div className="row small">
          <span className="muted">
            Showing the first {formatBytes(limit)} of {formatBytes(bytes.length)}.
          </span>
          <button type="button" className="btn btn-sm" onClick={() => setCap((c) => c * 4)}>
            Show more
          </button>
        </div>
      )}
      <div className="row">
        <CopyButton text={copyText} label={effective === 'text' ? 'Copy' : 'Copy hexdump'} />
        <button type="button" className="btn" onClick={download} disabled={bytes.length === 0}>
          Download
        </button>
        <button type="button" className="btn" onClick={onReplaceInput} title="Use this output as the new input">
          Replace input with output
        </button>
      </div>
    </section>
  )
}
