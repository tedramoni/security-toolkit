import { useId, useRef, useState } from 'react'
import { CopyButton } from '../../lib/CopyButton'
import type { Operation } from './encoders'
import { OPERATIONS } from './encoders'

const GROUPS = [...new Set(OPERATIONS.map((o) => o.group))]

export function EncodeTab() {
  const [input, setInput] = useState('')
  const [output, setOutput] = useState('')
  const [error, setError] = useState<string>()
  const [lastOp, setLastOp] = useState<Operation>()
  const runSeq = useRef(0)
  const inId = useId()
  const outId = useId()

  async function run(op: Operation) {
    const seq = ++runSeq.current
    setLastOp(op)
    try {
      const result = await op.run(input)
      if (seq !== runSeq.current) return
      setOutput(result)
      setError(undefined)
    } catch (e) {
      if (seq !== runSeq.current) return
      setOutput('')
      setError((e as Error).message || 'Operation failed')
    }
  }

  return (
    <div className="stack">
      <p className="small muted">
        Everything runs locally in your browser. Encoding is not encryption: Base64, hex and URL encoding are trivially
        reversible. Plain SHA hashes are not suitable for storing passwords — use Argon2id, scrypt or bcrypt.
      </p>
      <label htmlFor={inId}>Input</label>
      <textarea
        id={inId}
        value={input}
        onChange={(e) => {
          // The output no longer matches the input (e.g. a stale hash) — clear it rather than let it be copied.
          runSeq.current++
          setInput(e.target.value)
          setOutput('')
          setError(undefined)
        }}
        spellCheck={false}
        rows={6}
      />

      <div className="toolbox-ops" role="group" aria-label="Operations">
        {GROUPS.map((g) => (
          <div key={g} className="toolbox-ops-group">
            <span className="toolbox-ops-label">{g}</span>
            {OPERATIONS.filter((o) => o.group === g).map((op) => (
              <button
                key={op.id}
                type="button"
                className="btn btn-sm toolbox-op"
                aria-pressed={lastOp?.id === op.id}
                onClick={() => void run(op)}
              >
                {op.label}
              </button>
            ))}
          </div>
        ))}
      </div>

      {lastOp?.note && <div className={`callout small${lastOp.group === 'Hash' && lastOp.id === 'sha1' ? ' warn' : ''}`}>{lastOp.note}</div>}
      {error && (
        <div className="callout error" role="alert">
          {lastOp ? `${lastOp.label}: ` : ''}
          {error}
        </div>
      )}

      <label htmlFor={outId}>Output{lastOp ? ` — ${lastOp.label}` : ''}</label>
      <textarea id={outId} value={output} readOnly spellCheck={false} rows={6} />
      <div className="row">
        <button
          type="button"
          className="btn"
          disabled={output === ''}
          onClick={() => {
            runSeq.current++ // a still-running hash must not overwrite the cleared output
            setInput(output)
            setOutput('')
            setError(undefined)
          }}
        >
          ↑ Swap: use output as input
        </button>
        <CopyButton text={output} label="Copy output" />
        <span className="spacer" />
        <span className="small muted">
          {input.length} chars in · {output.length} chars out
        </span>
      </div>
    </div>
  )
}
