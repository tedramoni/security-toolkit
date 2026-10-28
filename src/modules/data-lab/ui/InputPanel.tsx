import { useId, useRef, useState } from 'react'
import { isValidUtf8, utf8Decode } from '../engine/bytes'
import type { Bytes } from '../engine/types'
import { formatBytes } from './format'

export const MAX_FILE_BYTES = 50 * 1024 * 1024
export const AUTO_BAKE_MAX_BYTES = 5 * 1024 * 1024

export type InputState = { kind: 'text'; text: string } | { kind: 'file'; name: string; bytes: Bytes }

interface Props {
  input: InputState
  inputBytes: Bytes
  onChange(next: InputState): void
}

export function InputPanel({ input, inputBytes, onChange }: Props) {
  const id = useId()
  const fileRef = useRef<HTMLInputElement>(null)
  const [warning, setWarning] = useState<string>()

  const loadFile = async (file: File) => {
    setWarning(undefined)
    if (file.size > MAX_FILE_BYTES) {
      setWarning(`${file.name} is ${formatBytes(file.size)}; the limit is ${formatBytes(MAX_FILE_BYTES)}.`)
      return
    }
    const bytes = new Uint8Array(await file.arrayBuffer())
    onChange({ kind: 'file', name: file.name, bytes })
  }

  const editable = input.kind === 'file' && input.bytes.length <= 2 * 1024 * 1024 && isValidUtf8(input.bytes)

  return (
    <section className="card data-lab-io" aria-labelledby={`${id}-h`}>
      <div className="row data-lab-io-head">
        <h2 id={`${id}-h`}>Input</h2>
        <span className="spacer" />
        <input
          ref={fileRef}
          type="file"
          className="sr-only"
          tabIndex={-1}
          aria-hidden="true"
          onChange={(e) => {
            const f = e.target.files?.[0]
            if (f) void loadFile(f)
            e.target.value = ''
          }}
        />
        <button type="button" className="btn btn-sm" onClick={() => fileRef.current?.click()}>
          Load file…
        </button>
        <button
          type="button"
          className="btn btn-sm"
          disabled={input.kind === 'text' && input.text === ''}
          onClick={() => {
            setWarning(undefined)
            onChange({ kind: 'text', text: '' })
          }}
        >
          Clear
        </button>
      </div>
      {warning && (
        <p className="callout warn" role="alert">
          {warning}
        </p>
      )}
      {input.kind === 'file' ? (
        <div
          className="data-lab-file"
          onDragOver={(e) => e.preventDefault()}
          onDrop={(e) => {
            e.preventDefault()
            const f = e.dataTransfer.files[0]
            if (f) void loadFile(f)
          }}
        >
          <p>
            <strong>{input.name}</strong> — {formatBytes(input.bytes.length)} loaded as raw bytes.
          </p>
          {editable && (
            <button type="button" className="btn btn-sm" onClick={() => onChange({ kind: 'text', text: utf8Decode(input.bytes) })}>
              Edit as text
            </button>
          )}
        </div>
      ) : (
        <>
          <label htmlFor={id} className="sr-only">
            Input data
          </label>
          <textarea
            id={id}
            className="data-lab-input"
            value={input.text}
            rows={8}
            spellCheck={false}
            placeholder="Paste or type data here, or drop a file…"
            onChange={(e) => onChange({ kind: 'text', text: e.target.value })}
            onDragOver={(e) => {
              if (e.dataTransfer.types.includes('Files')) e.preventDefault()
            }}
            onDrop={(e) => {
              const f = e.dataTransfer.files[0]
              if (f) {
                e.preventDefault()
                void loadFile(f)
              }
            }}
          />
        </>
      )}
      <p className="small muted data-lab-stats">
        {formatBytes(inputBytes.length)} · {inputBytes.length.toLocaleString('en-US')} bytes
        {inputBytes.length > AUTO_BAKE_MAX_BYTES ? ' · large input: auto-bake is paused, press Bake' : ''}
      </p>
    </section>
  )
}
