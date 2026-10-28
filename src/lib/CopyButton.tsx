import { useState } from 'react'
import { copyToClipboard } from './download'

export function CopyButton({ text, label = 'Copy' }: { text: string; label?: string }) {
  const [state, setState] = useState<'idle' | 'ok' | 'err'>('idle')
  return (
    <button
      type="button"
      className="btn"
      onClick={async () => {
        setState((await copyToClipboard(text)) ? 'ok' : 'err')
        setTimeout(() => setState('idle'), 1500)
      }}
    >
      {state === 'ok' ? 'Copied ✓' : state === 'err' ? 'Copy failed' : label}
    </button>
  )
}
