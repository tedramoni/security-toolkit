import type { ArgValue, RecipeStep } from '../engine/types'
import type { RunResult } from '../engine/runner'
import { getOp } from '../ops'
import { ArgControl } from './ArgControl'
import { formatBytes } from './format'

interface Props {
  steps: RecipeStep[]
  onChange(steps: RecipeStep[]): void
  result: RunResult | null
  inspect: number | null
  onInspect(i: number | null): void
}

function move<T>(list: T[], from: number, to: number): T[] {
  const next = [...list]
  const [x] = next.splice(from, 1)
  next.splice(to, 0, x)
  return next
}

export function RecipePanel({ steps, onChange, result, inspect, onInspect }: Props) {
  const update = (i: number, patch: Partial<RecipeStep>) => onChange(steps.map((s, j) => (j === i ? { ...s, ...patch } : s)))
  const setArg = (i: number, key: string, v: ArgValue) => update(i, { args: { ...steps[i].args, [key]: v } })

  const remove = (i: number) => {
    onChange(steps.filter((_, j) => j !== i))
    if (inspect !== null && inspect >= i) onInspect(inspect === i ? null : inspect - 1)
  }
  const moveStep = (i: number, d: -1 | 1) => {
    const j = i + d
    if (j < 0 || j >= steps.length) return
    onChange(move(steps, i, j))
    if (inspect === i) onInspect(j)
    else if (inspect === j) onInspect(i)
  }

  if (steps.length === 0) {
    return (
      <p className="muted data-lab-empty">
        The recipe is empty. Add operations from the list, load an example, or run Magic on your input to get suggestions.
      </p>
    )
  }

  return (
    <ol className="data-lab-steps">
      {steps.map((s, i) => {
        const op = getOp(s.opId)
        const r = result?.steps[i]
        const paused = result?.pausedAt === i
        const cls = [
          'data-lab-step',
          s.disabled && 'is-disabled',
          r?.status === 'error' && 'is-error',
          inspect === i && 'is-selected',
          paused && 'is-paused',
        ]
          .filter(Boolean)
          .join(' ')
        const name = op?.name ?? s.opId
        return (
          <li key={i} className={cls}>
            <div className="data-lab-step-head">
              <span className="data-lab-step-num" aria-hidden="true">
                {i + 1}
              </span>
              <button
                type="button"
                className="data-lab-step-name"
                aria-pressed={inspect === i}
                title="Show the output after this step"
                onClick={() => onInspect(inspect === i ? null : i)}
              >
                {name}
              </button>
              {r?.status === 'ok' && (
                <span className="small muted data-lab-step-meta">
                  {formatBytes(r.outputLength ?? 0)}
                  {r.ms !== undefined && r.ms >= 1 ? ` · ${Math.round(r.ms)} ms` : ''}
                </span>
              )}
              {r?.status === 'error' && <span className="badge sev-critical">error</span>}
              {paused && <span className="badge sev-medium">paused</span>}
              <span className="spacer" />
              <div className="data-lab-step-tools" role="group" aria-label={`Step ${i + 1} controls`}>
                <button type="button" className="btn btn-sm" aria-label={`Move step ${i + 1} (${name}) up`} disabled={i === 0} onClick={() => moveStep(i, -1)}>
                  ↑
                </button>
                <button
                  type="button"
                  className="btn btn-sm"
                  aria-label={`Move step ${i + 1} (${name}) down`}
                  disabled={i === steps.length - 1}
                  onClick={() => moveStep(i, 1)}
                >
                  ↓
                </button>
                <button
                  type="button"
                  className="btn btn-sm"
                  aria-pressed={!!s.breakpoint}
                  aria-label={`Breakpoint on step ${i + 1} (${name})`}
                  title="Breakpoint: pause before this step"
                  onClick={() => update(i, { breakpoint: !s.breakpoint })}
                >
                  ⏸
                </button>
                <button
                  type="button"
                  className="btn btn-sm"
                  aria-pressed={!!s.disabled}
                  aria-label={`Disable step ${i + 1} (${name})`}
                  title="Disable (skip) this step"
                  onClick={() => update(i, { disabled: !s.disabled })}
                >
                  ⊘
                </button>
                <button type="button" className="btn btn-sm btn-danger" aria-label={`Remove step ${i + 1} (${name})`} title="Remove" onClick={() => remove(i)}>
                  ✕
                </button>
              </div>
            </div>
            {op && op.args.length > 0 && (
              <div className="data-lab-args">
                {op.args.map((def) => (
                  <ArgControl key={def.key} def={def} value={s.args[def.key] ?? def.default} onChange={(v) => setArg(i, def.key, v)} />
                ))}
              </div>
            )}
            {r?.status === 'error' && (
              <p className="data-lab-step-error" role="alert">
                {r.error}
              </p>
            )}
          </li>
        )
      })}
    </ol>
  )
}
