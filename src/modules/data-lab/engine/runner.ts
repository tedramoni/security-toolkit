import type { Bytes, OpDef, RecipeStep } from './types'
import { OpError } from './types'

export type StepStatus = 'ok' | 'error' | 'disabled' | 'not-run'

export interface StepResult {
  status: StepStatus
  /** Output after this step (only when intermediates are kept and within the memory budget). */
  output?: Bytes
  outputLength?: number
  error?: string
  ms?: number
}

export interface RunResult {
  /** Output of the last step that ran successfully (the input if none ran). */
  output: Bytes
  steps: StepResult[]
  /** Index of the step that failed. */
  failedAt?: number
  /** Execution paused before this step because it has a breakpoint. */
  pausedAt?: number
  aborted?: boolean
  totalMs: number
}

export interface RunOptions {
  signal?: AbortSignal
  /** Byte budget for keeping intermediate outputs (step-through). Default 64 MB. */
  intermediateBudget?: number
  /** Breakpoints at indices <= this value are ignored (used to "continue" past a pause). -1 = honour all. */
  resumeAfter?: number
  /** Ignore all breakpoints. */
  ignoreBreakpoints?: boolean
}

export const DEFAULT_INTERMEDIATE_BUDGET = 64 * 1024 * 1024

const now = () => (typeof performance !== 'undefined' ? performance.now() : Date.now())

export function errorMessage(e: unknown): string {
  if (e instanceof OpError) return e.message
  if (e instanceof Error) {
    if (e.name === 'AbortError') return 'Aborted'
    return e.message || e.name
  }
  return String(e)
}

/** Run a recipe sequentially. Never throws: per-step errors are recorded and execution stops at the failing step. */
export async function runRecipe(
  steps: readonly RecipeStep[],
  input: Bytes,
  lookup: (id: string) => OpDef | undefined,
  opts: RunOptions = {},
): Promise<RunResult> {
  const t0 = now()
  const results: StepResult[] = steps.map((s) => ({ status: s.disabled ? 'disabled' : 'not-run' }))
  let data = input
  let budget = opts.intermediateBudget ?? DEFAULT_INTERMEDIATE_BUDGET
  const resumeAfter = opts.resumeAfter ?? -1
  for (let i = 0; i < steps.length; i++) {
    const step = steps[i]
    if (opts.signal?.aborted) return { output: data, steps: results, aborted: true, totalMs: now() - t0 }
    if (step.breakpoint && !opts.ignoreBreakpoints && i > resumeAfter) {
      return { output: data, steps: results, pausedAt: i, totalMs: now() - t0 }
    }
    if (step.disabled) continue
    const op = lookup(step.opId)
    const r = results[i]
    const ts = now()
    try {
      if (!op) throw new OpError(`Unknown operation "${step.opId}"`)
      if (op.maxInputBytes !== undefined && data.length > op.maxInputBytes) {
        throw new OpError(`Input is ${data.length.toLocaleString('en-US')} bytes; ${op.name} is limited to ${op.maxInputBytes.toLocaleString('en-US')} bytes`)
      }
      const out = await op.run(data, step.args, { signal: opts.signal })
      data = out
      r.status = 'ok'
      r.outputLength = out.length
      if (out.length <= budget) {
        r.output = out
        budget -= out.length
      }
    } catch (e) {
      r.status = 'error'
      r.error = errorMessage(e)
      r.ms = now() - ts
      if (opts.signal?.aborted) return { output: data, steps: results, aborted: true, totalMs: now() - t0 }
      return { output: data, steps: results, failedAt: i, totalMs: now() - t0 }
    }
    r.ms = now() - ts
  }
  return { output: data, steps: results, totalMs: now() - t0 }
}
