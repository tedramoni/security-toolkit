/* Runs recipes and Magic off the main thread so heavy work (or a runaway user regex) never freezes the page.
 * The UI terminates this worker on cancel/timeout. */
import { getOp } from '../ops'
import { magic } from './magic'
import type { MagicResult } from './magic'
import { runRecipe } from './runner'
import type { RunOptions, RunResult } from './runner'
import type { Bytes, RecipeStep } from './types'

export type WorkerRequest =
  | { id: number; kind: 'run'; steps: RecipeStep[]; input: Bytes; options: Omit<RunOptions, 'signal'> }
  | { id: number; kind: 'magic'; input: Bytes; budgetMs?: number }

export type WorkerResponse =
  | { id: number; kind: 'run'; result: RunResult }
  | { id: number; kind: 'magic'; results: MagicResult[] }
  | { id: number; kind: 'error'; message: string }

/** Minimal typing of the dedicated worker scope (the app's tsconfig uses the DOM lib, not "webworker"). */
interface WorkerScope {
  onmessage: ((e: MessageEvent<WorkerRequest>) => void) | null
  postMessage(message: WorkerResponse, transfer?: Transferable[]): void
}
const scope = self as unknown as WorkerScope

scope.onmessage = async (e: MessageEvent<WorkerRequest>) => {
  const req = e.data
  try {
    if (req.kind === 'run') {
      const result = await runRecipe(req.steps, req.input, getOp, req.options)
      const buffers = new Set<ArrayBuffer>([result.output.buffer])
      for (const s of result.steps) if (s.output) buffers.add(s.output.buffer)
      buffers.delete(req.input.buffer)
      const msg: WorkerResponse = { id: req.id, kind: 'run', result }
      scope.postMessage(msg, [...buffers])
    } else {
      const results = await magic(req.input, { lookup: getOp, budgetMs: req.budgetMs })
      const msg: WorkerResponse = { id: req.id, kind: 'magic', results }
      scope.postMessage(msg)
    }
  } catch (err) {
    const msg: WorkerResponse = { id: req.id, kind: 'error', message: (err as Error).message || String(err) }
    scope.postMessage(msg)
  }
}
