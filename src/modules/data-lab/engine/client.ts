/* Main-thread side of the bake worker. One job at a time: a new request (or cancel) terminates the busy worker. */
import { getOp } from '../ops'
import { magic } from './magic'
import type { MagicResult } from './magic'
import { runRecipe } from './runner'
import type { RunOptions, RunResult } from './runner'
import type { Bytes, RecipeStep } from './types'
import type { WorkerRequest, WorkerResponse } from './worker'

export const BAKE_TIMEOUT_MS = 30_000

type Pending = { id: number; resolve: (r: WorkerResponse) => void; reject: (e: Error) => void; timer: ReturnType<typeof setTimeout> }

export class BakeClient {
  private worker: Worker | null = null
  private pending: Pending | null = null
  private seq = 0
  private workerBroken = false

  private ensureWorker(): Worker | null {
    if (this.workerBroken || typeof Worker === 'undefined') return null
    if (!this.worker) {
      try {
        this.worker = new Worker(new URL('./worker.ts', import.meta.url), { type: 'module' })
        this.worker.onmessage = (e: MessageEvent<WorkerResponse>) => {
          const p = this.pending
          if (!p || e.data.id !== p.id) return
          clearTimeout(p.timer)
          this.pending = null
          p.resolve(e.data)
        }
        this.worker.onerror = (e) => {
          const p = this.pending
          this.pending = null
          this.kill()
          if (p) {
            clearTimeout(p.timer)
            p.reject(new Error(`Worker crashed: ${e.message || 'unknown error'}`))
          } else this.workerBroken = true
        }
      } catch {
        this.workerBroken = true
        return null
      }
    }
    return this.worker
  }

  private kill() {
    this.worker?.terminate()
    this.worker = null
  }

  /** Stop the running job (terminates the worker; a fresh one is created on demand). */
  cancel(reason = 'Cancelled') {
    const p = this.pending
    if (!p) return
    this.pending = null
    clearTimeout(p.timer)
    this.kill()
    p.reject(new Error(reason))
  }

  get busy(): boolean {
    return this.pending !== null
  }

  private request(req: WorkerRequest, timeoutMs: number): Promise<WorkerResponse> {
    // Cancel first: cancelling terminates the busy worker, so the new job must go to a freshly created one
    // (posting to the terminated worker would silently drop the job and hang until the timeout).
    if (this.pending) this.cancel('Superseded')
    const w = this.ensureWorker()
    if (!w) return Promise.reject(new Error('no-worker'))
    return new Promise((resolve, reject) => {
      const timer = setTimeout(() => {
        this.cancel(`Timed out after ${timeoutMs / 1000} s (a regular expression with catastrophic backtracking, or a very large input?)`)
      }, timeoutMs)
      this.pending = { id: req.id, resolve, reject, timer }
      // Copy the input so the caller keeps its own buffer.
      w.postMessage(req)
    })
  }

  async run(steps: RecipeStep[], input: Bytes, options: Omit<RunOptions, 'signal'> = {}): Promise<RunResult> {
    const id = ++this.seq
    try {
      const res = await this.request({ id, kind: 'run', steps, input, options }, BAKE_TIMEOUT_MS)
      if (res.kind === 'run') return res.result
      throw new Error(res.kind === 'error' ? res.message : 'Unexpected worker response')
    } catch (e) {
      if ((e as Error).message === 'no-worker') return runRecipe(steps, input, getOp, options)
      throw e
    }
  }

  async magic(input: Bytes, budgetMs = 1500): Promise<MagicResult[]> {
    const id = ++this.seq
    try {
      const res = await this.request({ id, kind: 'magic', input, budgetMs }, budgetMs + 10_000)
      if (res.kind === 'magic') return res.results
      throw new Error(res.kind === 'error' ? res.message : 'Unexpected worker response')
    } catch (e) {
      if ((e as Error).message === 'no-worker') return magic(input, { lookup: getOp, budgetMs })
      throw e
    }
  }

  dispose() {
    this.cancel('Disposed')
    this.kill()
  }
}
