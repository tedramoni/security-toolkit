import { afterEach, describe, expect, it, vi } from 'vitest'
import { BakeClient } from './client'
import type { WorkerRequest, WorkerResponse } from './worker'

/** Minimal fake Worker: records posted jobs; a terminated worker silently drops messages, like a real one. */
class FakeWorker {
  static instances: FakeWorker[] = []
  onmessage: ((e: MessageEvent<WorkerResponse>) => void) | null = null
  onerror: ((e: ErrorEvent) => void) | null = null
  terminated = false
  received: WorkerRequest[] = []
  constructor() {
    FakeWorker.instances.push(this)
  }
  postMessage(req: WorkerRequest) {
    if (this.terminated) return
    this.received.push(req)
  }
  terminate() {
    this.terminated = true
  }
  /** Answer the last received job. */
  reply() {
    const req = this.received[this.received.length - 1]
    const res: WorkerResponse =
      req.kind === 'magic'
        ? { id: req.id, kind: 'magic', results: [] }
        : { id: req.id, kind: 'run', result: { output: req.input, steps: [], totalMs: 0 } }
    this.onmessage?.({ data: res } as MessageEvent<WorkerResponse>)
  }
}

describe('BakeClient', () => {
  afterEach(() => {
    vi.unstubAllGlobals()
    FakeWorker.instances = []
  })

  it('a superseding job goes to a fresh, live worker (regression: it was posted to the terminated one and hung)', async () => {
    vi.stubGlobal('Worker', FakeWorker)
    const client = new BakeClient()
    const first = client.run([], new Uint8Array([1]))
    const firstRejected = expect(first).rejects.toThrow('Superseded')
    const second = client.run([], new Uint8Array([2]))
    await firstRejected
    expect(FakeWorker.instances).toHaveLength(2)
    expect(FakeWorker.instances[0].terminated).toBe(true)
    const live = FakeWorker.instances[1]
    expect(live.terminated).toBe(false)
    expect(live.received).toHaveLength(1)
    live.reply()
    const r = await second
    expect([...r.output]).toEqual([2])
    client.dispose()
  })

  it('cancel rejects the pending job and the next job still runs', async () => {
    vi.stubGlobal('Worker', FakeWorker)
    const client = new BakeClient()
    const job = client.magic(new Uint8Array([1]))
    client.cancel()
    await expect(job).rejects.toThrow('Cancelled')
    const next = client.magic(new Uint8Array([1]))
    FakeWorker.instances[FakeWorker.instances.length - 1].reply()
    await expect(next).resolves.toEqual([])
    client.dispose()
  })
})
