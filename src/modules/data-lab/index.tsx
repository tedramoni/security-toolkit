import { useCallback, useEffect, useMemo, useRef, useState } from 'react'
import { useSearchParams } from 'react-router-dom'
import { readJSON, writeJSON } from '../../lib/storage'
import { BakeClient } from './engine/client'
import { utf8Encode } from './engine/bytes'
import type { MagicResult } from './engine/magic'
import { MAGIC_MAX_INPUT } from './engine/magic'
import { deserializeRecipe, newStep, recipeFromParam, serializeRecipe } from './engine/recipe'
import type { RunResult } from './engine/runner'
import type { Bytes, OpDef, RecipeStep } from './engine/types'
import { getOp } from './ops'
import { AUTO_BAKE_MAX_BYTES, InputPanel } from './ui/InputPanel'
import type { InputState } from './ui/InputPanel'
import { MagicPanel } from './ui/MagicPanel'
import { OperationList } from './ui/OperationList'
import { OutputPanel } from './ui/OutputPanel'
import { RecipePanel } from './ui/RecipePanel'
import { RecipeToolbar } from './ui/RecipeToolbar'
import './data-lab.css'

/** Working recipe + preferences. Secret args (keys, passwords) are not persisted here; input data never is. */
const SETTINGS_KEY = 'scp:data-lab-settings'

interface Settings {
  autoBake: boolean
  autoMagic: boolean
  recipe?: unknown
}

function loadSettings(): { settings: Settings; steps: RecipeStep[] } {
  const s = readJSON<Partial<Settings> | null>(SETTINGS_KEY, null)
  const settings: Settings = {
    autoBake: typeof s?.autoBake === 'boolean' ? s.autoBake : true,
    autoMagic: typeof s?.autoMagic === 'boolean' ? s.autoMagic : true,
  }
  let steps: RecipeStep[] = []
  try {
    if (s?.recipe) steps = deserializeRecipe(s.recipe, getOp)
  } catch {
    /* ignore a corrupt stored recipe */
  }
  return { settings, steps }
}

const EMPTY: Bytes = new Uint8Array(0)

/** Whether a run result still lines up with the recipe (same ops in the same order, same enabled steps). */
function sameShape(a: readonly RecipeStep[], b: readonly RecipeStep[]): boolean {
  return a.length === b.length && a.every((s, i) => s.opId === b[i].opId && !!s.disabled === !!b[i].disabled)
}

export default function DataLab() {
  const [initial] = useState(loadSettings)
  const [params, setParams] = useSearchParams()
  const [steps, setSteps] = useState<RecipeStep[]>(initial.steps)
  const [input, setInput] = useState<InputState>({ kind: 'text', text: '' })
  const [autoBake, setAutoBake] = useState(initial.settings.autoBake)
  const [autoMagic, setAutoMagic] = useState(initial.settings.autoMagic)
  const [baked, setBaked] = useState<{ result: RunResult; steps: RecipeStep[] } | null>(null)
  const [bakeError, setBakeError] = useState<string>()
  const [baking, setBaking] = useState(false)
  const [inspect, setInspect] = useState<number | null>(null)
  const [message, setMessage] = useState<{ kind: 'info' | 'error'; text: string } | null>(null)
  const [magicResults, setMagicResults] = useState<MagicResult[] | null>(null)
  const [magicRunning, setMagicRunning] = useState(false)
  const [magicError, setMagicError] = useState<string>()

  const bakeClient = useRef<BakeClient | null>(null)
  const magicClient = useRef<BakeClient | null>(null)
  const bakeSeq = useRef(0)
  const magicSeq = useRef(0)
  useEffect(() => {
    bakeClient.current = new BakeClient()
    magicClient.current = new BakeClient()
    return () => {
      bakeClient.current?.dispose()
      magicClient.current?.dispose()
    }
  }, [])

  // Load a shared recipe from ?recipe= (adjusting state during render), then drop the parameter from the URL so
  // later edits aren't overwritten on reload.
  const recipeParam = params.get('recipe')
  const [loadedParam, setLoadedParam] = useState<string | null>(null)
  if (recipeParam && recipeParam !== loadedParam) {
    setLoadedParam(recipeParam)
    try {
      const s = recipeFromParam(recipeParam, getOp)
      setSteps(s)
      setInspect(null)
      setMessage({ kind: 'info', text: `Loaded a shared recipe with ${s.length} step${s.length === 1 ? '' : 's'}. Review it before running it on sensitive data.` })
    } catch (e) {
      setMessage({ kind: 'error', text: `Could not load the shared recipe: ${(e as Error).message}` })
    }
  }
  useEffect(() => {
    if (!recipeParam) return
    setParams(
      (prev) => {
        const next = new URLSearchParams(prev)
        next.delete('recipe')
        return next
      },
      { replace: true },
    )
  }, [recipeParam, setParams])

  // Persist preferences and the working recipe (without secrets).
  useEffect(() => {
    writeJSON(SETTINGS_KEY, { autoBake, autoMagic, recipe: serializeRecipe(steps, getOp, { omitSecrets: true }) })
  }, [autoBake, autoMagic, steps])

  const inputBytes = useMemo<Bytes>(() => (input.kind === 'file' ? input.bytes : input.text ? utf8Encode(input.text) : EMPTY), [input])

  const bake = useCallback(
    async (resumeAfter = -1) => {
      const client = bakeClient.current
      if (!client) return
      const seq = ++bakeSeq.current
      setBaking(true)
      setBakeError(undefined)
      try {
        const r = await client.run(steps, inputBytes, { resumeAfter })
        if (seq !== bakeSeq.current) return
        setBaked({ result: r, steps })
      } catch (e) {
        if (seq !== bakeSeq.current) return
        const msg = (e as Error).message
        if (msg !== 'Superseded') setBakeError(msg)
      } finally {
        if (seq === bakeSeq.current) setBaking(false)
      }
    },
    [steps, inputBytes],
  )

  // Auto-bake (debounced) whenever the recipe or input changes.
  useEffect(() => {
    if (!autoBake || inputBytes.length > AUTO_BAKE_MAX_BYTES) return
    const t = setTimeout(() => void bake(), 300)
    return () => clearTimeout(t)
  }, [autoBake, bake, inputBytes.length])

  const cancel = () => {
    bakeSeq.current++
    bakeClient.current?.cancel()
    setBaking(false)
    setBakeError('Cancelled.')
  }

  // Per-step statuses/outputs only make sense while the recipe still has the shape it was baked with; after a step
  // is added, removed, moved or toggled (and before the next bake) they would be attached to the wrong steps.
  const result = baked && sameShape(baked.steps, steps) ? baked.result : null
  const staleOutput = baked && !result ? baked.result.output : undefined

  // The output pane shows the inspected step's output, or the final output.
  const inspected = inspect !== null && result ? result.steps[inspect] : undefined
  const shownBytes: Bytes = inspected?.output ?? result?.output ?? staleOutput ?? inputBytes
  const shownTitle =
    inspect !== null && inspected?.output
      ? `Output after step ${inspect + 1}: ${getOp(steps[inspect]?.opId ?? '')?.name ?? ''}`
      : result?.pausedAt !== undefined
        ? `Output (paused before step ${result.pausedAt + 1})`
        : result?.failedAt !== undefined
          ? result.failedAt === 0
            ? 'Output (step 1 failed: showing the input)'
            : `Output (up to step ${result.failedAt})`
          : staleOutput && !autoBake
            ? 'Output (recipe changed: press Bake)'
            : 'Output'

  const runMagic = useCallback(async (data: Bytes) => {
    const client = magicClient.current
    if (!client) return
    const seq = ++magicSeq.current
    setMagicRunning(true)
    setMagicError(undefined)
    try {
      const r = await client.magic(data)
      if (seq === magicSeq.current) setMagicResults(r)
    } catch (e) {
      if (seq === magicSeq.current && (e as Error).message !== 'Superseded') setMagicError((e as Error).message)
    } finally {
      if (seq === magicSeq.current) setMagicRunning(false)
    }
  }, [])

  useEffect(() => {
    if (!autoMagic || baking || shownBytes.length === 0 || shownBytes.length > MAGIC_MAX_INPUT) return
    const t = setTimeout(() => void runMagic(shownBytes), 400)
    return () => clearTimeout(t)
  }, [autoMagic, baking, shownBytes, runMagic])

  const addOp = (op: OpDef) => setSteps((s) => [...s, newStep(op)])

  const applyMagic = (r: MagicResult) => {
    // Magic analysed the inspected step's output when one is shown, so insert right after that step.
    const at = inspect !== null && inspected?.output ? inspect + 1 : steps.length
    setSteps((s) => [...s.slice(0, at), ...r.steps, ...s.slice(at)])
    setInspect(null)
  }

  const replaceInput = () => {
    const out = shownBytes
    let text: string | null
    try {
      text = new TextDecoder('utf-8', { fatal: true }).decode(out)
    } catch {
      text = null
    }
    setInput(text !== null && out.length <= 2 * 1024 * 1024 ? { kind: 'text', text } : { kind: 'file', name: 'previous-output.bin', bytes: out.slice() })
    setSteps([])
    setInspect(null)
    setMessage({ kind: 'info', text: 'Output moved to the input; the recipe was cleared.' })
  }

  const failed = result?.failedAt !== undefined ? result.steps[result.failedAt] : undefined

  return (
    <div className="data-lab">
      <header className="page-header">
        <h1>Data Lab</h1>
        <p>
          Chain encoding, crypto, compression, hashing, extraction and parsing operations into a recipe, inspect every
          intermediate step, and let Magic guess how unknown data is encoded. Everything runs locally in your browser, in a
          background worker. Your input is never stored or put into share links.
        </p>
      </header>

      {message && (
        <div className={`callout data-lab-message${message.kind === 'error' ? ' error' : ''}`} role={message.kind === 'error' ? 'alert' : 'status'}>
          <span>{message.text}</span>
          <button type="button" className="btn btn-sm" onClick={() => setMessage(null)} aria-label="Dismiss message">
            ✕
          </button>
        </div>
      )}

      <div className="data-lab-layout">
        <OperationList onAdd={addOp} />

        <section className="card data-lab-recipe" aria-labelledby="data-lab-recipe-h">
          <div className="row data-lab-io-head">
            <h2 id="data-lab-recipe-h">Recipe</h2>
            <span className="muted small">
              {steps.length} step{steps.length === 1 ? '' : 's'}
            </span>
          </div>
          <RecipeToolbar
            steps={steps}
            onLoad={(s, text) => {
              setSteps(s)
              setInspect(null)
              setBaked(null)
              if (text !== undefined) setInput({ kind: 'text', text })
            }}
            onMessage={setMessage}
          />
          <RecipePanel steps={steps} onChange={setSteps} result={result} inspect={inspect} onInspect={setInspect} />
          <div className="row data-lab-bake">
            <button type="button" className="btn btn-primary" onClick={() => void bake()} disabled={baking}>
              {baking ? 'Baking…' : 'Bake'}
            </button>
            {baking && (
              <button type="button" className="btn" onClick={cancel}>
                Cancel
              </button>
            )}
            <label className="inline">
              <input type="checkbox" checked={autoBake} onChange={(e) => setAutoBake(e.target.checked)} />
              Auto-bake
            </label>
            {result && !baking && <span className="small muted">Baked in {Math.max(1, Math.round(result.totalMs))} ms</span>}
          </div>
        </section>

        <div className="stack data-lab-io-col">
          <InputPanel input={input} inputBytes={inputBytes} onChange={setInput} />
          {bakeError && (
            <p className="callout error" role="alert">
              Bake failed: {bakeError}
            </p>
          )}
          {failed && result?.failedAt !== undefined && (
            <div className="callout error" role="alert">
              <strong>
                Step {result.failedAt + 1} ({getOp(steps[result.failedAt]?.opId ?? '')?.name ?? 'unknown'}) failed.
              </strong>{' '}
              The output below is from the last step that succeeded.
              <pre className="data-lab-callout-detail">{failed.error}</pre>
            </div>
          )}
          {result?.pausedAt !== undefined && (
            <div className="callout warn row">
              <span>Paused at the breakpoint before step {result.pausedAt + 1}.</span>
              <button type="button" className="btn btn-sm" onClick={() => void bake(result.pausedAt)}>
                Continue
              </button>
            </div>
          )}
          {inspect !== null && inspected && !inspected.output && (
            <p className="callout warn">
              {inspected.status === 'ok'
                ? 'This intermediate output was not kept (memory budget exceeded), so the final output is shown.'
                : `Step ${inspect + 1} has no output (${inspected.status === 'disabled' ? 'disabled' : inspected.status === 'error' ? 'failed' : 'not run'}).`}
            </p>
          )}
          <OutputPanel bytes={shownBytes} title={shownTitle} onReplaceInput={replaceInput} />
          <MagicPanel
            results={shownBytes.length ? magicResults : null}
            running={magicRunning}
            error={magicError}
            auto={autoMagic}
            onAutoChange={setAutoMagic}
            onRun={() => void runMagic(shownBytes)}
            onApply={applyMagic}
            target={inspected?.output ? `output of step ${(inspect ?? 0) + 1}` : steps.length ? 'current output' : 'input'}
          />
        </div>
      </div>
    </div>
  )
}
