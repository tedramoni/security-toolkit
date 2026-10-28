import { useId, useRef, useState } from 'react'
import { copyToClipboard, downloadJSON, readFileText, slugify } from '../../../lib/download'
import { useLocalStorage } from '../../../lib/storage'
import { deserializeRecipe, hasSecrets, parseRecipeJson, serializeRecipe } from '../engine/recipe'
import type { RecipeStep } from '../engine/types'
import { EXAMPLES } from '../examples'
import { getOp } from '../ops'
import { isSavedRecipe, makeSavedRecipe, SAVED_RECIPES_KEY, shareLink } from './share'

interface Props {
  steps: RecipeStep[]
  onLoad(steps: RecipeStep[], input?: string): void
  onMessage(msg: { kind: 'info' | 'error'; text: string }): void
}

export function RecipeToolbar({ steps, onLoad, onMessage }: Props) {
  const [saved, setSaved] = useLocalStorage<unknown[]>(SAVED_RECIPES_KEY, [])
  const list = (Array.isArray(saved) ? saved : []).filter(isSavedRecipe)
  const [includeSecrets, setIncludeSecrets] = useState(false)
  const fileRef = useRef<HTMLInputElement>(null)
  const exId = useId()
  const loadId = useId()
  const secrets = hasSecrets(steps, getOp)

  const loadSerialized = (r: unknown, input?: string) => {
    try {
      onLoad(deserializeRecipe(r, getOp), input)
    } catch (e) {
      onMessage({ kind: 'error', text: (e as Error).message })
    }
  }

  const [saveName, setSaveName] = useState('')
  const nameId = useId()
  const save = () => {
    const name = saveName.trim()
    if (!name) return
    setSaveName('')
    const item = makeSavedRecipe(name, steps, includeSecrets)
    setSaved([...list.filter((x) => x.name !== item.name), item])
    onMessage({
      kind: 'info',
      text: `Saved "${item.name}" in this browser${secrets ? (includeSecrets ? ' (including keys/passwords)' : ' (keys and passwords left out)') : ''}.`,
    })
  }

  return (
    <div className="data-lab-toolbar">
      <div className="row">
        <label htmlFor={exId} className="sr-only">
          Load an example recipe
        </label>
        <select
          id={exId}
          value=""
          onChange={(e) => {
            const ex = EXAMPLES.find((x) => x.id === e.target.value)
            if (ex) {
              loadSerialized(ex.recipe, ex.input)
              onMessage({ kind: 'info', text: `Loaded example: ${ex.name}. ${ex.description}` })
            }
          }}
        >
          <option value="">Examples…</option>
          {EXAMPLES.map((ex) => (
            <option key={ex.id} value={ex.id}>
              {ex.name}
            </option>
          ))}
        </select>
        <label htmlFor={loadId} className="sr-only">
          Load a saved recipe
        </label>
        <select
          id={loadId}
          value=""
          disabled={list.length === 0}
          onChange={(e) => {
            const r = list.find((x) => x.id === e.target.value)
            if (r) {
              loadSerialized(r.recipe)
              onMessage({ kind: 'info', text: `Loaded "${r.name}".` })
            }
          }}
        >
          <option value="">{list.length ? `Saved (${list.length})…` : 'No saved recipes'}</option>
          {list.map((r) => (
            <option key={r.id} value={r.id}>
              {r.name}
            </option>
          ))}
        </select>
      </div>
      <div className="row">
        <button
          type="button"
          className="btn btn-sm"
          disabled={steps.length === 0}
          onClick={() => downloadJSON('data-lab-recipe.json', serializeRecipe(steps, getOp, { name: 'Data Lab recipe', omitSecrets: !includeSecrets }))}
        >
          Export
        </button>
        <input
          ref={fileRef}
          type="file"
          accept=".json,application/json"
          className="sr-only"
          tabIndex={-1}
          aria-hidden="true"
          onChange={async (e) => {
            const f = e.target.files?.[0]
            e.target.value = ''
            if (!f) return
            try {
              if (f.size > 64 * 1024) throw new Error('Recipe file is larger than 64 KB')
              const { steps: s, name } = parseRecipeJson(await readFileText(f), getOp)
              onLoad(s)
              onMessage({ kind: 'info', text: `Imported ${name ? `"${name}"` : f.name} (${s.length} steps).` })
            } catch (err) {
              onMessage({ kind: 'error', text: `Import failed: ${(err as Error).message}` })
            }
          }}
        />
        <button type="button" className="btn btn-sm" onClick={() => fileRef.current?.click()}>
          Import
        </button>
        <button
          type="button"
          className="btn btn-sm"
          disabled={steps.length === 0}
          onClick={async () => {
            let link: string
            try {
              link = shareLink(steps, includeSecrets)
            } catch (e) {
              onMessage({ kind: 'error', text: (e as Error).message })
              return
            }
            const ok = await copyToClipboard(link)
            onMessage({
              kind: ok ? 'info' : 'error',
              text: ok
                ? `Share link copied (recipe only, never your input${secrets && !includeSecrets ? '; keys and passwords left out' : ''}).`
                : 'Could not copy the link to the clipboard.',
            })
          }}
        >
          Copy share link
        </button>
        <button type="button" className="btn btn-sm btn-danger" disabled={steps.length === 0} onClick={() => onLoad([])}>
          Clear
        </button>
      </div>
      <form
        className="row"
        onSubmit={(e) => {
          e.preventDefault()
          save()
        }}
      >
        <label htmlFor={nameId} className="sr-only">
          Recipe name
        </label>
        <input id={nameId} type="text" className="data-lab-save-name" placeholder="Recipe name" maxLength={100} value={saveName} onChange={(e) => setSaveName(e.target.value)} />
        <button type="submit" className="btn btn-sm" disabled={steps.length === 0 || saveName.trim() === ''}>
          Save
        </button>
      </form>
      {secrets && (
        <label className="inline small">
          <input type="checkbox" checked={includeSecrets} onChange={(e) => setIncludeSecrets(e.target.checked)} />
          Include keys/passwords when sharing, saving or exporting
        </label>
      )}
      {list.length > 0 && (
        <details className="small">
          <summary>Manage saved recipes</summary>
          <ul className="data-lab-saved">
            {list.map((r) => (
              <li key={r.id} className="row">
                <span>{r.name}</span>
                <span className="muted">{r.recipe.steps?.length ?? 0} steps</span>
                <span className="spacer" />
                <button
                  type="button"
                  className="btn btn-sm"
                  onClick={() => downloadJSON(`${slugify(r.name)}.json`, { ...r.recipe, name: r.name })}
                  aria-label={`Export ${r.name}`}
                >
                  Export
                </button>
                <button
                  type="button"
                  className="btn btn-sm btn-danger"
                  onClick={() => setSaved(list.filter((x) => x.id !== r.id))}
                  aria-label={`Delete ${r.name}`}
                >
                  Delete
                </button>
              </li>
            ))}
          </ul>
        </details>
      )}
    </div>
  )
}
