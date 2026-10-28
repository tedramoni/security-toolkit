import { useCallback, useMemo } from 'react'
import { Navigate, Route, Routes, useLocation, useParams } from 'react-router-dom'
import { STORAGE_KEYS, useLocalStorage } from '../../lib/storage.ts'
import type { ThreatModel } from './model.ts'
import { partitionStored } from './model.ts'
import { ModelList } from './ModelList.tsx'
import { Wizard } from './Wizard.tsx'
import './threat-model.css'

export type SetModels = (update: (models: ThreatModel[]) => ThreatModel[]) => void

export default function ThreatModelModule() {
  const [stored, setStored] = useLocalStorage<unknown>(STORAGE_KEYS.threatModels, [])
  // localStorage is untrusted (manual edits, older versions, backup restores): only valid models are shown,
  // but unreadable entries are written back as-is so a single bad entry never wipes the user's data.
  const { models, invalid } = useMemo(() => partitionStored(stored), [stored])
  const setModels: SetModels = useCallback(
    (update) =>
      setStored((prev: unknown) => {
        const p = partitionStored(prev)
        return [...update(p.models), ...p.invalid]
      }),
    [setStored],
  )
  const discardInvalid = useCallback(() => setStored((prev: unknown) => partitionStored(prev).models), [setStored])

  // Absolute base path of this module (e.g. "/threat-model"), derived from the parent splat route,
  // so navigation never depends on how relative paths resolve inside splat routes.
  const { pathname } = useLocation()
  const splat = useParams()['*'] ?? ''
  const base = pathname.slice(0, pathname.length - splat.length).replace(/\/+$/, '')

  return (
    <Routes>
      <Route
        index
        element={<ModelList base={base} models={models} setModels={setModels} invalid={invalid} discardInvalid={discardInvalid} />}
      />
      <Route path=":id" element={<RedirectToFirstStep base={base} />} />
      <Route path=":id/:step" element={<Wizard base={base} models={models} setModels={setModels} />} />
      <Route path="*" element={<Navigate to={base} replace />} />
    </Routes>
  )
}

function RedirectToFirstStep({ base }: { base: string }) {
  const { id = '' } = useParams()
  return <Navigate to={`${base}/${encodeURIComponent(id)}/system`} replace />
}
