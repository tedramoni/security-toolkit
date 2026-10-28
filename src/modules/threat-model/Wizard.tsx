import { useCallback } from 'react'
import { Link, Navigate, useNavigate, useParams } from 'react-router-dom'
import type { SetModels } from './index.tsx'
import type { ThreatModel } from './model.ts'
import { touch } from './model.ts'
import { SystemStep } from './steps/SystemStep.tsx'
import { ElementsStep } from './steps/ElementsStep.tsx'
import { FlowsStep } from './steps/FlowsStep.tsx'
import { ThreatsStep } from './steps/ThreatsStep.tsx'
import { SummaryStep } from './steps/SummaryStep.tsx'
import type { StepId } from './wizardSteps.ts'
import { STEPS } from './wizardSteps.ts'

export type UpdateModel = (fn: (m: ThreatModel) => ThreatModel) => void

export interface StepProps {
  model: ThreatModel
  update: UpdateModel
  goTo: (step: StepId) => void
}

interface Props {
  base: string
  models: ThreatModel[]
  setModels: SetModels
}

export function Wizard({ base, models, setModels }: Props) {
  const { id = '', step = 'system' } = useParams()
  const navigate = useNavigate()
  const model = models.find((m) => m.id === id)

  const update: UpdateModel = useCallback(
    (fn) => setModels((ms) => ms.map((m) => (m.id === id ? touch(fn(m)) : m))),
    [id, setModels],
  )
  const goTo = useCallback((s: StepId) => navigate(`${base}/${encodeURIComponent(id)}/${s}`), [base, id, navigate])

  if (!model) {
    return (
      <div className="stack">
        <header className="page-header">
          <h1>Threat model not found</h1>
          <p>It may have been deleted, or it lives in another browser (models are stored locally).</p>
        </header>
        <p>
          <Link to={base}>← Back to all threat models</Link>
        </p>
      </div>
    )
  }
  const index = STEPS.findIndex((s) => s.id === step)
  if (index < 0) return <Navigate to={`${base}/${encodeURIComponent(id)}/system`} replace />
  const props: StepProps = { model, update, goTo }

  return (
    <div className="stack">
      <header className="page-header">
        <p className="small">
          <Link to={base}>← All threat models</Link>
        </p>
        <h1>{model.name || 'Untitled threat model'}</h1>
        <p>STRIDE per element — work through the steps in order, or jump to any step.</p>
      </header>

      <div className="tabs" role="tablist" aria-label="Threat model steps">
        {STEPS.map((s) => (
          <button
            key={s.id}
            type="button"
            role="tab"
            className="tab"
            aria-selected={s.id === step}
            onClick={() => goTo(s.id)}
          >
            {s.label}
          </button>
        ))}
      </div>

      <section role="tabpanel" aria-label={STEPS[index].label}>
        {step === 'system' && <SystemStep {...props} />}
        {step === 'elements' && <ElementsStep {...props} />}
        {step === 'flows' && <FlowsStep {...props} />}
        {step === 'threats' && <ThreatsStep {...props} />}
        {step === 'summary' && <SummaryStep {...props} />}
      </section>

      <div className="row">
        {index > 0 && (
          <button type="button" className="btn" onClick={() => goTo(STEPS[index - 1].id)}>
            ← {STEPS[index - 1].label}
          </button>
        )}
        <span className="spacer" />
        {index < STEPS.length - 1 && (
          <button type="button" className="btn btn-primary" onClick={() => goTo(STEPS[index + 1].id)}>
            {STEPS[index + 1].label} →
          </button>
        )}
      </div>
    </div>
  )
}
