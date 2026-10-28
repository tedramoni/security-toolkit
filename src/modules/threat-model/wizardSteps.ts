/** Wizard steps, in order. The id is the URL segment. */
export const STEPS = [
  { id: 'system', label: '1. System' },
  { id: 'elements', label: '2. Elements' },
  { id: 'flows', label: '3. Data flows' },
  { id: 'threats', label: '4. Threats' },
  { id: 'summary', label: '5. Summary & export' },
] as const
export type StepId = (typeof STEPS)[number]['id']
