import type { Stack } from './types'
import { STACK_LABELS, STACKS } from './types'

export function StackPicker({
  value,
  onChange,
  legend = 'Technology scope (none selected = show all items)',
}: {
  value: readonly Stack[]
  onChange: (next: Stack[]) => void
  legend?: string
}) {
  return (
    <fieldset className="checklists-stacks">
      <legend>{legend}</legend>
      {STACKS.map((s) => (
        <label key={s} className="inline">
          <input
            type="checkbox"
            checked={value.includes(s)}
            onChange={(e) =>
              onChange(e.target.checked ? STACKS.filter((x) => x === s || value.includes(x)) : value.filter((x) => x !== s))
            }
          />
          {STACK_LABELS[s]}
        </label>
      ))}
    </fieldset>
  )
}
