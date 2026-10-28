import { describe, expect, it } from 'vitest'
import { newStep, recipeFromParam } from '../engine/recipe'
import type { RecipeStep } from '../engine/types'
import { getOp } from '../ops'
import { makeSavedRecipe, shareLink } from './share'

const op = (id: string) => {
  const o = getOp(id)
  if (!o) throw new Error(id)
  return o
}

describe('saved recipes and share links', () => {
  const withKey: RecipeStep[] = [newStep(op('xor'), { key: { value: 'topsecret', encoding: 'utf8' } })]

  it('saved recipes leave keys out of localStorage unless the user opts in', () => {
    expect(JSON.stringify(makeSavedRecipe('x', withKey))).not.toContain('topsecret')
    expect(JSON.stringify(makeSavedRecipe('x', withKey, true))).toContain('topsecret')
  })

  it('share links round-trip and never contain secrets by default', () => {
    const link = shareLink(withKey, false)
    const param = link.split('recipe=')[1]
    const steps = recipeFromParam(param, getOp)
    expect(steps[0].opId).toBe('xor')
    expect(steps[0].args.key).toEqual({ value: '', encoding: 'hex' })
  })

  it('refuses to build a link too long to be loaded back (regression)', () => {
    const big = Array.from({ length: 20 }, () => newStep(op('find-replace'), { find: 'a'.repeat(4000) }))
    expect(() => shareLink(big, false)).toThrow(/too large for a share link/)
  })
})
