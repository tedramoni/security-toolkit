import { newId } from '../../../lib/storage'
import type { SerializedRecipe } from '../engine/recipe'
import { MAX_RECIPE_PARAM, RecipeError, recipeToParam, serializeRecipe } from '../engine/recipe'
import type { RecipeStep } from '../engine/types'
import { getOp } from '../ops'

export const SAVED_RECIPES_KEY = 'scp:data-lab-recipes'

export interface SavedRecipe {
  id: string
  name: string
  savedAt: string
  recipe: SerializedRecipe
}

export function isSavedRecipe(x: unknown): x is SavedRecipe {
  if (typeof x !== 'object' || x === null) return false
  const r = x as SavedRecipe
  return typeof r.id === 'string' && typeof r.name === 'string' && typeof r.recipe === 'object' && r.recipe !== null && Array.isArray(r.recipe.steps)
}

/** Saved recipes live in localStorage: keys/passwords are left out unless the user opts in. */
export function makeSavedRecipe(name: string, steps: readonly RecipeStep[], includeSecrets = false): SavedRecipe {
  return {
    id: newId(),
    name: name.slice(0, 100),
    savedAt: new Date().toISOString(),
    recipe: serializeRecipe(steps, getOp, { omitSecrets: !includeSecrets }),
  }
}

/**
 * Share link for the current page (hash route). The input data is never included.
 * Throws RecipeError when the recipe is too large to be loaded back from a link.
 */
export function shareLink(steps: readonly RecipeStep[], includeSecrets: boolean): string {
  const param = recipeToParam(steps, getOp, !includeSecrets)
  if (param.length > MAX_RECIPE_PARAM) {
    throw new RecipeError(`This recipe is too large for a share link (${Math.ceil(param.length / 1024)} KB, max ${MAX_RECIPE_PARAM / 1024} KB). Use Export instead.`)
  }
  const base = window.location.href.split('#')[0]
  return `${base}#/data-lab?recipe=${param}`
}
