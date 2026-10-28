/*
 * Recipe (de)serialization and validation. Recipes are shared through the URL, imported from files and read back
 * from localStorage — all untrusted — so everything is type-checked against the operation definitions.
 * The input data is never part of a recipe.
 */
import { base64Decode, base64Encode, B64_URL, utf8Decode, utf8Encode } from './bytes'
import type { ArgDef, ArgValue, ArgValues, OpDef, RecipeStep, ToggleValue } from './types'
import { TOGGLE_ENCODINGS } from './types'

export const RECIPE_VERSION = 1
export const MAX_STEPS = 100
export const MAX_STRING_ARG = 4096
/** Max length of the base64url `recipe` URL parameter (keeps share links well under browser URL limits). */
export const MAX_RECIPE_PARAM = 16 * 1024
export const MAX_RECIPE_JSON = 64 * 1024

/** Compact serialized form: only non-default args are stored. */
export interface SerializedStep {
  op: string
  args?: Record<string, ArgValue>
  off?: true
  bp?: true
}
export interface SerializedRecipe {
  v: number
  steps: SerializedStep[]
  name?: string
}

export class RecipeError extends Error {
  constructor(message: string) {
    super(message)
    this.name = 'RecipeError'
  }
}

export type OpLookup = (id: string) => OpDef | undefined

export function defaultArgs(op: OpDef): ArgValues {
  const out: ArgValues = {}
  for (const a of op.args) out[a.key] = typeof a.default === 'object' ? { ...a.default } : a.default
  return out
}

export function newStep(op: OpDef, args?: Partial<ArgValues>): RecipeStep {
  return { opId: op.id, args: { ...defaultArgs(op), ...(args as ArgValues | undefined) } }
}

function sameValue(a: ArgValue, b: ArgValue): boolean {
  if (typeof a === 'object' && typeof b === 'object') return a.value === b.value && a.encoding === b.encoding
  return a === b
}

export interface SerializeOptions {
  /** Replace secret args (keys, passwords) with their defaults. */
  omitSecrets?: boolean
  name?: string
}

export function serializeRecipe(steps: readonly RecipeStep[], lookup: OpLookup, opts: SerializeOptions = {}): SerializedRecipe {
  const out: SerializedRecipe = { v: RECIPE_VERSION, steps: [] }
  if (opts.name) out.name = opts.name
  for (const s of steps) {
    const op = lookup(s.opId)
    const step: SerializedStep = { op: s.opId }
    if (op) {
      const args: Record<string, ArgValue> = {}
      for (const def of op.args) {
        const v = s.args[def.key]
        if (v === undefined || (opts.omitSecrets && def.secret) || sameValue(v, def.default)) continue
        args[def.key] = v
      }
      if (Object.keys(args).length) step.args = args
    }
    if (s.disabled) step.off = true
    if (s.breakpoint) step.bp = true
    out.steps.push(step)
  }
  return out
}

/** Whether any step carries a non-default secret argument. */
export function hasSecrets(steps: readonly RecipeStep[], lookup: OpLookup): boolean {
  return steps.some((s) => lookup(s.opId)?.args.some((d) => d.secret && s.args[d.key] !== undefined && !sameValue(s.args[d.key], d.default)))
}

function isPlainObject(v: unknown): v is Record<string, unknown> {
  return typeof v === 'object' && v !== null && !Array.isArray(v)
}

function validateArg(def: ArgDef, v: unknown, where: string): ArgValue {
  switch (def.type) {
    case 'string': {
      if (typeof v !== 'string') throw new RecipeError(`${where}: "${def.key}" must be a string`)
      if (v.length > (def.maxLength ?? MAX_STRING_ARG)) throw new RecipeError(`${where}: "${def.key}" is too long`)
      return v
    }
    case 'number': {
      if (typeof v !== 'number' || !Number.isFinite(v)) throw new RecipeError(`${where}: "${def.key}" must be a finite number`)
      if (def.integer && !Number.isInteger(v)) throw new RecipeError(`${where}: "${def.key}" must be an integer`)
      if ((def.min !== undefined && v < def.min) || (def.max !== undefined && v > def.max)) {
        throw new RecipeError(`${where}: "${def.key}" must be between ${def.min ?? '-∞'} and ${def.max ?? '∞'}`)
      }
      return v
    }
    case 'boolean':
      if (typeof v !== 'boolean') throw new RecipeError(`${where}: "${def.key}" must be true or false`)
      return v
    case 'select':
      if (typeof v !== 'string' || !def.options.some((o) => o.value === v)) {
        throw new RecipeError(`${where}: "${def.key}" must be one of ${def.options.map((o) => o.value).join(', ')}`)
      }
      return v
    case 'toggleString': {
      if (!isPlainObject(v) || typeof v.value !== 'string' || !TOGGLE_ENCODINGS.includes(v.encoding as ToggleValue['encoding'])) {
        throw new RecipeError(`${where}: "${def.key}" must be {"value": string, "encoding": ${TOGGLE_ENCODINGS.join('|')}}`)
      }
      if (v.value.length > MAX_STRING_ARG) throw new RecipeError(`${where}: "${def.key}" is too long`)
      return { value: v.value, encoding: v.encoding as ToggleValue['encoding'] }
    }
  }
}

/** Validate an untrusted parsed recipe and expand it to full steps (defaults filled in). */
export function deserializeRecipe(data: unknown, lookup: OpLookup): RecipeStep[] {
  // Accept a bare steps array too, for hand-written recipes.
  const obj = Array.isArray(data) ? { v: RECIPE_VERSION, steps: data } : data
  if (!isPlainObject(obj)) throw new RecipeError('Recipe must be a JSON object with "v" and "steps"')
  if (obj.v !== RECIPE_VERSION) throw new RecipeError(`Unsupported recipe version ${JSON.stringify(obj.v)} (expected ${RECIPE_VERSION})`)
  if (!Array.isArray(obj.steps)) throw new RecipeError('Recipe "steps" must be an array')
  if (obj.steps.length > MAX_STEPS) throw new RecipeError(`Recipe has ${obj.steps.length} steps; the maximum is ${MAX_STEPS}`)
  return obj.steps.map((raw, i) => {
    const where = `Step ${i + 1}`
    if (!isPlainObject(raw)) throw new RecipeError(`${where}: must be an object`)
    if (typeof raw.op !== 'string') throw new RecipeError(`${where}: missing operation id ("op")`)
    const op = lookup(raw.op)
    if (!op) throw new RecipeError(`${where}: unknown operation "${raw.op.slice(0, 60)}"`)
    const args = defaultArgs(op)
    if (raw.args !== undefined) {
      if (!isPlainObject(raw.args)) throw new RecipeError(`${where} (${op.name}): "args" must be an object`)
      for (const [k, v] of Object.entries(raw.args)) {
        const def = op.args.find((d) => d.key === k)
        if (!def) throw new RecipeError(`${where} (${op.name}): unknown argument "${k.slice(0, 40)}"`)
        args[k] = validateArg(def, v, `${where} (${op.name})`)
      }
    }
    for (const flag of ['off', 'bp'] as const) {
      if (raw[flag] !== undefined && typeof raw[flag] !== 'boolean') throw new RecipeError(`${where}: "${flag}" must be a boolean`)
    }
    const step: RecipeStep = { opId: op.id, args }
    if (raw.off === true) step.disabled = true
    if (raw.bp === true) step.breakpoint = true
    return step
  })
}

export function parseRecipeJson(text: string, lookup: OpLookup): { steps: RecipeStep[]; name?: string } {
  if (text.length > MAX_RECIPE_JSON) throw new RecipeError(`Recipe JSON is larger than ${MAX_RECIPE_JSON / 1024} KB`)
  let data: unknown
  try {
    data = JSON.parse(text)
  } catch (e) {
    throw new RecipeError(`Recipe is not valid JSON: ${(e as Error).message}`)
  }
  const name = isPlainObject(data) && typeof data.name === 'string' ? data.name.slice(0, 200) : undefined
  return { steps: deserializeRecipe(data, lookup), name }
}

/** base64url(JSON) for the `?recipe=` parameter. */
export function recipeToParam(steps: readonly RecipeStep[], lookup: OpLookup, omitSecrets = true): string {
  return base64Encode(utf8Encode(JSON.stringify(serializeRecipe(steps, lookup, { omitSecrets }))), B64_URL, false)
}

export function recipeFromParam(param: string, lookup: OpLookup): RecipeStep[] {
  if (param.length > MAX_RECIPE_PARAM) throw new RecipeError(`Recipe link is too long (max ${MAX_RECIPE_PARAM / 1024} KB)`)
  let json: string
  try {
    json = utf8Decode(base64Decode(param, 'url'))
  } catch {
    throw new RecipeError('Recipe link is corrupted (not valid base64url)')
  }
  return parseRecipeJson(json, lookup).steps
}
