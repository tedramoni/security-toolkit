/* Core types for the Data Lab recipe engine. Values flowing between operations are always bytes. */

/** Byte buffers flowing between operations. Backed by a plain ArrayBuffer so they can go straight into WebCrypto. */
export type Bytes = Uint8Array<ArrayBuffer>

/** Encodings a "toggle string" argument (keys, IVs, salts…) can be typed in. */
export type ToggleEncoding = 'utf8' | 'hex' | 'base64' | 'latin1'
export const TOGGLE_ENCODINGS: readonly ToggleEncoding[] = ['utf8', 'hex', 'base64', 'latin1']
export const TOGGLE_ENCODING_LABELS: Record<ToggleEncoding, string> = {
  utf8: 'UTF-8',
  hex: 'Hex',
  base64: 'Base64',
  latin1: 'Latin1',
}

export interface ToggleValue {
  value: string
  encoding: ToggleEncoding
}

export type ArgValue = string | number | boolean | ToggleValue
export type ArgValues = Record<string, ArgValue>

interface ArgBase {
  key: string
  label: string
  /** Optional hint shown under / next to the control. */
  hint?: string
  /** Secrets (keys, passwords) are left out of share links and the autosaved working recipe by default. */
  secret?: boolean
}

export interface StringArg extends ArgBase {
  type: 'string'
  default: string
  placeholder?: string
  /** Maximum accepted length (default MAX_STRING_ARG). */
  maxLength?: number
}
export interface NumberArg extends ArgBase {
  type: 'number'
  default: number
  min?: number
  max?: number
  /** Only integers are accepted when true. */
  integer?: boolean
}
export interface BooleanArg extends ArgBase {
  type: 'boolean'
  default: boolean
}
export interface SelectArg extends ArgBase {
  type: 'select'
  default: string
  options: readonly { value: string; label: string }[]
}
export interface ToggleStringArg extends ArgBase {
  type: 'toggleString'
  default: ToggleValue
}

export type ArgDef = StringArg | NumberArg | BooleanArg | SelectArg | ToggleStringArg

export const CATEGORIES = [
  'Encoding',
  'Ciphers & crypto',
  'Hashing',
  'Compression',
  'Text',
  'Extractors',
  'Data formats',
  'Bytes & utilities',
] as const
export type Category = (typeof CATEGORIES)[number]

export interface OpContext {
  signal?: AbortSignal
}

export interface OpDef {
  id: string
  name: string
  category: Category
  description: string
  args: readonly ArgDef[]
  run(input: Bytes, args: ArgValues, ctx: OpContext): Bytes | Promise<Bytes>
  /** Output differs between runs for the same input (random bytes, UUIDs). Magic never uses these. */
  nondeterministic?: boolean
  /** Hard cap on input size for operations with super-linear cost (e.g. Base58). */
  maxInputBytes?: number
}

export interface RecipeStep {
  opId: string
  args: ArgValues
  disabled?: boolean
  breakpoint?: boolean
}

/** Error thrown by operations for invalid input — the message is shown to the user as-is. */
export class OpError extends Error {
  constructor(message: string) {
    super(message)
    this.name = 'OpError'
  }
}
