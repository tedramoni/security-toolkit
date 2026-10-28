/* Shared helpers for the Data Lab unit tests. */
import { bytesToHex, hexToBytes, utf8Decode, utf8Encode } from './engine/bytes'
import { defaultArgs } from './engine/recipe'
import type { ArgValues, Bytes } from './engine/types'
import { getOp } from './ops'

export async function runOpBytes(id: string, input: string | Bytes, args: Partial<ArgValues> = {}): Promise<Bytes> {
  const op = getOp(id)
  if (!op) throw new Error(`no op ${id}`)
  const data = typeof input === 'string' ? utf8Encode(input) : input
  return op.run(data, { ...defaultArgs(op), ...(args as ArgValues) }, {})
}

export async function runOp(id: string, input: string | Bytes, args: Partial<ArgValues> = {}): Promise<string> {
  return utf8Decode(await runOpBytes(id, input, args))
}

export async function runOpHex(id: string, input: string | Bytes, args: Partial<ArgValues> = {}): Promise<string> {
  return bytesToHex(await runOpBytes(id, input, args))
}

export const hex = (h: string): Bytes => hexToBytes(h)
export { bytesToHex }
