import { utf8Decode, utf8Encode } from '../engine/bytes'
import type { ArgValues, Bytes, SelectArg } from '../engine/types'

/** Wrap a string -> string function as a bytes -> bytes operation body. */
export function textFn(fn: (text: string, args: ArgValues) => string) {
  return (input: Bytes, args: ArgValues): Bytes => utf8Encode(fn(utf8Decode(input), args))
}

/** Split text into lines (LF or CRLF). A single trailing newline does not create an empty last line. */
export function splitLines(text: string): string[] {
  if (text === '') return []
  const lines = text.split(/\r?\n/)
  if (lines.length > 1 && lines[lines.length - 1] === '') lines.pop()
  return lines
}

export const DELIMITERS: Record<string, string> = {
  space: ' ',
  none: '',
  comma: ',',
  semicolon: ';',
  colon: ':',
  newline: '\n',
  crlf: '\r\n',
  tab: '\t',
}

export function delimiterArg(def = 'space', withNone = true): SelectArg {
  const options = [
    { value: 'space', label: 'Space' },
    ...(withNone ? [{ value: 'none', label: 'None' }] : []),
    { value: 'comma', label: 'Comma' },
    { value: 'semicolon', label: 'Semicolon' },
    { value: 'colon', label: 'Colon' },
    { value: 'newline', label: 'Line feed' },
    { value: 'crlf', label: 'CRLF' },
    { value: 'tab', label: 'Tab' },
  ]
  return { key: 'delimiter', label: 'Delimiter', type: 'select', default: def, options }
}

export function sel(key: string, label: string, def: string, options: readonly (readonly [string, string])[]): SelectArg {
  return { key, label, type: 'select', default: def, options: options.map(([value, l]) => ({ value, label: l })) }
}

/** Show a short, safe preview of possibly-binary text (control chars escaped). */
export function safePreview(text: string, max = 80): string {
  let out = ''
  for (const ch of text) {
    if (out.length >= max) return out + '…'
    const c = ch.codePointAt(0) ?? 0
    if (c === 10) out += '\\n'
    else if (c === 13) out += '\\r'
    else if (c === 9) out += '\\t'
    else if (c < 0x20 || c === 0x7f || (c >= 0x80 && c < 0xa0)) out += '\\x' + c.toString(16).padStart(2, '0')
    else out += ch
  }
  return out
}

/** Tokens separated by whitespace, commas or semicolons. */
export function tokens(text: string): string[] {
  return text.split(/[\s,;]+/).filter((t) => t !== '')
}
