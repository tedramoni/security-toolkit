import { describe, expect, it } from 'vitest'
import { runOp, runOpHex } from '../testUtil'
import { escapeString, splitWords, titleCase, toCase, unescapeString } from './text'

describe('case conversions', () => {
  it('upper / lower / title', async () => {
    expect(await runOp('upper-case', 'straße')).toBe('STRASSE')
    expect(await runOp('lower-case', 'ÉCOLE')).toBe('école')
    expect(titleCase("hello WORLD, it's élan-vital")).toBe("Hello World, It's Élan-Vital")
  })
  it('splits identifiers into words', () => {
    expect(splitWords('XMLHttpRequest')).toEqual(['XML', 'Http', 'Request'])
    expect(splitWords('user_id-value')).toEqual(['user', 'id', 'value'])
    expect(splitWords('getHTTP2Response')).toEqual(['get', 'HTTP2', 'Response'])
    expect(splitWords('  ')).toEqual([])
  })
  it('snake / camel / kebab / pascal / constant', async () => {
    expect(toCase('Hello World Example', 'snake')).toBe('hello_world_example')
    expect(toCase('hello_world_example', 'camel')).toBe('helloWorldExample')
    expect(toCase('helloWorldExample', 'kebab')).toBe('hello-world-example')
    expect(toCase('hello-world', 'pascal')).toBe('HelloWorld')
    expect(toCase('helloWorld', 'constant')).toBe('HELLO_WORLD')
    expect(await runOp('to-case', 'fooBar\nbaz qux', { style: 'kebab' })).toBe('foo-bar\nbaz-qux')
  })
})

describe('line operations', () => {
  it('reverse by char / line / byte', async () => {
    expect(await runOp('reverse', 'ab😀')).toBe('😀ba')
    expect(await runOp('reverse', 'a\nb\nc', { by: 'lines' })).toBe('c\nb\na')
    expect(await runOpHex('reverse', 'ab', { by: 'bytes' })).toBe('6261')
  })
  it('sort lines', async () => {
    expect(await runOp('sort-lines', 'b\nA\na\nb')).toBe('A\na\nb\nb')
    expect(await runOp('sort-lines', 'b\nA\na\nb', { unique: true, order: 'desc' })).toBe('b\na\nA')
    expect(await runOp('sort-lines', '10 x\n9 y\n-1\nfoo\n2.5', { compare: 'numeric' })).toBe('-1\n2.5\n9 y\n10 x\nfoo')
    expect(await runOp('sort-lines', 'ccc\na\nbb', { compare: 'length' })).toBe('a\nbb\nccc')
  })
  it('unique, blank lines, trim, head, tail, numbers, pad', async () => {
    expect(await runOp('unique-lines', 'a\nb\na')).toBe('a\nb')
    expect(await runOp('unique-lines', 'a\nb\na', { count: true })).toBe('     2 a\n     1 b')
    expect(await runOp('remove-blank-lines', 'a\n\n  \nb\r\n')).toBe('a\nb')
    expect(await runOp('trim', '  a  \n b ')).toBe('a\nb')
    expect(await runOp('trim', '  a  ', { side: 'end' })).toBe('  a')
    expect(await runOp('head', '1\n2\n3', { n: 2 })).toBe('1\n2')
    expect(await runOp('tail', '1\n2\n3', { n: 2 })).toBe('2\n3')
    expect(await runOp('tail', '1\n2\n3', { n: 0 })).toBe('')
    expect(await runOp('line-numbers', 'a\nb')).toBe('1  a\n2  b')
    expect(await runOp('pad-lines', '7\n42', { width: 3, char: '0' })).toBe('007\n042')
    expect(await runOp('pad-lines', 'a', { width: 3, side: 'end', char: '.' })).toBe('a..')
  })
  it('split / join', async () => {
    expect(await runOp('split', 'a,b,c')).toBe('a\nb\nc')
    expect(await runOp('split', 'a b', { split: ' ', join: '\\t' })).toBe('a\tb')
    expect(await runOp('join-lines', 'a\nb\nc')).toBe('a,b,c')
  })
})

describe('find / replace and filter', () => {
  it('literal mode does not interpret $ patterns or regex syntax', async () => {
    expect(await runOp('find-replace', 'a.b.c', { find: '.', replace: '$&!' })).toBe('a$&!b$&!c')
    expect(await runOp('find-replace', 'Aa', { find: 'a', replace: 'x', caseInsensitive: true })).toBe('xx')
    expect(await runOp('find-replace', 'aa', { find: 'a', replace: 'x', global: false })).toBe('xa')
  })
  it('regex mode supports groups and flags', async () => {
    expect(await runOp('find-replace', 'john smith', { find: '(\\w+) (\\w+)', replace: '$2, $1', mode: 'regex' })).toBe('smith, john')
    expect(await runOp('find-replace', 'a\nb', { find: '^', replace: '> ', mode: 'regex' })).toBe('> a\n> b')
    await expect(runOp('find-replace', 'x', { find: '(', mode: 'regex' })).rejects.toThrow(/Invalid regular expression/)
    await expect(runOp('find-replace', 'x', { find: '', mode: 'regex' })).rejects.toThrow(/empty/)
  })
  it('caps regex input size', async () => {
    await expect(runOp('find-replace', 'a'.repeat(2 * 1024 * 1024 + 1), { find: 'a', mode: 'regex' })).rejects.toThrow(/limited to 2 MB/)
  })
  it('filter lines', async () => {
    expect(await runOp('filter-lines', 'error: x\ninfo: y\nERROR: z', { pattern: '^error', caseInsensitive: true })).toBe('error: x\nERROR: z')
    expect(await runOp('filter-lines', 'error: x\ninfo: y', { pattern: '^error', invert: true })).toBe('info: y')
  })
})

describe('whitespace, escapes, count', () => {
  it('remove whitespace', async () => {
    expect(await runOp('remove-whitespace', 'a b\tc\r\nd e')).toBe('abcde')
    expect(await runOp('remove-whitespace', 'a b\nc', { lf: false })).toBe('ab\nc')
  })
  it('escape / unescape round-trip', () => {
    const s = 'line1\nline2\t"quoted" \\ \u0001 é 😀 \0 1'
    expect(escapeString(s, 'double', false)).toBe('line1\\nline2\\t\\"quoted\\" \\\\ \\x01 é 😀 \\x00 1')
    expect(unescapeString(escapeString(s, 'double', false))).toBe(s)
    expect(unescapeString(escapeString(s, 'single', true))).toBe(s)
    expect(escapeString('é', 'double', true)).toBe('\\u00e9')
    expect(escapeString('`${x}`', 'backtick', false)).toBe('\\`\\${x}\\`')
  })
  it('unescape handles all forms', () => {
    expect(unescapeString('\\x41\\u0042\\u{1F600}\\q\\\\')).toBe('AB😀q\\')
    expect(unescapeString('trailing\\')).toBe('trailing\\')
    expect(unescapeString('bad \\u{110000}')).toBe('bad u{110000}')
  })
  it('count report', async () => {
    const out = await runOp('count', 'héllo world\n👍🏽 ok\n')
    expect(out).toMatch(/Bytes:\s+25/)
    expect(out).toMatch(/Words:\s+4/)
    expect(out).toMatch(/Lines:\s+2/)
    expect(out).toMatch(/Code points:\s+18/)
    expect(out).toMatch(/Characters:\s+17/) // 👍🏽 is one grapheme
    expect(out).toMatch(/UTF-16 units:\s+20/)
  })
})

describe('review regressions (text)', () => {
  it('pad lines refuses outputs that would exhaust memory', async () => {
    await expect(runOp('pad-lines', 'x\n'.repeat(10_000), { width: 10_000 })).rejects.toThrow(/would produce more than/)
    expect(await runOp('pad-lines', 'ab', { width: 4, char: '0' })).toBe('00ab')
  })
  it('invalid user regex message is not doubled', async () => {
    const err = await runOp('find-replace', 'abc', { find: '(', mode: 'regex' }).catch((e: Error) => e.message)
    expect(err).toMatch(/^Invalid regular expression: /)
    expect(String(err).match(/Invalid regular expression/g)).toHaveLength(1)
  })
})
