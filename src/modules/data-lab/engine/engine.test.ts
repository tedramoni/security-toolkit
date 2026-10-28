import { describe, expect, it } from 'vitest'
import { getOp, OPERATIONS } from '../ops'
import { compress } from '../ops/hashing'
import { jsonErrorOffset } from '../ops/json'
import { detectFileType, detectType, englishScore, shannonEntropy } from './analysis'
import { base64Encode, utf8Decode, utf8Encode } from './bytes'
import { magic, MAGIC_MAX_INPUT, scoreOutput } from './magic'
import {
  defaultArgs,
  deserializeRecipe,
  hasSecrets,
  MAX_STEPS,
  newStep,
  parseRecipeJson,
  recipeFromParam,
  recipeToParam,
  serializeRecipe,
} from './recipe'
import { runRecipe } from './runner'
import type { RecipeStep } from './types'
import { CATEGORIES } from './types'

const step = (opId: string, args: Record<string, unknown> = {}, extra: Partial<RecipeStep> = {}): RecipeStep => {
  const op = getOp(opId)
  if (!op) throw new Error(opId)
  return { ...newStep(op, args as RecipeStep['args']), ...extra }
}

describe('operation registry', () => {
  it('has 70+ ops with unique ids, known categories and valid defaults', () => {
    expect(OPERATIONS.length).toBeGreaterThanOrEqual(70)
    expect(new Set(OPERATIONS.map((o) => o.id)).size).toBe(OPERATIONS.length)
    for (const op of OPERATIONS) {
      expect(CATEGORIES).toContain(op.category)
      expect(op.description.length, op.id).toBeGreaterThan(10)
      expect(new Set(op.args.map((a) => a.key)).size, op.id).toBe(op.args.length)
      // defaults must pass the recipe validator
      expect(() => deserializeRecipe({ v: 1, steps: [{ op: op.id, args: defaultArgs(op) }] }, getOp), op.id).not.toThrow()
    }
  })
  it('every op either succeeds or throws a clean Error on assorted inputs (no crashes, no hangs)', async () => {
    const inputs = ['', 'Hello, World!', '\u0000ÿ\u0080garbage', '{"a":[1,2]}', 'aGVsbG8=', '0'.repeat(2000)]
    for (const op of OPERATIONS) {
      for (const text of inputs) {
        try {
          const out = await op.run(utf8Encode(text), defaultArgs(op), {})
          expect(out, `${op.id}`).toBeInstanceOf(Uint8Array)
        } catch (e) {
          expect(e, `${op.id} on ${JSON.stringify(text.slice(0, 10))}`).toBeInstanceOf(Error)
          expect((e as Error).message.length).toBeGreaterThan(0)
        }
      }
    }
  }, 60_000)
})

describe('recipe serialization', () => {
  const recipe = [
    step('from-base64', { alphabet: 'url' }),
    step('xor', { key: { value: 'secret', encoding: 'utf8' } }, { disabled: true }),
    step('gunzip', {}, { breakpoint: true }),
  ]
  it('round-trips through JSON with only non-default args', () => {
    const ser = serializeRecipe(recipe, getOp)
    expect(ser).toEqual({
      v: 1,
      steps: [{ op: 'from-base64', args: { alphabet: 'url' } }, { op: 'xor', args: { key: { value: 'secret', encoding: 'utf8' } }, off: true }, { op: 'gunzip', bp: true }],
    })
    expect(deserializeRecipe(JSON.parse(JSON.stringify(ser)), getOp)).toEqual(recipe)
  })
  it('round-trips through the URL parameter and strips secrets by default', () => {
    expect(hasSecrets(recipe, getOp)).toBe(true)
    const p = recipeToParam(recipe, getOp)
    expect(p).toMatch(/^[A-Za-z0-9_-]+$/)
    const back = recipeFromParam(p, getOp)
    expect(back[1].args.key).toEqual({ value: '', encoding: 'hex' })
    expect(recipeFromParam(recipeToParam(recipe, getOp, false), getOp)).toEqual(recipe)
  })
  it('rejects unknown ops, bad args and oversize recipes with clear errors', () => {
    const bad = (data: unknown) => () => deserializeRecipe(data, getOp)
    expect(bad({ v: 1, steps: [{ op: 'rm-rf' }] })).toThrow(/Step 1: unknown operation "rm-rf"/)
    expect(bad({ v: 2, steps: [] })).toThrow(/Unsupported recipe version/)
    expect(bad({ v: 1, steps: [{ op: 'head', args: { n: 'ten' } }] })).toThrow(/"n" must be a finite number/)
    expect(bad({ v: 1, steps: [{ op: 'head', args: { n: 1.5 } }] })).toThrow(/integer/)
    expect(bad({ v: 1, steps: [{ op: 'head', args: { n: -1 } }] })).toThrow(/between/)
    expect(bad({ v: 1, steps: [{ op: 'to-base64', args: { alphabet: 'evil' } }] })).toThrow(/must be one of/)
    expect(bad({ v: 1, steps: [{ op: 'to-base64', args: { padding: 'yes' } }] })).toThrow(/true or false/)
    expect(bad({ v: 1, steps: [{ op: 'xor', args: { key: { value: 'x', encoding: 'rot13' } } }] })).toThrow(/encoding/)
    expect(bad({ v: 1, steps: [{ op: 'to-base64', args: { nope: 1 } }] })).toThrow(/unknown argument "nope"/)
    expect(bad({ v: 1, steps: [{ op: 'to-base64', args: JSON.parse('{"__proto__":{"x":1}}') }] })).toThrow(/unknown argument "__proto__"/)
    expect(bad({ v: 1, steps: [{ op: 'find-replace', args: { find: 'x'.repeat(5000) } }] })).toThrow(/too long/)
    expect(bad({ v: 1, steps: Array.from({ length: MAX_STEPS + 1 }, () => ({ op: 'rot13' })) })).toThrow(/maximum is/)
    expect(bad({ v: 1, steps: [{ op: 'rot13', off: 'yes' }] })).toThrow(/"off" must be a boolean/)
    expect(bad('nope')).toThrow(/JSON object/)
    expect(() => parseRecipeJson('{oops', getOp)).toThrow(/not valid JSON/)
    expect(() => recipeFromParam('!!!', getOp)).toThrow(/corrupted/)
    expect(() => recipeFromParam('A'.repeat(20000), getOp)).toThrow(/too long/)
  })
  it('accepts a bare steps array and a name', () => {
    expect(deserializeRecipe([{ op: 'rot13' }], getOp)).toHaveLength(1)
    expect(parseRecipeJson('{"v":1,"name":"My recipe","steps":[]}', getOp).name).toBe('My recipe')
  })
})

describe('runner', () => {
  it('runs steps in order, skips disabled, records intermediates', async () => {
    const r = await runRecipe([step('to-base64'), step('upper-case', {}, { disabled: true }), step('to-hex', { delimiter: 'none' })], utf8Encode('hi'), getOp)
    expect(utf8Decode(r.output)).toBe('61476b3d')
    expect(r.steps.map((s) => s.status)).toEqual(['ok', 'disabled', 'ok'])
    expect(utf8Decode(r.steps[0].output as Uint8Array)).toBe('aGk=')
    expect(r.failedAt).toBeUndefined()
  })
  it('stops at the failing step, keeps earlier outputs and explains why', async () => {
    const r = await runRecipe([step('upper-case'), step('from-base64'), step('to-hex')], utf8Encode('not base64!'), getOp)
    expect(r.failedAt).toBe(1)
    expect(r.steps[1].status).toBe('error')
    expect(r.steps[1].error).toMatch(/Invalid Base64 character '!'/)
    expect(r.steps[2].status).toBe('not-run')
    expect(utf8Decode(r.output)).toBe('NOT BASE64!')
  })
  it('reports unknown operations as a step error', async () => {
    const r = await runRecipe([{ opId: 'ghost', args: {} }], utf8Encode('x'), getOp)
    expect(r.steps[0].error).toMatch(/Unknown operation/)
  })
  it('pauses at breakpoints and can resume past them', async () => {
    const steps = [step('to-base64'), step('to-hex', {}, { breakpoint: true }), step('upper-case')]
    const paused = await runRecipe(steps, utf8Encode('hi'), getOp)
    expect(paused.pausedAt).toBe(1)
    expect(utf8Decode(paused.output)).toBe('aGk=')
    const resumed = await runRecipe(steps, utf8Encode('hi'), getOp, { resumeAfter: 1 })
    expect(resumed.pausedAt).toBeUndefined()
    expect(utf8Decode(resumed.output)).toBe('61 47 6B 3D')
  })
  it('honours AbortSignal', async () => {
    const ac = new AbortController()
    ac.abort()
    const r = await runRecipe([step('rot13')], utf8Encode('x'), getOp, { signal: ac.signal })
    expect(r.aborted).toBe(true)
  })
  it('drops intermediates beyond the memory budget but still finishes', async () => {
    const r = await runRecipe([step('to-hex'), step('to-hex')], new Uint8Array(1000), getOp, { intermediateBudget: 3500 })
    expect(r.steps[0].output).toBeDefined()
    expect(r.steps[1].output).toBeUndefined()
    expect(r.steps[1].outputLength).toBe(r.output.length)
  })
  it('enforces per-op input caps', async () => {
    const r = await runRecipe([step('to-base58')], new Uint8Array(70_000), getOp)
    expect(r.steps[0].error).toMatch(/limited to 65,536 bytes/)
  })
})

describe('analysis', () => {
  it('entropy, English score and type detection', () => {
    expect(shannonEntropy(new Uint8Array(0))).toBe(0)
    expect(shannonEntropy(Uint8Array.from({ length: 512 }, (_, i) => i & 255))).toBeCloseTo(8)
    const english = utf8Encode('The quick brown fox jumps over the lazy dog while the cat sleeps in the sun')
    expect(englishScore(english)).toBeGreaterThan(0.6)
    expect(englishScore(utf8Encode('Gur dhvpx oebja sbk whzcf bire gur ynml qbt'))).toBeLessThan(englishScore(english))
    expect(detectFileType(Uint8Array.of(0x1f, 0x8b, 0x08, 0))?.name).toMatch(/Gzip/)
    expect(detectFileType(Uint8Array.of(0x78, 0x9c))?.name).toMatch(/Zlib/)
    expect(detectType(utf8Encode('{"a":1}'))).toBe('JSON')
    expect(detectType(utf8Encode('eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.sig'))).toMatch(/JWT/)
    expect(detectType(Uint8Array.of(0xff, 0xfe, 0x00))).toBe('binary data')
  })
  it('JSON error offsets', () => {
    expect(jsonErrorOffset('{"a":1}')).toBe(-1)
    expect(jsonErrorOffset('{"a":1,}')).toBe(7)
    expect(jsonErrorOffset('[1 2]')).toBe(3)
    expect(jsonErrorOffset('01')).toBe(1)
    expect(jsonErrorOffset('"\\x"')).toBe(1) // points at the bad escape
    expect(jsonErrorOffset('[')).toBe(1)
    expect(jsonErrorOffset('['.repeat(100000))).toBe(100000)
  })
})

describe('Magic', () => {
  const text = 'The quick brown fox jumps over the lazy dog. Security champions love decoding data.'
  const names = (r: Awaited<ReturnType<typeof magic>>) => r.map((x) => x.steps.map((s) => s.opId).join('>'))

  it('finds plain Base64', async () => {
    const res = await magic(utf8Encode(base64Encode(utf8Encode(text))), { lookup: getOp })
    expect(names(res)[0]).toBe('from-base64')
    expect(utf8Decode(res[0].output)).toBe(text)
  })
  it('finds hex(base64(text)) as a 2-step chain', async () => {
    const hexed = Array.from(utf8Encode(base64Encode(utf8Encode(text))), (b) => b.toString(16).padStart(2, '0')).join('')
    const res = await magic(utf8Encode(hexed), { lookup: getOp })
    expect(names(res)[0]).toBe('from-hex>from-base64')
    expect(utf8Decode(res[0].output)).toBe(text)
  })
  it('finds base64(gzip(text))', async () => {
    const gz = await compress(utf8Encode(text), 'gzip')
    const res = await magic(utf8Encode(base64Encode(gz)), { lookup: getOp })
    expect(names(res)[0]).toBe('from-base64>gunzip')
    expect(utf8Decode(res[0].output)).toBe(text)
  })
  it('finds URL encoding, ROT13 and HTML entities', async () => {
    expect(names(await magic(utf8Encode(encodeURIComponent('a <script> & "quoted" text for you')), { lookup: getOp }))[0]).toBe('url-decode')
    const rot = text.replace(/[a-z]/gi, (c) => String.fromCharCode(((c.toLowerCase().charCodeAt(0) - 97 + 13) % 26) + (c < 'a' ? 65 : 97)))
    expect(names(await magic(utf8Encode(rot), { lookup: getOp }))[0]).toBe('rot13')
    expect(names(await magic(utf8Encode('&lt;b&gt;Tom &amp; Jerry&lt;/b&gt; are friends'), { lookup: getOp }))[0]).toBe('html-entity-decode')
  })
  it('suggests nothing useful for plain English', async () => {
    const res = await magic(utf8Encode(text), { lookup: getOp })
    expect(res.every((r) => r.score < scoreOutput(utf8Encode(text)).score + 0.05)).toBe(true)
  })
  it('caps decompressed outputs it keeps and returns (regression: whole bomb outputs were explored and posted back)', async () => {
    const gz = await compress(utf8Encode(text.repeat(40_000)), 'gzip') // ≈ 3.3 MB of text
    const res = await magic(utf8Encode(base64Encode(gz)), { lookup: getOp })
    expect(names(res)[0]).toBe('from-base64>gunzip')
    expect(res[0].output.length).toBe(MAGIC_MAX_INPUT)
    for (const r of res) expect(r.output.length).toBeLessThanOrEqual(MAGIC_MAX_INPUT)
  })
  it('respects the time budget on large inputs', async () => {
    const big = utf8Encode('QUJD'.repeat(400_000))
    const t0 = performance.now()
    await magic(big, { lookup: getOp, budgetMs: 300 })
    expect(performance.now() - t0).toBeLessThan(5000)
  })
})
