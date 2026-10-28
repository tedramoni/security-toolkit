// @vitest-environment node
import { describe, expect, it } from 'vitest'
import { bytesToScanFile, ingest } from './ingest'
import type { InputFile } from './ingest'
import { crc32 } from './zip'

const txt = (s: string) => new TextEncoder().encode(s)
const input = (path: string, bytes: Uint8Array): InputFile => ({ path, size: bytes.length, bytes: async () => bytes })

/** Single stored entry ZIP. */
function storedZip(name: string, data: Uint8Array): Uint8Array {
  const n = txt(name)
  const loc = new Uint8Array(30 + n.length + data.length)
  const lv = new DataView(loc.buffer)
  lv.setUint32(0, 0x04034b50, true)
  lv.setUint32(14, crc32(data), true)
  lv.setUint32(18, data.length, true)
  lv.setUint32(22, data.length, true)
  lv.setUint16(26, n.length, true)
  loc.set(n, 30)
  loc.set(data, 30 + n.length)
  const cen = new Uint8Array(46 + n.length)
  const cv = new DataView(cen.buffer)
  cv.setUint32(0, 0x02014b50, true)
  cv.setUint32(16, crc32(data), true)
  cv.setUint32(20, data.length, true)
  cv.setUint32(24, data.length, true)
  cv.setUint16(28, n.length, true)
  cen.set(n, 46)
  const eocd = new Uint8Array(22)
  const ev = new DataView(eocd.buffer)
  ev.setUint32(0, 0x06054b50, true)
  ev.setUint16(8, 1, true)
  ev.setUint16(10, 1, true)
  ev.setUint32(12, cen.length, true)
  ev.setUint32(16, loc.length, true)
  const out = new Uint8Array(loc.length + cen.length + 22)
  out.set(loc, 0)
  out.set(cen, loc.length)
  out.set(eocd, loc.length + cen.length)
  return out
}

describe('bytesToScanFile', () => {
  it('text files keep their content', () => {
    expect(bytesToScanFile('a.md', txt('# hi'))).toMatchObject({ path: 'a.md', content: '# hi' })
  })
  it('executables are flagged by magic or extension, other binaries dropped', () => {
    expect(bytesToScanFile('tool', new Uint8Array([0x7f, 0x45, 0x4c, 0x46, 0]))?.executable).toBe('ELF executable')
    expect(bytesToScanFile('m.pyc', new Uint8Array([1, 2, 3]))?.content).toBeUndefined()
    expect(bytesToScanFile('logo.png', new Uint8Array([0x89, 0x50]))).toBeUndefined()
    expect(bytesToScanFile('data.bin2', new Uint8Array([65, 0, 66]))).toBeUndefined()
  })
})

describe('ingest', () => {
  it('expands ZIP archives and reports unsafe entries', async () => {
    const zip = storedZip('skill/SKILL.md', txt('---\nname: x\n---\n'))
    const bad = storedZip('../escape.sh', txt('x'))
    const r = await ingest([input('a.zip', zip), input('b.zip', bad), input('notes.md', txt('hello'))])
    expect(r.files.map((f) => f.path)).toEqual(['a.zip/skill/SKILL.md', 'notes.md'])
    expect(r.issues).toEqual([{ archive: 'b.zip', entry: '../escape.sh', kind: 'traversal', detail: expect.any(String) }])
  })

  it('a single uploaded zip keeps entry paths unprefixed', async () => {
    const r = await ingest([input('skill.zip', storedZip('SKILL.md', txt('# x')))])
    expect(r.files[0].path).toBe('SKILL.md')
  })

  it('ignores node_modules / .git and reports corrupt archives', async () => {
    const r = await ingest([input('p/node_modules/x/index.js', txt('x')), input('p/.git/config', txt('x')), input('broken.zip', txt('PK nope'))])
    expect(r.files).toEqual([])
    expect(r.warnings.join(' ')).toMatch(/ignored/)
    expect(r.warnings.join(' ')).toMatch(/broken\.zip/)
  })
})

describe('ingest regressions', () => {
  it('does not silently ignore dist/ or build/ (payloads can hide there)', async () => {
    const r = await ingest([input('s/dist/index.js', txt('x')), input('s/build/run.sh', txt('y'))])
    expect(r.files.map((f) => f.path)).toEqual(['s/dist/index.js', 's/build/run.sh'])
  })
})
