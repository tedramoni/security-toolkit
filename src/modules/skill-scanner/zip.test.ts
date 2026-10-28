// @vitest-environment node
import { describe, expect, it } from 'vitest'
import { crc32, readZip, unsafeEntryName, ZipError } from './zip'

interface E {
  name: string
  data: Uint8Array
  deflate?: boolean
  /** Override declared uncompressed size. */
  size?: number
  crc?: number
  flags?: number
  madeBy?: number
  extAttr?: number
}

async function deflateRaw(data: Uint8Array): Promise<Uint8Array> {
  const cs = new CompressionStream('deflate-raw')
  const out = new Response(new Blob([data as Uint8Array<ArrayBuffer>]).stream().pipeThrough(cs))
  return new Uint8Array(await out.arrayBuffer())
}

/** Minimal ZIP writer for tests (local headers + central directory + EOCD). */
async function buildZip(entries: E[], opts: { totalOverride?: number } = {}): Promise<Uint8Array> {
  const enc = new TextEncoder()
  const locals: Uint8Array[] = []
  const centrals: Uint8Array[] = []
  let offset = 0
  for (const e of entries) {
    const name = enc.encode(e.name)
    const body = e.deflate ? await deflateRaw(e.data) : e.data
    const crc = e.crc ?? crc32(e.data)
    const size = e.size ?? e.data.length
    const loc = new Uint8Array(30 + name.length + body.length)
    const lv = new DataView(loc.buffer)
    lv.setUint32(0, 0x04034b50, true)
    lv.setUint16(4, 20, true)
    lv.setUint16(6, e.flags ?? 0, true)
    lv.setUint16(8, e.deflate ? 8 : 0, true)
    lv.setUint32(14, crc, true)
    lv.setUint32(18, body.length, true)
    lv.setUint32(22, size, true)
    lv.setUint16(26, name.length, true)
    loc.set(name, 30)
    loc.set(body, 30 + name.length)
    const cen = new Uint8Array(46 + name.length)
    const cv = new DataView(cen.buffer)
    cv.setUint32(0, 0x02014b50, true)
    cv.setUint16(4, e.madeBy ?? 20, true)
    cv.setUint16(6, 20, true)
    cv.setUint16(8, e.flags ?? 0, true)
    cv.setUint16(10, e.deflate ? 8 : 0, true)
    cv.setUint32(16, crc, true)
    cv.setUint32(20, body.length, true)
    cv.setUint32(24, size, true)
    cv.setUint16(28, name.length, true)
    cv.setUint32(38, e.extAttr ?? 0, true)
    cv.setUint32(42, offset, true)
    cen.set(name, 46)
    locals.push(loc)
    centrals.push(cen)
    offset += loc.length
  }
  const cdSize = centrals.reduce((n, c) => n + c.length, 0)
  const eocd = new Uint8Array(22)
  const ev = new DataView(eocd.buffer)
  ev.setUint32(0, 0x06054b50, true)
  ev.setUint16(8, opts.totalOverride ?? entries.length, true)
  ev.setUint16(10, opts.totalOverride ?? entries.length, true)
  ev.setUint32(12, cdSize, true)
  ev.setUint32(16, offset, true)
  const all = new Uint8Array(offset + cdSize + 22)
  let p = 0
  for (const part of [...locals, ...centrals, eocd]) {
    all.set(part, p)
    p += part.length
  }
  return all
}

const txt = (s: string) => new TextEncoder().encode(s)
const dec = (b?: Uint8Array) => new TextDecoder().decode(b)

describe('crc32', () => {
  it('matches the standard check value', () => {
    // CRC-32/ISO-HDLC check value for "123456789"
    expect(crc32(txt('123456789'))).toBe(0xcbf43926)
    expect(crc32(new Uint8Array())).toBe(0)
  })
})

describe('unsafeEntryName', () => {
  it.each(['../evil.sh', 'a/../../b', '/etc/passwd', 'C:\\Windows\\x.dll', 'a\\..\\b', 'x\0y'])('rejects %s', (n) => expect(unsafeEntryName(n)).toBeDefined())
  it.each(['skill/SKILL.md', 'a/b..c/d.txt', '..hidden'])('accepts %s', (n) => expect(unsafeEntryName(n)).toBeUndefined())
})

describe('readZip', () => {
  it('reads stored and deflated entries, skipping directories', async () => {
    const zip = await buildZip([
      { name: 'skill/', data: new Uint8Array() },
      { name: 'skill/SKILL.md', data: txt('---\nname: x\n---\n') },
      { name: 'skill/scripts/run.sh', data: txt('echo hi\n'.repeat(200)), deflate: true },
    ])
    const r = await readZip(zip)
    expect(r.issues).toEqual([])
    expect(r.entries.map((e) => e.name)).toEqual(['skill/SKILL.md', 'skill/scripts/run.sh'])
    expect(dec(r.entries[1].data)).toBe('echo hi\n'.repeat(200))
  })

  it('rejects path traversal and absolute names (Zip Slip)', async () => {
    const zip = await buildZip([
      { name: '../../.bashrc', data: txt('x') },
      { name: '/etc/cron.d/x', data: txt('x') },
      { name: 'ok.txt', data: txt('fine') },
    ])
    const r = await readZip(zip)
    expect(r.entries.map((e) => e.name)).toEqual(['ok.txt'])
    expect(r.issues.filter((i) => i.kind === 'traversal')).toHaveLength(2)
  })

  it('reports symlink entries without extracting them', async () => {
    const zip = await buildZip([{ name: 'link', data: txt('/home/u/.ssh/id_rsa'), madeBy: (3 << 8) | 20, extAttr: (0o120777 << 16) >>> 0 }])
    const r = await readZip(zip)
    expect(r.entries).toEqual([])
    expect(r.issues[0].kind).toBe('symlink')
  })

  it('skips high-ratio entries (zip bomb)', async () => {
    const zip = await buildZip([{ name: 'bomb.txt', data: new Uint8Array(3 * 1024 * 1024), deflate: true }])
    expect(zip.length).toBeLessThan(10_000)
    const r = await readZip(zip)
    expect(r.entries[0].data).toBeUndefined()
    expect(r.issues[0].detail).toMatch(/ratio/)
  })

  it('enforces the declared size while inflating (lying header)', async () => {
    const zip = await buildZip([{ name: 'lie.txt', data: txt('A'.repeat(5000)), deflate: true, size: 10 }])
    const r = await readZip(zip)
    expect(r.entries[0].data).toBeUndefined()
    expect(r.issues[0].detail).toMatch(/inflates beyond/)
  })

  it('enforces per-entry and total size limits', async () => {
    const zip = await buildZip([
      { name: 'a.txt', data: new Uint8Array(600).fill(65) },
      { name: 'b.txt', data: new Uint8Array(600).fill(66) },
    ])
    const r = await readZip(zip, { maxEntries: 10, maxEntryBytes: 1000, maxTotalBytes: 1000, maxRatio: 100, maxArchiveBytes: 1e6 })
    expect(r.entries[0].data?.length).toBe(600)
    expect(r.entries[1].data).toBeUndefined()
    expect(r.issues[0].detail).toMatch(/Total/)
    const r2 = await readZip(zip, { maxEntries: 10, maxEntryBytes: 100, maxTotalBytes: 1e6, maxRatio: 100, maxArchiveBytes: 1e6 })
    expect(r2.issues).toHaveLength(2)
  })

  it('detects CRC mismatches', async () => {
    const zip = await buildZip([{ name: 'x.txt', data: txt('hello'), crc: 1234 }])
    const r = await readZip(zip)
    expect(r.issues[0].detail).toMatch(/CRC/)
  })

  it('skips encrypted entries', async () => {
    const zip = await buildZip([{ name: 'x.txt', data: txt('hello'), flags: 1 }])
    expect((await readZip(zip)).issues[0].detail).toMatch(/Encrypted/)
  })

  it('rejects too many entries, ZIP64 and non-zips', async () => {
    const many = await buildZip(Array.from({ length: 5 }, (_, i) => ({ name: `f${i}`, data: txt('x') })))
    await expect(readZip(many, { maxEntries: 3, maxEntryBytes: 1e6, maxTotalBytes: 1e6, maxRatio: 100, maxArchiveBytes: 1e6 })).rejects.toThrow(ZipError)
    const z64 = await buildZip([{ name: 'x', data: txt('x') }], { totalOverride: 0xffff })
    await expect(readZip(z64)).rejects.toThrow(/ZIP64/)
    await expect(readZip(txt('not a zip file at all, definitely not'))).rejects.toThrow(/Not a ZIP/)
    await expect(readZip(new Uint8Array(5))).rejects.toThrow(/too small/)
  })

  it('handles garbage compressed data gracefully', async () => {
    const zip = await buildZip([{ name: 'x.txt', data: txt('hello world'), deflate: true }])
    // Corrupt the deflate stream bytes (after the 30-byte local header + 5-byte name).
    zip[35] = 0xff
    zip[36] = 0xff
    const r = await readZip(zip)
    expect(r.entries[0].data).toBeUndefined()
    expect(r.issues).toHaveLength(1)
  })
})
