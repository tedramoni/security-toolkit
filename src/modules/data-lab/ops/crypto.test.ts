import { describe, expect, it } from 'vitest'
import { bytesToHex, hex, runOp, runOpBytes, runOpHex } from '../testUtil'
import { aesDecrypt, aesEncrypt, atbash, rot47, rotLetters, vigenere, xorBruteForce, xorBytes } from './crypto'

const hx = (value: string) => ({ value, encoding: 'hex' as const })
const u8 = (value: string) => ({ value, encoding: 'utf8' as const })

describe('classical ciphers', () => {
  it('ROT13 / ROT47 / Caesar / Atbash', async () => {
    expect(rotLetters('Hello, World!', 13)).toBe('Uryyb, Jbeyq!')
    expect(rotLetters('abc123', 13, true)).toBe('nop678')
    expect(rot47('Hello, World!')).toBe('w6==@[ (@C=5P')
    expect(rot47(rot47('round trip ~!'))).toBe('round trip ~!')
    expect(await runOp('caesar', 'xyz', { shift: 3 })).toBe('abc')
    expect(await runOp('caesar', 'abc', { shift: -3 })).toBe('xyz')
    expect(atbash('Hello')).toBe('Svool')
  })
  it('Vigenère (classic "ATTACKATDAWN"/"LEMON" example)', () => {
    expect(vigenere('ATTACKATDAWN', 'LEMON', false)).toBe('LXFOPVEFRNHR')
    expect(vigenere('LXFOPVEFRNHR', 'lemon', true)).toBe('ATTACKATDAWN')
    expect(vigenere('Attack at dawn!', 'LEMON', false)).toBe('Lxfopv ef rnhr!')
    expect(() => vigenere('x', '123', false)).toThrow(/at least one letter/)
  })
})

describe('XOR', () => {
  it('repeating key, empty key is identity', async () => {
    expect(bytesToHex(xorBytes(hex('00ff10'), hex('0f')))).toBe('0ff01f')
    expect(await runOpHex('xor', 'ABC', { key: u8('k') })).toBe(bytesToHex(xorBytes(new TextEncoder().encode('ABC'), hex('6b'))))
    expect(await runOp('xor', 'abc', { key: hx('') })).toBe('abc')
    expect(await runOpHex('xor', hex('0000'), { key: { value: 'AQI=', encoding: 'base64' } })).toBe('0102')
  })
  it('brute force ranks the real key first', () => {
    const plain = new TextEncoder().encode('The quick brown fox jumps over the lazy dog and keeps running')
    const ct = xorBytes(plain, Uint8Array.of(0x5a))
    const top = xorBruteForce(ct, '', 3)
    expect(top[0].key).toBe(0x5a)
    expect(xorBruteForce(ct, 'lazy dog', 10).map((c) => c.key)).toContain(0x5a)
  })
  it('brute force op output lists keys', async () => {
    const out = await runOp('xor-brute-force', xorBytes(new TextEncoder().encode('attack at dawn, the password is hunter2'), Uint8Array.of(0x21)), { top: 2 })
    expect(out.split('\n')[0]).toMatch(/^Key 0x21 .*attack at dawn/)
  })
})

describe('AES (WebCrypto)', () => {
  // McGrew & Viega, "The Galois/Counter Mode of Operation", test cases 2 and 3 (also in NIST GCM validation).
  it('AES-128-GCM test case 2', async () => {
    const out = await aesEncrypt(new Uint8Array(16), { mode: 'GCM', key: new Uint8Array(16), iv: new Uint8Array(12) })
    expect(bytesToHex(out)).toBe('0388dace60b6a392f328c2b971b2fe78' + 'ab6e47d42cec13bdf53a67b21257bddf')
  })
  it('AES-128-GCM test case 3 (encrypt + decrypt via ops)', async () => {
    const key = hx('feffe9928665731c6d6a8f9467308308')
    const iv = hx('cafebabefacedbaddecaf888')
    const pt =
      'd9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b391aafd255'
    const ct =
      '42831ec2217774244b7221b784d0d49ce3aa212f2c02a4e035c17e2329aca12e21d514b25466931c7d8f6a5aac84aa051ba30b396a0aac973d58e091473f5985'
    const tag = '4d5c2af327cd64a62cf35abd2ba6fab4'
    expect(await runOp('aes-encrypt', hex(pt), { key, iv })).toBe(ct + tag)
    expect(await runOpHex('aes-decrypt', ct + tag, { key, iv })).toBe(pt)
    // tag supplied separately
    expect(await runOpHex('aes-decrypt', ct, { key, iv, tag: hx(tag) })).toBe(pt)
  })
  it('GCM detects tampering and wrong AAD', async () => {
    const key = hx('00'.repeat(32))
    const iv = hx('00'.repeat(12))
    const ct = await runOp('aes-encrypt', 'secret', { key, iv, aad: u8('header') })
    expect(await runOp('aes-decrypt', ct, { key, iv, aad: u8('header') })).toBe('secret')
    await expect(runOp('aes-decrypt', ct, { key, iv, aad: u8('other') })).rejects.toThrow(/authentication failed/)
    const flipped = (ct[0] === '0' ? '1' : '0') + ct.slice(1)
    await expect(runOp('aes-decrypt', flipped, { key, iv, aad: u8('header') })).rejects.toThrow(/authentication failed/)
  })
  it('AES-128-CBC (NIST SP 800-38A F.2.1, first block) with PKCS#7 padding', async () => {
    const key = hex('2b7e151628aed2a6abf7158809cf4f3c')
    const iv = hex('000102030405060708090a0b0c0d0e0f')
    const out = await aesEncrypt(hex('6bc1bee22e409f96e93d7e117393172a'), { mode: 'CBC', key, iv })
    expect(out.length).toBe(32) // one full padding block appended
    expect(bytesToHex(out.subarray(0, 16))).toBe('7649abac8119b246cee98e9b12e9197d')
    expect(bytesToHex(await aesDecrypt(out, { mode: 'CBC', key, iv }))).toBe('6bc1bee22e409f96e93d7e117393172a')
  })
  it('AES-128-CTR (NIST SP 800-38A F.5.1, first block)', async () => {
    const out = await aesEncrypt(hex('6bc1bee22e409f96e93d7e117393172a'), {
      mode: 'CTR',
      key: hex('2b7e151628aed2a6abf7158809cf4f3c'),
      iv: hex('f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff'),
    })
    expect(bytesToHex(out)).toBe('874d6191b620e3261bef6864990db6ce')
  })
  it('validates key and IV sizes', async () => {
    await expect(runOp('aes-encrypt', 'x', { key: hx('0011'), iv: hx('00'.repeat(12)) })).rejects.toThrow(/16, 24 or 32 bytes/)
    await expect(runOp('aes-encrypt', 'x', { mode: 'CBC', key: hx('00'.repeat(16)), iv: hx('00'.repeat(12)) })).rejects.toThrow(/16-byte IV/)
    await expect(runOp('aes-encrypt', 'x', { key: hx('00'.repeat(16)), iv: hx('') })).rejects.toThrow(/needs an IV/)
    await expect(runOp('aes-decrypt', 'zz', { key: hx('00'.repeat(16)), iv: hx('00'.repeat(12)) })).rejects.toThrow(/Invalid hex/)
  })
  it('base64 output/input formats', async () => {
    const args = { key: hx('00'.repeat(16)), iv: hx('00'.repeat(12)) }
    const b64 = await runOp('aes-encrypt', 'hello', { ...args, output: 'base64' })
    expect(await runOp('aes-decrypt', b64, { ...args, inputFormat: 'base64' })).toBe('hello')
  })
})

describe('PBKDF2-HMAC-SHA1 (RFC 6070)', () => {
  const cases: [string, string, number, number, string][] = [
    ['password', 'salt', 1, 20, '0c60c80f961f0e71f3a9b524af6012062fe037a6'],
    ['password', 'salt', 2, 20, 'ea6c014dc72d6f8ccd1ed92ace1d41f0d8de8957'],
    ['password', 'salt', 4096, 20, '4b007901b765489abead49d926f721d065a429c1'],
    ['passwordPASSWORDpassword', 'saltSALTsaltSALTsaltSALTsaltSALTsalt', 4096, 25, '3d2eec4fe41c849b80c8d83662c0e44a8b291a964cf2f07038'],
    ['pass\u0000word', 'sa\u0000lt', 4096, 16, '56fa6aa75548099dcc37d7f03425e0c3'],
  ]
  for (const [p, s, c, len, dk] of cases) {
    it(`P="${p.replace('\u0000', '\\0')}" c=${c}`, async () => {
      expect(await runOp('pbkdf2', p, { salt: u8(s), iterations: c, hash: 'SHA-1', length: len })).toBe(dk)
    })
  }
})

describe('HMAC (RFC 4231)', () => {
  it('test case 1', async () => {
    const key = hx('0b'.repeat(20))
    expect(await runOp('hmac', 'Hi There', { key, hash: 'SHA-256' })).toBe('b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7')
    expect(await runOp('hmac', 'Hi There', { key, hash: 'SHA-384' })).toBe(
      'afd03944d84895626b0825f4ab46907f15f9dadbe4101ec682aa034c7cebc59cfaea9ea9076ede7f4af152e8b2fa9cb6',
    )
    expect(await runOp('hmac', 'Hi There', { key, hash: 'SHA-512' })).toBe(
      '87aa7cdea5ef619d4ff0b4241a1d6cb02379f4e2ce4ec2787ad0b30545e17cdedaa833b7d6b8a702038b274eaea3f4e4be9d914eeb61f1702e696c203a126854',
    )
  })
  it('test case 2 (key "Jefe")', async () => {
    expect(await runOp('hmac', 'what do ya want for nothing?', { key: u8('Jefe') })).toBe(
      '5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843',
    )
  })
  it('rejects empty keys with a clear message', async () => {
    await expect(runOp('hmac', 'x', { key: u8('') })).rejects.toThrow(/must not be empty/)
  })
})

describe('random bytes', () => {
  it('produces the requested length and differs between runs', async () => {
    const a = await runOpBytes('random-bytes', '', { length: 100000, output: 'raw' })
    expect(a.length).toBe(100000)
    const h1 = await runOp('random-bytes', '', { length: 16 })
    const h2 = await runOp('random-bytes', '', { length: 16 })
    expect(h1).toMatch(/^[0-9a-f]{32}$/)
    expect(h1).not.toBe(h2)
  })
})
