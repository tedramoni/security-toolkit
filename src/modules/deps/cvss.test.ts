import { describe, expect, it } from 'vitest'
import { cvssRating, parseCvss3, roundUp30, roundUp31 } from './cvss.ts'

// Expected scores are the published NVD / FIRST calculator base scores for these vectors.
describe('parseCvss3 base score', () => {
  it.each([
    ['CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H', 9.8],
    ['CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H', 10.0], // Log4Shell CVE-2021-44228
    ['CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N', 6.1], // typical reflected XSS
    ['CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H', 7.8],
    ['CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H', 7.5],
    ['CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N', 5.9],
    ['CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:N/A:N', 4.3],
    ['CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H', 8.8],
    ['CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N', 5.3],
    ['CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N', 6.5],
    ['CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N', 5.4], // typical stored XSS
    ['CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H', 7.2],
    ['CVSS:3.1/AV:P/AC:H/PR:H/UI:R/S:U/C:L/I:N/A:N', 1.6],
    ['CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N', 0.0],
    ['CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H', 9.8],
    ['CVSS:3.0/AV:N/AC:H/PR:N/UI:R/S:U/C:H/I:H/A:H', 7.5],
  ])('%s -> %f', (vector, score) => {
    expect(parseCvss3(vector)?.baseScore).toBe(score)
  })

  it('accepts metrics in any order and ignores temporal metrics', () => {
    expect(parseCvss3('CVSS:3.1/S:U/AV:N/AC:L/PR:N/UI:N/C:H/I:H/A:H/E:P/RL:O')?.baseScore).toBe(9.8)
  })

  it.each([
    '',
    'AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H', // missing prefix
    'CVSS:2.0/AV:N/AC:L/Au:N/C:P/I:P/A:P',
    'CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N',
    'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H', // missing A
    'CVSS:3.1/AV:X/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H', // invalid value
    'CVSS:3.1/AV:N/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H', // duplicate
    'CVSS:3.1/AV:N:X/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H',
  ])('rejects invalid vector %s', (vector) => {
    expect(parseCvss3(vector)).toBeNull()
  })
})

describe('rounding', () => {
  it('roundUp31 avoids floating point artefacts', () => {
    expect(roundUp31(4.0)).toBe(4.0)
    expect(roundUp31(4.02)).toBe(4.1)
    expect(roundUp31(4.000000000000001)).toBe(4.0)
    expect(roundUp31(9.79)).toBe(9.8)
  })
  it('roundUp30 rounds up to one decimal', () => {
    expect(roundUp30(4.01)).toBe(4.1)
    expect(roundUp30(4.0)).toBe(4.0)
  })
})

describe('cvssRating', () => {
  it('maps scores to qualitative ratings', () => {
    expect(cvssRating(0)).toBe('none')
    expect(cvssRating(0.1)).toBe('low')
    expect(cvssRating(3.9)).toBe('low')
    expect(cvssRating(4.0)).toBe('medium')
    expect(cvssRating(6.9)).toBe('medium')
    expect(cvssRating(7.0)).toBe('high')
    expect(cvssRating(8.9)).toBe('high')
    expect(cvssRating(9.0)).toBe('critical')
    expect(cvssRating(10)).toBe('critical')
  })
})
