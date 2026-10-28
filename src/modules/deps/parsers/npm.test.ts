import { describe, expect, it } from 'vitest'
import { parseNpmAlias, parsePackageLock } from './npm.ts'
import { dedupeDeps } from '../types.ts'

const V3 = JSON.stringify({
  name: 'my-app',
  version: '1.0.0',
  lockfileVersion: 3,
  requires: true,
  packages: {
    '': { name: 'my-app', version: '1.0.0', dependencies: { express: '^4.18.2' }, devDependencies: { vitest: '^1.0.0' } },
    'node_modules/express': {
      version: '4.18.2',
      resolved: 'https://registry.npmjs.org/express/-/express-4.18.2.tgz',
      integrity: 'sha512-xxx',
    },
    'node_modules/express/node_modules/debug': {
      version: '2.6.9',
      resolved: 'https://registry.npmjs.org/debug/-/debug-2.6.9.tgz',
    },
    'node_modules/@babel/core': {
      version: '7.23.0',
      resolved: 'https://registry.npmjs.org/@babel/core/-/core-7.23.0.tgz',
      dev: true,
    },
    'node_modules/vitest/node_modules/@vitest/utils': {
      version: '1.0.4',
      resolved: 'https://registry.npmjs.org/@vitest/utils/-/utils-1.0.4.tgz',
      dev: true,
    },
    'node_modules/my-lib': { resolved: 'packages/my-lib', link: true },
    'packages/my-lib': { name: 'my-lib', version: '0.1.0' },
    'node_modules/string-width-cjs': {
      name: 'string-width',
      version: '4.2.3',
      resolved: 'https://registry.npmjs.org/string-width/-/string-width-4.2.3.tgz',
    },
    'node_modules/from-git': {
      version: '1.0.0',
      resolved: 'git+ssh://git@github.com/acme/from-git.git#abc123',
    },
    'node_modules/opt': { version: '1.0.0', resolved: 'https://registry.npmjs.org/opt/-/opt-1.0.0.tgz', devOptional: true },
  },
})

describe('parsePackageLock v2/v3', () => {
  const r = parsePackageLock(V3)
  const byName = Object.fromEntries(r.deps.map((d) => [d.name, d]))

  it('extracts names from node_modules paths, including nested and scoped', () => {
    expect(byName.express).toEqual({ name: 'express', version: '4.18.2', ecosystem: 'npm', dev: false })
    expect(byName.debug.version).toBe('2.6.9')
    expect(byName['@babel/core'].version).toBe('7.23.0')
    expect(byName['@vitest/utils'].version).toBe('1.0.4')
  })

  it('skips the root entry, workspace folders and links', () => {
    expect(byName['my-app']).toBeUndefined()
    expect(byName['my-lib']).toBeUndefined()
  })

  it('marks dev dependencies (devOptional is not dev-only)', () => {
    expect(byName['@babel/core'].dev).toBe(true)
    expect(byName.opt.dev).toBe(false)
  })

  it('uses the real package name for aliases', () => {
    expect(byName['string-width'].version).toBe('4.2.3')
    expect(byName['string-width-cjs']).toBeUndefined()
  })

  it('reports git dependencies as skipped', () => {
    expect(byName['from-git']).toBeUndefined()
    expect(r.skipped).toEqual([expect.objectContaining({ entry: 'from-git@1.0.0' })])
  })
})

describe('parsePackageLock v1', () => {
  const V1 = JSON.stringify({
    name: 'old',
    lockfileVersion: 1,
    dependencies: {
      lodash: { version: '4.17.15', resolved: 'https://registry.npmjs.org/lodash/-/lodash-4.17.15.tgz' },
      mocha: {
        version: '5.2.0',
        dev: true,
        dependencies: { debug: { version: '3.1.0', dev: true } },
      },
      '@types/node': { version: '12.0.0', dev: true },
      aliased: { version: 'npm:left-pad@1.3.0' },
      local: { version: 'file:../local' },
      gitdep: { version: 'github:user/repo#abc' },
    },
  })
  const r = parsePackageLock(V1)

  it('walks nested dependencies recursively', () => {
    expect(r.deps).toContainEqual({ name: 'debug', version: '3.1.0', ecosystem: 'npm', dev: true })
    expect(r.deps).toContainEqual({ name: 'lodash', version: '4.17.15', ecosystem: 'npm', dev: false })
    expect(r.deps).toContainEqual({ name: '@types/node', version: '12.0.0', ecosystem: 'npm', dev: true })
  })

  it('resolves npm: aliases and skips file/git versions', () => {
    expect(r.deps).toContainEqual({ name: 'left-pad', version: '1.3.0', ecosystem: 'npm', dev: false })
    expect(r.skipped.map((s) => s.entry)).toEqual(['local@file:../local', 'gitdep@github:user/repo#abc'])
  })
})

describe('parsePackageLock errors', () => {
  it('rejects invalid JSON', () => {
    expect(() => parsePackageLock('{nope')).toThrow(/not valid JSON/)
  })
  it('rejects JSON without packages/dependencies', () => {
    expect(() => parsePackageLock('{"name":"x"}')).toThrow(/package-lock/)
  })
  it('rejects non-object JSON', () => {
    expect(() => parsePackageLock('[]')).toThrow()
  })
  it('handles an empty lockfile', () => {
    expect(parsePackageLock('{"lockfileVersion":3,"packages":{"":{}}}').deps).toEqual([])
  })
})

describe('parseNpmAlias', () => {
  it('parses scoped and unscoped aliases', () => {
    expect(parseNpmAlias('npm:@scope/pkg@2.0.0')).toEqual({ name: '@scope/pkg', version: '2.0.0' })
    expect(parseNpmAlias('npm:pkg@1.0.0')).toEqual({ name: 'pkg', version: '1.0.0' })
    expect(parseNpmAlias('1.0.0')).toBeNull()
    expect(parseNpmAlias('npm:@scope')).toBeNull()
  })
})

describe('dedupeDeps', () => {
  it('merges duplicates; prod wins over dev', () => {
    const out = dedupeDeps([
      { name: 'a', version: '1', ecosystem: 'npm', dev: true },
      { name: 'a', version: '1', ecosystem: 'npm' },
      { name: 'a', version: '2', ecosystem: 'npm', dev: true },
      { name: 'a', version: '1', ecosystem: 'PyPI', dev: true },
    ])
    expect(out).toEqual([
      { name: 'a', version: '1', ecosystem: 'npm', dev: false },
      { name: 'a', version: '2', ecosystem: 'npm', dev: true },
      { name: 'a', version: '1', ecosystem: 'PyPI', dev: true },
    ])
  })
})
