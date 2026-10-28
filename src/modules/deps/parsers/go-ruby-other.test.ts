import { describe, expect, it } from 'vitest'
import { compareGoVersions, parseGoMod, parseGoSum } from './go.ts'
import { parseCargoLock, parseComposerLock, parsePoetryLock, readTomlPackages } from './other.ts'
import { parseGemfileLock } from './ruby.ts'

describe('parseGoMod', () => {
  const GOMOD = `module github.com/acme/service

go 1.21

toolchain go1.21.5

require github.com/gin-gonic/gin v1.9.0

require (
	golang.org/x/net v0.17.0
	github.com/old/thing v2.0.0+incompatible // indirect
	github.com/replaced/one v1.0.0
	github.com/local/two v0.1.0
)

replace github.com/replaced/one => github.com/fork/one v1.0.1

replace github.com/local/two => ../two
`
  const r = parseGoMod(GOMOD)

  it('reads single-line and block requires, keeping the leading v', () => {
    expect(r.deps).toEqual([
      { name: 'github.com/gin-gonic/gin', version: 'v1.9.0', ecosystem: 'Go' },
      { name: 'golang.org/x/net', version: 'v0.17.0', ecosystem: 'Go' },
      { name: 'github.com/old/thing', version: 'v2.0.0+incompatible', ecosystem: 'Go' },
      { name: 'github.com/fork/one', version: 'v1.0.1', ecosystem: 'Go' },
    ])
  })

  it('reports local replacements as skipped', () => {
    expect(r.skipped).toEqual([{ entry: 'github.com/local/two@v0.1.0', reason: 'replaced by local path ../two' }])
  })

  it('honours version-specific replace', () => {
    const mod = 'module x\nrequire a.com/b v1.0.0\nreplace a.com/b v1.0.0 => a.com/b v1.0.5\n'
    expect(parseGoMod(mod).deps).toEqual([{ name: 'a.com/b', version: 'v1.0.5', ecosystem: 'Go' }])
  })

  it('accepts quoted module paths', () => {
    const mod = 'module x\nrequire "golang.org/x/text" v0.3.0\nreplace "a.com/b" => "a.com/c" v1.2.0\nrequire a.com/b v1.0.0\n'
    expect(parseGoMod(mod).deps).toEqual([
      { name: 'golang.org/x/text', version: 'v0.3.0', ecosystem: 'Go' },
      { name: 'a.com/c', version: 'v1.2.0', ecosystem: 'Go' },
    ])
  })

  it('stays fast on a hostile replace line', () => {
    const start = Date.now()
    parseGoMod(`module x\nreplace ${'a'.repeat(200_000)}\n`)
    expect(Date.now() - start).toBeLessThan(1000)
  })

  it('rejects non-go.mod text', () => {
    expect(() => parseGoMod('hello world')).toThrow()
  })
})

describe('parseGoSum', () => {
  const SUM = `github.com/gin-gonic/gin v1.8.1 h1:4+fr/el88TOO3ewCmQr8cx/CtZ/umlIRIs5M4NTNjf8=
github.com/gin-gonic/gin v1.8.1/go.mod h1:ji8BvRH1azfM+SYow9zQ6SZMvR8qOMZHmsCuWR9tTTk=
github.com/gin-gonic/gin v1.9.0 h1:OjyFBKICoexlu99ctXNR2gg+c5pKrKMuyjgARg9qeY8=
github.com/gin-gonic/gin v1.9.0/go.mod h1:W1Me9+hsUSyj3CePGrd1/QrKJMSJ1Tu/0hFEH89961k=
golang.org/x/text v0.3.0/go.mod h1:NqM8EUOU14njkJ3fqMW+pc6Ldnwhi/IjpwHt7yyuwOQ=
golang.org/x/net v0.17.0 h1:pVaXccu2ozPjCXewfr1S7xza/zcXTity9cCdXQYSjIM=
`
  it('keeps full-module lines and the highest version per module', () => {
    const r = parseGoSum(SUM)
    expect(r.deps).toEqual([
      { name: 'github.com/gin-gonic/gin', version: 'v1.9.0', ecosystem: 'Go' },
      { name: 'golang.org/x/net', version: 'v0.17.0', ecosystem: 'Go' },
    ])
    expect(r.skipped[0].reason).toMatch(/go\.mod/)
  })
  it('rejects text without go.sum lines', () => {
    expect(() => parseGoSum('nothing here')).toThrow()
  })
  it('compareGoVersions orders semver with prereleases', () => {
    expect(compareGoVersions('v1.10.0', 'v1.9.0')).toBeGreaterThan(0)
    expect(compareGoVersions('v1.0.0', 'v1.0.0-rc.1')).toBeGreaterThan(0)
    expect(compareGoVersions('v0.0.0-20230101000000-abcdef', 'v0.0.0-20220101000000-abcdef')).toBeGreaterThan(0)
    expect(compareGoVersions('v1.2.3', 'v1.2.3')).toBe(0)
  })
})

describe('parseGemfileLock', () => {
  const LOCK = `GIT
  remote: https://github.com/acme/private_gem.git
  revision: 0123456789abcdef
  specs:
    private_gem (0.1.0)

PATH
  remote: .
  specs:
    myapp (1.0.0)

GEM
  remote: https://rubygems.org/
  specs:
    actionpack (7.0.4)
      actionview (= 7.0.4)
      rack (~> 2.0, >= 2.2.0)
    nokogiri (1.13.10-x86_64-linux)
      racc (~> 1.4)
    rack (2.2.4)
    rails-html-sanitizer (1.4.3)

PLATFORMS
  x86_64-linux

DEPENDENCIES
  actionpack
  nokogiri

BUNDLED WITH
   2.4.10
`
  const r = parseGemfileLock(LOCK)
  it('reads GEM specs only at 4-space indentation and strips platforms', () => {
    expect(r.deps).toEqual([
      { name: 'actionpack', version: '7.0.4', ecosystem: 'RubyGems' },
      { name: 'nokogiri', version: '1.13.10', ecosystem: 'RubyGems' },
      { name: 'rack', version: '2.2.4', ecosystem: 'RubyGems' },
      { name: 'rails-html-sanitizer', version: '1.4.3', ecosystem: 'RubyGems' },
    ])
  })
  it('reports GIT and PATH gems as skipped', () => {
    expect(r.skipped.map((s) => s.entry)).toEqual(['private_gem (0.1.0)', 'myapp (1.0.0)'])
  })
  it('rejects text without sections', () => {
    expect(() => parseGemfileLock('    rack (1.0)')).toThrow()
  })
})

describe('parseComposerLock', () => {
  const LOCK = JSON.stringify({
    'content-hash': 'abc',
    packages: [
      { name: 'symfony/http-kernel', version: 'v5.4.1' },
      { name: 'guzzlehttp/guzzle', version: '7.4.0' },
      { name: 'acme/wip', version: 'dev-main' },
    ],
    'packages-dev': [{ name: 'phpunit/phpunit', version: '9.5.10' }],
  })
  it('strips the leading v and marks dev packages', () => {
    const r = parseComposerLock(LOCK)
    expect(r.deps).toEqual([
      { name: 'symfony/http-kernel', version: '5.4.1', ecosystem: 'Packagist', dev: false },
      { name: 'guzzlehttp/guzzle', version: '7.4.0', ecosystem: 'Packagist', dev: false },
      { name: 'phpunit/phpunit', version: '9.5.10', ecosystem: 'Packagist', dev: true },
    ])
    expect(r.skipped).toHaveLength(1)
  })
  it('rejects invalid JSON', () => {
    expect(() => parseComposerLock('{')).toThrow()
  })
})

describe('Cargo.lock and poetry.lock', () => {
  const CARGO = `# This file is automatically @generated by Cargo.
version = 3

[[package]]
name = "my-crate"
version = "0.1.0"
dependencies = [
 "serde",
]

[[package]]
name = "serde"
version = "1.0.150"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "e326c9ec8042f1b5da33252c8a37e9ffbd2c9bef0155215b6e6c80c790e05f91"

[[package]]
name = "forked"
version = "0.2.0"
source = "git+https://github.com/acme/forked?rev=abc#abc"
`
  it('reads registry crates and skips workspace and git crates', () => {
    const r = parseCargoLock(CARGO)
    expect(r.deps).toEqual([{ name: 'serde', version: '1.0.150', ecosystem: 'crates.io' }])
    expect(r.skipped).toEqual([expect.objectContaining({ entry: 'forked 0.2.0' })])
  })

  const POETRY = `[[package]]
name = "Django"
version = "4.2.1"
description = "A high-level Python web framework"
optional = false
python-versions = ">=3.8"
files = [
    {file = "Django-4.2.1-py3-none-any.whl", hash = "sha256:066b6debb5ac335458d2a713ed995570536c8b59a580005acb0732378d5eb1ee"},
]

[package.dependencies]
asgiref = ">=3.6.0,<4"

[[package]]
name = "pytest"
version = "7.0.0"
category = "dev"

[metadata]
lock-version = "2.0"
content-hash = "abc"
`
  it('reads poetry packages with normalized names', () => {
    expect(parsePoetryLock(POETRY).deps).toEqual([
      { name: 'django', version: '4.2.1', ecosystem: 'PyPI', dev: false },
      { name: 'pytest', version: '7.0.0', ecosystem: 'PyPI', dev: true },
    ])
  })
  it('readTomlPackages ignores sub-tables', () => {
    const pk = readTomlPackages(POETRY)
    expect(pk).toHaveLength(2)
    expect(pk[0].asgiref).toBeUndefined()
  })
  it('poetry: skips git/directory sources and reads Poetry 2 groups', () => {
    const lock = [
      '[[package]]',
      'name = "mylib"',
      'version = "0.1.0"',
      'groups = ["main"]',
      '',
      '[package.source]',
      'type = "git"',
      'url = "https://github.com/me/mylib.git"',
      'reference = "main"',
      '',
      '[[package]]',
      'name = "requests"',
      'version = "2.19.0"',
      'groups = ["main", "dev"]',
      '',
      '[[package]]',
      'name = "pytest"',
      'version = "7.0.0"',
      'groups = ["dev"]',
      '',
      '[[package]]',
      'name = "internal"',
      'version = "1.0.0"',
      '',
      '[package.source]',
      'type = "legacy"',
      'url = "https://pypi.example.com/simple"',
      'reference = "mirror"',
    ].join('\n')
    const r = parsePoetryLock(lock)
    expect(r.deps).toEqual([
      { name: 'requests', version: '2.19.0', ecosystem: 'PyPI', dev: false },
      { name: 'pytest', version: '7.0.0', ecosystem: 'PyPI', dev: true },
      { name: 'internal', version: '1.0.0', ecosystem: 'PyPI', dev: false },
    ])
    expect(r.skipped).toEqual([expect.objectContaining({ entry: 'mylib 0.1.0', reason: expect.stringMatching(/git/) })])
  })
})
