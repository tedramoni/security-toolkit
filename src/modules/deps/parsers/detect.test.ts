import { describe, expect, it } from 'vitest'
import { detectByContent, detectByFilename, detectFormat, parseLockfile } from './detect.ts'

describe('detectByFilename', () => {
  it.each([
    ['package-lock.json', 'package-lock'],
    ['frontend/npm-shrinkwrap.json', 'package-lock'],
    ['C:\\repo\\yarn.lock', 'yarn-lock'],
    ['requirements.txt', 'requirements'],
    ['requirements-dev.txt', 'requirements'],
    ['requirements/prod.txt', null],
    ['constraints.txt', 'requirements'],
    ['Pipfile.lock', 'pipfile-lock'],
    ['poetry.lock', 'poetry-lock'],
    ['pom.xml', 'pom'],
    ['go.mod', 'go-mod'],
    ['go.sum', 'go-sum'],
    ['Gemfile.lock', 'gemfile-lock'],
    ['composer.lock', 'composer-lock'],
    ['Cargo.lock', 'cargo-lock'],
    ['package.json', null],
  ])('%s -> %s', (name, expected) => {
    expect(detectByFilename(name)).toBe(expected)
  })
})

describe('detectByContent', () => {
  it.each([
    ['{"name":"x","lockfileVersion":3,"packages":{}}', 'package-lock'],
    ['{"content-hash":"x","packages":[]}', 'composer-lock'],
    ['{"_meta":{},"default":{}}', 'pipfile-lock'],
    ['{"foo":1}', null],
    ['<?xml version="1.0"?>\n<project xmlns="x"></project>', 'pom'],
    ['# yarn lockfile v1\n\nlodash@^4:\n  version "4.17.21"\n', 'yarn-lock'],
    ['__metadata:\n  version: 6\n', 'yarn-lock'],
    ['GEM\n  remote: https://rubygems.org/\n  specs:\n    rack (2.2.4)\n', 'gemfile-lock'],
    ['version = 3\n\n[[package]]\nname = "serde"\nversion = "1.0.0"\nsource = "registry+https://x"\n', 'cargo-lock'],
    ['[[package]]\nname = "django"\nversion = "4.2"\n', 'poetry-lock'],
    ['module example.com/x\n\ngo 1.21\n', 'go-mod'],
    ['golang.org/x/net v0.17.0 h1:pVaXccu2ozPjCXewfr1S7xza/zcXTity9cCdXQYSjIM=\n', 'go-sum'],
    ['# deps\nDjango==3.2\nrequests>=2\n', 'requirements'],
    ['just some prose', null],
  ])('%#', (text, expected) => {
    expect(detectByContent(text)).toBe(expected)
  })
})

describe('detectFormat / parseLockfile', () => {
  it('prefers the filename, falls back to content', () => {
    expect(detectFormat('requirements.txt', '{"lockfileVersion":2}')).toBe('requirements')
    expect(detectFormat('pasted', '{"lockfileVersion":2}')).toBe('package-lock')
    expect(detectFormat(undefined, 'flask==2.0.0')).toBe('requirements')
  })
  it('dispatches to the right parser', () => {
    expect(parseLockfile('requirements', 'flask==2.0.0').deps).toEqual([{ name: 'flask', version: '2.0.0', ecosystem: 'PyPI' }])
  })
})
