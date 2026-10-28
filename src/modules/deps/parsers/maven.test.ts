import { describe, expect, it } from 'vitest'
import { parsePom, resolveProps } from './maven.ts'

const POM = `<?xml version="1.0" encoding="UTF-8"?>
<project xmlns="http://maven.apache.org/POM/4.0.0"
         xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
         xsi:schemaLocation="http://maven.apache.org/POM/4.0.0 https://maven.apache.org/xsd/maven-4.0.0.xsd">
  <modelVersion>4.0.0</modelVersion>
  <parent>
    <groupId>org.springframework.boot</groupId>
    <artifactId>spring-boot-starter-parent</artifactId>
    <version>3.1.0</version>
  </parent>
  <groupId>com.example</groupId>
  <artifactId>demo</artifactId>
  <version>1.2.0</version>
  <properties>
    <java.version>17</java.version>
    <log4j.version>2.14.1</log4j.version>
    <jackson.base>2.13</jackson.base>
    <jackson.version>\${jackson.base}.0</jackson.version>
  </properties>
  <dependencies>
    <dependency>
      <groupId>org.apache.logging.log4j</groupId>
      <artifactId>log4j-core</artifactId>
      <version>\${log4j.version}</version>
    </dependency>
    <dependency>
      <groupId>com.fasterxml.jackson.core</groupId>
      <artifactId>jackson-databind</artifactId>
      <version>\${jackson.version}</version>
    </dependency>
    <dependency>
      <groupId>org.springframework.boot</groupId>
      <artifactId>spring-boot-starter-web</artifactId>
    </dependency>
    <dependency>
      <groupId>com.example</groupId>
      <artifactId>demo-common</artifactId>
      <version>\${project.version}</version>
    </dependency>
    <dependency>
      <groupId>junit</groupId>
      <artifactId>junit</artifactId>
      <version>4.12</version>
      <scope>test</scope>
    </dependency>
    <dependency>
      <groupId>org.example</groupId>
      <artifactId>unknown-prop</artifactId>
      <version>\${not.defined}</version>
    </dependency>
    <dependency>
      <groupId>org.example</groupId>
      <artifactId>ranged</artifactId>
      <version>[1.0,2.0)</version>
    </dependency>
  </dependencies>
  <build>
    <plugins>
      <plugin>
        <groupId>org.apache.maven.plugins</groupId>
        <artifactId>maven-enforcer-plugin</artifactId>
        <version>3.0.0</version>
        <dependencies>
          <dependency>
            <groupId>org.codehaus.mojo</groupId>
            <artifactId>extra-enforcer-rules</artifactId>
            <version>1.0</version>
          </dependency>
        </dependencies>
      </plugin>
    </plugins>
  </build>
</project>`

describe('parsePom', () => {
  const r = parsePom(POM)

  it('resolves properties, nested properties and project.version', () => {
    expect(r.deps).toEqual([
      { name: 'org.apache.logging.log4j:log4j-core', version: '2.14.1', ecosystem: 'Maven', dev: false },
      { name: 'com.fasterxml.jackson.core:jackson-databind', version: '2.13.0', ecosystem: 'Maven', dev: false },
      { name: 'com.example:demo-common', version: '1.2.0', ecosystem: 'Maven', dev: false },
      { name: 'junit:junit', version: '4.12', ecosystem: 'Maven', dev: true },
    ])
  })

  it('reports managed, unresolvable and ranged versions; ignores plugin dependencies', () => {
    const entries = r.skipped.map((s) => s.entry)
    expect(entries).toEqual([
      'org.springframework.boot:spring-boot-starter-web',
      'org.example:unknown-prop:${not.defined}',
      'org.example:ranged:[1.0,2.0)',
    ])
    expect(r.skipped[0].reason).toMatch(/parent POM or BOM/)
  })

  it('uses the parent version when the project has none', () => {
    const pom = `<project><parent><groupId>g</groupId><artifactId>p</artifactId><version>9.9</version></parent>
      <artifactId>child</artifactId>
      <dependencies><dependency><groupId>g</groupId><artifactId>sib</artifactId><version>\${project.version}</version></dependency></dependencies></project>`
    expect(parsePom(pom).deps).toEqual([{ name: 'g:sib', version: '9.9', ecosystem: 'Maven', dev: false }])
  })

  it('takes versions from the same POM dependencyManagement and skips imported BOMs', () => {
    const pom = `<project xmlns="http://maven.apache.org/POM/4.0.0"><groupId>g</groupId><artifactId>a</artifactId><version>1</version>
      <properties><jackson.version>2.9.8</jackson.version></properties>
      <dependencyManagement><dependencies>
        <dependency><groupId>com.fasterxml.jackson</groupId><artifactId>jackson-bom</artifactId><version>2.17.0</version><type>pom</type><scope>import</scope></dependency>
        <dependency><groupId>com.fasterxml.jackson.core</groupId><artifactId>jackson-databind</artifactId><version>\${jackson.version}</version></dependency>
      </dependencies></dependencyManagement>
      <dependencies>
        <dependency><groupId>com.fasterxml.jackson.core</groupId><artifactId>jackson-databind</artifactId></dependency>
        <dependency><groupId>org.yaml</groupId><artifactId>snakeyaml</artifactId></dependency>
      </dependencies></project>`
    const res = parsePom(pom)
    expect(res.deps).toEqual([
      { name: 'com.fasterxml.jackson.core:jackson-databind', version: '2.9.8', ecosystem: 'Maven', dev: false },
      { name: 'com.fasterxml.jackson.core:jackson-databind', version: '2.9.8', ecosystem: 'Maven', dev: false },
    ])
    expect(res.skipped.map((s) => s.entry)).toEqual(['com.fasterxml.jackson:jackson-bom', 'org.yaml:snakeyaml'])
    expect(res.skipped[0].reason).toMatch(/BOM/)
  })

  it('rejects malformed XML and non-POM XML', () => {
    expect(() => parsePom('<project><dependencies>')).toThrow(/well-formed/)
    expect(() => parsePom('<settings/>')).toThrow(/project/)
  })
})

describe('resolveProps', () => {
  const props = new Map([
    ['a', '1'],
    ['b', '${a}.2'],
    ['loop', '${loop}'],
  ])
  it('resolves recursively', () => {
    expect(resolveProps('${b}.3', props)).toBe('1.2.3')
    expect(resolveProps('plain', props)).toBe('plain')
  })
  it('returns undefined for unknown or cyclic properties', () => {
    expect(resolveProps('${x}', props)).toBeUndefined()
    expect(resolveProps('${loop}', props)).toBeUndefined()
  })
})
