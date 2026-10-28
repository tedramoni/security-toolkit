import { lazy } from 'react'

export interface ModuleDef {
  path: string
  title: string
  icon: string
  description: string
  Component: React.LazyExoticComponent<React.ComponentType>
}

export const MODULES: ModuleDef[] = [
  {
    path: '/threat-model',
    title: 'Threat Modeling',
    icon: '🧭',
    description: 'Model components and data flows, generate STRIDE threats, track mitigations, export Markdown.',
    Component: lazy(() => import('../modules/threat-model/index.tsx')),
  },
  {
    path: '/toolbox',
    title: 'Dev Toolbox',
    icon: '🧰',
    description: 'JWT decoder & linter, CSP evaluator, security headers checker, encoders, hashes, secrets scanner.',
    Component: lazy(() => import('../modules/toolbox/index.tsx')),
  },
  {
    path: '/checklists',
    title: 'Review Checklists',
    icon: '✅',
    description: 'OWASP Top 10, API Security Top 10 and ASVS checklists for code reviews — copy as a PR comment.',
    Component: lazy(() => import('../modules/checklists/index.tsx')),
  },
  {
    path: '/deps',
    title: 'Dependencies & CI',
    icon: '📦',
    description: 'Check lockfiles against OSV.dev for known vulnerabilities and generate GitHub Actions security workflows.',
    Component: lazy(() => import('../modules/deps/index.tsx')),
  },
  {
    path: '/data-lab',
    title: 'Data Lab',
    icon: '🧪',
    description: 'CyberChef-style recipes: chain encoding, crypto, compression, hashing and extraction operations, with Magic auto-detect.',
    Component: lazy(() => import('../modules/data-lab/index.tsx')),
  },
  {
    path: '/pki',
    title: 'PKI Tools',
    icon: '🔐',
    description: 'Decode and lint certificates, CSRs and CRLs, generate CSRs, match keys, convert formats, plan key ceremonies.',
    Component: lazy(() => import('../modules/pki/index.tsx')),
  },
  {
    path: '/skill-scanner',
    title: 'AI Skill Scanner',
    icon: '🤖',
    description: 'Scan AI agent skills, MCP configs and agent hooks for prompt injection, exfiltration and dangerous commands.',
    Component: lazy(() => import('../modules/skill-scanner/index.tsx')),
  },
]
