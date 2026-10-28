import type { ThreatModel } from './model.ts'
import { createFlow, createModel, createNode } from './model.ts'

/**
 * Realistic sample: a web shop with an SPA, a REST API, PostgreSQL, a payment provider and an audit log.
 * One flow is deliberately weak (plain HTTP to the legacy CDN) to show what the rule engine flags.
 */
export function exampleModel(id: string, now: string = new Date().toISOString()): ThreatModel {
  const m = createModel(id, 'Example: online shop', now)
  m.description =
    'Customers browse products and pay through a single-page application. The API stores orders and customer accounts in PostgreSQL, charges cards through an external payment provider (which confirms payments with webhooks) and writes security events to an audit log.'
  m.owner = 'Shop platform team'
  m.assumptions = [
    'The API and database run in a private cloud network (VPC); only the load balancer is public.',
    'Card numbers never touch our systems: the SPA uses the payment provider’s hosted fields.',
    'Staff access the back office through the same API with an "admin" role.',
  ]
  const user = createNode('ex-user', 'external', 'Customer (browser)', ['human'], 'Anonymous visitors and logged-in customers.')
  const spa = createNode('ex-spa', 'process', 'SPA (static front-end)', [], 'React app served from a CDN; runs in the customer browser and calls the API.')
  const api = createNode(
    'ex-api',
    'process',
    'Shop API',
    ['internet-facing', 'handles-auth', 'processes-payments', 'admin', 'stores-pii'],
    'REST API: authentication, catalogue, orders, back-office endpoints.',
  )
  const db = createNode('ex-db', 'datastore', 'PostgreSQL', ['stores-pii', 'stores-credentials'], 'Customers, password hashes, orders.')
  const psp = createNode('ex-psp', 'external', 'Payment provider', ['third-party'], 'Card processing (hosted fields + webhooks).')
  const audit = createNode('ex-audit', 'datastore', 'Audit log', ['logs'], 'Security and admin events.')
  const cdn = createNode('ex-cdn', 'external', 'Legacy image CDN', ['third-party'], 'Product images, still served over HTTP.')

  m.elements = [
    user,
    spa,
    api,
    db,
    psp,
    audit,
    cdn,
    createFlow('ex-f1', user.id, spa.id, { name: 'Load app', protocol: 'HTTPS', dataClassification: 'public', crossesTrustBoundary: true }),
    createFlow('ex-f2', spa.id, api.id, { name: 'API calls (login, orders)', protocol: 'HTTPS', dataClassification: 'confidential', crossesTrustBoundary: true }),
    createFlow('ex-f3', api.id, db.id, { name: 'SQL queries', protocol: 'PostgreSQL', dataClassification: 'confidential', crossesTrustBoundary: false }),
    createFlow('ex-f4', api.id, psp.id, { name: 'Create payment', protocol: 'HTTPS', dataClassification: 'secret', crossesTrustBoundary: true }),
    createFlow('ex-f5', psp.id, api.id, { name: 'Payment webhook', protocol: 'HTTPS', dataClassification: 'confidential', crossesTrustBoundary: true }),
    createFlow('ex-f6', api.id, audit.id, { name: 'Security events', protocol: 'TLS syslog', dataClassification: 'internal', crossesTrustBoundary: false }),
    createFlow('ex-f7', cdn.id, user.id, { name: 'Product images', protocol: 'HTTP', dataClassification: 'public', crossesTrustBoundary: true }),
  ]
  return m
}
