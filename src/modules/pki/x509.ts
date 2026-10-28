/**
 * Single entry point for @peculiar/x509 inside the PKI module.
 *
 * The library uses tsyringe, which needs a Reflect metadata polyfill loaded BEFORE the library module is evaluated.
 * ES modules evaluate imports in order, so the polyfill import must stay first. Everything in this module imports
 * x509 from here (never from '@peculiar/x509' directly) so the polyfill is only loaded with the lazy PKI chunk.
 */
import '@abraham/reflection'
import * as x509 from '@peculiar/x509'

x509.cryptoProvider.set(globalThis.crypto)

export { x509 }
