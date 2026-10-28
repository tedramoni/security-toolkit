import { StrictMode } from 'react'
import { createRoot } from 'react-dom/client'
import './index.css'
import App from './app/App.tsx'
import { legacyHashTarget } from './app/legacyHash.ts'

// Links from before the switch to path URLs looked like /security-toolkit/#/pki?tab=csr: keep them working.
const legacy = legacyHashTarget(window.location.hash, import.meta.env.BASE_URL)
if (legacy) window.history.replaceState(null, '', legacy)

createRoot(document.getElementById('root')!).render(
  <StrictMode>
    <App />
  </StrictMode>,
)
