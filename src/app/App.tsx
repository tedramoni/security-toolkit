import { Suspense } from 'react'
import { HashRouter, Navigate, Route, Routes } from 'react-router-dom'
import { ErrorBoundary } from './ErrorBoundary.tsx'
import { Layout } from './Layout.tsx'
import { Home } from './Home.tsx'
import { MODULES } from './modules.ts'

export default function App() {
  return (
    <HashRouter>
      <Routes>
        <Route element={<Layout />}>
          <Route index element={<Home />} />
          {MODULES.map(({ path, Component }) => (
            <Route
              key={path}
              path={`${path}/*`}
              element={
                <ErrorBoundary key={path}>
                  <Suspense fallback={<p className="muted">Loading…</p>}>
                    <Component />
                  </Suspense>
                </ErrorBoundary>
              }
            />
          ))}
          <Route path="*" element={<Navigate to="/" replace />} />
        </Route>
      </Routes>
    </HashRouter>
  )
}
