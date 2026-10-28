import { NavLink, Outlet } from 'react-router-dom'
import { MODULES } from './modules.ts'
import { usePageMeta } from './usePageMeta.ts'

export function Layout() {
  usePageMeta()
  return (
    <div className="shell">
      <aside className="sidebar">
        <NavLink to="/" className="brand">
          <img src={`${import.meta.env.BASE_URL}favicon.svg`} alt="" width={26} height={26} />
          Security Toolkit
        </NavLink>
        <nav className="nav" aria-label="Modules">
          <NavLink to="/" end>
            <span aria-hidden>🏠</span> Home
          </NavLink>
          {MODULES.map((m) => (
            <NavLink key={m.path} to={`${m.path}/`}>
              <span aria-hidden>{m.icon}</span> {m.title}
            </NavLink>
          ))}
        </nav>
        <div className="sidebar-foot">🔒 Runs 100% in your browser. Your data never leaves this device.</div>
      </aside>
      <main className="main">
        <Outlet />
      </main>
    </div>
  )
}
