import { NavLink, Outlet } from 'react-router-dom'
import { MODULES } from './modules.ts'

export function Layout() {
  return (
    <div className="shell">
      <aside className="sidebar">
        <NavLink to="/" className="brand">
          <img src={`${import.meta.env.BASE_URL}favicon.svg`} alt="" />
          Security Champion
        </NavLink>
        <nav className="nav" aria-label="Modules">
          <NavLink to="/" end>
            <span aria-hidden>🏠</span> Home
          </NavLink>
          {MODULES.map((m) => (
            <NavLink key={m.path} to={m.path}>
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
