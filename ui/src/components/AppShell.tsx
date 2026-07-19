import { useEffect, useRef } from "react";
import { NavLink, Outlet, useLocation } from "react-router-dom";

const navigation = [
  { to: "/", label: "Overview", glyph: "OV", end: true },
  { to: "/repositories", label: "Repositories", glyph: "RP" },
  { to: "/agents", label: "Agent tasks", glyph: "AG" },
  { to: "/twin", label: "Security Twin", glyph: "TW" },
  { to: "/runs", label: "Runs", glyph: "RN" },
  { to: "/findings", label: "Findings", glyph: "FD" },
  { to: "/system", label: "System", glyph: "SY" },
];

export function AppShell() {
  const location = useLocation();
  const mainRef = useRef<HTMLElement>(null);
  const previousLocationRef = useRef(`${location.pathname}${location.hash}`);

  useEffect(() => {
    const currentLocation = `${location.pathname}${location.hash}`;
    const locationChanged = previousLocationRef.current !== currentLocation;
    previousLocationRef.current = currentLocation;

    if (location.hash) {
      let frame: number | undefined;
      let observer: MutationObserver | undefined;
      let timeout: number | undefined;

      const focusTarget = () => {
        const target = document.getElementById(location.hash.slice(1));
        if (!target) return false;
        frame = window.requestAnimationFrame(() => {
          target.focus({ preventScroll: true });
          target.scrollIntoView({ block: "start" });
        });
        observer?.disconnect();
        if (timeout !== undefined) window.clearTimeout(timeout);
        return true;
      };

      if (!focusTarget()) {
        observer = new MutationObserver(() => focusTarget());
        observer.observe(mainRef.current ?? document.body, { childList: true, subtree: true });
        timeout = window.setTimeout(() => observer?.disconnect(), 2_000);
      }

      return () => {
        observer?.disconnect();
        if (frame !== undefined) window.cancelAnimationFrame(frame);
        if (timeout !== undefined) window.clearTimeout(timeout);
      };
    }

    if (locationChanged) {
      mainRef.current?.focus();
      window.scrollTo({ top: 0 });
    }
  }, [location.hash, location.pathname]);

  return (
    <div className="app-shell">
      <aside className="sidebar">
        <NavLink to="/" className="brand" aria-label="LogicLab overview">
          <span className="brand-mark" aria-hidden="true">
            LL
          </span>
          <span>
            <strong>LogicLab</strong>
            <small>Forensic workbench</small>
          </span>
        </NavLink>

        <nav className="primary-nav" aria-label="Primary navigation">
          {navigation.map((item) => (
            <NavLink
              key={item.to}
              to={item.to}
              end={item.end}
              className={({ isActive }) => (isActive ? "nav-link active" : "nav-link")}
            >
              <span className="nav-glyph" aria-hidden="true">
                {item.glyph}
              </span>
              <span>{item.label}</span>
            </NavLink>
          ))}
        </nav>

        <div className="sidebar-foot">
          <span className="system-dot" aria-hidden="true" />
          <span>
            <strong>Local control plane</strong>
            <small>Default-deny policy</small>
          </span>
        </div>
      </aside>

      <div className="workspace">
        <header className="topbar">
          <div className="crumb">
            <span>Workspace</span>
            <span aria-hidden="true">/</span>
            <strong>{routeLabel(location.pathname)}</strong>
          </div>
          <div className="topbar-meta">
            <span className="environment-tag">LOCAL</span>
            <span>Policy rev. 4</span>
            <NavLink className="session-link" to="/system#session">Unlock API</NavLink>
          </div>
        </header>
        <main id="main-content" className="main-content" ref={mainRef} tabIndex={-1}>
          <Outlet />
        </main>
      </div>
    </div>
  );
}

function routeLabel(pathname: string): string {
  if (pathname.startsWith("/repositories/")) return "Repository dossier";
  return navigation.find((item) => item.to !== "/" && pathname.startsWith(item.to))?.label ?? "Overview";
}
