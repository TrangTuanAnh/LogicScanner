# LogicLab forensic workbench

React + TypeScript + Vite frontend for repository analysis, agent task graphs,
the Program Security Twin, runs, findings, and control-plane readiness.

```powershell
npm install
npm run dev
npm run test
npm run build
```

The browser client uses same-origin `/v1` requests. During development Vite
proxies `/v1` to `http://127.0.0.1:8088`; override it with
`VITE_LOGICLAB_API_TARGET`. `VITE_API_ROOT` can change the browser-visible API
root when the UI is deployed behind a different gateway.

Repository intake calls:

- `GET /v1/repository-analyses`
- `POST /v1/repository-analyses` with `{ name?, repository_url, commit }`
- `GET /v1/repository-analyses/{id}`

Authentication exchanges the operator token through `POST /v1/session` for an
HttpOnly cookie. The token is held only in component state and is never written
to browser storage.

When an unimplemented repository, run, or finding endpoint returns a service or
not-found response, the workbench shows explicitly labelled demonstration data.
Authentication and authorization errors remain visible and do not fall back.
