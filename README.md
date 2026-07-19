# LogicLab Universal

LogicLab is a local-first forensic workbench for understanding an unfamiliar Git
repository before any target code is allowed to run. A pinned commit is fetched
as immutable Git objects, materialized without checkout hooks or symlinks,
normalized into a repository IR, and processed by an eight-role analysis graph.
The React UI exposes capability scores, components, diagnostics, tasks, claims,
and source provenance.

## What works now

- Static intake for credential-free HTTPS repositories on GitHub, GitLab,
  Bitbucket, and Codeberg, pinned to an exact 40-character commit SHA.
- Stack and build discovery for Python, Java/JVM, JavaScript/TypeScript, Go,
  Rust, .NET, Ruby, PHP, Elixir, Dart, Bazel, CMake, Make, and Nix projects.
- Python AST extraction plus conservative multi-language symbol, import,
  endpoint, manifest, component, and test-path discovery.
- A deterministic role DAG: research director, repo surveyor, architecture
  mapper, build/runtime scout, test-path analyst, security/domain mapper,
  Project Twin synthesizer, and independent skeptic. Each producing role emits
  its own cited claims under its own provenance, or abstains with a typed reason
  when the evidence is not there.
- Enforced budgets (`StopRules` over accumulated `BudgetUsage`), enforced role
  `max_parallelism`, and deterministic conflict adjudication that refuses to
  break a tie the evidence does not break.
- An optional, default-off local-model proposer for semantic claims that static
  parsing cannot establish. Every proposal must cite an allow-listed
  materialized path and is admitted only as `INFERRED`.
- Typed claims with immutable commit, tree digest, blob SHA-256, line span,
  producer, and tool provenance.
- Same-origin React UI with HttpOnly-cookie session exchange, responsive routes,
  accessible forms, readable API failures, and job polling.
- Versioned Alembic migrations and a wheel containing both UI assets and
  migrations.

Understanding (`U0`–`U4`) and runtime readiness (`R0`–`R4`) are deliberately
independent. Universal analysis currently remains static (`R0`/`R1`). The role
graph is deterministic by default and makes no claim to independent runtime
verification. Semantic review exists only through the opt-in proposer, whose
output is always marked `INFERRED` and never treated as observation.

## Safety boundary

Universal repository submission never runs repository code. Git transfer occurs
in a prompt-free subprocess with an allowlisted forge, public-DNS check,
redirect denial, a pinned shallow fetch, wall-time limit, disk quota, and partial
snapshot cleanup. Materialization skips symlinks, non-regular files, sensitive
paths, binaries, oversized files, unsafe paths, and case collisions. Every
omission lowers coverage and produces `needs_review` rather than a false 100%.

The earlier TLS experiment engine remains in the codebase for compatibility, but
its API mutations and background worker are disabled by default. Enabling
`LOGICLAB_LEGACY_RUNTIME_ENABLED=true` is an explicit opt-in and is not part of
the universal static workflow.

## Quick start on Windows

Requirements: Python 3.12, Git, and Node.js 20+.

```powershell
py -3.12 -m venv .venv
.\.venv\Scripts\python.exe -m pip install -e ".[dev]"
npm --prefix ui ci
npm --prefix ui run build
Copy-Item .env.logiclab.example .env.logiclab
.\.venv\Scripts\python.exe -c "import secrets; print(secrets.token_urlsafe(32))"
```

Put the generated value in `LOGICLAB_API_TOKEN` inside `.env.logiclab`, then:

```powershell
.\.venv\Scripts\logiclab.exe serve
```

Open `http://127.0.0.1:8088`, choose **Unlock API**, and submit a public Git URL
with its exact commit SHA. The app applies Alembic migrations automatically.
SQLite is configured in the example file; for PostgreSQL, replace
`LOGICLAB_DATABASE_URL` or start the included control database:

```powershell
docker compose -f docker-compose.logiclab.yml up -d
```

Repository analysis is persisted before work begins and the HTTP endpoint returns
`202`. The server starts the bounded job in the background. If the process stops
before a queued job starts, resume it with:

```powershell
.\.venv\Scripts\logiclab.exe analysis-worker
```

## Verification

```powershell
.\.venv\Scripts\python.exe -m ruff check src tests migrations
.\.venv\Scripts\python.exe -m pytest --cov=logiclab
npm --prefix ui test -- --run
npm --prefix ui run build
```

The main API routes are under `/v1/repository-analyses`; `/health` is public and
all `/v1` data routes require the configured bearer token or the exchanged
HttpOnly session cookie.

## Current limits

“Universal” means repository and stack independent, not unlimited or unsafe.
Private repositories, arbitrary forge hosts, repositories exceeding configured
transfer/snapshot budgets, full semantic resolution for every language, and
dynamic execution of arbitrary build files are intentionally unsupported in this
release. Unsupported areas remain visible in diagnostics and coverage instead of
being guessed.
