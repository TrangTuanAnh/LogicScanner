# LogicLab Universal v1

Build a local-first repository intelligence product that can safely inventory any readable Git
repository and progressively understand supported components without executing repository code.

## First vertical slice

1. Accept a pinned repository snapshot or an already prepared local snapshot.
2. Discover languages, manifests, components, and static source structure.
3. Produce normalized, source-cited IR and explicit U/R capability levels.
4. Run a deterministic typed agent-task DAG over the report and persist its output.
5. Expose analyses through the FastAPI control API.
6. Render repositories, capabilities, components, tasks, claims, and diagnostics in the React UI.

## Locked constraints

- Static-only is the default and the only execution policy in this slice.
- Never execute a repository Dockerfile, Compose file, build script, hook, or arbitrary shell.
- Never dereference repository symlinks while inventorying.
- Every accepted claim has immutable snapshot provenance and source references.
- Partial and abstained results are valid; unknown areas must remain visible.
- Existing TLS IDS scan/replay behavior and its tests remain compatible.

## Deferred

- Arbitrary repository build/boot/runtime.
- MicroVM runner broker.
- Dynamic adapters beyond the curated TLS IDS lab.
- Enterprise authentication and multi-tenant deployment.
