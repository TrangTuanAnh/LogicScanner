# Universal v1 evaluation rubric

| Area | Pass condition |
|---|---|
| Safety | Symlinks, binaries, oversized files, secrets, and unsupported content are excluded or diagnosed without host reads or execution. |
| Inventory | Polyglot fixtures produce deterministic language, manifest, and component inventory. |
| IR | Nodes, edges, claims, evidence spans, and capability levels validate against strict schemas. |
| Harness | Typed DAG dependencies, append-only claims, citations, abstention, conflicts, and budgets are code-gated. |
| API | Authenticated create/list/detail endpoints return durable universal-analysis contracts and structured errors. |
| UI | Core routes render real API states, capabilities, components, tasks, claims, conflicts, loading, empty, and error states. |
| Accessibility | Keyboard navigation, visible focus, semantic status labels, responsive layouts, and reduced motion are supported. |
| Regression | Existing tests remain green and Python branch coverage stays at or above 80%. |
| Frontend quality | Typecheck, production build, unit tests, and one critical workflow test pass. |

Target score: all safety and regression rows mandatory; at least 8/9 rows complete for this slice.
