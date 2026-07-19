import { useState } from "react";
import { useRepositoryAnalyses } from "../api/queries";
import { DataSourceBanner, EmptyState, ErrorState, LoadingRows, PageHeader, StatusPill } from "../components/Primitives";

export function AgentTasksPage() {
  const query = useRepositoryAnalyses();
  const [selected, setSelected] = useState<string>("");

  if (query.isLoading) return <LoadingRows label="Loading agent task graph" />;
  if (query.isError) return <ErrorState message={query.error.message} />;

  const result = query.data!;
  const analysis = result.items.find((item) => item.id === selected) ?? result.items.find((item) => item.agent_tasks.length) ?? result.items[0];
  const tasks = analysis?.agent_tasks ?? [];

  return (
    <div className="page-stack">
      <PageHeader
        eyebrow="Research director"
        title="Agent task graph"
        description="Deterministic repository-analysis roles follow a typed dependency graph. This static phase grants them no shell, network, or runner privileges."
        actions={result.items.length ? (
          <div className="compact-field">
            <label htmlFor="agent-repository">Repository</label>
            <select id="agent-repository" value={analysis?.id ?? ""} onChange={(event) => setSelected(event.target.value)}>
              {result.items.map((item) => <option value={item.id} key={item.id}>{item.name}</option>)}
            </select>
          </div>
        ) : undefined}
      />
      <DataSourceBanner source={result.source} />

      {tasks.length ? (
        <>
          <section className="agent-graph" aria-labelledby="task-flow-heading">
            <div className="section-label">
              <p className="eyebrow">Dependency view</p>
              <h2 id="task-flow-heading">Task flow</h2>
              <p>Edges represent evidence dependencies, not conversational turns.</p>
            </div>
            <ol className="task-flow-list">
              {tasks.map((task, index) => (
                <li key={task.id} className={`task-node task-${task.status}`}>
                  <span className="task-index">{String(index + 1).padStart(2, "0")}</span>
                  <span className="task-node-main">
                    <strong>{task.title}</strong>
                    <small>{task.agent}</small>
                  </span>
                  <StatusPill status={task.status} />
                </li>
              ))}
            </ol>
          </section>

          <section className="panel" aria-labelledby="task-ledger-heading">
            <div className="panel-heading">
              <div>
                <p className="eyebrow">Stage ledger</p>
                <h2 id="task-ledger-heading">Task records</h2>
              </div>
              <span className="count-label">{tasks.length} tasks</span>
            </div>
            <div className="table-wrap">
              <table>
                <thead>
                  <tr>
                    <th scope="col">Task</th>
                    <th scope="col">Agent</th>
                    <th scope="col">Dependencies</th>
                    <th scope="col">Output</th>
                    <th scope="col">Duration</th>
                    <th scope="col">Status</th>
                  </tr>
                </thead>
                <tbody>
                  {tasks.map((task) => (
                    <tr key={task.id}>
                      <td><strong>{task.title}</strong><small className="cell-detail"><code>{task.id}</code></small></td>
                      <td>{task.agent}</td>
                      <td>{task.depends_on.length ? task.depends_on.join(", ") : "root"}</td>
                      <td>{task.output ?? "—"}</td>
                      <td>{task.duration_ms ? `${(task.duration_ms / 1000).toFixed(1)}s` : "—"}</td>
                      <td><StatusPill status={task.status} /></td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </section>
        </>
      ) : (
        <EmptyState title="No agent tasks yet" detail="Tasks appear after the immutable repository snapshot has been accepted for static analysis." />
      )}
    </div>
  );
}
