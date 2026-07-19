import { useRuns } from "../api/queries";
import { DataSourceBanner, EmptyState, ErrorState, LoadingRows, PageHeader, StatusPill } from "../components/Primitives";

export function RunsPage() {
  const query = useRuns();
  if (query.isLoading) return <LoadingRows label="Loading run ledger" />;
  if (query.isError) return <ErrorState message={query.error.message} />;
  const result = query.data!;

  return (
    <div className="page-stack">
      <PageHeader
        eyebrow="Experiment operations"
        title="Run ledger"
        description="Each run is bound to one repository snapshot, manifest revision, policy decision, and isolated attempt."
      />
      <DataSourceBanner source={result.source} />
      <section className="panel" aria-labelledby="run-ledger-heading">
        <div className="panel-heading">
          <div><p className="eyebrow">Provenance rail</p><h2 id="run-ledger-heading">Recent runs</h2></div>
          <span className="count-label">{result.items.length}</span>
        </div>
        {result.items.length ? (
          <ol className="run-ledger">
            {result.items.map((run) => (
              <li key={run.id}>
                <span className={`run-rail-node run-${run.status}`} aria-hidden="true" />
                <div className="run-record-head">
                  <div><strong>{run.repository}</strong><code>{run.id}</code></div>
                  <StatusPill status={run.status} />
                </div>
                <dl className="run-record-meta">
                  <div><dt>Stage</dt><dd>{run.stage}</dd></div>
                  <div><dt>Started</dt><dd>{run.started_at}</dd></div>
                  <div><dt>Elapsed</dt><dd>{run.elapsed}</dd></div>
                  <div><dt>Policy</dt><dd><code>{run.policy}</code></dd></div>
                </dl>
              </li>
            ))}
          </ol>
        ) : (
          <EmptyState title="No runs recorded" detail="A run starts only after static analysis or an approved runtime manifest is queued." />
        )}
      </section>
    </div>
  );
}
