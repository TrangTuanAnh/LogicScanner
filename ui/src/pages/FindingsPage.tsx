import { useFindings } from "../api/queries";
import { DataSourceBanner, EmptyState, ErrorState, LoadingRows, PageHeader, StatusPill } from "../components/Primitives";

export function FindingsPage() {
  const query = useFindings();
  if (query.isLoading) return <LoadingRows label="Loading findings" />;
  if (query.isError) return <ErrorState message={query.error.message} />;
  const result = query.data!;

  return (
    <div className="page-stack">
      <PageHeader
        eyebrow="Independent verification"
        title="Findings"
        description="A hypothesis becomes a finding only when its invariant, experiment, evidence, replay, and verifier decision remain linked."
      />
      <DataSourceBanner source={result.source} />
      <section className="panel" aria-labelledby="finding-list-heading">
        <div className="panel-heading">
          <div><p className="eyebrow">Evidence queue</p><h2 id="finding-list-heading">Investigation records</h2></div>
          <span className="count-label">{result.items.length}</span>
        </div>
        {result.items.length ? (
          <div className="finding-list">
            {result.items.map((finding) => (
              <article className="finding-row" key={finding.id}>
                <div className="finding-id"><span>Finding</span><code>{finding.id}</code></div>
                <div className="finding-main">
                  <div className="finding-title-line"><h2>{finding.title}</h2><StatusPill status={finding.status} /></div>
                  <p><span>Invariant</span>{finding.invariant}</p>
                  <small>{finding.repository}</small>
                </div>
                <dl className="finding-numbers">
                  <div><dt>Confidence</dt><dd>{finding.confidence}%</dd></div>
                  <div><dt>Evidence</dt><dd>{finding.evidence}</dd></div>
                </dl>
              </article>
            ))}
          </div>
        ) : (
          <EmptyState title="No findings yet" detail="Confirmed or inconclusive investigation records will appear here after independent verification." />
        )}
      </section>
    </div>
  );
}
