import { useState } from "react";
import { useRepositoryAnalyses, useRepositoryAnalysis } from "../api/queries";
import { DataSourceBanner, EmptyState, ErrorState, LoadingRows, PageHeader, StatusPill } from "../components/Primitives";

export function TwinPage() {
  const query = useRepositoryAnalyses();
  const [selected, setSelected] = useState("");
  const repositoryId = selected || query.data?.items[0]?.id || "";
  const detailQuery = useRepositoryAnalysis(repositoryId);

  if (query.isLoading || (repositoryId && detailQuery.isLoading)) {
    return <LoadingRows label="Loading security twin" />;
  }
  if (query.isError) return <ErrorState message={query.error.message} />;
  if (detailQuery.isError) return <ErrorState message={detailQuery.error.message} />;

  const result = query.data!;
  const analysis = detailQuery.data?.item ?? result.items.find((item) => item.id === repositoryId);
  const claims = analysis?.claims ?? [];
  const conflicts = claims.filter((claim) => claim.status === "conflicted");
  const derived = Math.max(0, (analysis?.claim_total ?? claims.length) - (analysis?.conflict_total ?? conflicts.length));

  return (
    <div className="page-stack">
      <PageHeader
        eyebrow="Program Security Twin"
        title="Claims and conflicts"
        description="Every inferred security rule remains a claim with provenance, confidence, and explicit contradiction state."
        actions={result.items.length ? (
          <div className="compact-field">
            <label htmlFor="twin-repository">Repository</label>
            <select id="twin-repository" value={repositoryId} onChange={(event) => setSelected(event.target.value)}>
              {result.items.map((item) => <option value={item.id} key={item.id}>{item.name}</option>)}
            </select>
          </div>
        ) : undefined}
      />
      <DataSourceBanner source={detailQuery.data?.source ?? result.source} />

      <section className="twin-summary" aria-label="Security Twin summary">
        <div><span>Total claims</span><strong>{analysis?.claim_total ?? claims.length}</strong></div>
        <div><span>Derived</span><strong>{derived}</strong></div>
        <div><span>Conflicts</span><strong className="text-warning">{analysis?.conflict_total ?? conflicts.length}</strong></div>
        <div><span>Mean confidence</span><strong>{claims.length ? Math.round((claims.reduce((sum, claim) => sum + claim.confidence, 0) / claims.length) * 100) : 0}%</strong></div>
      </section>

      {conflicts.length ? (
        <section className="conflict-band" aria-labelledby="conflict-heading">
          <div>
            <p className="eyebrow">Contradiction queue</p>
            <h2 id="conflict-heading">{conflicts.length} claim {conflicts.length === 1 ? "needs" : "need"} independent verification</h2>
          </div>
          <ul>
            {conflicts.map((claim) => <li key={claim.id}><strong>{claim.subject}</strong><span>{claim.value}</span></li>)}
          </ul>
        </section>
      ) : null}

      <section className="panel" aria-labelledby="claim-ledger-heading">
        <div className="panel-heading">
          <div>
            <p className="eyebrow">Evidence-backed model</p>
            <h2 id="claim-ledger-heading">Claim ledger</h2>
          </div>
          <span className="count-label">{claims.length} / {analysis?.claim_total ?? claims.length}</span>
        </div>
        {claims.length ? (
          <div className="claim-list">
            {claims.map((claim) => (
              <article className="claim-row" key={claim.id}>
                <div className="claim-statement">
                  <code>{claim.subject}</code>
                  <span>{claim.predicate}</span>
                  <strong>{claim.value}</strong>
                </div>
                <div className="claim-meta">
                  <StatusPill status={claim.status} />
                  <span>{Math.round(claim.confidence * 100)}% confidence</span>
                  <span>{claim.source_refs.length} sources</span>
                </div>
                <ul className="source-ref-list">
                  {claim.source_refs.map((ref) => <li key={ref}><code>{ref}</code></li>)}
                </ul>
              </article>
            ))}
          </div>
        ) : (
          <EmptyState title="No Twin claims yet" detail="Claims appear after architecture, entry-point, and data-model agents have completed their dependency tasks." />
        )}
      </section>
    </div>
  );
}
