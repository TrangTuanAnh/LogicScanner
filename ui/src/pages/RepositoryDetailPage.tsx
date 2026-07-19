import { useParams } from "react-router-dom";
import { useRepositoryAnalysis } from "../api/queries";
import {
  BackLink,
  CapabilityMeter,
  DataSourceBanner,
  EmptyState,
  ErrorState,
  LoadingRows,
  PageHeader,
  StatusPill,
  formatDate,
  shortCommit,
} from "../components/Primitives";

export function RepositoryDetailPage() {
  const { analysisId = "" } = useParams();
  const query = useRepositoryAnalysis(analysisId);

  if (query.isLoading) return <LoadingRows label="Loading repository dossier" />;
  if (query.isError) return <ErrorState message={query.error.message} />;

  const result = query.data!;
  const analysis = result.item;

  return (
    <div className="page-stack">
      <BackLink to="/repositories">Repositories</BackLink>
      <PageHeader
        eyebrow="Repository dossier"
        title={analysis.name}
        description={`${analysis.repository_url} · immutable commit ${shortCommit(analysis.commit)}`}
        actions={<StatusPill status={analysis.status} />}
      />
      <DataSourceBanner source={result.source} />

      {analysis.error_message ? (
        <ErrorState
          message={`${analysis.error_code ?? "ANALYSIS_FAILED"}: ${analysis.error_message}`}
        />
      ) : null}

      <section className="capability-section" aria-labelledby="capability-heading">
        <div className="section-label">
          <p className="eyebrow">Capability U / R</p>
          <h2 id="capability-heading">Understanding versus runtime</h2>
          <p>Runtime never inherits trust from static understanding. Each capability is evaluated separately.</p>
        </div>
        <div className="capability-stack">
          <CapabilityMeter short="U" title="Repository understanding" capability={analysis.capabilities.understanding} />
          <CapabilityMeter short="R" title="Runtime readiness" capability={analysis.capabilities.runtime} />
          <CapabilityMeter short="C" title="Source analysis coverage" capability={analysis.capabilities.coverage} />
        </div>
      </section>

      <div className="detail-grid">
        <section className="panel" aria-labelledby="components-heading">
          <div className="panel-heading">
            <div>
              <p className="eyebrow">Architecture map</p>
              <h2 id="components-heading">Components</h2>
            </div>
            <span className="count-label">{analysis.components.length} / {analysis.component_total} mapped</span>
          </div>
          {analysis.components.length ? (
            <div className="table-wrap">
              <table>
                <thead>
                  <tr>
                    <th scope="col">Component</th>
                    <th scope="col">Kind</th>
                    <th scope="col">Location</th>
                    <th scope="col">Language</th>
                    <th scope="col">Confidence</th>
                  </tr>
                </thead>
                <tbody>
                  {analysis.components.map((component) => (
                    <tr key={component.id}>
                      <td>
                        <strong>{component.name}</strong>
                        {component.exposure ? <small className="cell-detail">{component.exposure}</small> : null}
                      </td>
                      <td>{component.kind}</td>
                      <td><code>{component.path}</code></td>
                      <td>{component.language ?? "—"}</td>
                      <td>{component.confidence === undefined ? "—" : `${Math.round(component.confidence * 100)}%`}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          ) : (
            <EmptyState title="Component map pending" detail="The cartographer has not emitted a component inventory yet." />
          )}
        </section>

        <aside className="panel dossier-panel" aria-labelledby="provenance-heading">
          <div className="panel-heading">
            <div>
              <p className="eyebrow">Chain of custody</p>
              <h2 id="provenance-heading">Snapshot</h2>
            </div>
          </div>
          <dl className="dossier-list">
            <div><dt>Analysis ID</dt><dd><code>{analysis.id}</code></dd></div>
            <div><dt>Commit</dt><dd><code>{analysis.commit || "not pinned"}</code></dd></div>
            <div><dt>Tree digest</dt><dd><code>{analysis.snapshot_digest ?? "pending"}</code></dd></div>
            <div><dt>Created</dt><dd>{formatDate(analysis.created_at)}</dd></div>
            <div><dt>Cited claims</dt><dd>{analysis.provenance.length} / {analysis.claim_total}</dd></div>
            <div><dt>Source mode</dt><dd>static-only</dd></div>
            <div><dt>Runtime policy</dt><dd>{analysis.capabilities.runtime.score > 0 ? "review required" : "locked"}</dd></div>
          </dl>
        </aside>
      </div>

      {analysis.provenance.length ? (
        <section className="panel" aria-labelledby="evidence-provenance-heading">
          <div className="panel-heading">
            <div>
              <p className="eyebrow">Verifiable evidence</p>
              <h2 id="evidence-provenance-heading">Claim provenance</h2>
            </div>
            <span className="count-label">{analysis.provenance.length} / {analysis.claim_total}</span>
          </div>
          <div className="table-wrap">
            <table>
              <thead><tr><th scope="col">Claim</th><th scope="col">Producer</th><th scope="col">Tool</th><th scope="col">Evidence</th></tr></thead>
              <tbody>
                {analysis.provenance.slice(0, 100).map((entry) => (
                  <tr key={entry.claim_id}>
                    <td><code>{entry.claim_id}</code></td>
                    <td>{entry.producer_role}</td>
                    <td>{entry.tool_name} {entry.tool_version}</td>
                    <td>
                      {entry.sources.map((source) => (
                        <small className="cell-detail" key={source.ref_id}>
                          <code>{source.path ?? source.ref_id}:{source.start_line ?? "?"}–{source.end_line ?? "?"} · {source.sha256.slice(0, 12)}</code>
                        </small>
                      ))}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </section>
      ) : null}

      <section className="panel" aria-labelledby="diagnostics-heading">
        <div className="panel-heading">
          <div>
            <p className="eyebrow">Analysis notes</p>
            <h2 id="diagnostics-heading">Diagnostics</h2>
          </div>
          <span className="count-label">{analysis.diagnostics.length} / {analysis.diagnostic_total}</span>
        </div>
        {analysis.diagnostics.length ? (
          <ul className="diagnostic-list">
            {analysis.diagnostics.map((diagnostic) => (
              <li key={diagnostic.id}>
                <StatusPill status={diagnostic.severity} />
                <span><strong>{diagnostic.message}</strong>{diagnostic.path ? <code>{diagnostic.path}</code> : null}</span>
              </li>
            ))}
          </ul>
        ) : (
          <p className="quiet-copy">No diagnostics were emitted for this snapshot.</p>
        )}
      </section>
    </div>
  );
}
