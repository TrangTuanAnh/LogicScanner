import { useState } from "react";
import { Link } from "react-router-dom";
import { useRepositoryAnalyses } from "../api/queries";
import { RepositoryForm } from "../components/RepositoryForm";
import {
  DataSourceBanner,
  EmptyState,
  ErrorState,
  LoadingRows,
  PageHeader,
  StatusPill,
  formatDate,
  shortCommit,
} from "../components/Primitives";

export function RepositoriesPage() {
  const pageSize = 20;
  const [page, setPage] = useState(0);
  const query = useRepositoryAnalyses(pageSize, page * pageSize);

  return (
    <div className="page-stack">
      <PageHeader
        eyebrow="Repository intelligence"
        title="Repository analyses"
        description="Every repository starts as immutable, static-only evidence. Understanding and runtime readiness are scored independently."
      />
      <RepositoryForm />

      {query.isLoading ? <LoadingRows /> : null}
      {query.isError ? <ErrorState message={query.error.message} /> : null}
      {query.data ? (
        <>
          <DataSourceBanner source={query.data.source} />
          <section className="panel" aria-labelledby="repository-list-heading">
            <div className="panel-heading">
              <div>
                <p className="eyebrow">Evidence inventory</p>
                <h2 id="repository-list-heading">Pinned snapshots</h2>
              </div>
              <span className="count-label">{query.data.total} total</span>
            </div>
            {query.data.items.length ? (
              <>
                <div className="table-wrap">
                  <table>
                  <thead>
                    <tr>
                      <th scope="col">Repository</th>
                      <th scope="col">Commit</th>
                      <th scope="col">U / R</th>
                      <th scope="col">Coverage</th>
                      <th scope="col">Status</th>
                      <th scope="col">Created</th>
                    </tr>
                  </thead>
                  <tbody>
                    {query.data.items.map((analysis) => (
                      <tr key={analysis.id}>
                        <td>
                          <Link className="table-link" to={`/repositories/${analysis.id}`}>{analysis.name}</Link>
                          <small className="cell-detail">{analysis.repository_url}</small>
                        </td>
                        <td><code>{shortCommit(analysis.commit)}</code></td>
                        <td>
                          <span className="ur-score" aria-label={`Understanding ${analysis.capabilities.understanding.score} percent, runtime ${analysis.capabilities.runtime.score} percent`}>
                            <strong>{analysis.capabilities.understanding.score}</strong>
                            <span>/</span>
                            <strong>{analysis.capabilities.runtime.score}</strong>
                          </span>
                        </td>
                        <td>{analysis.capabilities.coverage.score}%</td>
                        <td><StatusPill status={analysis.status} /></td>
                        <td>{formatDate(analysis.created_at)}</td>
                      </tr>
                    ))}
                  </tbody>
                  </table>
                </div>
                <div className="form-footer" aria-label="Repository pagination">
                  <span className="form-message">Page {page + 1} of {Math.max(1, Math.ceil(query.data.total / pageSize))}</span>
                  <div className="session-actions">
                    <button className="secondary-button" type="button" disabled={page === 0} onClick={() => setPage((value) => Math.max(0, value - 1))}>Previous</button>
                    <button className="secondary-button" type="button" disabled={(page + 1) * pageSize >= query.data.total} onClick={() => setPage((value) => value + 1)}>Next</button>
                  </div>
                </div>
              </>
            ) : (
              <EmptyState
                title="No repositories analyzed"
                detail="Submit a pinned Git commit above. LogicLab begins with static analysis and does not execute repository code."
              />
            )}
          </section>
        </>
      ) : null}
    </div>
  );
}
