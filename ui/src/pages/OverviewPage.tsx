import { Link } from "react-router-dom";
import { useRepositoryAnalyses } from "../api/queries";
import {
  DataSourceBanner,
  ErrorState,
  LoadingRows,
  Metric,
  PageHeader,
  StatusPill,
  formatDate,
  shortCommit,
} from "../components/Primitives";

export function OverviewPage() {
  const query = useRepositoryAnalyses();

  if (query.isLoading) return <LoadingRows label="Loading workbench overview" />;
  if (query.isError) return <ErrorState message={query.error.message} />;

  const result = query.data!;
  const ready = result.items.filter((item) => item.status === "ready").length;
  const review = result.items.filter((item) => item.status.includes("review")).length;
  const activeTasks = result.items.flatMap((item) => item.agent_tasks).filter((task) => task.status === "running").length;
  const conflictCount = result.items.reduce((total, item) => total + item.conflict_total, 0);

  return (
    <div className="page-stack">
      <PageHeader
        eyebrow="Control plane"
        title="Security research, with a chain of custody"
        description="Understand unfamiliar repositories first. Runtime capabilities remain locked until a deterministic policy and reviewer approve the exact manifest."
        actions={<Link className="primary-button" to="/repositories">Analyze repository</Link>}
      />
      <DataSourceBanner source={result.source} />

      <section className="metric-strip" aria-label="Workspace summary">
        <Metric label="Repositories" value={String(result.total)} detail={`${ready} ready for investigation`} />
        <Metric label="Review gates" value={String(review)} detail="Human capability decisions" />
        <Metric label="Active agents" value={String(activeTasks)} detail="Deterministic task graph" />
        <Metric label="Twin conflicts" value={String(conflictCount)} detail="Require independent verification" />
      </section>

      <div className="overview-grid">
        <section className="panel" aria-labelledby="recent-repositories-heading">
          <div className="panel-heading">
            <div>
              <p className="eyebrow">Recent intake</p>
              <h2 id="recent-repositories-heading">Repository analyses</h2>
            </div>
            <Link className="text-link" to="/repositories">View all</Link>
          </div>
          <div className="record-list">
            {result.items.slice(0, 4).map((analysis) => (
              <Link className="record-row" to={`/repositories/${analysis.id}`} key={analysis.id}>
                <span className="record-main">
                  <strong>{analysis.name}</strong>
                  <small><code>{shortCommit(analysis.commit)}</code> · {formatDate(analysis.created_at)}</small>
                </span>
                <span className="record-score">
                  <small>Understanding</small>
                  <strong>{analysis.capabilities.understanding.score}%</strong>
                </span>
                <StatusPill status={analysis.status} />
              </Link>
            ))}
          </div>
        </section>

        <aside className="panel policy-panel" aria-labelledby="policy-posture-heading">
          <div className="panel-heading">
            <div>
              <p className="eyebrow">Effective policy</p>
              <h2 id="policy-posture-heading">Default deny</h2>
            </div>
            <span className="policy-revision">REV 4</span>
          </div>
          <dl className="policy-list">
            <div><dt>Static analyzers</dt><dd><StatusPill status="allowed" /></dd></div>
            <div><dt>Target code execution</dt><dd><StatusPill status="approval required" /></dd></div>
            <div><dt>Internet egress</dt><dd><StatusPill status="denied" /></dd></div>
            <div><dt>Host mounts</dt><dd><StatusPill status="denied" /></dd></div>
            <div><dt>Production secrets</dt><dd><StatusPill status="denied" /></dd></div>
          </dl>
          <Link className="secondary-button full-width" to="/system">Inspect system policy</Link>
        </aside>
      </div>
    </div>
  );
}
