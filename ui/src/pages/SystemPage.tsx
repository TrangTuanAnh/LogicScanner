import { useSystemHealth } from "../api/queries";
import { ErrorState, LoadingRows, PageHeader, StatusPill } from "../components/Primitives";
import { SessionForm } from "../components/SessionForm";

const controls = [
  { control: "Repository intake", posture: "Static only", enforcement: "Bounded Git subprocess + immutable tree" },
  { control: "Analysis roles", posture: "Read only", enforcement: "Typed deterministic stage contracts" },
  { control: "Target execution", posture: "Disabled", enforcement: "Universal API does not expose runtime mutation" },
  { control: "Fetcher redirects", posture: "Denied", enforcement: "Allowlisted HTTPS forge, public DNS, no redirects" },
  { control: "Host filesystem", posture: "Contained", enforcement: "Dedicated snapshot root; no repository symlinks" },
  { control: "Transfer budget", posture: "Bounded", enforcement: "Wall-time and on-disk fetch quota" },
];

export function SystemPage() {
  const query = useSystemHealth();
  if (query.isLoading) return <LoadingRows label="Loading system health" />;
  if (query.isError) return <ErrorState message={query.error.message} />;
  const health = query.data!;

  return (
    <div className="page-stack">
      <PageHeader
        eyebrow="System readiness"
        title="Trust boundaries"
        description="Control-plane health and the effective deterministic policy for repository, agent, and runner workloads."
        actions={<StatusPill status={health.status} />}
      />

      <section className="health-strip" aria-label="System health">
        <div><span>API version</span><strong>{health.version}</strong></div>
        <div><span>Control database</span><strong>{health.database}</strong></div>
        <div><span>Model gateway</span><strong>{health.model_gateway}</strong></div>
        <div><span>Runner</span><strong>{health.runner}</strong></div>
      </section>

      <SessionForm />

      <section className="panel" aria-labelledby="control-matrix-heading">
        <div className="panel-heading">
          <div><p className="eyebrow">Policy revision 4</p><h2 id="control-matrix-heading">Effective control matrix</h2></div>
          <span className="policy-revision">{health.policy}</span>
        </div>
        <div className="table-wrap">
          <table>
            <thead><tr><th scope="col">Control</th><th scope="col">Posture</th><th scope="col">Enforcement</th></tr></thead>
            <tbody>
              {controls.map((item) => (
                <tr key={item.control}><td><strong>{item.control}</strong></td><td><StatusPill status={item.posture} /></td><td>{item.enforcement}</td></tr>
              ))}
            </tbody>
          </table>
        </div>
      </section>

      <section className="system-note" aria-labelledby="hard-deny-heading">
        <div><p className="eyebrow">Universal static mode</p><h2 id="hard-deny-heading">Default hard-deny capabilities</h2></div>
        <ul>
          <li>Privileged containers and host namespaces</li>
          <li>Docker socket, device, or arbitrary host mounts</li>
          <li>Wildcard Internet egress or private-network access</li>
          <li>Production credentials and user-provided model endpoints</li>
        </ul>
      </section>
    </div>
  );
}
