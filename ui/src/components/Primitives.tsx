import type { ReactNode } from "react";
import { Link } from "react-router-dom";
import type { CapabilityScore, DataSource } from "../types";

export function PageHeader({
  eyebrow,
  title,
  description,
  actions,
}: {
  eyebrow: string;
  title: string;
  description: string;
  actions?: ReactNode;
}) {
  return (
    <header className="page-header">
      <div>
        <p className="eyebrow">{eyebrow}</p>
        <h1>{title}</h1>
        <p className="page-description">{description}</p>
      </div>
      {actions ? <div className="page-actions">{actions}</div> : null}
    </header>
  );
}

export function StatusPill({ status }: { status: string }) {
  const normalized = status.toLowerCase().replace(/\s+/g, "_");
  return <span className={`status-pill status-${normalized}`}>{status.replace(/_/g, " ")}</span>;
}

export function DataSourceBanner({ source }: { source: DataSource }) {
  if (source !== "demo") return null;
  return (
    <div className="data-banner" role="status">
      <span className="data-banner-mark" aria-hidden="true">D</span>
      <span>
        <strong>Demonstration data</strong>
        <span>The control API is unavailable; actions still target the same-origin API.</span>
      </span>
    </div>
  );
}

export function Metric({ label, value, detail }: { label: string; value: string; detail: string }) {
  return (
    <div className="metric">
      <span>{label}</span>
      <strong>{value}</strong>
      <small>{detail}</small>
    </div>
  );
}

export function CapabilityMeter({
  short,
  title,
  capability,
}: {
  short: string;
  title: string;
  capability: CapabilityScore;
}) {
  return (
    <div className="capability-meter">
      <div className="capability-code" aria-hidden="true">{short}</div>
      <div className="capability-body">
        <div className="capability-title">
          <span>{title}</span>
          <strong>{capability.label}</strong>
        </div>
        <div
          className="meter-track"
          role="progressbar"
          aria-label={`${title}: ${capability.score}%`}
          aria-valuemin={0}
          aria-valuemax={100}
          aria-valuenow={capability.score}
        >
          <span style={{ width: `${capability.score}%` }} />
        </div>
        {capability.detail ? <small>{capability.detail}</small> : null}
      </div>
    </div>
  );
}

export function EmptyState({
  title,
  detail,
  action,
  headingLevel = 2,
}: {
  title: string;
  detail: string;
  action?: ReactNode;
  headingLevel?: 1 | 2;
}) {
  const Heading = headingLevel === 1 ? "h1" : "h2";
  return (
    <div className="empty-state">
      <span className="empty-mark" aria-hidden="true">∅</span>
      <Heading>{title}</Heading>
      <p>{detail}</p>
      {action}
    </div>
  );
}

export function ErrorState({ message }: { message: string }) {
  return (
    <div className="error-state" role="alert">
      <strong>Unable to load this view</strong>
      <span>{message}</span>
    </div>
  );
}

export function LoadingRows({ label = "Loading analysis" }: { label?: string }) {
  return (
    <div className="loading-state" role="status" aria-live="polite">
      <span className="loading-line" />
      <span className="loading-line short" />
      <span className="visually-hidden">{label}</span>
    </div>
  );
}

export function BackLink({ to, children }: { to: string; children: ReactNode }) {
  return (
    <Link className="back-link" to={to}>
      <span aria-hidden="true">←</span> {children}
    </Link>
  );
}

export function formatDate(value: string): string {
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return value;
  return new Intl.DateTimeFormat("en-GB", {
    dateStyle: "medium",
    timeStyle: "short",
  }).format(date);
}

export function shortCommit(value: string): string {
  return value ? value.slice(0, 10) : "not pinned";
}
