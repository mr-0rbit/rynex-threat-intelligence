import type { ReactNode } from "react";

export function Card({ children, className = "" }: { children: ReactNode; className?: string }) {
  return (
    <div className={`rounded-lg border border-rynex-border bg-rynex-panel ${className}`}>
      {children}
    </div>
  );
}

export function CardHeader({ title, subtitle }: { title: string; subtitle?: string }) {
  return (
    <div className="border-b border-rynex-border px-4 py-3">
      <h3 className="text-sm font-semibold text-slate-100">{title}</h3>
      {subtitle && <p className="mt-0.5 text-xs text-slate-500">{subtitle}</p>}
    </div>
  );
}

const severityStyles: Record<string, string> = {
  critical: "bg-red-500/10 text-red-400 border-red-500/30",
  high: "bg-orange-500/10 text-orange-400 border-orange-500/30",
  medium: "bg-yellow-500/10 text-yellow-400 border-yellow-500/30",
  low: "bg-sky-500/10 text-sky-400 border-sky-500/30",
  informational: "bg-slate-500/10 text-slate-400 border-slate-500/30",
};

export function SeverityBadge({ severity }: { severity: string }) {
  return (
    <span
      className={`inline-flex items-center rounded border px-1.5 py-0.5 text-[10px] font-semibold uppercase tracking-wider ${
        severityStyles[severity] ?? severityStyles.informational
      }`}
    >
      {severity}
    </span>
  );
}

const statusStyles: Record<string, string> = {
  new: "bg-cyan-500/10 text-cyan-300 border-cyan-500/30",
  acknowledged: "bg-blue-500/10 text-blue-300 border-blue-500/30",
  investigating: "bg-purple-500/10 text-purple-300 border-purple-500/30",
  confirmed: "bg-emerald-500/10 text-emerald-300 border-emerald-500/30",
  false_positive: "bg-slate-500/10 text-slate-400 border-slate-500/30",
  resolved: "bg-slate-500/10 text-slate-500 border-slate-500/30",
  claimed: "bg-orange-500/10 text-orange-300 border-orange-500/30",
  reported: "bg-blue-500/10 text-blue-300 border-blue-500/30",
  unverified: "bg-slate-500/10 text-slate-400 border-slate-500/30",
  disputed: "bg-red-500/10 text-red-300 border-red-500/30",
  healthy: "bg-emerald-500/10 text-emerald-300 border-emerald-500/30",
  degraded: "bg-yellow-500/10 text-yellow-300 border-yellow-500/30",
  failing: "bg-red-500/10 text-red-300 border-red-500/30",
  unknown: "bg-slate-500/10 text-slate-400 border-slate-500/30",
};

export function StatusBadge({ status }: { status: string }) {
  return (
    <span
      className={`inline-flex items-center rounded border px-1.5 py-0.5 text-[10px] font-medium capitalize ${
        statusStyles[status] ?? statusStyles.unknown
      }`}
    >
      {status.replace("_", " ")}
    </span>
  );
}

export function StatCard({
  label,
  value,
  hint,
  accent = false,
}: {
  label: string;
  value: string | number;
  hint?: string;
  accent?: boolean;
}) {
  return (
    <Card className={`p-4 ${accent ? "border-rynex-accent/40" : ""}`}>
      <p className="text-[11px] font-medium uppercase tracking-wider text-slate-500">{label}</p>
      <p className={`mt-1.5 text-2xl font-bold tabular-nums ${accent ? "text-rynex-accent" : "text-slate-100"}`}>
        {typeof value === "number" ? value.toLocaleString() : value}
      </p>
      {hint && <p className="mt-0.5 text-xs text-slate-500">{hint}</p>}
    </Card>
  );
}

export function Spinner({ label = "Loading…" }: { label?: string }) {
  return (
    <div className="flex items-center justify-center gap-2 py-12 text-sm text-slate-500">
      <div className="h-4 w-4 animate-spin rounded-full border-2 border-rynex-border border-t-rynex-accent" />
      {label}
    </div>
  );
}

export function EmptyState({ message }: { message: string }) {
  return (
    <div className="flex flex-col items-center justify-center py-12 text-sm text-slate-500">
      <div className="mb-2 h-8 w-8 rounded-full border border-rynex-border bg-rynex-bg" />
      {message}
    </div>
  );
}

export function timeAgo(iso: string | null | undefined): string {
  if (!iso) return "—";
  const diff = Date.now() - new Date(iso).getTime();
  const mins = Math.floor(diff / 60000);
  if (mins < 1) return "just now";
  if (mins < 60) return `${mins}m ago`;
  const hours = Math.floor(mins / 60);
  if (hours < 24) return `${hours}h ago`;
  return `${Math.floor(hours / 24)}d ago`;
}
