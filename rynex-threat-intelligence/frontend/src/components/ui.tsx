import type { ReactNode } from "react";

/* Strict palette components: black, white, #00D4FF only. */

export function Card({ children, className = "" }: { children: ReactNode; className?: string }) {
  return (
    <div className={`border border-ink-600 bg-ink-800 ${className}`}>{children}</div>
  );
}

export function CardHeader({ title, subtitle }: { title: string; subtitle?: string }) {
  return (
    <div className="border-b border-ink-600 px-4 py-2.5">
      <h3 className="text-2xs font-semibold uppercase tracking-[0.12em] text-ink-100">{title}</h3>
      {subtitle && <p className="mt-0.5 text-2xs text-ink-400">{subtitle}</p>}
    </div>
  );
}

/**
 * Monochrome severity system (only black / white / #00D4FF):
 *  critical       → solid white on black (highest contrast)
 *  high           → solid #00D4FF on black
 *  medium         → #00D4FF outline
 *  low            → neutral outline
 *  informational  → neutral muted
 */
const severityStyles: Record<string, string> = {
  critical: "bg-white text-black font-bold",
  high: "bg-accent text-black font-bold",
  medium: "border border-accent text-accent",
  low: "border border-ink-400 text-ink-200",
  informational: "border border-ink-600 text-ink-300",
};

export function SeverityBadge({ severity }: { severity: string }) {
  return (
    <span
      className={`inline-flex min-w-[4.5rem] items-center justify-center px-1.5 py-0.5 text-2xs font-semibold uppercase tracking-[0.08em] ${
        severityStyles[severity] ?? severityStyles.informational
      }`}
    >
      {severity}
    </span>
  );
}

const statusStyles: Record<string, string> = {
  new: "bg-accent text-black font-semibold",
  acknowledged: "border border-accent-dim text-accent-dim",
  investigating: "border border-accent text-accent",
  confirmed: "bg-white text-black",
  false_positive: "border border-ink-500 text-ink-400",
  resolved: "bg-ink-700 text-ink-300",
  claimed: "border border-accent text-accent",
  reported: "bg-ink-200 text-black",
  unverified: "border border-ink-500 text-ink-400",
  disputed: "bg-ink-500 text-white",
  healthy: "border border-accent-dim text-accent-dim",
  degraded: "border border-ink-300 text-ink-100",
  failing: "bg-ink-300 text-black font-semibold",
  unknown: "border border-ink-600 text-ink-400",
  success: "border border-accent-dim text-accent-dim",
};

export function StatusBadge({ status }: { status: string }) {
  return (
    <span
      className={`inline-flex items-center px-1.5 py-0.5 text-2xs uppercase tracking-[0.08em] ${
        statusStyles[status] ?? statusStyles.unknown
      }`}
    >
      {status.replace(/_/g, " ")}
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
    <div className={`border bg-ink-800 p-4 ${accent ? "border-l-2 border-l-accent border-ink-600" : "border-ink-600"}`}>
      <p className="text-2xs font-medium uppercase tracking-[0.12em] text-ink-400">{label}</p>
      <p className={`mt-2 text-2xl font-bold tabular-nums leading-none ${accent ? "text-accent" : "text-white"}`}>
        {typeof value === "number" ? value.toLocaleString() : value}
      </p>
      {hint && <p className="mt-1.5 text-2xs text-ink-400">{hint}</p>}
    </div>
  );
}

export function Spinner({ label = "Loading…" }: { label?: string }) {
  return (
    <div className="flex items-center justify-center gap-2 py-12 text-xs text-ink-400">
      <div className="h-3.5 w-3.5 animate-spin border border-ink-600 border-t-accent" />
      {label}
    </div>
  );
}

export function EmptyState({ message }: { message: string }) {
  return (
    <div className="flex flex-col items-center justify-center py-12 text-xs text-ink-400">
      <div className="mb-3 h-6 w-6 border border-ink-600 bg-ink-850" />
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

/** Opacity steps of the single accent hue for data series. */
export const ACCENT = "#00D4FF";
export const ACCENT_STEPS = [
  "#00D4FF",
  "rgba(0,212,255,0.72)",
  "rgba(0,212,255,0.52)",
  "rgba(0,212,255,0.36)",
  "rgba(0,212,255,0.24)",
  "rgba(255,255,255,0.60)",
  "rgba(255,255,255,0.38)",
  "rgba(255,255,255,0.22)",
  "rgba(255,255,255,0.12)",
];
