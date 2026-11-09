import type { ReactNode } from "react";

/* Strict palette components: black, white, #00D4FF only. Classical SOC design. */

export function Card({ children, className = "" }: { children: ReactNode; className?: string }) {
  return (
    <div className={`border border-ink-700/80 bg-ink-900/90 shadow-sm backdrop-blur-sm transition-colors hover:border-ink-600 ${className}`}>
      {children}
    </div>
  );
}

export function CardHeader({ title, subtitle }: { title: string; subtitle?: string }) {
  return (
    <div className="border-b border-ink-700/80 px-4 py-3 flex items-center justify-between">
      <div>
        <h3 className="text-2xs font-bold uppercase tracking-[0.14em] text-white font-mono">{title}</h3>
        {subtitle && <p className="mt-0.5 text-2xs text-ink-400 font-mono">{subtitle}</p>}
      </div>
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
  critical: "bg-white text-black font-bold shadow-[0_0_8px_rgba(255,255,255,0.3)]",
  high: "bg-accent text-black font-bold shadow-[0_0_8px_rgba(0,212,255,0.3)]",
  medium: "border border-accent text-accent font-medium",
  low: "border border-ink-500 text-ink-200",
  informational: "border border-ink-700 text-ink-400",
};

export function SeverityBadge({ severity }: { severity: string }) {
  return (
    <span
      className={`inline-flex min-w-[4.5rem] items-center justify-center rounded-sm px-1.5 py-0.5 text-2xs font-mono uppercase tracking-[0.1em] ${
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
  confirmed: "bg-white text-black font-semibold",
  false_positive: "border border-ink-500 text-ink-400",
  resolved: "bg-ink-700 text-ink-300",
  claimed: "border border-accent text-accent",
  reported: "bg-ink-200 text-black",
  unverified: "border border-ink-600 text-ink-400",
  disputed: "bg-ink-500 text-white",
  healthy: "border border-accent-dim text-accent-dim",
  degraded: "border border-ink-400 text-ink-100",
  failing: "bg-ink-300 text-black font-semibold",
  unknown: "border border-ink-700 text-ink-400",
  success: "border border-accent-dim text-accent-dim",
};

export function StatusBadge({ status }: { status: string }) {
  return (
    <span
      className={`inline-flex items-center rounded-sm px-1.5 py-0.5 text-2xs font-mono uppercase tracking-[0.1em] ${
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
    <div
      className={`relative overflow-hidden border bg-ink-900/95 p-4 transition-all hover:border-ink-500/80 ${
        accent ? "border-l-[3px] border-l-accent border-ink-700/80 shadow-[inset_0_0_15px_rgba(0,212,255,0.03)]" : "border-ink-700/80"
      }`}
    >
      {accent && (
        <div className="pointer-events-none absolute -top-8 -right-8 h-20 w-20 bg-accent/5 rounded-full blur-xl" />
      )}
      <p className="text-2xs font-semibold uppercase tracking-[0.14em] text-ink-400 font-mono">{label}</p>
      <p className={`mt-2.5 text-2xl font-bold font-mono tabular-nums leading-none tracking-tight ${accent ? "text-accent drop-shadow-[0_0_12px_rgba(0,212,255,0.3)]" : "text-white"}`}>
        {typeof value === "number" ? value.toLocaleString() : value}
      </p>
      {hint && <p className="mt-2 text-2xs text-ink-400 font-mono">{hint}</p>}
    </div>
  );
}

export function Spinner({ label = "Loading…" }: { label?: string }) {
  return (
    <div className="flex flex-col items-center justify-center gap-3 py-16 text-xs font-mono text-ink-400">
      <div className="relative h-6 w-6">
        <div className="h-6 w-6 rounded-full border-2 border-ink-700 border-t-accent animate-spin" />
      </div>
      <span className="tracking-wider uppercase text-2xs">{label}</span>
    </div>
  );
}

export function EmptyState({ message }: { message: string }) {
  return (
    <div className="flex flex-col items-center justify-center py-12 text-xs font-mono text-ink-400">
      <div className="mb-3 h-8 w-8 border border-ink-700 bg-ink-950 flex items-center justify-center text-ink-500 rounded">
        <span className="block h-1.5 w-1.5 rounded-full bg-accent/60" />
      </div>
      <span className="tracking-wider text-2xs uppercase text-ink-400">{message}</span>
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
