import type { ReactNode, ComponentType } from "react";

/* Modern SOC Cyber Design System: High-contrast, rich obsidian surfaces,
 * specular edge lighting, and vibrant semantic security indicators.
 */

export function Card({
  children,
  className = "",
  glow = false,
}: {
  children: ReactNode;
  className?: string;
  glow?: boolean;
}) {
  return (
    <div
      className={`rounded-xl border border-ink-700/80 bg-gradient-to-b from-ink-900/90 to-ink-950/90 backdrop-blur-md shadow-lg shadow-black/30 transition-all duration-200 hover:border-ink-600/90 ${
        glow ? "ring-1 ring-accent/30 shadow-[0_0_25px_rgba(0,212,255,0.12)]" : ""
      } ${className}`}
    >
      {children}
    </div>
  );
}

export function CardHeader({
  title,
  subtitle,
  icon: Icon,
  action,
}: {
  title: string;
  subtitle?: string;
  icon?: ComponentType<{ className?: string }>;
  action?: ReactNode;
}) {
  return (
    <div className="border-b border-ink-700/60 px-5 py-3.5 flex items-center justify-between gap-3">
      <div className="flex items-center gap-2.5 min-w-0">
        {Icon && (
          <div className="flex h-7 w-7 shrink-0 items-center justify-center rounded-lg border border-ink-700 bg-ink-950/80 text-accent shadow-sm">
            <Icon className="h-4 w-4" />
          </div>
        )}
        <div className="min-w-0">
          <h3 className="text-xs font-bold uppercase tracking-[0.12em] text-white font-mono truncate">
            {title}
          </h3>
          {subtitle && (
            <p className="mt-0.5 text-2xs text-ink-400 font-sans truncate">{subtitle}</p>
          )}
        </div>
      </div>
      {action && <div className="shrink-0">{action}</div>}
    </div>
  );
}

/**
 * Semantic security severity badge system:
 *  critical       → glowing crimson / rose (highest threat urgency)
 *  high           → glowing amber / orange
 *  medium         → electric cyan / teal
 *  low            → calm sky / slate
 *  informational  → muted neutral indigo
 */
const severityConfig: Record<
  string,
  { bg: string; dot: string; text: string; shadow: string }
> = {
  critical: {
    bg: "border-rose-500/35 bg-rose-500/15 text-rose-300",
    dot: "bg-rose-400 shadow-[0_0_6px_#f43f5e]",
    text: "CRITICAL",
    shadow: "shadow-[0_0_12px_rgba(244,63,94,0.22)]",
  },
  high: {
    bg: "border-amber-500/35 bg-amber-500/15 text-amber-300",
    dot: "bg-amber-400 shadow-[0_0_6px_#f59e0b]",
    text: "HIGH",
    shadow: "shadow-[0_0_12px_rgba(245,158,11,0.22)]",
  },
  medium: {
    bg: "border-cyan-500/35 bg-cyan-500/15 text-cyan-300",
    dot: "bg-cyan-400 shadow-[0_0_6px_#00e5ff]",
    text: "MEDIUM",
    shadow: "shadow-[0_0_10px_rgba(0,212,255,0.18)]",
  },
  low: {
    bg: "border-sky-500/25 bg-sky-500/10 text-sky-300",
    dot: "bg-sky-400",
    text: "LOW",
    shadow: "",
  },
  informational: {
    bg: "border-ink-600/70 bg-ink-800/80 text-ink-300",
    dot: "bg-ink-400",
    text: "INFO",
    shadow: "",
  },
};

export function SeverityBadge({
  severity,
  className = "",
}: {
  severity: string;
  className?: string;
}) {
  const norm = (severity || "informational").toLowerCase();
  const cfg = severityConfig[norm] ?? severityConfig.informational;

  return (
    <span
      className={`inline-flex items-center gap-1.5 rounded-md border px-2 py-0.5 text-2xs font-mono font-semibold uppercase tracking-[0.08em] ${cfg.bg} ${cfg.shadow} ${className}`}
    >
      <span className={`h-1.5 w-1.5 rounded-full shrink-0 ${cfg.dot}`} />
      <span>{cfg.text}</span>
    </span>
  );
}

export function Badge({
  children,
  variant = "neutral",
  size = "sm",
}: {
  children: ReactNode;
  variant?:
    | "cyan"
    | "neutral"
    | "critical"
    | "warning"
    | "success"
    | "purple"
    | "outline";
  size?: "xs" | "sm";
}) {
  const styles: Record<string, string> = {
    cyan: "border-accent/40 bg-accent/15 text-accent shadow-[0_0_10px_rgba(0,212,255,0.15)] font-semibold",
    neutral: "border-ink-600 bg-ink-800/80 text-ink-300",
    critical: "border-rose-500/40 bg-rose-500/15 text-rose-300 shadow-[0_0_10px_rgba(244,63,94,0.18)] font-semibold",
    warning: "border-amber-500/40 bg-amber-500/15 text-amber-300 shadow-[0_0_10px_rgba(245,158,11,0.18)] font-semibold",
    success: "border-emerald-500/40 bg-emerald-500/15 text-emerald-300 shadow-[0_0_10px_rgba(16,185,129,0.18)] font-semibold",
    purple: "border-purple-500/40 bg-purple-500/15 text-purple-300 shadow-[0_0_10px_rgba(168,85,247,0.18)] font-semibold",
    outline: "border-ink-600 bg-transparent text-ink-300",
  };

  const sizeClass = size === "xs" ? "px-1.5 py-0.2 text-[10px]" : "px-2 py-0.5 text-2xs";

  return (
    <span
      className={`inline-flex items-center rounded-md border font-mono uppercase tracking-[0.08em] ${sizeClass} ${
        styles[variant] ?? styles.neutral
      }`}
    >
      {children}
    </span>
  );
}

const statusConfig: Record<string, { bg: string; dot: string; label?: string }> = {
  new: { bg: "border-accent/40 bg-accent/15 text-accent font-semibold", dot: "bg-accent shadow-[0_0_6px_#00d4ff] animate-pulse" },
  acknowledged: { bg: "border-sky-500/30 bg-sky-500/10 text-sky-300", dot: "bg-sky-400" },
  investigating: { bg: "border-amber-500/40 bg-amber-500/15 text-amber-300 font-medium", dot: "bg-amber-400 animate-pulse" },
  confirmed: { bg: "border-rose-500/40 bg-rose-500/15 text-rose-300 font-semibold", dot: "bg-rose-400 shadow-[0_0_6px_#f43f5e]" },
  false_positive: { bg: "border-ink-600 bg-ink-800 text-ink-400", dot: "bg-ink-500" },
  resolved: { bg: "border-emerald-500/40 bg-emerald-500/15 text-emerald-300 font-semibold", dot: "bg-emerald-400 shadow-[0_0_6px_#10b981]" },
  claimed: { bg: "border-purple-500/40 bg-purple-500/15 text-purple-300 font-medium", dot: "bg-purple-400" },
  reported: { bg: "border-cyan-500/30 bg-cyan-500/10 text-cyan-200", dot: "bg-cyan-400" },
  unverified: { bg: "border-ink-600 bg-ink-800/80 text-ink-400", dot: "bg-ink-500" },
  disputed: { bg: "border-rose-600/30 bg-rose-950/40 text-rose-300", dot: "bg-rose-500" },
  healthy: { bg: "border-emerald-500/40 bg-emerald-500/15 text-emerald-300 font-semibold", dot: "bg-emerald-400 shadow-[0_0_6px_#10b981]" },
  degraded: { bg: "border-amber-500/40 bg-amber-500/15 text-amber-300", dot: "bg-amber-400" },
  failing: { bg: "border-rose-500/40 bg-rose-500/15 text-rose-300 font-bold", dot: "bg-rose-500 animate-pulse" },
  unknown: { bg: "border-ink-600 bg-ink-800 text-ink-400", dot: "bg-ink-500" },
  success: { bg: "border-emerald-500/40 bg-emerald-500/15 text-emerald-300", dot: "bg-emerald-400" },
  open: { bg: "border-accent/40 bg-accent/15 text-accent font-semibold", dot: "bg-accent shadow-[0_0_6px_#00d4ff]" },
  in_progress: { bg: "border-amber-500/40 bg-amber-500/15 text-amber-300 font-medium", dot: "bg-amber-400 animate-pulse" },
  closed: { bg: "border-ink-600 bg-ink-800 text-ink-400", dot: "bg-ink-500" },
};

export function StatusBadge({ status }: { status: string }) {
  const norm = (status || "unknown").toLowerCase();
  const cfg = statusConfig[norm] ?? statusConfig.unknown;

  return (
    <span
      className={`inline-flex items-center gap-1.5 rounded-md border px-2 py-0.5 text-2xs font-mono uppercase tracking-[0.08em] ${cfg.bg}`}
    >
      <span className={`h-1.5 w-1.5 rounded-full shrink-0 ${cfg.dot}`} />
      <span>{cfg.label ?? status.replace(/_/g, " ")}</span>
    </span>
  );
}

export function StatCard({
  label,
  value,
  hint,
  accent = false,
  variant = "cyan",
  icon: Icon,
}: {
  label: string;
  value: string | number;
  hint?: string;
  accent?: boolean;
  variant?: "cyan" | "rose" | "amber" | "emerald" | "purple";
  icon?: ComponentType<{ className?: string }>;
}) {
  const variantStyles = {
    cyan: {
      border: "hover:border-accent/40",
      iconBg: "bg-accent/10 border-accent/25 text-accent shadow-[0_0_12px_rgba(0,212,255,0.15)]",
      valColor: "text-white group-hover:text-accent",
      glow: "from-accent/10 to-transparent",
    },
    rose: {
      border: "hover:border-rose-500/40",
      iconBg: "bg-rose-500/10 border-rose-500/25 text-rose-400 shadow-[0_0_12px_rgba(244,63,94,0.15)]",
      valColor: "text-white group-hover:text-rose-300",
      glow: "from-rose-500/10 to-transparent",
    },
    amber: {
      border: "hover:border-amber-500/40",
      iconBg: "bg-amber-500/10 border-amber-500/25 text-amber-400 shadow-[0_0_12px_rgba(245,158,11,0.15)]",
      valColor: "text-white group-hover:text-amber-300",
      glow: "from-amber-500/10 to-transparent",
    },
    emerald: {
      border: "hover:border-emerald-500/40",
      iconBg: "bg-emerald-500/10 border-emerald-500/25 text-emerald-400 shadow-[0_0_12px_rgba(16,185,129,0.15)]",
      valColor: "text-white group-hover:text-emerald-300",
      glow: "from-emerald-500/10 to-transparent",
    },
    purple: {
      border: "hover:border-purple-500/40",
      iconBg: "bg-purple-500/10 border-purple-500/25 text-purple-400 shadow-[0_0_12px_rgba(168,85,247,0.15)]",
      valColor: "text-white group-hover:text-purple-300",
      glow: "from-purple-500/10 to-transparent",
    },
  }[variant];

  return (
    <div
      className={`group relative overflow-hidden rounded-xl border border-ink-700/80 bg-gradient-to-b from-ink-900/90 to-ink-950/90 p-4 sm:p-5 shadow-lg shadow-black/30 backdrop-blur-md transition-all duration-300 ${
        accent ? "ring-1 ring-accent/30 shadow-[0_0_20px_rgba(0,212,255,0.08)]" : ""
      } ${variantStyles.border}`}
    >
      {/* Top subtle glow highlight */}
      <div
        className={`pointer-events-none absolute -top-12 -right-12 h-28 w-28 rounded-full bg-gradient-to-b ${variantStyles.glow} blur-2xl transition-opacity group-hover:opacity-100 opacity-60`}
      />

      <div className="relative z-10 flex items-start justify-between gap-3">
        <div className="min-w-0">
          <p className="text-2xs font-semibold uppercase tracking-[0.14em] text-ink-400 font-mono">
            {label}
          </p>
          <p
            className={`mt-2 text-2xl sm:text-3xl font-extrabold font-mono tabular-nums leading-none tracking-tight transition-colors ${variantStyles.valColor}`}
          >
            {typeof value === "number" ? value.toLocaleString() : value}
          </p>
          {hint && (
            <div className="mt-2.5 flex items-center gap-1.5 text-2xs text-ink-300 font-mono">
              <span className="h-1 w-1 rounded-full bg-ink-400" />
              <span>{hint}</span>
            </div>
          )}
        </div>

        {Icon && (
          <div
            className={`flex h-10 w-10 shrink-0 items-center justify-center rounded-xl border p-2 transition-transform duration-300 group-hover:scale-105 ${variantStyles.iconBg}`}
          >
            <Icon className="h-5 w-5" />
          </div>
        )}
      </div>
    </div>
  );
}

export function Spinner({ label = "Loading intelligence…" }: { label?: string }) {
  return (
    <div className="flex flex-col items-center justify-center gap-4 py-16 text-xs font-mono text-ink-300">
      <div className="relative h-10 w-10">
        <div className="absolute inset-0 rounded-full border-2 border-ink-700/60" />
        <div className="absolute inset-0 rounded-full border-2 border-transparent border-t-accent animate-spin shadow-[0_0_12px_rgba(0,212,255,0.5)]" />
        <div className="absolute inset-2 rounded-full border border-ink-800" />
      </div>
      <span className="tracking-[0.14em] uppercase text-2xs text-ink-400 font-medium">
        {label}
      </span>
    </div>
  );
}

export function EmptyState({ message }: { message: string }) {
  return (
    <div className="flex flex-col items-center justify-center py-14 px-4 text-center font-mono text-ink-400">
      <div className="mb-3.5 flex h-12 w-12 items-center justify-center rounded-xl border border-ink-700/80 bg-ink-900/80 shadow-inner">
        <span className="block h-2.5 w-2.5 rounded-full bg-accent/70 shadow-[0_0_8px_#00d4ff]" />
      </div>
      <p className="text-xs uppercase tracking-wider text-ink-300 max-w-sm font-medium">
        {message}
      </p>
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

/** Standard primary cyber accent */
export const ACCENT = "#00D4FF";

/** Rich, high-aesthetic color step palette for data visualizations */
export const ACCENT_STEPS = [
  "#00D4FF", // Electric Cyan
  "#f43f5e", // Crimson Rose
  "#f59e0b", // Amber
  "#10b981", // Emerald
  "#a855f7", // Purple
  "#38bdf8", // Sky Blue
  "#ec4899", // Pink
  "#6366f1", // Indigo
  "#14b8a6", // Teal
  "#84cc16", // Lime
];

/** Standard chart tooltip style for Recharts */
export const chartTooltipStyle = {
  backgroundColor: "rgba(11, 14, 23, 0.95)",
  border: "1px solid rgba(255, 255, 255, 0.12)",
  borderRadius: "8px",
  boxShadow: "0 8px 24px rgba(0, 0, 0, 0.6)",
  fontSize: "12px",
  color: "#f1f5f9",
  padding: "8px 12px",
};
