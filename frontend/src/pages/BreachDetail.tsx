/* BreachDetail.tsx — RTIP specific breach detail page.
 *
 * Shows detailed information for a single breach incident, navigated to from
 * the Breaches list via /breaches/:breachId. Data comes from
 * GET /api/v1/breaches/{breach_id}.
 */

import { useEffect, useState } from "react";
import { Link, useParams } from "react-router-dom";
import { ArrowLeft, Database, ExternalLink, Tag } from "lucide-react";
import { api } from "../api/client";
import { Card, CardHeader, EmptyState, Spinner, StatusBadge, timeAgo } from "../components/ui";

interface BreachDetailData {
  id: string;
  organization_name: string;
  organization_domain: string | null;
  industry: string | null;
  country: string | null;
  region: string | null;
  threat_actor_name: string | null;
  claimed_data_types: string[] | null;
  record_count: number | null;
  record_count_reliability: string | null;
  summary: string | null;
  published_at: string | null;
  verification_status: string;
  confidence: number;
  confidence_reasons: { reasons?: string[] } | null;
  source_slug: string;
  source_url: string | null;
  evidence_references: string[] | null;
}

export function BreachDetail() {
  const { breachId } = useParams<{ breachId: string }>();
  const [loading, setLoading] = useState(true);
  const [breach, setBreach] = useState<BreachDetailData | null>(null);
  const [failed, setFailed] = useState(false);

  useEffect(() => {
    let cancelled = false;
    setLoading(true);
    setFailed(false);
    api<BreachDetailData>(`/breaches/${breachId}`)
      .then((data) => {
        if (!cancelled) setBreach(data);
      })
      .catch(() => {
        if (!cancelled) {
          setBreach(null);
          setFailed(true);
        }
      })
      .finally(() => {
        if (!cancelled) setLoading(false);
      });
    return () => {
      cancelled = true;
    };
  }, [breachId]);

  if (loading) return <Spinner label="Retrieving breach incident dossier…" />;
  if (!breach) return <EmptyState message={failed ? "Failed to load breach incident" : "Breach dossier not found"} />;

  const reasons = breach.confidence_reasons?.reasons ?? [];

  return (
    <div className="space-y-6">
      {/* Back button */}
      <div>
        <Link
          to="/breaches"
          className="inline-flex items-center gap-2 rounded-lg border border-ink-700 bg-ink-900 px-3.5 py-1.5 text-xs font-mono text-ink-300 hover:border-accent hover:text-accent transition-colors"
        >
          <ArrowLeft className="h-3.5 w-3.5" />
          <span>Back to Breach Intelligence</span>
        </Link>
      </div>

      {/* Incident Header Banner */}
      <div className="flex flex-wrap items-center justify-between gap-4 border-b border-ink-700/60 pb-5">
        <div>
          <div className="flex flex-wrap items-center gap-2.5">
            <h1 className="text-2xl font-bold tracking-tight text-white font-mono">
              {breach.organization_name}
            </h1>
            <StatusBadge status={breach.verification_status} />
          </div>
          <p className="mt-1.5 text-xs text-ink-400 font-mono">
            {breach.industry || "Industry General"} · {breach.country || "Global Region"} · Published {timeAgo(breach.published_at)} · via {breach.source_slug}
          </p>
        </div>

        <div className="flex items-center gap-3">
          {breach.source_url && (
            <a
              href={breach.source_url}
              target="_blank"
              rel="noreferrer noopener"
              className="inline-flex items-center gap-2 rounded-xl border border-accent/40 bg-accent/10 px-4 py-2 text-xs font-mono font-bold text-accent hover:bg-accent hover:text-black transition-all shadow-sm"
              title="Inspect original dark web disclosure"
            >
              <span>Original Source</span>
              <ExternalLink className="h-3.5 w-3.5" />
            </a>
          )}
        </div>
      </div>

      {/* Primary Details Grid */}
      <Card>
        <CardHeader
          title="Incident Dossier &amp; Metadata"
          subtitle="Threat actor attribution and exfiltration scope"
          icon={Database}
        />
        <div className="p-5">
          <dl className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-4">
            <div className="rounded-xl border border-ink-700/80 bg-ink-950/70 p-4">
              <dt className="text-[10px] font-mono font-semibold uppercase tracking-wider text-ink-400">Target Organization</dt>
              <dd className="mt-1 text-sm font-bold text-white font-mono">{breach.organization_name}</dd>
            </div>
            <div className="rounded-xl border border-ink-700/80 bg-ink-950/70 p-4">
              <dt className="text-[10px] font-mono font-semibold uppercase tracking-wider text-ink-400">Primary Domain</dt>
              <dd className="mt-1 text-sm font-mono text-accent">{breach.organization_domain || "—"}</dd>
            </div>
            <div className="rounded-xl border border-ink-700/80 bg-ink-950/70 p-4">
              <dt className="text-[10px] font-mono font-semibold uppercase tracking-wider text-ink-400">Claiming Syndicate</dt>
              <dd className="mt-1 text-sm font-mono font-bold text-purple-300">
                {breach.threat_actor_name || "Unattributed"}
              </dd>
            </div>
            <div className="rounded-xl border border-ink-700/80 bg-ink-950/70 p-4">
              <dt className="text-[10px] font-mono font-semibold uppercase tracking-wider text-ink-400">Claimed Exfiltration Volume</dt>
              <dd className="mt-1 text-sm font-mono text-white">
                {breach.record_count != null ? breach.record_count.toLocaleString() : "Unspecified"}
                {breach.record_count_reliability && (
                  <span className="text-2xs text-ink-400 ml-1">({breach.record_count_reliability})</span>
                )}
              </dd>
            </div>
            <div className="rounded-xl border border-ink-700/80 bg-ink-950/70 p-4">
              <dt className="text-[10px] font-mono font-semibold uppercase tracking-wider text-ink-400">Incident Timestamp</dt>
              <dd className="mt-1 text-sm font-mono text-ink-200">
                {breach.published_at ? new Date(breach.published_at).toUTCString() : "—"}
              </dd>
            </div>
            <div className="rounded-xl border border-ink-700/80 bg-ink-950/70 p-4">
              <dt className="text-[10px] font-mono font-semibold uppercase tracking-wider text-ink-400">Corroboration Confidence</dt>
              <dd className="mt-1 text-sm font-mono font-bold text-accent">
                {(breach.confidence * 100).toFixed(0)}%
              </dd>
            </div>
          </dl>

          {breach.summary && (
            <div className="mt-4 pt-4 border-t border-ink-700/60 text-xs text-ink-200 font-sans leading-relaxed">
              <p className="font-bold text-2xs uppercase tracking-wider text-ink-400 font-mono mb-1">
                Executive Incident Summary:
              </p>
              {breach.summary}
            </div>
          )}
        </div>
      </Card>

      {/* Claimed Data Types */}
      <Card>
        <CardHeader title="Exfiltrated &amp; Compromised Data Categories" />
        <div className="p-5">
          {breach.claimed_data_types && breach.claimed_data_types.length > 0 ? (
            <div className="flex flex-wrap gap-2">
              {breach.claimed_data_types.map((d, i) => (
                <span
                  key={i}
                  className="inline-flex items-center gap-1.5 rounded-lg border border-ink-700 bg-ink-950 px-3 py-1.5 text-xs font-mono text-ink-200 shadow-sm"
                >
                  <Tag className="h-3 w-3 text-accent" />
                  <span>{d}</span>
                </span>
              ))}
            </div>
          ) : (
            <p className="text-xs text-ink-500 font-mono">No specific data classifications published.</p>
          )}
        </div>
      </Card>

      {/* Confidence Reasoning */}
      <Card>
        <CardHeader
          title="Deterministic Scoring Factors"
          subtitle="Auditable evidentiary criteria used to assess incident veracity"
        />
        <div className="p-5">
          {reasons.length > 0 ? (
            <ul className="space-y-2 text-xs font-mono text-ink-300">
              {reasons.map((r, i) => (
                <li key={i} className="flex items-center gap-2">
                  <span className="text-accent font-bold">›</span>
                  <span>{r}</span>
                </li>
              ))}
            </ul>
          ) : (
            <p className="text-xs text-ink-500 font-mono">No algorithmic confidence notes logged.</p>
          )}
        </div>
      </Card>
    </div>
  );
}
