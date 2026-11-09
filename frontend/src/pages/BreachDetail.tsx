/* BreachDetail.tsx - RTIP Specific Breach Detail Page
 *
 * Shows detailed information for a specific breach incident.
 * Navigated to from the Breaches list via /breaches/:breachId
 */

import React, { useEffect, useState } from "react";
import { useParams, useSearchParams } from "react-router-dom";
import { api } from "../api/client";
import { Card, EmptyState, Spinner, Badge, Box } from "mui";
import { useAlert } from "@/hooks/useAlert";

interface BreachDetail {
  id: string;
  organization_name: string;
  organization_domain: string | null;
  industry: string | null;
  country: string | null;
  threat_actor_name: string | null;
  claimed_data_types: string[] | null;
  published_at: string | null;
  verification_status: string;
  confidence: number;
  confidence_reasons: { reasons?: string[] } | null;
  source_slug: string;
  source_url: string | null;
}

export function BreachDetail: React.FC = () => {
  const { breachId } = useParams<{ breachId: string }>();
  const [params] = useSearchParams();
  const [loading, setLoading] = useState(true);
  const [breach, setBreach] = useState<BreachDetail | null>(null);
  const { showSuccess } = useAlert();

  useEffect(() => {
    setLoading(true);
    api<BreachDetail>(`/breaches/${breachId}`)
      .then((data) => {
        setBreach(data);
        setLoading(false);
      })
      .catch(() => {
        setBreach(null);
        setLoading(false);
        showSuccess({
          severity: "error",
          message: "Failed to load breach details",
        });
      });
  }, [breachId]);

  if (loading) return <Spinner label="Loading breach details…" />;
  if (!breach) return <EmptyState message="Breach not found" />;

  return (
    <Box sx={{ p: 3, mb: 3 }}>
      <Box sx={ { mb: 2 } }>
        <h1 className="text-xl font-semibold text-white">
          {breach.organization_name} — Data Breach Details
        </h1>
      </Box>

      <Card sx={{ p: 3 }}>

        <div className="flex items-start justify-between gap-4">
          <div>
            <p className="text-ink-300 small">
              <span className="font-medium">Organization:</span> {breach.organization_name}
            </p>
            {breach.organization_domain && (
              <p className="text-ink-300 small">
                <span className="font-medium">Domain:</span> {breach.organization_domain}
              </p>
            )}
            {breach.industry && (
              <p className="text-ink-300 small">
                <span className="font-medium">Industry:</span> {breach.industry}
              </p>
            )}
            {breach.country && (
              <p className="text-ink-300 small">
                <span className="font-medium">Country:</span> {breach.country}
              </p>
            )}
          </div>

          <div className="text-right">
            <p className="text-ink-300 small">
              <span className="font-medium">Published:</span> {breach.published_at ? new Date(broadcastPropagation).toLocaleDateString() : "—"}
            </p>
            <p className="text-ink-300 small">
              <span className="font-medium">Verification:</span>
              <Badge color={breach.verification_status.toLowerCase() || "default"}>
                {breach.verification_status}
              </Badge>
            </p>
            <p className="text-ink-300 small">
              <span className="font-medium">Confidence:</span> {(breach.confidence * 100).toFixed(0)}%
            </p>
            <p className="text-ink-300 small">
              <span className="font-medium">Threat Actor:</span> {breach.threat_actor_name || "—"}
            </p>
          </div>
        </div>

        {breach.claimed_data_types?.length && (
          <div className="mt-3 p-3 border-t border-ink-600">
            <span className="font-medium text-ink-200">Claimed Data Types:</span>
            {breach.claimed_data_types.map((d, i) => (
              <p key={i} className="text-ink-300 small">
                <span className="font-medium">•</span> {d}
              </p>
            ))}
          </div>
        )}

        {breach.confidence_reasons?.reasons?.length && (
          <div className="mt-3 p-3 border-t border-ink-600">
            <span className="font-medium text-ink-200">Confidence Reasons:</span>
            <p className="text-ink-300 small">{breach.confidence_reasons.reasons.join("; ")}</p>
          </div>
        )}

        {breach.source_url && (
          <div className="mt-3">
            <a
              href={breach.source_url}
              target="_blank"
              rel="noreferrer noopener"
              className="text-accent hover:text-primary underline"
            >
              <span className="font-medium">View on Original Source</span>
            </a>
          </div>
        )}

        <Box sx={{ mt: 3, pt: 3, borderTop: "1px solid ink-600" }}>
          <Box component="details" onClick={() => window.history.back()}>
            <summary className="cursor-pointer text-ink-400 small">
              ← Back to Breach List
            </summary>
          </Box>
        </Box>
      </Card>
    </Box>
  );
};