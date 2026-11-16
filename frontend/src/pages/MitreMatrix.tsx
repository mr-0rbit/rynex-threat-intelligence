import { useEffect, useState } from "react";
import { Crosshair, ExternalLink, Layers, ShieldCheck, Terminal } from "lucide-react";
import { api } from "../api/client";
import { Badge, Card, Spinner } from "../components/ui";

interface Technique {
  id: string;
  name: string;
  tactic_id: string;
  description: string;
  detection: string;
  mitigation: string;
  intel_link?: string;
  active_detections?: number;
}

interface TacticColumn {
  tactic: {
    id: string;
    name: string;
    description: string;
  };
  techniques: Technique[];
}

interface MitreData {
  version: string;
  matrix: TacticColumn[];
  total_tactics: number;
  total_techniques: number;
}

export function MitreMatrix() {
  const [data, setData] = useState<MitreData | null>(null);
  const [loading, setLoading] = useState(true);
  const [selectedTech, setSelectedTech] = useState<Technique | null>(null);

  useEffect(() => {
    api<MitreData>("/mitre/matrix")
      .then((res) => {
        setData(res);
        if (res.matrix.length > 0 && res.matrix[2]?.techniques.length > 0) {
          setSelectedTech(res.matrix[2].techniques[0]);
        }
      })
      .catch((err) => console.error("Failed to load MITRE matrix:", err))
      .finally(() => setLoading(false));
  }, []);

  if (loading) return <Spinner label="Loading MITRE ATT&CK Matrix…" />;
  if (!data) return <p className="text-sm text-ink-400">Failed to load MITRE ATT&CK data.</p>;

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col gap-2 sm:flex-row sm:items-center sm:justify-between border-b border-ink-800 pb-4">
        <div>
          <div className="flex items-center gap-2">
            <h1 className="text-xl font-bold tracking-tight text-white font-mono flex items-center gap-2">
              <Layers className="h-5 w-5 text-accent" />
              MITRE ATT&CK® Enterprise Matrix
            </h1>
            <Badge variant="cyan">{data.version}</Badge>
          </div>
          <p className="mt-1 text-xs text-ink-400 font-mono">
            Adversary tactics, techniques & platform indicator correlations ({data.total_tactics} tactics · {data.total_techniques} core techniques)
          </p>
        </div>
      </div>

      {/* Main Grid: Scrollable Matrix Columns */}
      <div className="overflow-x-auto pb-4">
        <div className="flex gap-3 min-w-max">
          {data.matrix.map((col) => (
            <div
              key={col.tactic.id}
              className="w-56 shrink-0 rounded border border-ink-700/80 bg-ink-900/60 backdrop-blur flex flex-col"
            >
              <div className="border-b border-ink-700 p-2.5 bg-ink-950/70">
                <p className="text-[10px] font-mono font-semibold uppercase text-accent tracking-wider">
                  {col.tactic.id}
                </p>
                <h3 className="text-xs font-bold text-white font-mono mt-0.5 truncate" title={col.tactic.name}>
                  {col.tactic.name}
                </h3>
                <p className="text-[10px] text-ink-400 mt-1 line-clamp-1" title={col.tactic.description}>
                  {col.tactic.description}
                </p>
              </div>

              <div className="p-1.5 space-y-1.5 flex-1 overflow-y-auto max-h-[500px]">
                {col.techniques.length === 0 ? (
                  <p className="p-2 text-[10px] text-ink-500 italic font-mono">No active mapped items</p>
                ) : (
                  col.techniques.map((tech) => {
                    const isSelected = selectedTech?.id === tech.id;
                    const hasHits = (tech.active_detections ?? 0) > 0;
                    return (
                      <button
                        key={tech.id}
                        type="button"
                        onClick={() => setSelectedTech(tech)}
                        className={`w-full text-left rounded p-2 transition-all border ${
                          isSelected
                            ? "bg-accent/15 border-accent text-white shadow-[0_0_10px_rgba(0,212,255,0.2)]"
                            : "bg-ink-950/80 border-ink-800 text-ink-200 hover:border-ink-600 hover:text-white"
                        }`}
                      >
                        <div className="flex items-center justify-between gap-1">
                          <span className="text-[10px] font-mono font-bold text-ink-400 group-hover:text-accent">
                            {tech.id}
                          </span>
                          {hasHits && (
                            <span className="text-[9px] font-mono px-1.5 py-0.5 rounded bg-critical/20 text-critical border border-critical/40 font-bold">
                              {tech.active_detections} hits
                            </span>
                          )}
                        </div>
                        <p className="text-xs font-mono font-medium mt-1 leading-tight line-clamp-2">
                          {tech.name}
                        </p>
                      </button>
                    );
                  })
                )}
              </div>
            </div>
          ))}
        </div>
      </div>

      {/* Selected Technique Detail Drawer */}
      {selectedTech && (
        <Card className="border-accent/40 bg-ink-900/90 shadow-[0_0_20px_rgba(0,212,255,0.06)]">
          <div className="flex flex-col md:flex-row md:items-start justify-between gap-4 border-b border-ink-800 pb-4">
            <div>
              <div className="flex items-center gap-2">
                <Badge variant="cyan">{selectedTech.id}</Badge>
                <Badge variant="neutral">{selectedTech.tactic_id}</Badge>
                {(selectedTech.active_detections ?? 0) > 0 && (
                  <Badge variant="critical">
                    {selectedTech.active_detections} active telemetry matches
                  </Badge>
                )}
              </div>
              <h2 className="text-lg font-bold text-white font-mono mt-2">
                {selectedTech.name}
              </h2>
            </div>
            <a
              href={`https://attack.mitre.org/techniques/${selectedTech.id}/`}
              target="_blank"
              rel="noopener noreferrer"
              className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded border border-ink-700 bg-ink-800 text-xs font-mono text-ink-200 hover:text-white hover:border-accent transition-colors"
            >
              <span>MITRE ATT&CK Reference</span>
              <ExternalLink className="h-3.5 w-3.5" />
            </a>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-3 gap-6 mt-4">
            <div className="space-y-2">
              <h4 className="text-xs font-mono font-bold uppercase tracking-wider text-ink-400 flex items-center gap-1.5">
                <Crosshair className="h-3.5 w-3.5 text-accent" />
                Adversary Behavior
              </h4>
              <p className="text-xs text-ink-200 leading-relaxed bg-ink-950/60 p-3 rounded border border-ink-800">
                {selectedTech.description}
              </p>
            </div>

            <div className="space-y-2">
              <h4 className="text-xs font-mono font-bold uppercase tracking-wider text-ink-400 flex items-center gap-1.5">
                <Terminal className="h-3.5 w-3.5 text-warning" />
                Detection Strategy
              </h4>
              <p className="text-xs text-ink-200 leading-relaxed bg-ink-950/60 p-3 rounded border border-ink-800">
                {selectedTech.detection}
              </p>
            </div>

            <div className="space-y-2">
              <h4 className="text-xs font-mono font-bold uppercase tracking-wider text-ink-400 flex items-center gap-1.5">
                <ShieldCheck className="h-3.5 w-3.5 text-success" />
                Enterprise Mitigation
              </h4>
              <p className="text-xs text-ink-200 leading-relaxed bg-ink-950/60 p-3 rounded border border-ink-800">
                {selectedTech.mitigation}
              </p>
            </div>
          </div>
        </Card>
      )}
    </div>
  );
}
