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

  if (loading) return <Spinner label="Mapping MITRE ATT&CK Enterprise Matrix…" />;
  if (!data) return <p className="text-sm text-ink-400">Failed to load MITRE ATT&CK data.</p>;

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col gap-2 sm:flex-row sm:items-center sm:justify-between border-b border-ink-700/60 pb-5">
        <div>
          <div className="flex items-center gap-2.5">
            <h1 className="text-xl font-bold tracking-tight text-white font-mono flex items-center gap-2">
              <Layers className="h-5 w-5 text-accent" />
              MITRE ATT&CK® Enterprise Matrix
            </h1>
            <Badge variant="cyan">{data.version}</Badge>
          </div>
          <p className="mt-1 text-xs text-ink-400 font-sans">
            Tactics, techniques & procedures (TTPs) mapped to real-world adversary behaviors ({data.total_tactics} tactics · {data.total_techniques} core techniques).
          </p>
        </div>
      </div>

      {/* Main Grid: Scrollable Matrix Columns */}
      <div className="overflow-x-auto pb-4">
        <div className="flex gap-3.5 min-w-max">
          {data.matrix.map((col) => (
            <div
              key={col.tactic.id}
              className="w-60 shrink-0 rounded-xl border border-ink-700/80 bg-gradient-to-b from-ink-900/95 to-ink-950/95 backdrop-blur-md flex flex-col shadow-lg overflow-hidden"
            >
              {/* Column Header */}
              <div className="border-b border-ink-700/80 p-3.5 bg-ink-950/90">
                <p className="text-[10px] font-mono font-bold uppercase text-accent tracking-wider">
                  {col.tactic.id}
                </p>
                <h3 className="text-xs font-bold text-white font-mono mt-0.5 truncate" title={col.tactic.name}>
                  {col.tactic.name}
                </h3>
                <p className="text-[10px] text-ink-400 mt-1 line-clamp-1 font-sans" title={col.tactic.description}>
                  {col.tactic.description}
                </p>
              </div>

              {/* Column Technique Cards */}
              <div className="p-2 space-y-1.5 flex-1 overflow-y-auto max-h-[500px]">
                {col.techniques.length === 0 ? (
                  <p className="p-3 text-[10px] text-ink-500 italic font-mono text-center">No mapped items</p>
                ) : (
                  col.techniques.map((tech) => {
                    const isSelected = selectedTech?.id === tech.id;
                    const hasHits = (tech.active_detections ?? 0) > 0;
                    return (
                      <button
                        key={tech.id}
                        type="button"
                        onClick={() => setSelectedTech(tech)}
                        className={`w-full text-left rounded-lg p-2.5 transition-all border ${
                          isSelected
                            ? "bg-accent/20 border-accent text-white shadow-[0_0_12px_rgba(0,212,255,0.25)] ring-1 ring-accent/30"
                            : "bg-ink-950/80 border-ink-800 text-ink-200 hover:border-ink-600 hover:text-white hover:bg-ink-900/80"
                        }`}
                      >
                        <div className="flex items-center justify-between gap-1">
                          <span className="text-[10px] font-mono font-bold text-accent">
                            {tech.id}
                          </span>
                          {hasHits && (
                            <span className="text-[9px] font-mono px-1.5 py-0.2 rounded bg-rose-500/20 text-rose-300 border border-rose-500/40 font-bold shadow-[0_0_6px_rgba(244,63,94,0.3)]">
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
        <Card className="border-accent/40 bg-gradient-to-b from-ink-900/95 to-ink-950/95 shadow-[0_0_30px_rgba(0,212,255,0.08)] p-6">
          <div className="flex flex-col md:flex-row md:items-start justify-between gap-4 border-b border-ink-700/60 pb-5">
            <div>
              <div className="flex flex-wrap items-center gap-2">
                <Badge variant="cyan">{selectedTech.id}</Badge>
                <Badge variant="neutral">{selectedTech.tactic_id}</Badge>
                {(selectedTech.active_detections ?? 0) > 0 && (
                  <Badge variant="critical">
                    {selectedTech.active_detections} active telemetry matches
                  </Badge>
                )}
              </div>
              <h2 className="text-xl font-bold text-white font-mono mt-2.5">
                {selectedTech.name}
              </h2>
            </div>
            <a
              href={`https://attack.mitre.org/techniques/${selectedTech.id}/`}
              target="_blank"
              rel="noopener noreferrer"
              className="inline-flex items-center gap-1.5 px-3.5 py-2 rounded-lg border border-ink-700 bg-ink-950 text-xs font-mono font-semibold text-accent hover:border-accent hover:bg-accent/10 transition-all shadow-sm"
            >
              <span>MITRE ATT&CK Matrix Reference</span>
              <ExternalLink className="h-3.5 w-3.5" />
            </a>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-3 gap-5 mt-5">
            <div className="space-y-2">
              <h4 className="text-xs font-mono font-bold uppercase tracking-wider text-ink-300 flex items-center gap-1.5">
                <Crosshair className="h-4 w-4 text-accent" />
                Adversary Behavior
              </h4>
              <div className="text-xs text-ink-200 leading-relaxed bg-ink-950/80 p-4 rounded-xl border border-ink-700/70 font-sans">
                {selectedTech.description}
              </div>
            </div>

            <div className="space-y-2">
              <h4 className="text-xs font-mono font-bold uppercase tracking-wider text-ink-300 flex items-center gap-1.5">
                <Terminal className="h-4 w-4 text-amber-400" />
                Detection Strategy
              </h4>
              <div className="text-xs text-ink-200 leading-relaxed bg-ink-950/80 p-4 rounded-xl border border-ink-700/70 font-sans">
                {selectedTech.detection}
              </div>
            </div>

            <div className="space-y-2">
              <h4 className="text-xs font-mono font-bold uppercase tracking-wider text-ink-300 flex items-center gap-1.5">
                <ShieldCheck className="h-4 w-4 text-emerald-400" />
                Enterprise Mitigation
              </h4>
              <div className="text-xs text-ink-200 leading-relaxed bg-ink-950/80 p-4 rounded-xl border border-ink-700/70 font-sans">
                {selectedTech.mitigation}
              </div>
            </div>
          </div>
        </Card>
      )}
    </div>
  );
}
