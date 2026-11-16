import { useEffect, useState } from "react";
import {
  Check,
  Copy,
  Flame,
  Lock,
  Radio,
  Server,
  ShieldCheck,
  Terminal,
} from "lucide-react";
import { api } from "../api/client";
import { Badge } from "../components/ui";

interface AuditVerifyResult {
  valid: boolean;
  total_records: number;
  status: string;
  error?: string;
}

export function Integrations() {
  const [copiedKey, setCopiedKey] = useState<string | null>(null);
  const [auditStatus, setAuditStatus] = useState<AuditVerifyResult | null>(null);
  const [verifying, setVerifying] = useState(false);

  const origin = window.location.origin;

  const copyToClipboard = (text: string, id: string) => {
    navigator.clipboard.writeText(text);
    setCopiedKey(id);
    setTimeout(() => setCopiedKey(null), 2000);
  };

  const runAuditVerification = () => {
    setVerifying(true);
    api<AuditVerifyResult>("/admin/audit-logs/verify")
      .then((res) => setAuditStatus(res))
      .catch((err) => console.error("Audit verification error:", err))
      .finally(() => setVerifying(false));
  };

  useEffect(() => {
    runAuditVerification();
  }, []);

  const edlEndpoints = [
    {
      id: "edl-ips",
      title: "Palo Alto / Fortinet IP Blocklist",
      type: "IPv4 / IPv6",
      desc: "Newline-separated list of active malicious IP addresses with confidence >= 60%.",
      url: `${origin}/api/v1/edl/ips?min_confidence=0.60`,
      target: "Palo Alto Networks PAN-OS EDL / FortiGate Threat Feeds / pfBlockerNG",
    },
    {
      id: "edl-domains",
      title: "DNS Sinkhole Domain Blocklist",
      type: "FQDN / Domains",
      desc: "Malicious domains for DNS sinkholing, RPZ zone files, and web gateways.",
      url: `${origin}/api/v1/edl/domains?min_confidence=0.60`,
      target: "Pi-hole / CoreDNS / Infoblox / Unbound / Cisco Umbrella",
    },
    {
      id: "edl-urls",
      title: "Web Gateway Malicious URLs",
      type: "HTTP / HTTPS URLs",
      desc: "Live phishing & malware distribution URLs for outbound proxy blocking.",
      url: `${origin}/api/v1/edl/urls?min_confidence=0.60`,
      target: "Squid / Blue Coat / Zscaler / F5 BIG-IP",
    },
    {
      id: "edl-hashes",
      title: "EDR Malicious File Hashes",
      type: "SHA-256",
      desc: "High-confidence file hashes for endpoint protection detection rules.",
      url: `${origin}/api/v1/edl/hashes?hash_type=sha256&min_confidence=0.70`,
      target: "CrowdStrike Falcon / SentinelOne / Microsoft Defender for Endpoint",
    },
  ];

  const taxiiCollections = [
    {
      id: "high-confidence-iocs",
      title: "High-Confidence IOC Feed",
      media: "STIX 2.1 / TAXII 2.1",
      url: `${origin}/taxii2/api1/collections/high-confidence-iocs/objects/`,
    },
    {
      id: "cisa-kev",
      title: "CISA KEV Exploited CVEs",
      media: "STIX 2.1 / TAXII 2.1",
      url: `${origin}/taxii2/api1/collections/cisa-kev/objects/`,
    },
    {
      id: "ransomware-breaches",
      title: "Ransomware Breach Claims",
      media: "STIX 2.1 / TAXII 2.1",
      url: `${origin}/taxii2/api1/collections/ransomware-breaches/objects/`,
    },
    {
      id: "all-intel",
      title: "Consolidated Enterprise Feed",
      media: "STIX 2.1 / TAXII 2.1",
      url: `${origin}/taxii2/api1/collections/all-intel/objects/`,
    },
  ];

  return (
    <div className="space-y-8">
      {/* Header */}
      <div className="border-b border-ink-700/60 pb-5">
        <div className="flex items-center gap-2.5">
          <h1 className="text-xl font-bold tracking-tight text-white font-mono flex items-center gap-2">
            <Radio className="h-5 w-5 text-accent" />
            Enterprise Integrations: TAXII, EDLs &amp; SIEM
          </h1>
          <Badge variant="cyan">ENTERPRISE CONNECTIVITY</Badge>
        </div>
        <p className="mt-1 text-xs text-ink-400 font-sans">
          Connect next-gen firewalls, EDR platforms, SIEMs, and threat sharing communities to RTIP via standardized protocols.
        </p>
      </div>

      {/* Audit Integrity Status Banner */}
      <div className="relative overflow-hidden rounded-xl border border-emerald-500/30 bg-gradient-to-r from-emerald-500/10 via-ink-900/90 to-ink-950 p-5 shadow-lg backdrop-blur-md">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
          <div className="flex items-center gap-3.5">
            <div
              className={`p-2.5 rounded-xl border shadow-inner ${
                auditStatus?.valid
                  ? "bg-emerald-500/15 border-emerald-500/40 text-emerald-400 shadow-[0_0_12px_rgba(16,185,129,0.2)]"
                  : "bg-rose-500/15 border-rose-500/40 text-rose-400 shadow-[0_0_12px_rgba(244,63,94,0.2)]"
              }`}
            >
              {auditStatus?.valid ? <ShieldCheck className="h-6 w-6" /> : <Lock className="h-6 w-6" />}
            </div>
            <div>
              <div className="flex items-center gap-2">
                <h3 className="text-sm font-bold text-white font-mono">
                  Cryptographic Audit Trail Ledger
                </h3>
                <Badge variant={auditStatus?.valid ? "success" : "critical"}>
                  {auditStatus?.valid ? "HMAC HASH CHAIN VERIFIED" : "TAMPER ANOMALY DETECTED"}
                </Badge>
              </div>
              <p className="text-xs text-ink-300 font-sans mt-1">
                {auditStatus?.total_records ?? 0} historical operations cryptographically anchored with SHA-256 block verification.
              </p>
            </div>
          </div>
          <button
            type="button"
            onClick={runAuditVerification}
            disabled={verifying}
            className="rounded-lg border border-ink-700 bg-ink-950 px-4 py-2 text-xs font-mono font-bold text-ink-200 hover:border-accent hover:text-accent transition-all shadow-sm shrink-0"
          >
            {verifying ? "Auditing Ledger…" : "Re-Verify Chain"}
          </button>
        </div>
      </div>

      {/* Section 1: TAXII 2.1 */}
      <div className="space-y-4">
        <div className="flex flex-wrap items-center justify-between gap-2">
          <div className="flex items-center gap-2">
            <Server className="h-4 w-4 text-accent" />
            <h2 className="text-sm font-bold uppercase tracking-wider text-white font-mono">
              OASIS TAXII 2.1 Server Feeds
            </h2>
            <Badge variant="cyan">STIX 2.1</Badge>
          </div>
          <span className="text-2xs font-mono text-ink-400">
            Discovery Root: <code className="text-accent">{origin}/taxii2/</code>
          </span>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          {taxiiCollections.map((col) => (
            <div
              key={col.id}
              className="rounded-xl border border-ink-700/80 bg-gradient-to-b from-ink-900/90 to-ink-950/90 p-5 shadow-lg flex flex-col justify-between hover:border-ink-600 transition-colors"
            >
              <div>
                <div className="flex items-center justify-between">
                  <h4 className="text-xs font-bold text-white font-mono">{col.title}</h4>
                  <Badge variant="neutral" size="xs">
                    {col.media}
                  </Badge>
                </div>
                <div className="mt-3 p-2.5 rounded-lg border border-ink-800 bg-ink-950 font-mono text-[11px] text-ink-300 break-all select-all">
                  {col.url}
                </div>
              </div>
              <div className="mt-4 flex items-center justify-end">
                <button
                  type="button"
                  onClick={() => copyToClipboard(col.url, col.id)}
                  className="inline-flex items-center gap-1.5 rounded-lg border border-ink-700 bg-ink-950 px-3 py-1.5 text-xs font-mono text-ink-200 hover:border-accent hover:text-accent transition-colors"
                >
                  {copiedKey === col.id ? (
                    <Check className="h-3.5 w-3.5 text-emerald-400" />
                  ) : (
                    <Copy className="h-3.5 w-3.5" />
                  )}
                  <span>{copiedKey === col.id ? "URL Copied" : "Copy TAXII URL"}</span>
                </button>
              </div>
            </div>
          ))}
        </div>
      </div>

      {/* Section 2: Firewall External Dynamic Lists */}
      <div className="space-y-4">
        <div className="flex items-center gap-2">
          <Flame className="h-4 w-4 text-amber-400" />
          <h2 className="text-sm font-bold uppercase tracking-wider text-white font-mono">
            Next-Gen Firewall External Dynamic Lists (EDLs)
          </h2>
          <Badge variant="warning">High-Throughput Plaintext</Badge>
        </div>

        <div className="space-y-3">
          {edlEndpoints.map((edl) => (
            <div
              key={edl.id}
              className="rounded-xl border border-ink-700/80 bg-gradient-to-b from-ink-900/90 to-ink-950/90 p-5 shadow-lg"
            >
              <div className="flex flex-col md:flex-row md:items-center justify-between gap-3">
                <div className="min-w-0 flex-1">
                  <div className="flex items-center gap-2">
                    <h4 className="text-xs font-bold text-white font-mono">{edl.title}</h4>
                    <Badge variant="neutral" size="xs">
                      {edl.type}
                    </Badge>
                  </div>
                  <p className="text-xs text-ink-300 font-sans mt-1">{edl.desc}</p>
                  <p className="text-2xs text-ink-500 font-mono mt-0.5">Compatible with: {edl.target}</p>
                </div>

                <div className="shrink-0">
                  <button
                    type="button"
                    onClick={() => copyToClipboard(edl.url, edl.id)}
                    className="inline-flex items-center gap-1.5 rounded-lg border border-ink-700 bg-ink-950 px-3 py-1.5 text-xs font-mono text-ink-200 hover:border-accent hover:text-accent transition-colors"
                  >
                    {copiedKey === edl.id ? (
                      <Check className="h-3.5 w-3.5 text-emerald-400" />
                    ) : (
                      <Copy className="h-3.5 w-3.5" />
                    )}
                    <span>{copiedKey === edl.id ? "Copied" : "Copy Feed URL"}</span>
                  </button>
                </div>
              </div>
              <div className="mt-3 p-2.5 rounded-lg border border-ink-800 bg-ink-950 font-mono text-[11px] text-accent truncate select-all">
                {edl.url}
              </div>
            </div>
          ))}
        </div>
      </div>

      {/* Section 3: Enterprise SIEM Stream Endpoints */}
      <div className="space-y-4">
        <div className="flex items-center gap-2">
          <Terminal className="h-4 w-4 text-accent" />
          <h2 className="text-sm font-bold uppercase tracking-wider text-white font-mono">
            SIEM &amp; Syslog Event Forwarding
          </h2>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          <div className="rounded-xl border border-ink-700/80 bg-gradient-to-b from-ink-900/90 to-ink-950/90 p-5 shadow-lg space-y-3">
            <div className="flex items-center justify-between">
              <h4 className="text-xs font-bold text-white font-mono">ArcSight CEF Log Stream</h4>
              <Badge variant="neutral" size="xs">
                Common Event Format
              </Badge>
            </div>
            <p className="text-xs text-ink-400 font-sans">
              Micro Focus ArcSight, Splunk, and IBM QRadar compatible alert event stream.
            </p>
            <div className="p-2.5 rounded-lg border border-ink-800 bg-ink-950 font-mono text-[11px] text-ink-300 break-all select-all">
              {`${origin}/api/v1/admin/audit-logs/export?format=cef`}
            </div>
            <button
              type="button"
              onClick={() => copyToClipboard(`${origin}/api/v1/admin/audit-logs/export?format=cef`, "cef-url")}
              className="inline-flex items-center gap-1.5 rounded-lg border border-ink-700 bg-ink-950 px-3 py-1.5 text-xs font-mono text-ink-200 hover:border-accent hover:text-accent transition-colors"
            >
              {copiedKey === "cef-url" ? <Check className="h-3.5 w-3.5 text-emerald-400" /> : <Copy className="h-3.5 w-3.5" />}
              <span>Copy CEF Endpoint</span>
            </button>
          </div>

          <div className="rounded-xl border border-ink-700/80 bg-gradient-to-b from-ink-900/90 to-ink-950/90 p-5 shadow-lg space-y-3">
            <div className="flex items-center justify-between">
              <h4 className="text-xs font-bold text-white font-mono">RFC 5424 Syslog Export</h4>
              <Badge variant="neutral" size="xs">
                Standard Syslog
              </Badge>
            </div>
            <p className="text-xs text-ink-400 font-sans">
              Standard RFC 5424 syslog stream for rsyslog, syslog-ng, and Logstash ingest.
            </p>
            <div className="p-2.5 rounded-lg border border-ink-800 bg-ink-950 font-mono text-[11px] text-ink-300 break-all select-all">
              {`${origin}/api/v1/admin/audit-logs/export?format=syslog`}
            </div>
            <button
              type="button"
              onClick={() => copyToClipboard(`${origin}/api/v1/admin/audit-logs/export?format=syslog`, "syslog-url")}
              className="inline-flex items-center gap-1.5 rounded-lg border border-ink-700 bg-ink-950 px-3 py-1.5 text-xs font-mono text-ink-200 hover:border-accent hover:text-accent transition-colors"
            >
              {copiedKey === "syslog-url" ? <Check className="h-3.5 w-3.5 text-emerald-400" /> : <Copy className="h-3.5 w-3.5" />}
              <span>Copy Syslog Endpoint</span>
            </button>
          </div>
        </div>
      </div>
    </div>
  );
}
