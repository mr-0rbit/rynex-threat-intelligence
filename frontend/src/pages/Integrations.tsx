import { useEffect, useState } from "react";
import {
  Check,
  Copy,
  Flame,
  Lock,
  Radio,
  Server,
  Terminal,
} from "lucide-react";
import { api } from "../api/client";
import { Badge, Card } from "../components/ui";

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
      <div className="border-b border-ink-800 pb-4">
        <h1 className="text-xl font-bold tracking-tight text-white font-mono flex items-center gap-2">
          <Radio className="h-5 w-5 text-accent" />
          Enterprise Integrations: TAXII, EDLs & SIEM
        </h1>
        <p className="mt-1 text-xs text-ink-400 font-mono">
          Connect firewalls, EDRs, SIEMs, and threat sharing communities to RTIP via standardized protocols.
        </p>
      </div>

      {/* Audit Integrity Status Banner */}
      <Card className="border-ink-700 bg-ink-900/60 p-4">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
          <div className="flex items-center gap-3">
            <div className={`p-2 rounded border ${
              auditStatus?.valid
                ? "bg-success/15 border-success/40 text-success"
                : "bg-critical/15 border-critical/40 text-critical"
            }`}>
              <Lock className="h-5 w-5" />
            </div>
            <div>
              <div className="flex items-center gap-2">
                <h3 className="text-sm font-bold text-white font-mono">
                  Cryptographic Audit Trail Integrity
                </h3>
                <Badge variant={auditStatus?.valid ? "success" : "critical"}>
                  {auditStatus?.valid ? "HMAC CHAIN INTACT" : "TAMPER DETECTED"}
                </Badge>
              </div>
              <p className="text-xs text-ink-400 font-mono mt-0.5">
                {auditStatus?.total_records} audit log entries cryptographically verified with HMAC-SHA256 hash chaining.
              </p>
            </div>
          </div>
          <button
            type="button"
            onClick={runAuditVerification}
            disabled={verifying}
            className="px-3 py-1.5 rounded border border-ink-700 bg-ink-800 text-xs font-mono text-ink-200 hover:text-white hover:border-accent transition-colors"
          >
            {verifying ? "Verifying…" : "Re-Verify Ledger"}
          </button>
        </div>
      </Card>

      {/* Section 1: TAXII 2.1 */}
      <div className="space-y-4">
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-2">
            <Server className="h-4 w-4 text-accent" />
            <h2 className="text-sm font-bold uppercase tracking-wider text-white font-mono">
              OASIS TAXII 2.1 Server Feeds
            </h2>
            <Badge variant="cyan">STIX 2.1</Badge>
          </div>
          <span className="text-[11px] font-mono text-ink-400">
            Discovery: <code className="text-accent">{origin}/taxii2/</code>
          </span>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          {taxiiCollections.map((col) => (
            <Card key={col.id} className="p-4 bg-ink-900/80 border-ink-800 flex flex-col justify-between">
              <div>
                <div className="flex items-center justify-between">
                  <h4 className="text-xs font-bold text-white font-mono">{col.title}</h4>
                  <Badge variant="neutral">{col.media}</Badge>
                </div>
                <p className="text-[11px] text-ink-400 font-mono mt-2 break-all bg-ink-950 p-2 rounded border border-ink-800">
                  {col.url}
                </p>
              </div>
              <div className="mt-4 flex items-center justify-end gap-2">
                <button
                  type="button"
                  onClick={() => copyToClipboard(col.url, col.id)}
                  className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded border border-ink-700 bg-ink-800 text-xs font-mono text-ink-200 hover:text-white hover:border-accent"
                >
                  {copiedKey === col.id ? <Check className="h-3.5 w-3.5 text-success" /> : <Copy className="h-3.5 w-3.5" />}
                  <span>{copiedKey === col.id ? "Copied" : "Copy TAXII URL"}</span>
                </button>
              </div>
            </Card>
          ))}
        </div>
      </div>

      {/* Section 2: Firewall External Dynamic Lists */}
      <div className="space-y-4">
        <div className="flex items-center gap-2">
          <Flame className="h-4 w-4 text-warning" />
          <h2 className="text-sm font-bold uppercase tracking-wider text-white font-mono">
            Next-Gen Firewall External Dynamic Lists (EDL)
          </h2>
          <Badge variant="warning">High-Speed Plaintext</Badge>
        </div>

        <div className="space-y-3">
          {edlEndpoints.map((edl) => (
            <Card key={edl.id} className="p-4 bg-ink-900/80 border-ink-800">
              <div className="flex flex-col md:flex-row md:items-center justify-between gap-2">
                <div>
                  <div className="flex items-center gap-2">
                    <h4 className="text-xs font-bold text-white font-mono">{edl.title}</h4>
                    <Badge variant="neutral">{edl.type}</Badge>
                  </div>
                  <p className="text-xs text-ink-400 mt-1">{edl.desc}</p>
                  <p className="text-[10px] text-ink-500 font-mono mt-0.5">Compatible with: {edl.target}</p>
                </div>

                <div className="flex items-center gap-2 mt-2 md:mt-0 shrink-0">
                  <button
                    type="button"
                    onClick={() => copyToClipboard(edl.url, edl.id)}
                    className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded border border-ink-700 bg-ink-800 text-xs font-mono text-ink-200 hover:text-white hover:border-accent"
                  >
                    {copiedKey === edl.id ? <Check className="h-3.5 w-3.5 text-success" /> : <Copy className="h-3.5 w-3.5" />}
                    <span>{copiedKey === edl.id ? "Copied URL" : "Copy EDL Feed URL"}</span>
                  </button>
                </div>
              </div>
              <div className="mt-3 p-2 bg-ink-950 rounded border border-ink-800 font-mono text-[11px] text-accent truncate">
                {edl.url}
              </div>
            </Card>
          ))}
        </div>
      </div>

      {/* Section 3: Enterprise SIEM Stream Endpoints */}
      <div className="space-y-4">
        <div className="flex items-center gap-2">
          <Terminal className="h-4 w-4 text-accent" />
          <h2 className="text-sm font-bold uppercase tracking-wider text-white font-mono">
            SIEM & Syslog Log Forwarding
          </h2>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          <Card className="p-4 bg-ink-900/80 border-ink-800 space-y-3">
            <div className="flex items-center justify-between">
              <h4 className="text-xs font-bold text-white font-mono">ArcSight CEF Log Export</h4>
              <Badge variant="neutral">Common Event Format</Badge>
            </div>
            <p className="text-xs text-ink-400">
              Micro Focus ArcSight, Splunk, and QRadar compatible event stream.
            </p>
            <div className="p-2 bg-ink-950 rounded border border-ink-800 font-mono text-[11px] text-ink-300 break-all">
              {`${origin}/api/v1/admin/audit-logs/export?format=cef`}
            </div>
            <button
              type="button"
              onClick={() => copyToClipboard(`${origin}/api/v1/admin/audit-logs/export?format=cef`, "cef-url")}
              className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded border border-ink-700 bg-ink-800 text-xs font-mono text-ink-200 hover:text-white hover:border-accent"
            >
              {copiedKey === "cef-url" ? <Check className="h-3.5 w-3.5 text-success" /> : <Copy className="h-3.5 w-3.5" />}
              <span>Copy CEF Endpoint</span>
            </button>
          </Card>

          <Card className="p-4 bg-ink-900/80 border-ink-800 space-y-3">
            <div className="flex items-center justify-between">
              <h4 className="text-xs font-bold text-white font-mono">RFC 5424 Syslog Export</h4>
              <Badge variant="neutral">Standard Syslog</Badge>
            </div>
            <p className="text-xs text-ink-400">
              Standard RFC 5424 syslog stream for rsyslog, syslog-ng, and Logstash.
            </p>
            <div className="p-2 bg-ink-950 rounded border border-ink-800 font-mono text-[11px] text-ink-300 break-all">
              {`${origin}/api/v1/admin/audit-logs/export?format=syslog`}
            </div>
            <button
              type="button"
              onClick={() => copyToClipboard(`${origin}/api/v1/admin/audit-logs/export?format=syslog`, "syslog-url")}
              className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded border border-ink-700 bg-ink-800 text-xs font-mono text-ink-200 hover:text-white hover:border-accent"
            >
              {copiedKey === "syslog-url" ? <Check className="h-3.5 w-3.5 text-success" /> : <Copy className="h-3.5 w-3.5" />}
              <span>Copy Syslog Endpoint</span>
            </button>
          </Card>
        </div>
      </div>
    </div>
  );
}
