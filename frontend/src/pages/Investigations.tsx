/* Investments/Investigations.tsx - RTIP Investigation & Correlation UI
 *
 * Features:
 * - Alert correlation timeline
 * - IOC grouping by campaign/actor
 * - Filter by severity, status, category
 * - Export to PDF / investigation case link
 * - Drill-down from IOCs to related alerts
 */

import React, { useEffect, useState, useCallback } from "react";
import { Card, Table, TableBody, TableHeader, TableRow, Input, Button, Select, MenuItem, Badge, Alert as UAlert, Icon } from "mui";
import { useParams, useNavigate } from "react-router-dom";
import { useAlert } from "@/hooks/useAlert";
import { fetchIOCs, fetchAlerts } from "@/services/api";
import { PIPELINE, REPORT_TYPE } from "@/types";

export const Investigations: React.FC = () => {
  const { id: alertId } = useParams<{ id: string }>();
  const navigate = useNavigate();
  const { data: iocs, error: iocError, isLoading: iocLoading } = useIOCs();
  const { data: alerts, error: alertError, isLoading: alertLoading } = useAlerts();
  const { runReport, isReportLoading } = useReport();
  const [filters, setFilters] = useState<{
    status: string;
    severity: string;
    category: string;
    search: string;
  }>({
    status: "all",
    severity: "all",
    category: "all",
    search: "",
  });

  // Load data
  useEffect(() => {
    fetchIOCs();
    fetchAlerts();
  }, []);

  // Build correlation view
  const correlatedAlerts = alerts
    .filter(applyFilters)
    .sort((a, b) => new Date(b.detected_at).getTime() - new Date(a.detected_at).getTime());

  function applyFilters(alert: any) {
    if (filters.status !== "all" && alert.status !== filters.status) return false;
    if (filters.severity !== "all" && alert.severity !== filters.severity) return false;
    if (filters.category !== "all" && alert.category !== filters.category) return false;
    if (filters.search && !alert.title.toLowerCase().includes(filters.search.toLowerCase())) return false;
    return true;
  }

  // Generate investigation PDF
  const handleGeneratePDF = useCallback(async () => {
    if (id) {
      const success = await runReport(id, PIPELINE.PDF);
      if (success) {
        UAlert({
          severity: "info",
          message: "PDF report generated successfully",
        });
      }
    }
  }, [id, runReport]);

  return (
    <Card sx={{ p: 2, mb: 2 }}>
      <h2>Investigation & Correlation</h2>

      {/* Filters */}
      <div sx={{ mb: 2, pt: 1 }}>
        <Select
          labelStatus="Status"
          value={filters.status}
          onValueChange={setFilters => setFilters({ ...filters, status: filters.value })}
        >
          <MenuItem value="all">All</MenuItem>
          <MenuItem value="new">New</MenuItem>
          <MenuItem value="investigating">Investigating</MenuItem>
          <MenuItem value="confirmed">Confirmed</MenuItem>
        </Select>

        <Select
          labelStatus="Severity"
          value={filters.severity}
          onValueChange={setFilters => setFilters({ ...filters, severity: filters.value })}
        >
          <MenuItem value="all">All</MenuItem>
          <MenuItem value="critical">Critical</MenuItem>
          <MenuItem value="high">High</MenuItem>
          <MenuItem value="medium">Medium</MenuItem>
          <MenuItem value="low">Low</MenuItem>
        </Select>

        <Select
          labelStatus="Category"
          value={filters.category}
          onValueChange={setFilters => setFilters({ ...filters, category: filters.value })}
        >
          <MenuItem value="all">All</MenuItem>
          {["malware", "phishing", "brute-force", "exfiltration", "credential-theft"].map(value => (
            <MenuItem key={value} value={value}>
              {value}
            </MenuItem>
          ))}
        </Select>

        <Input
          placeholder="Search alerts..."
          value={filters.search}
          onChange={e => setFilters({ ...filters, search: e.target.value })}
          sx={{ mr: 1, width: 200 }}
        />
        <Button variant="contained" color="primary" onClick={handleGeneratePDF}>
          Generate PDF Report
        </Button>
      </div>

      {/* Correlation Timeline */}
      <UAlert severity="info" sx={{ pt: 1, mb: 2 }}>
        <Icon icon="search" sx={{ mr: 1 }} /> Showing {correlatedAlerts.length} correlated alerts
      </UAlert>

      <Table size="small" aria-label="correlation timeline">
        <TableHeader>
          <TableRow>
            <TableHeader>#</TableHeader>
            <TableHeader>Alert</TableHeader>
            <TableHeader>Severity</TableHeader>
            <TableHeader>Category</TableHeader>
            <TableHeader>Detected</TableHeader>
            <Tableheader>Status</TableHeader>
          </TableRow>
        </TableHeader>
        <TableBody>
          {correlatedAlerts.slice(0, 20).map((alert: any, idx: number) => (
            <TableRow key={alert.id}>
              <TableCell component="th" scope="row">
                {idx + 1}
              </TableCell>
              <TableCell>{alert.title.substring(0, 50)}{alert.title.length > 50 && "..."}</TableCell>
              <TableCell>
                <Badge color={alert.severity?.toLowerCase() || "info"}>
                  {alert.severity?.toUpperCase() || "—"}
                </Badge>
              </TableCell>
              <TableCell>{alert.category || "—"}</TableCell>
              <TableCell>{new Date(alert.detected_at).toLocaleDateString()}</TableCell>
              <TableCell>
                <Badge
                  color={alert.status?.toLowerCase() || "default"}
                  variant="outline"
                >
                  {alert.status?.toUpperCase() || "—"}
                </Badge>
              </TableCell>
            </TableRow>
          ))}
        </TableBody>
      </Table>

      {/* No results */}
      {correlatedAlerts.length === 0 && (
        <UAlert severity="info">
          No alerts match the applied filters. Adjust filters to narrow the correlation view.
        </UAlert>
      )}
    </Card>
  );
};

export default Investigations;