"use client";

import React, { useEffect, useState } from "react";

const API_BASE = process.env.NEXT_PUBLIC_API_URL || "http://localhost:8000";

export default function ASOPDashboard() {
  const [data, setData] = useState<any>(null);
  const [loading, setLoading] = useState(true);
  const [simulating, setSimulating] = useState(false);
  const [generatingReport, setGeneratingReport] = useState(false);
  const [activeTab, setActiveTab] = useState<"logs" | "controls" | "evidence" | "reports">("logs");
  const [customIp, setCustomIp] = useState("203.0.113.77");
  const [customEndpoint, setCustomEndpoint] = useState("/api/v1/auth/login");
  const [customPayload, setCustomPayload] = useState("username=admin' OR 1=1--");

  const fetchDashboard = async () => {
    try {
      const res = await fetch(`${API_BASE}/api/dashboard`);
      const json = await res.json();
      setData(json);
    } catch (err) {
      console.error("Failed to fetch ASOP telemetry:", err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchDashboard();
  }, []);

  const handleSimulateWave = async () => {
    setSimulating(true);
    try {
      await fetch(`${API_BASE}/api/logs/simulate`, { method: "POST" });
      await fetchDashboard();
    } finally {
      setSimulating(false);
    }
  };

  const handleCustomIngest = async (e: React.FormEvent) => {
    e.preventDefault();
    await fetch(`${API_BASE}/api/logs/ingest`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        source_ip: customIp,
        service: "edge-gateway",
        endpoint: customEndpoint,
        method: "POST",
        payload: customPayload,
      }),
    });
    await fetchDashboard();
  };

  const handleGenerateReport = async () => {
    setGeneratingReport(true);
    try {
      await fetch(`${API_BASE}/api/reports/generate`, { method: "POST" });
      await fetchDashboard();
      setActiveTab("reports");
    } finally {
      setGeneratingReport(false);
    }
  };

  if (loading || !data) {
    return (
      <div className="flex items-center justify-center min-h-screen bg-[#090d16] text-slate-200">
        <div className="text-center space-y-2">
          <div className="text-xl font-semibold text-cyan-400 animate-pulse">
            Initializing ASOP Telemetry & Gemini Assurance Engine...
          </div>
          <p className="text-sm text-slate-400">Connecting to FastAPI & PostgreSQL</p>
        </div>
      </div>
    );
  }

  const { metrics, logs, controls, evidence, reports } = data;

  return (
    <div className="max-w-7xl mx-auto px-6 py-8 space-y-8">
      {/* Header */}
      <header className="flex flex-col md:flex-row md:items-center md:justify-between gap-4 border-b border-slate-800 pb-6">
        <div>
          <div className="flex items-center gap-3">
            <span className="px-2.5 py-1 text-xs font-bold uppercase tracking-wider bg-cyan-500/10 text-cyan-400 border border-cyan-500/30 rounded">
              ASOP v1.0
            </span>
            <span className="text-xs text-slate-400">
              FastAPI · PostgreSQL · Next.js · Google Gemini AI · Docker
            </span>
          </div>
          <h1 className="text-2xl md:text-3xl font-bold text-white mt-2">
            Autonomous Security Operations Platform
          </h1>
          <p className="text-sm text-slate-400 mt-1">
            AI Threat Anomaly Classification (SQLi, XSS, Brute Force), Automated Risk Scoring & Real-Time Control Assurance
          </p>
        </div>

        <div className="flex flex-wrap gap-3">
          <button
            onClick={handleSimulateWave}
            disabled={simulating}
            className="px-4 py-2.5 rounded-lg font-medium text-sm bg-rose-600 hover:bg-rose-500 text-white shadow-lg shadow-rose-600/20 transition disabled:opacity-50"
          >
            {simulating ? "Injecting Attack Wave..." : "⚡ Simulate Live Attack Wave"}
          </button>
          <button
            onClick={handleGenerateReport}
            disabled={generatingReport}
            className="px-4 py-2.5 rounded-lg font-medium text-sm bg-cyan-600 hover:bg-cyan-500 text-white shadow-lg shadow-cyan-600/20 transition disabled:opacity-50"
          >
            {generatingReport ? "Generating with Gemini..." : "📄 Generate Gemini Compliance Report"}
          </button>
        </div>
      </header>

      {/* KPI Metrics Row */}
      <section className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-5 gap-4">
        <div className="bg-slate-900/90 border border-slate-800 rounded-xl p-4">
          <p className="text-xs uppercase text-slate-400">Automated Risk Score</p>
          <p className="text-3xl font-bold text-rose-400 mt-1">
            {metrics.overall_risk_score}
            <span className="text-sm text-slate-500 font-normal"> / 100</span>
          </p>
          <p className="text-xs text-slate-400 mt-1">Weighted AI Threat Index</p>
        </div>

        <div className="bg-slate-900/90 border border-slate-800 rounded-xl p-4">
          <p className="text-xs uppercase text-slate-400">Control Assurance</p>
          <p className="text-3xl font-bold text-emerald-400 mt-1">{metrics.compliance_score}%</p>
          <p className="text-xs text-slate-400 mt-1">ISO 27001 / NIST / OWASP</p>
        </div>

        <div className="bg-slate-900/90 border border-slate-800 rounded-xl p-4">
          <p className="text-xs uppercase text-slate-400">SQLi / XSS / Brute Force</p>
          <p className="text-2xl font-bold text-amber-400 mt-1">
            {metrics.threat_counts["SQLi"] || 0} / {metrics.threat_counts["XSS"] || 0} /{" "}
            {metrics.threat_counts["Brute Force"] || 0}
          </p>
          <p className="text-xs text-slate-400 mt-1">Classified Threat Anomalies</p>
        </div>

        <div className="bg-slate-900/90 border border-slate-800 rounded-xl p-4">
          <p className="text-xs uppercase text-slate-400">Audit Evidence Hashes</p>
          <p className="text-3xl font-bold text-cyan-400 mt-1">{metrics.evidence_collected}</p>
          <p className="text-xs text-slate-400 mt-1">SHA-256 Chain of Custody</p>
        </div>

        <div className="bg-slate-900/90 border border-slate-800 rounded-xl p-4">
          <p className="text-xs uppercase text-slate-400">Live Logs Ingested</p>
          <p className="text-3xl font-bold text-white mt-1">{metrics.total_logs}</p>
          <p className="text-xs text-slate-400 mt-1">Real-Time Telemetry Stream</p>
        </div>
      </section>

      {/* Custom Payload Tester */}
      <form
        onSubmit={handleCustomIngest}
        className="bg-slate-900/70 border border-slate-800 rounded-xl p-4 flex flex-col md:flex-row gap-3 items-end"
      >
        <div className="w-full md:w-44">
          <label className="text-xs text-slate-400 block mb-1">Source IP</label>
          <input
            value={customIp}
            onChange={(e) => setCustomIp(e.target.value)}
            className="w-full bg-slate-950 border border-slate-700 rounded px-3 py-2 text-sm text-white"
          />
        </div>
        <div className="w-full md:w-60">
          <label className="text-xs text-slate-400 block mb-1">Target Endpoint</label>
          <input
            value={customEndpoint}
            onChange={(e) => setCustomEndpoint(e.target.value)}
            className="w-full bg-slate-950 border border-slate-700 rounded px-3 py-2 text-sm text-white"
          />
        </div>
        <div className="flex-1 w-full">
          <label className="text-xs text-slate-400 block mb-1">
            Live Log Payload (Test SQLi, XSS, or Brute Force)
          </label>
          <input
            value={customPayload}
            onChange={(e) => setCustomPayload(e.target.value)}
            className="w-full bg-slate-950 border border-slate-700 rounded px-3 py-2 text-sm font-mono text-amber-300"
          />
        </div>
        <button
          type="submit"
          className="px-4 py-2 rounded bg-slate-800 hover:bg-slate-700 text-cyan-300 border border-cyan-500/30 text-sm font-medium whitespace-nowrap"
        >
          Ingest & Score Log →
        </button>
      </form>

      {/* Navigation Tabs */}
      <div className="flex gap-2 border-b border-slate-800 pb-2">
        {[
          { key: "logs", label: `1. AI Threat Classification & Risk Feed (${logs.length})` },
          { key: "controls", label: `2. Real-Time Control Validation (${controls.length})` },
          { key: "evidence", label: `3. Automated Audit Evidence (${evidence.length})` },
          { key: "reports", label: `4. LLM Compliance & Incident Reports (${reports.length})` },
        ].map((t) => (
          <button
            key={t.key}
            onClick={() => setActiveTab(t.key as any)}
            className={`px-4 py-2 rounded-t-lg text-sm font-medium transition ${
              activeTab === t.key
                ? "bg-slate-800 text-cyan-400 border-b-2 border-cyan-400"
                : "text-slate-400 hover:text-white"
            }`}
          >
            {t.label}
          </button>
        ))}
      </div>

      {/* Tab 1: Threat Logs */}
      {activeTab === "logs" && (
        <div className="space-y-3">
          {logs.map((log: any) => (
            <div
              key={log.id}
              className="bg-slate-900/90 border border-slate-800 rounded-xl p-4 flex flex-col md:flex-row justify-between gap-4"
            >
              <div className="space-y-1.5">
                <div className="flex flex-wrap items-center gap-2">
                  <span
                    className={`px-2.5 py-0.5 text-xs font-bold rounded ${
                      log.threat_type === "Normal"
                        ? "bg-emerald-500/10 text-emerald-400 border border-emerald-500/30"
                        : "bg-rose-500/10 text-rose-400 border border-rose-500/30"
                    }`}
                  >
                    {log.threat_type}
                  </span>
                  <span className="text-xs font-mono text-slate-400">{log.source_ip}</span>
                  <span className="text-xs font-semibold text-cyan-300">
                    {log.method} {log.endpoint}
                  </span>
                  <span className="text-xs text-slate-500">{log.mitre_tactic}</span>
                </div>
                <p className="text-xs font-mono bg-slate-950 p-2 rounded border border-slate-800 text-amber-300 break-all">
                  {log.payload}
                </p>
                <p className="text-xs text-slate-300">
                  <strong className="text-cyan-400">AI Classification Analysis:</strong>{" "}
                  {log.ai_reasoning}
                </p>
              </div>
              <div className="flex md:flex-col justify-between items-end min-w-[170px] text-right">
                <div>
                  <span className="text-xs text-slate-400 block">Risk Score</span>
                  <span
                    className={`text-2xl font-bold ${
                      log.risk_score >= 70 ? "text-rose-400" : "text-emerald-400"
                    }`}
                  >
                    {log.risk_score} / 100
                  </span>
                </div>
                <span className="px-2 py-1 text-[11px] font-mono bg-slate-800 text-cyan-300 rounded">
                  {log.automated_action}
                </span>
              </div>
            </div>
          ))}
        </div>
      )}

      {/* Tab 2: Control Validation */}
      {activeTab === "controls" && (
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          {controls.map((c: any) => (
            <div key={c.control_id} className="bg-slate-900 border border-slate-800 rounded-xl p-5 space-y-2">
              <div className="flex justify-between items-center">
                <span className="text-xs font-mono text-cyan-400">
                  {c.control_id} · {c.framework}
                </span>
                <span
                  className={`px-2.5 py-0.5 text-xs font-bold rounded ${
                    c.status === "PASS"
                      ? "bg-emerald-500/10 text-emerald-400"
                      : "bg-amber-500/10 text-amber-400"
                  }`}
                >
                  {c.status} ({c.pass_rate}%)
                </span>
              </div>
              <h3 className="text-base font-semibold text-white">{c.name}</h3>
              <p className="text-xs text-slate-400">{c.description}</p>
              <p className="text-xs text-slate-500 pt-1">
                Linked Audit Evidence Items: <strong className="text-slate-300">{c.evidence_count}</strong>
              </p>
            </div>
          ))}
        </div>
      )}

      {/* Tab 3: Audit Evidence */}
      {activeTab === "evidence" && (
        <div className="bg-slate-900 border border-slate-800 rounded-xl overflow-hidden">
          <table className="w-full text-left text-xs">
            <thead className="bg-slate-950 text-slate-400 uppercase">
              <tr>
                <th className="p-3">Control ID</th>
                <th className="p-3">Threat Class</th>
                <th className="p-3">Source IP</th>
                <th className="p-3">Automated Response</th>
                <th className="p-3">SHA-256 Evidence Hash</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800">
              {evidence.map((e: any) => (
                <tr key={e.id}>
                  <td className="p-3 font-mono text-cyan-400">{e.control_id}</td>
                  <td className="p-3 font-semibold text-rose-400">{e.threat_type}</td>
                  <td className="p-3 font-mono">{e.source_ip}</td>
                  <td className="p-3 font-mono text-emerald-400">{e.response_taken}</td>
                  <td className="p-3 font-mono text-slate-400">{e.evidence_hash}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      {/* Tab 4: Compliance Reports */}
      {activeTab === "reports" && (
        <div className="space-y-6">
          {reports.map((r: any) => (
            <div key={r.id} className="bg-slate-900 border border-slate-800 rounded-xl p-6 space-y-4">
              <div className="flex justify-between items-center border-b border-slate-800 pb-3">
                <div>
                  <h3 className="text-lg font-bold text-white">{r.title}</h3>
                  <p className="text-xs text-cyan-400">Engine: {r.generated_by}</p>
                </div>
                <span className="text-xs text-slate-400">
                  Risk: {r.overall_risk_score}/100 · Compliance: {r.compliance_score}%
                </span>
              </div>
              <pre className="whitespace-pre-wrap text-xs font-mono text-slate-200 bg-slate-950 p-4 rounded-lg border border-slate-800 leading-relaxed">
                {r.markdown_content}
              </pre>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}
