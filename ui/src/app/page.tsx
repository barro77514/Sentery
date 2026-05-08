"use client";

import React, { useState, useEffect, useRef } from 'react';

interface TrafficEntry {
  id: string;
  method: string;
  url: string;
  request_body: string;
  response_status: number;
  timestamp: string;
}

interface AttackSuggestion {
  id: string;
  traffic_id: string;
  flaw_type: string;
  description: string;
  suggested_payload: string;
  status: string;
}

interface VAAlert {
  id: string;
  traffic_id: string;
  title: string;
  severity: string;
  description: string;
  recommendation: string;
}

export default function Dashboard() {
  const [traffic, setTraffic] = useState<TrafficEntry[]>([]);
  const [attacks, setAttacks] = useState<AttackSuggestion[]>([]);
  const [alerts, setAlerts] = useState<VAAlert[]>([]);
  const [aiLogs, setAiLogs] = useState<string[]>([]);
  const [explorerUrl, setExplorerUrl] = useState('');

  const aiLogsEndRef = useRef<HTMLDivElement>(null);
  const API_URL = process.env.NEXT_PUBLIC_API_URL || 'http://localhost:8000';

  const fetchData = async () => {
    try {
      const [t, a, v, l] = await Promise.all([
        fetch(`${API_URL}/traffic`).then(r => r.json()),
        fetch(`${API_URL}/attacks`).then(r => r.json()),
        fetch(`${API_URL}/va/alerts`).then(r => r.json()),
        fetch(`${API_URL}/ai-logs`).then(r => r.json())
      ]);
      setTraffic(t);
      setAttacks(a);
      setAlerts(v);
      setAiLogs(l);
    } catch (err) {
      console.error("Failed to fetch data", err);
    }
  };

  const launchExplorer = async () => {
    if (!explorerUrl) return;
    try {
      await fetch(`${API_URL}/explorer/launch`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ url: explorerUrl })
      });
      alert("Autonomous Explorer launched!");
    } catch (err) {
      console.error("Failed to launch explorer", err);
    }
  };

  const approveAndExecute = async (id: string) => {
    try {
      const res = await fetch(`${API_URL}/attacks/${id}/approve`, { method: 'POST' });
      if (res.ok) {
        fetchData();
        alert("Attack approved and executed (Knowledge Base updated)!");
      }
    } catch (err) {
      console.error("Failed to approve attack", err);
    }
  };

  useEffect(() => {
    fetchData();
    const interval = setInterval(fetchData, 3000);
    return () => clearInterval(interval);
  }, []);

  useEffect(() => {
    aiLogsEndRef.current?.scrollIntoView({ behavior: "smooth" });
  }, [aiLogs]);

  const getFlowNodes = () => {
    const nodes: { label: string, url: string, type: 'normal' | 'sensitive' | 'bypass' }[] = [];
    traffic.forEach(t => {
      let label = "Page View";
      let type: 'normal' | 'sensitive' | 'bypass' = 'normal';
      const url = t.url.toLowerCase();
      if (url.includes("cart")) {
        label = "Cart";
        type = 'sensitive';
      } else if (url.includes("checkout") && !url.includes("success")) {
        label = "Checkout";
        type = 'sensitive';
      } else if (url.includes("purchase") || url.includes("success")) {
        label = "Purchase Success";
        type = 'sensitive';
        const hasCheckout = traffic.some(prev =>
            prev.id !== t.id &&
            prev.url.includes("checkout") &&
            !prev.url.includes("success") &&
            new Date(prev.timestamp) < new Date(t.timestamp)
        );
        if (!hasCheckout) {
          label = "BYPASS DETECTED";
          type = 'bypass';
        }
      }
      nodes.push({ label, url: t.url, type });
    });
    return nodes;
  };

  const flowNodes = getFlowNodes();

  return (
    <div className="min-h-screen bg-gray-50 p-8 font-sans">
      <header className="mb-10">
        <h1 className="text-4xl font-black text-gray-900 tracking-tighter flex items-center">
          Sentery <span className="ml-4 text-xs font-mono bg-green-500 text-black px-2 py-1 rounded">v1.0 AUTONOMOUS</span>
        </h1>
        <p className="text-gray-500 mt-1 font-medium italic">FoxyProxy Integrated | AI-Driven Navigation | Feedback Loop</p>
      </header>

      {/* Control Center */}
      <section className="mb-12 bg-white rounded-2xl shadow-xl p-6 border-b-8 border-green-500">
        <h2 className="text-lg font-bold mb-4 flex items-center">🚀 Launch Autonomous Explorer</h2>
        <div className="flex space-x-4">
          <input
            type="text"
            placeholder="https://target-ecommerce.com"
            className="flex-1 p-3 border-2 border-gray-100 rounded-lg text-sm font-mono focus:border-green-400 outline-none transition-all"
            value={explorerUrl}
            onChange={(e) => setExplorerUrl(e.target.value)}
          />
          <button
            onClick={launchExplorer}
            className="bg-black text-white font-bold px-8 py-3 rounded-lg hover:bg-gray-800 transition-all active:scale-95 uppercase text-xs tracking-widest"
          >
            Start Active Scanning
          </button>
        </div>
      </section>

      {/* AI Reasoning Terminal */}
      <section className="mb-12 bg-black rounded-2xl shadow-2xl p-6 overflow-hidden border-t-4 border-green-400">
        <h2 className="text-xs font-black text-green-400 uppercase tracking-[0.2em] mb-4">AI Reasoning & Analysis Logs</h2>
        <div className="h-48 overflow-y-auto font-mono text-[10px] text-green-300 space-y-1 bg-gray-900 p-4 rounded-lg">
          {aiLogs.map((log, i) => (
            <div key={i}><span className="opacity-40">[{i}]</span> {log}</div>
          ))}
          {aiLogs.length === 0 && <div className="text-gray-700 italic">Initializing autonomous analysis...</div>}
          <div ref={aiLogsEndRef} />
        </div>
      </section>

      {/* Timeline View */}
      <section className="mb-12 bg-white rounded-xl shadow-md p-6 border-t-4 border-black">
        <h2 className="text-xl font-bold mb-6 uppercase tracking-widest text-gray-400">User Flow Timeline</h2>
        <div className="flex items-center space-x-4 overflow-x-auto pb-4">
          {flowNodes.map((node, i) => (
            <React.Fragment key={i}>
              <div className={`flex-shrink-0 p-4 rounded-lg border-2 transition-all ${
                node.type === 'bypass' ? 'bg-red-100 border-red-500 animate-pulse' :
                node.type === 'sensitive' ? 'bg-blue-50 border-blue-400' : 'bg-gray-50 border-gray-200'
              }`}>
                <div className="text-xs font-bold uppercase mb-1">{node.type === 'bypass' ? '⚠️ ' : ''}{node.label}</div>
                <div className="text-[10px] text-gray-500 truncate w-32 font-mono">{node.url}</div>
              </div>
              {i < flowNodes.length - 1 && <div className="text-gray-300">→</div>}
            </React.Fragment>
          ))}
          {flowNodes.length === 0 && <div className="text-gray-400 italic text-sm">Navigate to generate flow data...</div>}
        </div>
      </section>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-10">
        {/* Left Column: Traffic Log */}
        <section className="bg-white rounded-xl shadow-lg p-6">
          <h2 className="text-2xl font-bold text-gray-800 mb-6">Traffic Log</h2>
          <div className="overflow-x-auto">
            <table className="min-w-full divide-y divide-gray-200">
              <thead>
                <tr>
                  <th className="px-4 py-3 text-left text-xs font-semibold text-gray-500 uppercase">Method</th>
                  <th className="px-4 py-3 text-left text-xs font-semibold text-gray-500 uppercase">URL</th>
                  <th className="px-4 py-3 text-left text-xs font-semibold text-gray-500 uppercase">Status</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-gray-100">
                {traffic.map((entry) => (
                  <tr key={entry.id} className="hover:bg-gray-50">
                    <td className="px-4 py-4"><span className="px-2 py-1 rounded text-[10px] font-bold uppercase bg-blue-100 text-blue-800">{entry.method}</span></td>
                    <td className="px-4 py-4 text-xs font-mono truncate max-w-xs">{entry.url}</td>
                    <td className="px-4 py-4 text-xs font-bold">{entry.response_status}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </section>

        {/* Right Column: AI Insights */}
        <section className="bg-white rounded-xl shadow-lg p-6 border-l-8 border-indigo-600">
          <h2 className="text-2xl font-bold text-gray-800 mb-6">AI Insights</h2>
          <div className="space-y-6">
            {attacks.map((attack) => (
              <div key={attack.id} className="bg-indigo-50 border border-indigo-100 p-5 rounded-lg shadow-sm">
                <div className="flex justify-between items-start mb-3">
                  <h3 className="font-bold text-lg text-indigo-900">{attack.flaw_type}</h3>
                  <span className="px-3 py-1 rounded-full text-[10px] font-black uppercase bg-orange-400 text-white tracking-tighter">{attack.status}</span>
                </div>
                <p className="text-indigo-800 text-sm mb-4">{attack.description}</p>
                <div className="bg-black text-white p-3 rounded text-xs font-mono mb-4 border-b-2 border-indigo-400 overflow-x-auto">
                  {attack.suggested_payload}
                </div>
                {attack.status === 'pending' && (
                  <button onClick={() => approveAndExecute(attack.id)} className="w-full bg-indigo-600 text-white font-black py-4 rounded hover:bg-indigo-700 uppercase tracking-widest text-xs">
                    Approve & Execute
                  </button>
                )}
              </div>
            ))}
            {attacks.length === 0 && <div className="text-gray-400 text-center py-10 italic font-bold">No vulnerabilities detected.</div>}
          </div>
        </section>
      </div>

      {/* VA Alerts */}
      <section className="mt-12 bg-white rounded-xl shadow-md p-6 border-l-8 border-red-500">
        <h2 className="text-xl font-bold mb-6">🛡️ Vulnerability Assessment</h2>
        <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
          {alerts.map((alert) => (
            <div key={alert.id} className="border border-gray-100 bg-gray-50 p-4 rounded-lg">
              <h3 className="font-bold text-sm mb-1">{alert.title}</h3>
              <p className="text-[10px] text-gray-600 mb-2">{alert.description}</p>
              <div className="text-[10px] bg-white p-2 rounded border italic">Fix: {alert.recommendation}</div>
            </div>
          ))}
        </div>
      </section>
    </div>
  );
}
