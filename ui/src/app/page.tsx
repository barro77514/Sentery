"use client";

import React, { useState, useEffect } from 'react';

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

export default function Dashboard() {
  const [traffic, setTraffic] = useState<TrafficEntry[]>([]);
  const [attacks, setAttacks] = useState<AttackSuggestion[]>([]);

  const fetchTraffic = async () => {
    try {
      const res = await fetch('http://localhost:8000/traffic');
      if (!res.ok) throw new Error('Network response was not ok');
      const data = await res.json();
      setTraffic(data);
    } catch (err) {
      console.error("Failed to fetch traffic", err);
    }
  };

  const fetchAttacks = async () => {
    try {
      const res = await fetch('http://localhost:8000/attacks');
      if (!res.ok) throw new Error('Network response was not ok');
      const data = await res.json();
      setAttacks(data);
    } catch (err) {
      console.error("Failed to fetch attacks", err);
    }
  };

  const approveAndExecute = async (id: string) => {
    try {
      const res = await fetch(`http://localhost:8000/attacks/${id}/approve`, { method: 'POST' });
      if (res.ok) {
        fetchAttacks();
        alert("Attack approved and executed (Knowledge Base updated)!");
      }
    } catch (err) {
      console.error("Failed to approve attack", err);
    }
  };

  useEffect(() => {
    fetchTraffic();
    fetchAttacks();
    const interval = setInterval(() => {
      fetchTraffic();
      fetchAttacks();
    }, 5000);
    return () => clearInterval(interval);
  }, []);

  // Simple logic to determine user flow nodes for Timeline View
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

        // Check for bypass: if we see purchase/success but didn't see checkout recently
        // Refined bypass check: exclude itself from the search
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
      <header className="mb-12">
        <h1 className="text-4xl font-extrabold text-gray-900 tracking-tight flex items-center">
          Sentery <span className="ml-4 text-sm font-normal bg-black text-white px-2 py-1 rounded">v0.2 - Semantic Memory</span>
        </h1>
        <p className="text-gray-600 mt-2 italic font-serif">Autonomous Business Logic Intelligence</p>
      </header>

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
              {i < flowNodes.length - 1 && (
                <div className="text-gray-300">→</div>
              )}
            </React.Fragment>
          ))}
          {flowNodes.length === 0 && <div className="text-gray-400 italic">Navigate to generate flow data...</div>}
        </div>
      </section>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-10">
        {/* Left Column: Traffic Log */}
        <section className="bg-white rounded-xl shadow-lg p-6 overflow-hidden">
          <div className="flex justify-between items-center mb-6">
            <h2 className="text-2xl font-bold text-gray-800">Traffic Log</h2>
            <span className="bg-green-100 text-green-800 text-xs font-semibold px-2.5 py-0.5 rounded-full uppercase">Monitoring</span>
          </div>
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
                  <tr key={entry.id} className="hover:bg-gray-50 transition-colors">
                    <td className="px-4 py-4 whitespace-nowrap">
                      <span className={`px-2 py-1 rounded text-xs font-bold uppercase ${entry.method === 'POST' ? 'bg-orange-100 text-orange-800' : 'bg-blue-100 text-blue-800'}`}>
                        {entry.method}
                      </span>
                    </td>
                    <td className="px-4 py-4 text-sm text-gray-600 truncate max-w-xs font-mono">{entry.url}</td>
                    <td className="px-4 py-4 text-sm font-semibold text-gray-700">{entry.response_status}</td>
                  </tr>
                ))}
                {traffic.length === 0 && (
                  <tr>
                    <td colSpan={3} className="px-4 py-10 text-center text-gray-400 italic">Waiting for traffic...</td>
                  </tr>
                )}
              </tbody>
            </table>
          </div>
        </section>

        {/* Right Column: AI Insights */}
        <section className="bg-white rounded-xl shadow-lg p-6 border-l-8 border-indigo-600">
          <div className="flex justify-between items-center mb-6">
            <h2 className="text-2xl font-bold text-gray-800 tracking-tighter">AI Insights</h2>
            <span className="bg-indigo-100 text-indigo-800 text-xs font-bold px-3 py-1 rounded-md uppercase">Semantic Memory Active</span>
          </div>
          <div className="space-y-6">
            {attacks.map((attack) => (
              <div key={attack.id} className="bg-indigo-50 border border-indigo-100 p-5 rounded-lg shadow-sm transition-all hover:scale-[1.01]">
                <div className="flex justify-between items-start mb-3">
                  <h3 className="font-bold text-lg text-indigo-900">{attack.flaw_type}</h3>
                  <span className={`px-3 py-1 rounded-full text-[10px] font-black uppercase tracking-tighter ${attack.status === 'approved' ? 'bg-green-600 text-white' : 'bg-orange-400 text-white animate-pulse'}`}>
                    {attack.status}
                  </span>
                </div>
                <p className="text-indigo-800 text-sm leading-relaxed mb-4 font-medium">{attack.description}</p>
                <div className="bg-black text-white p-3 rounded text-xs font-mono mb-6 overflow-x-auto border-b-2 border-indigo-400">
                  <span className="text-indigo-400 mr-2">PROPOSED PAYLOAD:</span> {attack.suggested_payload}
                </div>
                {attack.status === 'pending' && (
                  <button
                    onClick={() => approveAndExecute(attack.id)}
                    className="w-full bg-indigo-600 text-white font-black py-4 rounded hover:bg-indigo-700 shadow-xl transition-all active:translate-y-1 uppercase tracking-widest text-xs"
                  >
                    Approve & Execute Attack
                  </button>
                )}
              </div>
            ))}
            {attacks.length === 0 && (
              <div className="text-gray-400 border-2 border-dotted border-gray-300 py-16 rounded-lg text-center font-bold italic">No logical vulnerabilities detected. Sentery is listening.</div>
            )}
          </div>
        </section>
      </div>
    </div>
  );
}
