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
        alert("Attack approved and queued for execution!");
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

  return (
    <div className="min-h-screen bg-gray-100 p-8 font-sans">
      <header className="mb-12">
        <h1 className="text-4xl font-extrabold text-gray-900 tracking-tight">Sentery Dashboard</h1>
        <p className="text-gray-600 mt-2">Autonomous Web Business Logic Security Testing</p>
      </header>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-10">
        {/* Left Column: Traffic Log */}
        <section className="bg-white rounded-xl shadow-lg p-6">
          <div className="flex justify-between items-center mb-6">
            <h2 className="text-2xl font-bold text-gray-800">Traffic Log</h2>
            <span className="bg-blue-100 text-blue-800 text-xs font-semibold px-2.5 py-0.5 rounded-full uppercase">Live</span>
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
                      <span className={`px-2 py-1 rounded text-xs font-bold uppercase ${entry.method === 'POST' ? 'bg-orange-100 text-orange-800' : 'bg-green-100 text-green-800'}`}>
                        {entry.method}
                      </span>
                    </td>
                    <td className="px-4 py-4 text-sm text-gray-600 truncate max-w-xs font-mono">{entry.url}</td>
                    <td className="px-4 py-4 text-sm font-semibold text-gray-700">{entry.response_status}</td>
                  </tr>
                ))}
                {traffic.length === 0 && (
                  <tr>
                    <td colSpan={3} className="px-4 py-10 text-center text-gray-400 italic">Waiting for traffic data...</td>
                  </tr>
                )}
              </tbody>
            </table>
          </div>
        </section>

        {/* Right Column: AI Insights */}
        <section className="bg-white rounded-xl shadow-lg p-6 border-l-4 border-purple-500">
          <div className="flex justify-between items-center mb-6">
            <h2 className="text-2xl font-bold text-gray-800">AI Insights</h2>
            <span className="bg-purple-100 text-purple-800 text-xs font-semibold px-2.5 py-0.5 rounded-full uppercase font-mono">Powered by Gemini</span>
          </div>
          <div className="space-y-6">
            {attacks.map((attack) => (
              <div key={attack.id} className="bg-gray-50 border border-gray-200 p-5 rounded-lg shadow-sm transition-all hover:border-purple-300">
                <div className="flex justify-between items-start mb-3">
                  <h3 className="font-bold text-lg text-red-600">{attack.flaw_type}</h3>
                  <span className={`px-3 py-1 rounded-full text-xs font-bold uppercase tracking-wider ${attack.status === 'approved' ? 'bg-green-200 text-green-800' : 'bg-yellow-200 text-yellow-800'}`}>
                    {attack.status}
                  </span>
                </div>
                <p className="text-gray-700 text-sm leading-relaxed mb-4">{attack.description}</p>
                <div className="bg-gray-900 text-green-400 p-3 rounded text-xs font-mono mb-6 overflow-x-auto">
                  <span className="text-gray-500 mr-2">$ payload:</span> {attack.suggested_payload}
                </div>
                {attack.status === 'pending' && (
                  <button
                    onClick={() => approveAndExecute(attack.id)}
                    className="w-full bg-purple-600 text-white font-bold py-3 rounded-lg hover:bg-purple-700 shadow-md transition-all active:scale-95"
                  >
                    Approve & Execute
                  </button>
                )}
              </div>
            ))}
            {attacks.length === 0 && (
              <div className="text-gray-400 border-2 border-dashed border-gray-200 py-16 rounded-lg text-center font-medium italic">No security flaws identified yet</div>
            )}
          </div>
        </section>
      </div>
    </div>
  );
}
