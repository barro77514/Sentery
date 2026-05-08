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
      const data = await res.json();
      setTraffic(data);
    } catch (err) {
      console.error("Failed to fetch traffic", err);
    }
  };

  const fetchAttacks = async () => {
    try {
      const res = await fetch('http://localhost:8000/attacks');
      const data = await res.json();
      setAttacks(data);
    } catch (err) {
      console.error("Failed to fetch attacks", err);
    }
  };

  const approveAttack = async (id: string) => {
    try {
      await fetch(`http://localhost:8000/attacks/${id}/approve`, { method: 'POST' });
      fetchAttacks();
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
    <div className="p-8 font-sans">
      <h1 className="text-3xl font-bold mb-8">Sentery Dashboard</h1>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-8">
        <section>
          <h2 className="text-2xl font-semibold mb-4">Traffic Log</h2>
          <div className="border rounded-lg overflow-hidden">
            <table className="min-w-full divide-y divide-gray-200">
              <thead className="bg-gray-50">
                <tr>
                  <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Method</th>
                  <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">URL</th>
                  <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Status</th>
                </tr>
              </thead>
              <tbody className="bg-white divide-y divide-gray-200">
                {traffic.map((entry) => (
                  <tr key={entry.id}>
                    <td className="px-6 py-4 whitespace-nowrap text-sm font-medium text-gray-900">{entry.method}</td>
                    <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-500 truncate max-w-xs">{entry.url}</td>
                    <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-500">{entry.response_status}</td>
                  </tr>
                ))}
                {traffic.length === 0 && (
                  <tr>
                    <td colSpan={3} className="px-6 py-4 text-center text-gray-500">No traffic intercepted yet</td>
                  </tr>
                )}
              </tbody>
            </table>
          </div>
        </section>

        <section>
          <h2 className="text-2xl font-semibold mb-4">Attack Suggestions</h2>
          <div className="space-y-4">
            {attacks.map((attack) => (
              <div key={attack.id} className="border p-4 rounded-lg shadow-sm">
                <div className="flex justify-between items-start mb-2">
                  <h3 className="font-bold text-lg text-red-600">{attack.flaw_type}</h3>
                  <span className={`px-2 py-1 rounded text-xs font-bold uppercase ${attack.status === 'approved' ? 'bg-green-100 text-green-800' : 'bg-yellow-100 text-yellow-800'}`}>
                    {attack.status}
                  </span>
                </div>
                <p className="text-gray-700 mb-2">{attack.description}</p>
                <div className="bg-gray-100 p-2 rounded text-sm font-mono mb-4">
                  Payload: {attack.suggested_payload}
                </div>
                {attack.status === 'pending' && (
                  <div className="flex space-x-2">
                    <button
                      onClick={() => approveAttack(attack.id)}
                      className="bg-blue-600 text-white px-4 py-2 rounded hover:bg-blue-700 transition"
                    >
                      Approve Attack
                    </button>
                    <button className="bg-gray-200 text-gray-800 px-4 py-2 rounded hover:bg-gray-300 transition">
                      Reject
                    </button>
                  </div>
                )}
              </div>
            ))}
            {attacks.length === 0 && (
              <div className="text-gray-500 border p-4 rounded-lg text-center">No attack suggestions yet</div>
            )}
          </div>
        </section>
      </div>
    </div>
  );
}
