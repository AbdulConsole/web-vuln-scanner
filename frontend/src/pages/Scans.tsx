import { useEffect, useState } from 'react';
import { Link } from 'react-router-dom';
import { api, Scan, Target } from '../api';
import { StatusBadge } from '../components/Badges';

export default function Scans() {
  const [scans, setScans] = useState<Scan[]>([]);
  const [targets, setTargets] = useState<Target[]>([]);
  const [loading, setLoading] = useState(true);
  const [selectedTarget, setSelectedTarget] = useState('');

  const load = async () => {
    try {
      const [s, t] = await Promise.all([api.listScans(), api.listTargets()]);
      setScans(s.items);
      setTargets(t);
    } catch (e) {
      console.error(e);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => { load(); }, []);

  const handleStartScan = async () => {
    if (!selectedTarget) return;
    try {
      await api.createScan(selectedTarget);
      load();
    } catch (e: any) {
      alert(e.message || 'Failed to start scan');
    }
  };

  const handleCancel = async (id: string) => {
    if (!confirm('Cancel this scan?')) return;
    await api.cancelScan(id);
    load();
  };

  if (loading) return <div className="text-center py-8 text-gray-500">Loading...</div>;

  return (
    <div>
      <div className="flex items-center justify-between mb-6">
        <h1 className="text-2xl font-bold">Scans</h1>
        <div className="flex items-center gap-2">
          <select
            value={selectedTarget}
            onChange={e => setSelectedTarget(e.target.value)}
            className="border rounded px-3 py-2 text-sm"
          >
            <option value="">Select target...</option>
            {targets.map(t => (
              <option key={t.id} value={t.id}>{t.name}</option>
            ))}
          </select>
          <button
            onClick={handleStartScan}
            disabled={!selectedTarget}
            className="bg-green-600 text-white px-4 py-2 rounded hover:bg-green-700 disabled:opacity-50"
          >
            Start Scan
          </button>
        </div>
      </div>

      <div className="bg-white rounded-lg shadow overflow-hidden">
        <table className="w-full text-sm">
          <thead className="bg-gray-50">
            <tr>
              <th className="px-4 py-3 text-left">Status</th>
              <th className="px-4 py-3 text-left">URLs Crawled</th>
              <th className="px-4 py-3 text-left">Requests Sent</th>
              <th className="px-4 py-3 text-left">Started</th>
              <th className="px-4 py-3 text-left">Finished</th>
              <th className="px-4 py-3 text-right">Actions</th>
            </tr>
          </thead>
          <tbody>
            {scans.map(scan => (
              <tr key={scan.id} className="border-t hover:bg-gray-50">
                <td className="px-4 py-3"><StatusBadge status={scan.status} /></td>
                <td className="px-4 py-3">{scan.urls_crawled}</td>
                <td className="px-4 py-3">{scan.requests_sent}</td>
                <td className="px-4 py-3 text-gray-500">
                  {scan.started_at ? new Date(scan.started_at).toLocaleString() : '-'}
                </td>
                <td className="px-4 py-3 text-gray-500">
                  {scan.finished_at ? new Date(scan.finished_at).toLocaleString() : '-'}
                </td>
                <td className="px-4 py-3 text-right space-x-2">
                  <Link to={`/scans/${scan.id}`} className="text-blue-500 hover:underline">
                    View
                  </Link>
                  {scan.status === 'running' && (
                    <button
                      onClick={() => handleCancel(scan.id)}
                      className="text-red-500 hover:underline"
                    >
                      Cancel
                    </button>
                  )}
                </td>
              </tr>
            ))}
            {scans.length === 0 && (
              <tr><td colSpan={6} className="px-4 py-8 text-center text-gray-400">No scans yet</td></tr>
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
}
