import { useEffect, useState } from 'react';
import { Link } from 'react-router-dom';
import { api, Target, Scan, Finding } from '../api';
import { StatusBadge } from '../components/Badges';

export default function Dashboard() {
  const [targets, setTargets] = useState<Target[]>([]);
  const [scans, setScans] = useState<Scan[]>([]);
  const [findings, setFindings] = useState<Finding[]>([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    async function load() {
      try {
        const [t, s] = await Promise.all([api.listTargets(), api.listScans()]);
        setTargets(t);
        setScans(s.items);

        // Fetch findings from all completed scans.
        const completedScans = s.items.filter((scan: Scan) => scan.status === 'completed');
        const findingsResults = await Promise.all(
          completedScans.map((scan: Scan) =>
            api.listScanFindings(scan.id).catch(() => ({ items: [], total: 0 }))
          )
        );
        const allFindings = findingsResults.flatMap((r) => r.items);
        setFindings(allFindings);
      } catch (e) {
        console.error(e);
      } finally {
        setLoading(false);
      }
    }
    load();
  }, []);

  if (loading) return <div className="text-center py-8 text-gray-500">Loading...</div>;

  const recentScans = scans.slice(0, 5);

  return (
    <div>
      <h1 className="text-2xl font-bold mb-6">Dashboard</h1>

      <div className="grid grid-cols-4 gap-4 mb-8">
        <div className="bg-white rounded-lg shadow p-4">
          <div className="text-3xl font-bold text-blue-600">{targets.length}</div>
          <div className="text-gray-500">Targets</div>
        </div>
        <div className="bg-white rounded-lg shadow p-4">
          <div className="text-3xl font-bold text-green-600">{scans.length}</div>
          <div className="text-gray-500">Total Scans</div>
        </div>
        <div className="bg-white rounded-lg shadow p-4">
          <div className="text-3xl font-bold text-orange-600">
            {scans.filter(s => s.status === 'running').length}
          </div>
          <div className="text-gray-500">Running</div>
        </div>
        <div className="bg-white rounded-lg shadow p-4">
          <div className="text-3xl font-bold text-red-600">{findings.length}</div>
          <div className="text-gray-500">Findings</div>
        </div>
      </div>

      <div className="grid grid-cols-2 gap-6">
        <div className="bg-white rounded-lg shadow p-4">
          <h2 className="text-lg font-semibold mb-4">Recent Scans</h2>
          {recentScans.length === 0 ? (
            <p className="text-gray-400">No scans yet</p>
          ) : (
            <table className="w-full text-sm">
              <thead>
                <tr className="text-left text-gray-500 border-b">
                  <th className="pb-2">Status</th>
                  <th className="pb-2">URLs</th>
                  <th className="pb-2">Requests</th>
                  <th className="pb-2">Created</th>
                </tr>
              </thead>
              <tbody>
                {recentScans.map(scan => (
                  <tr key={scan.id} className="border-b hover:bg-gray-50">
                    <td className="py-2"><StatusBadge status={scan.status} /></td>
                    <td>{scan.urls_crawled}</td>
                    <td>{scan.requests_sent}</td>
                    <td>{new Date(scan.created_at).toLocaleDateString()}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </div>

        <div className="bg-white rounded-lg shadow p-4">
          <h2 className="text-lg font-semibold mb-4">Targets</h2>
          {targets.length === 0 ? (
            <p className="text-gray-400">No targets configured</p>
          ) : (
            <ul className="space-y-2">
              {targets.map(target => (
                <li key={target.id} className="flex items-center justify-between p-2 rounded hover:bg-gray-50">
                  <div>
                    <div className="font-medium">{target.name}</div>
                    <div className="text-xs text-gray-400">{target.base_url}</div>
                  </div>
                  <Link to="/scans" className="text-blue-500 text-sm hover:underline">
                    View Scans
                  </Link>
                </li>
              ))}
            </ul>
          )}
        </div>
      </div>
    </div>
  );
}
