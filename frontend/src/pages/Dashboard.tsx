import { useEffect, useState } from 'react';
import { Link } from 'react-router-dom';
import { api, Target, Scan, Finding } from '../api';
import { StatusBadge, SeverityCard } from '../components/Badges';
import Spinner from '../components/Spinner';
import EmptyState from '../components/EmptyState';

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

  if (loading) return <Spinner />;

  const recentScans = scans.slice(0, 5);
  const severityCounts = findings.reduce(
    (acc, f) => {
      acc[f.severity] = (acc[f.severity] || 0) + 1;
      return acc;
    },
    {} as Record<string, number>
  );
  const severityOrder = ['critical', 'high', 'medium', 'low', 'informational'];

  return (
    <div>
      <h1 className="text-2xl font-bold mb-6">Dashboard</h1>

      <div className="grid grid-cols-4 gap-4 mb-6">
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

      {findings.length > 0 && (
        <div className="grid grid-cols-5 gap-3 mb-8">
          {severityOrder.map(sev => (
            <SeverityCard key={sev} severity={sev} count={severityCounts[sev] || 0} />
          ))}
        </div>
      )}

      <div className="grid grid-cols-2 gap-6">
        <div className="bg-white rounded-lg shadow p-4">
          <h2 className="text-lg font-semibold mb-4">Recent Scans</h2>
          {recentScans.length === 0 ? (
            <EmptyState icon="🔍" title="No scans yet" description="Create a target and start your first scan" />
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
            <EmptyState icon="🎯" title="No targets configured" description="Add a target URL to begin scanning" />
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
