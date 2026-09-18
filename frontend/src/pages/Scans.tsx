import { useEffect, useState, useRef, useCallback } from 'react';
import { Link } from 'react-router-dom';
import { api, Scan, Target } from '../api';
import { StatusBadge } from '../components/Badges';
import Spinner from '../components/Spinner';
import EmptyState from '../components/EmptyState';
import ConfirmDialog from '../components/ConfirmDialog';
import { useToast } from '../components/Toast';

export default function Scans() {
  const [scans, setScans] = useState<Scan[]>([]);
  const [targets, setTargets] = useState<Target[]>([]);
  const [loading, setLoading] = useState(true);
  const [selectedTarget, setSelectedTarget] = useState('');
  const [cancelId, setCancelId] = useState<string | null>(null);
  const [isLive, setIsLive] = useState(false);
  const { addToast } = useToast();
  const intervalRef = useRef<ReturnType<typeof setInterval> | null>(null);

  const load = useCallback(async () => {
    try {
      const [s, t] = await Promise.all([api.listScans(), api.listTargets()]);
      setScans(s.items);
      setTargets(t);
      return s.items;
    } catch (e) {
      console.error(e);
      return scans;
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => { load(); }, []);

  // Auto-refresh when scans are running
  useEffect(() => {
    const hasRunning = scans.some(s => s.status === 'running');
    setIsLive(hasRunning);

    if (hasRunning && !intervalRef.current) {
      intervalRef.current = setInterval(async () => {
        const updated = await load();
        const stillRunning = updated.some((s: Scan) => s.status === 'running');
        if (!stillRunning && intervalRef.current) {
          clearInterval(intervalRef.current);
          intervalRef.current = null;
          setIsLive(false);
        }
      }, 5000);
    }

    if (!hasRunning && intervalRef.current) {
      clearInterval(intervalRef.current);
      intervalRef.current = null;
    }

    return () => {
      if (intervalRef.current) {
        clearInterval(intervalRef.current);
        intervalRef.current = null;
      }
    };
  }, [scans]);

  const handleStartScan = async () => {
    if (!selectedTarget) return;
    try {
      await api.createScan(selectedTarget);
      addToast('Scan started', 'success');
      load();
    } catch (e: any) {
      addToast(e.message || 'Failed to start scan', 'error');
    }
  };

  const handleCancel = async () => {
    if (!cancelId) return;
    try {
      await api.cancelScan(cancelId);
      addToast('Scan cancelled', 'success');
      load();
    } catch (e: any) {
      addToast(e.message || 'Failed to cancel scan', 'error');
    } finally {
      setCancelId(null);
    }
  };

  if (loading) return <Spinner />;

  return (
    <div>
      <div className="flex items-center justify-between mb-6">
        <div className="flex items-center gap-3">
          <h1 className="text-2xl font-bold">Scans</h1>
          {isLive && (
            <span className="flex items-center gap-1.5 text-xs text-green-600 bg-green-50 px-2 py-1 rounded-full">
              <span className="w-2 h-2 bg-green-500 rounded-full animate-pulse" />
              Live
            </span>
          )}
        </div>
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
        {scans.length === 0 ? (
          <EmptyState
            icon="🔍"
            title="No scans yet"
            description="Select a target and start your first vulnerability scan"
          />
        ) : (
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
                        onClick={() => setCancelId(scan.id)}
                        className="text-red-500 hover:underline"
                      >
                        Cancel
                      </button>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>

      <ConfirmDialog
        open={cancelId !== null}
        title="Cancel Scan"
        message="Are you sure you want to cancel this running scan?"
        confirmLabel="Cancel Scan"
        danger
        onConfirm={handleCancel}
        onCancel={() => setCancelId(null)}
      />
    </div>
  );
}
