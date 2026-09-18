import { useEffect, useState, useRef, useCallback } from 'react';
import { Link } from 'react-router-dom';
import { api, Scan, Target } from '../api';
import { StatusBadge } from '../components/Badges';
import Spinner from '../components/Spinner';
import EmptyState from '../components/EmptyState';
import ConfirmDialog from '../components/ConfirmDialog';
import { useToast } from '../components/Toast';

const DETECTOR_OPTIONS = [
  { value: 'sql_injection', label: 'SQL Injection' },
  { value: 'xss_reflected', label: 'Reflected XSS' },
  { value: 'xss_stored', label: 'Stored XSS' },
  { value: 'csrf', label: 'CSRF' },
  { value: 'access_control', label: 'Access Control' },
  { value: 'security_headers', label: 'Security Headers' },
  { value: 'information_disclosure', label: 'Information Disclosure' },
];

interface ScanForm {
  targetId: string;
  crawlDepth: number;
  requestRate: number;
  seedUrls: string;
  enabledDetectors: string[];
}

export default function Scans() {
  const [scans, setScans] = useState<Scan[]>([]);
  const [targets, setTargets] = useState<Target[]>([]);
  const [loading, setLoading] = useState(true);
  const [showConfig, setShowConfig] = useState(false);
  const [form, setForm] = useState<ScanForm>({
    targetId: '',
    crawlDepth: 3,
    requestRate: 5,
    seedUrls: '',
    enabledDetectors: DETECTOR_OPTIONS.map(d => d.value),
  });
  const [cancelId, setCancelId] = useState<string | null>(null);
  const [isLive, setIsLive] = useState(false);
  const [progressScan, setProgressScan] = useState<Scan | null>(null);
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
    const runningScans = scans.filter(s => s.status === 'running');
    const hasRunning = runningScans.length > 0;
    setIsLive(hasRunning);

    // Show progress panel for the first running scan
    if (runningScans.length > 0) {
      setProgressScan(runningScans[0]);
    } else {
      setProgressScan(null);
    }

    if (hasRunning && !intervalRef.current) {
      intervalRef.current = setInterval(async () => {
        const updated = await load();
        const stillRunning = updated.some((s: Scan) => s.status === 'running');
        if (!stillRunning && intervalRef.current) {
          clearInterval(intervalRef.current);
          intervalRef.current = null;
          setIsLive(false);
        }
      }, 3000);
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
    if (!form.targetId) return;
    try {
      // Update target's scan_config before starting scan
      const seedUrlsList = form.seedUrls
        .split('\n')
        .map(u => u.trim())
        .filter(u => u.length > 0);

      await api.updateTarget(form.targetId, {
        scan_config: {
          crawl_depth: form.crawlDepth,
          request_rate: form.requestRate,
          enabled_detectors: form.enabledDetectors,
          seed_urls: seedUrlsList,
        },
      });

      await api.createScan(form.targetId);
      addToast('Scan started', 'success');
      setShowConfig(false);
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

  const toggleDetector = (det: string) => {
    setForm(prev => ({
      ...prev,
      enabledDetectors: prev.enabledDetectors.includes(det)
        ? prev.enabledDetectors.filter(d => d !== det)
        : [...prev.enabledDetectors, det],
    }));
  };

  const selectAllDetectors = () => setForm(prev => ({ ...prev, enabledDetectors: DETECTOR_OPTIONS.map(d => d.value) }));
  const clearAllDetectors = () => setForm(prev => ({ ...prev, enabledDetectors: [] }));

  if (loading) return <Spinner />;

  const completedScans = scans.filter(s => s.status === 'completed');
  const failedScans = scans.filter(s => s.status === 'failed');
  const runningScans = scans.filter(s => s.status === 'running');

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
        <button
          onClick={() => setShowConfig(!showConfig)}
          className="bg-green-600 text-white px-4 py-2 rounded hover:bg-green-700"
        >
          {showConfig ? 'Cancel' : '+ New Scan'}
        </button>
      </div>

      {/* Scan Config Panel */}
      {showConfig && (
        <div className="bg-white rounded-lg shadow p-6 mb-6 animate-fade-in">
          <h2 className="text-lg font-semibold mb-4">Configure Scan</h2>
          <div className="grid grid-cols-2 gap-4 mb-4">
            <div>
              <label className="block text-sm font-medium text-gray-700">Target</label>
              <select
                value={form.targetId}
                onChange={e => setForm({ ...form, targetId: e.target.value })}
                className="mt-1 block w-full border rounded-md px-3 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-blue-500"
              >
                <option value="">Select target...</option>
                {targets.map(t => (
                  <option key={t.id} value={t.id}>{t.name} ({t.base_url})</option>
                ))}
              </select>
            </div>
            <div>
              <label className="block text-sm font-medium text-gray-700">Crawl Depth</label>
              <input
                type="number"
                min={0}
                max={25}
                value={form.crawlDepth}
                onChange={e => setForm({ ...form, crawlDepth: Number(e.target.value) })}
                className="mt-1 block w-full border rounded-md px-3 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-blue-500"
              />
              <p className="text-xs text-gray-400 mt-1">How many levels deep to crawl (0-25)</p>
            </div>
            <div>
              <label className="block text-sm font-medium text-gray-700">Request Rate (req/s)</label>
              <input
                type="number"
                min={0.1}
                max={50}
                step={0.5}
                value={form.requestRate}
                onChange={e => setForm({ ...form, requestRate: Number(e.target.value) })}
                className="mt-1 block w-full border rounded-md px-3 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-blue-500"
              />
              <p className="text-xs text-gray-400 mt-1">Max requests per second</p>
            </div>
            <div>
              <label className="block text-sm font-medium text-gray-700">Seed URLs</label>
              <textarea
                value={form.seedUrls}
                onChange={e => setForm({ ...form, seedUrls: e.target.value })}
                className="mt-1 block w-full border rounded-md px-3 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-blue-500"
                rows={2}
                placeholder="One URL per line (for SPAs)"
              />
              <p className="text-xs text-gray-400 mt-1">Additional URLs to probe beyond crawler discovery</p>
            </div>
          </div>

          <div className="mb-4">
            <div className="flex items-center justify-between mb-2">
              <label className="text-sm font-medium text-gray-700">Detectors</label>
              <div className="flex gap-2">
                <button type="button" onClick={selectAllDetectors} className="text-xs text-blue-500 hover:underline">Select All</button>
                <button type="button" onClick={clearAllDetectors} className="text-xs text-gray-500 hover:underline">Clear All</button>
              </div>
            </div>
            <div className="flex flex-wrap gap-2">
              {DETECTOR_OPTIONS.map(det => (
                <button
                  key={det.value}
                  type="button"
                  onClick={() => toggleDetector(det.value)}
                  className={`px-3 py-1 rounded-full text-xs font-medium border transition-colors ${
                    form.enabledDetectors.includes(det.value)
                      ? 'bg-blue-100 border-blue-300 text-blue-700'
                      : 'bg-gray-50 border-gray-200 text-gray-500 hover:bg-gray-100'
                  }`}
                >
                  {det.label}
                </button>
              ))}
            </div>
            <p className="text-xs text-gray-400 mt-1">
              {form.enabledDetectors.length === 0
                ? 'All detectors will run (empty = all)'
                : `${form.enabledDetectors.length} of ${DETECTOR_OPTIONS.length} selected`}
            </p>
          </div>

          <button
            onClick={handleStartScan}
            disabled={!form.targetId}
            className="bg-green-600 text-white px-4 py-2 rounded hover:bg-green-700 disabled:opacity-50"
          >
            Start Scan
          </button>
        </div>
      )}

      {/* Live Progress Panel */}
      {progressScan && (
        <div className="bg-blue-50 border border-blue-200 rounded-lg p-4 mb-6 animate-fade-in">
          <div className="flex items-center justify-between mb-3">
            <div className="flex items-center gap-2">
              <span className="w-2 h-2 bg-blue-500 rounded-full animate-pulse" />
              <h3 className="font-semibold text-blue-900">Scan in Progress</h3>
            </div>
            <button
              onClick={() => setCancelId(progressScan.id)}
              className="text-red-500 hover:underline text-sm"
            >
              Cancel
            </button>
          </div>
          <div className="grid grid-cols-3 gap-4">
            <div>
              <div className="text-xs text-blue-600 uppercase tracking-wide">URLs Crawled</div>
              <div className="text-2xl font-bold text-blue-900">{progressScan.urls_crawled}</div>
            </div>
            <div>
              <div className="text-xs text-blue-600 uppercase tracking-wide">Requests Sent</div>
              <div className="text-2xl font-bold text-blue-900">{progressScan.requests_sent}</div>
            </div>
            <div>
              <div className="text-xs text-blue-600 uppercase tracking-wide">Elapsed</div>
              <div className="text-2xl font-bold text-blue-900">
                {progressScan.started_at
                  ? formatDuration(Date.now() - new Date(progressScan.started_at).getTime())
                  : '-'}
              </div>
            </div>
          </div>
        </div>
      )}

      {/* Summary Stats */}
      <div className="grid grid-cols-4 gap-3 mb-6">
        <div className="bg-white rounded-lg shadow p-3 text-center">
          <div className="text-xl font-bold">{scans.length}</div>
          <div className="text-xs text-gray-500">Total</div>
        </div>
        <div className="bg-white rounded-lg shadow p-3 text-center">
          <div className="text-xl font-bold text-green-600">{completedScans.length}</div>
          <div className="text-xs text-gray-500">Completed</div>
        </div>
        <div className="bg-white rounded-lg shadow p-3 text-center">
          <div className="text-xl font-bold text-blue-600">{runningScans.length}</div>
          <div className="text-xs text-gray-500">Running</div>
        </div>
        <div className="bg-white rounded-lg shadow p-3 text-center">
          <div className="text-xl font-bold text-red-600">{failedScans.length}</div>
          <div className="text-xs text-gray-500">Failed</div>
        </div>
      </div>

      <div className="bg-white rounded-lg shadow overflow-hidden">
        {scans.length === 0 ? (
          <EmptyState
            icon="🔍"
            title="No scans yet"
            description="Click 'New Scan' to start your first vulnerability scan"
          />
        ) : (
          <table className="w-full text-sm">
            <thead className="bg-gray-50">
              <tr>
                <th className="px-4 py-3 text-left">Status</th>
                <th className="px-4 py-3 text-left">URLs Crawled</th>
                <th className="px-4 py-3 text-left">Requests Sent</th>
                <th className="px-4 py-3 text-left">Duration</th>
                <th className="px-4 py-3 text-left">Started</th>
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
                    {scan.duration_seconds != null
                      ? formatDuration(scan.duration_seconds * 1000)
                      : scan.status === 'running' && scan.started_at
                        ? formatDuration(Date.now() - new Date(scan.started_at).getTime())
                        : '-'}
                  </td>
                  <td className="px-4 py-3 text-gray-500">
                    {scan.started_at ? new Date(scan.started_at).toLocaleString() : '-'}
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

function formatDuration(ms: number): string {
  const seconds = Math.floor(ms / 1000);
  if (seconds < 60) return `${seconds}s`;
  const minutes = Math.floor(seconds / 60);
  const remaining = seconds % 60;
  if (minutes < 60) return `${minutes}m ${remaining}s`;
  const hours = Math.floor(minutes / 60);
  const remainingMin = minutes % 60;
  return `${hours}h ${remainingMin}m`;
}
