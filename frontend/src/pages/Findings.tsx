import { useEffect, useState } from 'react';
import { api, Finding, FindingDetail } from '../api';
import { SeverityBadge, StatusBadge } from '../components/Badges';
import { ScoreBar } from '../components/Badges';
import Spinner from '../components/Spinner';
import EmptyState from '../components/EmptyState';
import { useToast } from '../components/Toast';

export default function Findings() {
  const [findings, setFindings] = useState<Finding[]>([]);
  const [loading, setLoading] = useState(true);
  const [severityFilter, setSeverityFilter] = useState('');
  const [statusFilter, setStatusFilter] = useState('');
  const [selectedFinding, setSelectedFinding] = useState<FindingDetail | null>(null);
  const { addToast } = useToast();

  useEffect(() => {
    loadFindings();
  }, [severityFilter, statusFilter]);

  const loadFindings = async () => {
    setLoading(true);
    try {
      const scansResp = await api.listScans();
      const allFindings: Finding[] = [];
      for (const scan of scansResp.items) {
        const params: { severity?: string; status?: string } = {};
        if (severityFilter) params.severity = severityFilter;
        if (statusFilter) params.status = statusFilter;
        const f = await api.listScanFindings(scan.id, params);
        allFindings.push(...f.items);
      }
      setFindings(allFindings);
    } catch (e) {
      console.error(e);
    } finally {
      setLoading(false);
    }
  };

  const handleViewDetail = async (id: string) => {
    try {
      const detail = await api.getFinding(id);
      setSelectedFinding(detail);
    } catch (e) {
      console.error(e);
    }
  };

  const handleStatusChange = async (id: string, status: string) => {
    try {
      await api.updateFindingStatus(id, status);
      addToast(`Status updated to ${status.replace('_', ' ')}`, 'success');
      loadFindings();
      setSelectedFinding(null);
    } catch (e: any) {
      addToast(e.message || 'Failed to update status', 'error');
    }
  };

  if (loading && findings.length === 0) return <Spinner />;

  return (
    <div>
      <h1 className="text-2xl font-bold mb-6">Findings</h1>

      <div className="flex gap-4 mb-6">
        <select
          value={severityFilter}
          onChange={e => setSeverityFilter(e.target.value)}
          className="border rounded px-3 py-2 text-sm"
        >
          <option value="">All Severities</option>
          <option value="critical">Critical</option>
          <option value="high">High</option>
          <option value="medium">Medium</option>
          <option value="low">Low</option>
          <option value="informational">Informational</option>
        </select>
        <select
          value={statusFilter}
          onChange={e => setStatusFilter(e.target.value)}
          className="border rounded px-3 py-2 text-sm"
        >
          <option value="">All Statuses</option>
          <option value="open">Open</option>
          <option value="confirmed">Confirmed</option>
          <option value="false_positive">False Positive</option>
          <option value="resolved">Resolved</option>
          <option value="accepted_risk">Accepted Risk</option>
        </select>
      </div>

      <div className="bg-white rounded-lg shadow overflow-hidden">
        {findings.length === 0 && !loading ? (
          <EmptyState
            icon="🛡️"
            title="No findings"
            description={severityFilter || statusFilter ? 'Try adjusting your filters' : 'Run a scan to discover vulnerabilities'}
          />
        ) : (
          <table className="w-full text-sm">
            <thead className="bg-gray-50">
              <tr>
                <th className="px-4 py-3 text-left">Rank</th>
                <th className="px-4 py-3 text-left">Severity</th>
                <th className="px-4 py-3 text-left">Title</th>
                <th className="px-4 py-3 text-left">URL</th>
                <th className="px-4 py-3 text-left">Risk Score</th>
                <th className="px-4 py-3 text-left">Status</th>
                <th className="px-4 py-3 text-right">Actions</th>
              </tr>
            </thead>
            <tbody>
              {findings.map(f => (
                <tr key={f.id} className="border-t hover:bg-gray-50">
                  <td className="px-4 py-2">{f.priority_rank || '-'}</td>
                  <td className="px-4 py-2"><SeverityBadge severity={f.severity} /></td>
                  <td className="px-4 py-2 font-medium">{f.title}</td>
                  <td className="px-4 py-2 text-gray-600 max-w-xs truncate">{f.url}</td>
                  <td className="px-4 py-2">
                    <ScoreBar score={f.risk_score || 0} />
                  </td>
                  <td className="px-4 py-2"><StatusBadge status={f.status} /></td>
                  <td className="px-4 py-2 text-right">
                    <button
                      onClick={() => handleViewDetail(f.id)}
                      className="text-blue-500 hover:underline"
                    >
                      Details
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>

      {selectedFinding && (
        <div
          className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center p-4 z-50"
          onClick={() => setSelectedFinding(null)}
        >
          <div
            className="bg-white rounded-lg shadow-xl max-w-2xl w-full max-h-[90vh] overflow-y-auto animate-fade-in"
            onClick={e => e.stopPropagation()}
          >
            <div className="px-6 py-4 border-b flex items-center justify-between">
              <h2 className="text-lg font-semibold">{selectedFinding.title}</h2>
              <button onClick={() => setSelectedFinding(null)} className="text-gray-400 hover:text-gray-600 text-xl">&times;</button>
            </div>
            <div className="p-6 space-y-4">
              <div className="grid grid-cols-2 gap-4">
                <div>
                  <span className="text-sm text-gray-500">Severity</span>
                  <div><SeverityBadge severity={selectedFinding.severity} /></div>
                </div>
                <div>
                  <span className="text-sm text-gray-500">Risk Score</span>
                  <div><ScoreBar score={selectedFinding.risk_score || 0} /></div>
                </div>
                <div>
                  <span className="text-sm text-gray-500">URL</span>
                  <div className="text-sm break-all">{selectedFinding.url}</div>
                </div>
                <div>
                  <span className="text-sm text-gray-500">Parameter</span>
                  <div className="text-sm">{selectedFinding.parameter || '-'}</div>
                </div>
                <div>
                  <span className="text-sm text-gray-500">Detector</span>
                  <div className="text-sm">{selectedFinding.detector_name}</div>
                </div>
                <div>
                  <span className="text-sm text-gray-500">Status</span>
                  <div><StatusBadge status={selectedFinding.status} /></div>
                </div>
              </div>

              <div>
                <span className="text-sm text-gray-500">Description</span>
                <p className="text-sm mt-1">{selectedFinding.description}</p>
              </div>

              {selectedFinding.remediation && (
                <div>
                  <span className="text-sm text-gray-500">Remediation</span>
                  <p className="text-sm mt-1">{selectedFinding.remediation}</p>
                </div>
              )}

              {selectedFinding.risk_breakdowns.length > 0 && (
                <div>
                  <span className="text-sm text-gray-500">Risk Breakdown</span>
                  <table className="w-full text-sm mt-1">
                    <thead>
                      <tr className="text-left text-gray-500 border-b">
                        <th className="pb-1">Factor</th>
                        <th className="pb-1">Raw</th>
                        <th className="pb-1">Weight</th>
                        <th className="pb-1">Contribution</th>
                      </tr>
                    </thead>
                    <tbody>
                      {selectedFinding.risk_breakdowns.map(b => (
                        <tr key={b.id} className="border-b">
                          <td className="py-1">{b.factor_name.replace('_', ' ')}</td>
                          <td className="py-1">{b.raw_value.toFixed(2)}</td>
                          <td className="py-1">{b.weight.toFixed(2)}</td>
                          <td className="py-1">{b.contribution.toFixed(1)}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              )}

              <div className="flex gap-2 pt-4 border-t">
                <span className="text-sm text-gray-500">Update Status:</span>
                {['open', 'confirmed', 'false_positive', 'resolved', 'accepted_risk'].map(s => (
                  <button
                    key={s}
                    onClick={() => handleStatusChange(selectedFinding.id, s)}
                    className={`text-xs px-2 py-1 rounded border ${selectedFinding.status === s ? 'bg-gray-200' : 'hover:bg-gray-100'}`}
                  >
                    {s.replace('_', ' ')}
                  </button>
                ))}
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
