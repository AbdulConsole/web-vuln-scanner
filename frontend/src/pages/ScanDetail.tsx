import { useEffect, useState } from 'react';
import { useParams, Link } from 'react-router-dom';
import { api, Scan, Finding, Report } from '../api';
import { StatusBadge, SeverityBadge } from '../components/Badges';
import { RiskBandBadge, ScoreBar } from '../components/Badges';

export default function ScanDetail() {
  const { id } = useParams<{ id: string }>();
  const [scan, setScan] = useState<Scan | null>(null);
  const [findings, setFindings] = useState<Finding[]>([]);
  const [reports, setReports] = useState<Report[]>([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    if (!id) return;
    async function load() {
      try {
        const [s, f, r] = await Promise.all([
          api.getScan(id!),
          api.listScanFindings(id!),
          api.listScanReports(id!),
        ]);
        setScan(s);
        setFindings(f.items);
        setReports(r.items);
      } catch (e) {
        console.error(e);
      } finally {
        setLoading(false);
      }
    }
    load();
  }, [id]);

  const handleGenerateReport = async (format: string) => {
    if (!id) return;
    try {
      await api.createReport(id, format);
      const r = await api.listScanReports(id);
      setReports(r.items);
    } catch (e: any) {
      alert(e.message || 'Failed to generate report');
    }
  };

  if (loading) return <div className="text-center py-8 text-gray-500">Loading...</div>;
  if (!scan) return <div className="text-center py-8 text-red-500">Scan not found</div>;

  return (
    <div>
      <div className="flex items-center gap-2 mb-4 text-sm text-gray-500">
        <Link to="/scans" className="hover:underline">Scans</Link>
        <span>/</span>
        <span>{scan.id.slice(0, 8)}</span>
      </div>

      <div className="flex items-center justify-between mb-6">
        <h1 className="text-2xl font-bold">Scan Details</h1>
        <div className="flex gap-2">
          <button
            onClick={() => handleGenerateReport('json')}
            className="bg-blue-600 text-white px-3 py-1 rounded text-sm hover:bg-blue-700"
          >
            Export JSON
          </button>
          <button
            onClick={() => handleGenerateReport('html')}
            className="bg-blue-600 text-white px-3 py-1 rounded text-sm hover:bg-blue-700"
          >
            Export HTML
          </button>
          <button
            onClick={() => handleGenerateReport('pdf')}
            className="bg-blue-600 text-white px-3 py-1 rounded text-sm hover:bg-blue-700"
          >
            Export PDF
          </button>
        </div>
      </div>

      <div className="grid grid-cols-4 gap-4 mb-8">
        <div className="bg-white rounded-lg shadow p-4">
          <div className="text-sm text-gray-500">Status</div>
          <StatusBadge status={scan.status} />
        </div>
        <div className="bg-white rounded-lg shadow p-4">
          <div className="text-sm text-gray-500">URLs Crawled</div>
          <div className="text-2xl font-bold">{scan.urls_crawled}</div>
        </div>
        <div className="bg-white rounded-lg shadow p-4">
          <div className="text-sm text-gray-500">Requests Sent</div>
          <div className="text-2xl font-bold">{scan.requests_sent}</div>
        </div>
        <div className="bg-white rounded-lg shadow p-4">
          <div className="text-sm text-gray-500">Findings</div>
          <div className="text-2xl font-bold">{findings.length}</div>
        </div>
      </div>

      <div className="bg-white rounded-lg shadow overflow-hidden mb-8">
        <div className="px-4 py-3 bg-gray-50 border-b font-semibold">Findings</div>
        <table className="w-full text-sm">
          <thead>
            <tr className="text-left text-gray-500 border-b">
              <th className="px-4 py-2">#</th>
              <th className="px-4 py-2">Severity</th>
              <th className="px-4 py-2">Title</th>
              <th className="px-4 py-2">URL</th>
              <th className="px-4 py-2">Risk Score</th>
              <th className="px-4 py-2">Band</th>
              <th className="px-4 py-2">Detector</th>
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
                <td className="px-4 py-2">
                  <RiskBandBadge band={f.risk_score !== null ? getRiskBand(f.risk_score) : 'informational'} />
                </td>
                <td className="px-4 py-2 text-gray-500">{f.detector_name}</td>
              </tr>
            ))}
            {findings.length === 0 && (
              <tr><td colSpan={7} className="px-4 py-8 text-center text-gray-400">No findings</td></tr>
            )}
          </tbody>
        </table>
      </div>

      {reports.length > 0 && (
        <div className="bg-white rounded-lg shadow overflow-hidden">
          <div className="px-4 py-3 bg-gray-50 border-b font-semibold">Reports</div>
          <table className="w-full text-sm">
            <thead>
              <tr className="text-left text-gray-500 border-b">
                <th className="px-4 py-2">Format</th>
                <th className="px-4 py-2">Generated</th>
                <th className="px-4 py-2">Download</th>
              </tr>
            </thead>
            <tbody>
              {reports.map(r => (
                <tr key={r.id} className="border-t hover:bg-gray-50">
                  <td className="px-4 py-2 uppercase font-medium">{r.format}</td>
                  <td className="px-4 py-2 text-gray-500">{new Date(r.generated_at).toLocaleString()}</td>
                  <td className="px-4 py-2">
                    <a
                      href={api.downloadReportUrl(r.id)}
                      className="text-blue-500 hover:underline"
                      target="_blank"
                      rel="noreferrer"
                    >
                      Download
                    </a>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}

function getRiskBand(score: number): string {
  if (score >= 80) return 'critical';
  if (score >= 60) return 'high';
  if (score >= 40) return 'medium';
  if (score >= 20) return 'low';
  return 'informational';
}
