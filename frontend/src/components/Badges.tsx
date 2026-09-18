export function StatusBadge({ status }: { status: string }) {
  const colors: Record<string, string> = {
    queued: 'bg-gray-200 text-gray-700',
    running: 'bg-blue-100 text-blue-700',
    completed: 'bg-green-100 text-green-700',
    failed: 'bg-red-100 text-red-700',
    cancelled: 'bg-yellow-100 text-yellow-700',
    open: 'bg-gray-200 text-gray-700',
    confirmed: 'bg-red-100 text-red-700',
    false_positive: 'bg-gray-100 text-gray-500',
    resolved: 'bg-green-100 text-green-700',
    accepted_risk: 'bg-blue-100 text-blue-700',
  };
  return (
    <span className={`px-2 py-1 rounded text-xs font-medium ${colors[status] || 'bg-gray-100'}`}>
      {status.replace('_', ' ')}
    </span>
  );
}

export function SeverityCard({ severity, count }: { severity: string; count: number }) {
  const bgColors: Record<string, string> = {
    critical: 'bg-red-600 text-white',
    high: 'bg-orange-500 text-white',
    medium: 'bg-yellow-400 text-gray-900',
    low: 'bg-green-500 text-white',
    informational: 'bg-blue-500 text-white',
  };
  return (
    <div className={`rounded-lg p-4 ${bgColors[severity] || 'bg-gray-200'}`}>
      <div className="text-2xl font-bold">{count}</div>
      <div className="text-sm capitalize">{severity}</div>
    </div>
  );
}

export function SeverityBadge({ severity }: { severity: string }) {
  const colors: Record<string, string> = {
    critical: 'bg-red-600 text-white',
    high: 'bg-orange-500 text-white',
    medium: 'bg-yellow-400 text-gray-900',
    low: 'bg-green-500 text-white',
    informational: 'bg-blue-500 text-white',
  };
  return (
    <span className={`px-2 py-1 rounded text-xs font-medium ${colors[severity] || 'bg-gray-200'}`}>
      {severity}
    </span>
  );
}

export function RiskBandBadge({ band }: { band: string }) {
  const colors: Record<string, string> = {
    critical: 'bg-red-600 text-white',
    high: 'bg-orange-500 text-white',
    medium: 'bg-yellow-400 text-gray-900',
    low: 'bg-green-500 text-white',
    informational: 'bg-blue-500 text-white',
  };
  return (
    <span className={`px-2 py-1 rounded text-xs font-medium ${colors[band] || 'bg-gray-200'}`}>
      {band}
    </span>
  );
}

export function ScoreBar({ score }: { score: number }) {
  const color = score >= 80 ? 'bg-red-500' : score >= 60 ? 'bg-orange-500' : score >= 40 ? 'bg-yellow-400' : score >= 20 ? 'bg-green-500' : 'bg-blue-500';
  return (
    <div className="flex items-center gap-2">
      <div className="w-20 bg-gray-200 rounded-full h-2">
        <div className={`h-2 rounded-full ${color}`} style={{ width: `${Math.min(100, score)}%` }} />
      </div>
      <span className="text-sm font-mono">{score.toFixed(1)}</span>
    </div>
  );
}
