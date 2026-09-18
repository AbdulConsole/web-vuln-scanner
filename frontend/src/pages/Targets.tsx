import { useEffect, useState } from 'react';
import { api, Target } from '../api';
import Spinner from '../components/Spinner';
import EmptyState from '../components/EmptyState';
import ConfirmDialog from '../components/ConfirmDialog';
import { useToast } from '../components/Toast';

export default function Targets() {
  const [targets, setTargets] = useState<Target[]>([]);
  const [loading, setLoading] = useState(true);
  const [showCreate, setShowCreate] = useState(false);
  const [form, setForm] = useState({ name: '', base_url: '' });
  const [error, setError] = useState('');
  const [deleteId, setDeleteId] = useState<string | null>(null);
  const { addToast } = useToast();

  const load = async () => {
    try {
      setTargets(await api.listTargets());
    } catch (e) {
      console.error(e);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => { load(); }, []);

  const handleCreate = async (e: React.FormEvent) => {
    e.preventDefault();
    setError('');
    try {
      await api.createTarget(form);
      setShowCreate(false);
      setForm({ name: '', base_url: '' });
      addToast('Target created successfully', 'success');
      load();
    } catch (err: any) {
      const msg = err.message || 'Failed to create target';
      setError(msg);
      addToast(msg, 'error');
    }
  };

  const handleDelete = async () => {
    if (!deleteId) return;
    try {
      await api.deleteTarget(deleteId);
      addToast('Target deleted', 'success');
      load();
    } catch (err: any) {
      addToast(err.message || 'Failed to delete target', 'error');
    } finally {
      setDeleteId(null);
    }
  };

  if (loading) return <Spinner />;

  return (
    <div>
      <div className="flex items-center justify-between mb-6">
        <h1 className="text-2xl font-bold">Targets</h1>
        <button
          onClick={() => setShowCreate(true)}
          className="bg-blue-600 text-white px-4 py-2 rounded hover:bg-blue-700"
        >
          + New Target
        </button>
      </div>

      {showCreate && (
        <div className="bg-white rounded-lg shadow p-6 mb-6 animate-fade-in">
          <h2 className="text-lg font-semibold mb-4">Create Target</h2>
          {error && <div className="text-red-500 text-sm mb-4">{error}</div>}
          <form onSubmit={handleCreate} className="space-y-4">
            <div>
              <label className="block text-sm font-medium text-gray-700">Name</label>
              <input
                type="text"
                value={form.name}
                onChange={e => setForm({ ...form, name: e.target.value })}
                className="mt-1 block w-full border rounded-md px-3 py-2 focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-transparent"
                required
              />
            </div>
            <div>
              <label className="block text-sm font-medium text-gray-700">Base URL</label>
              <input
                type="url"
                value={form.base_url}
                onChange={e => setForm({ ...form, base_url: e.target.value })}
                className="mt-1 block w-full border rounded-md px-3 py-2 focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-transparent"
                placeholder="http://example.com"
                required
              />
            </div>
            <div className="flex gap-2">
              <button type="submit" className="bg-green-600 text-white px-4 py-2 rounded hover:bg-green-700">
                Create
              </button>
              <button type="button" onClick={() => setShowCreate(false)} className="bg-gray-200 px-4 py-2 rounded hover:bg-gray-300">
                Cancel
              </button>
            </div>
          </form>
        </div>
      )}

      <div className="bg-white rounded-lg shadow overflow-hidden">
        {targets.length === 0 ? (
          <EmptyState
            icon="🎯"
            title="No targets yet"
            description="Add a target URL to start scanning for vulnerabilities"
            action={
              <button
                onClick={() => setShowCreate(true)}
                className="bg-blue-600 text-white px-4 py-2 rounded hover:bg-blue-700 text-sm"
              >
                + New Target
              </button>
            }
          />
        ) : (
          <table className="w-full text-sm">
            <thead className="bg-gray-50">
              <tr>
                <th className="px-4 py-3 text-left">Name</th>
                <th className="px-4 py-3 text-left">Base URL</th>
                <th className="px-4 py-3 text-left">Allowed Domains</th>
                <th className="px-4 py-3 text-left">Auth</th>
                <th className="px-4 py-3 text-left">Created</th>
                <th className="px-4 py-3 text-right">Actions</th>
              </tr>
            </thead>
            <tbody>
              {targets.map(target => (
                <tr key={target.id} className="border-t hover:bg-gray-50">
                  <td className="px-4 py-3 font-medium">{target.name}</td>
                  <td className="px-4 py-3 text-gray-600">{target.base_url}</td>
                  <td className="px-4 py-3 text-gray-600">
                    {target.allowed_domains.length > 0 ? target.allowed_domains.join(', ') : '-'}
                  </td>
                  <td className="px-4 py-3">
                    {target.has_auth_config ? (
                      <span className="text-green-600 text-xs">Configured</span>
                    ) : (
                      <span className="text-gray-400 text-xs">None</span>
                    )}
                  </td>
                  <td className="px-4 py-3 text-gray-500">{new Date(target.created_at).toLocaleDateString()}</td>
                  <td className="px-4 py-3 text-right">
                    <button
                      onClick={() => setDeleteId(target.id)}
                      className="text-red-500 hover:underline text-sm"
                    >
                      Delete
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>

      <ConfirmDialog
        open={deleteId !== null}
        title="Delete Target"
        message="Are you sure you want to delete this target? This action cannot be undone."
        confirmLabel="Delete"
        danger
        onConfirm={handleDelete}
        onCancel={() => setDeleteId(null)}
      />
    </div>
  );
}
