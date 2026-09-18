import { BrowserRouter, Routes, Route, Link, useLocation } from 'react-router-dom';
import { ToastProvider } from './components/Toast';
import Dashboard from './pages/Dashboard';
import Targets from './pages/Targets';
import Scans from './pages/Scans';
import ScanDetail from './pages/ScanDetail';
import Findings from './pages/Findings';

const NAV_ITEMS = [
  { to: '/', label: 'Dashboard' },
  { to: '/targets', label: 'Targets' },
  { to: '/scans', label: 'Scans' },
  { to: '/findings', label: 'Findings' },
];

function Navbar() {
  const location = useLocation();
  const isActive = (path: string) => {
    if (path === '/') return location.pathname === '/';
    return location.pathname.startsWith(path);
  };

  return (
    <nav className="bg-gray-900 text-white px-6 py-3 flex items-center gap-6">
      <Link to="/" className="font-bold text-lg">VulnScanner</Link>
      {NAV_ITEMS.map(item => (
        <Link
          key={item.to}
          to={item.to}
          className={`relative py-1 transition-colors ${
            isActive(item.to)
              ? 'text-white font-semibold'
              : 'text-gray-400 hover:text-white'
          }`}
        >
          {item.label}
          {isActive(item.to) && (
            <span className="absolute bottom-0 left-0 right-0 h-0.5 bg-blue-400 rounded-full" />
          )}
        </Link>
      ))}
    </nav>
  );
}

function Footer() {
  return (
    <footer className="bg-gray-900 text-gray-400 text-center py-4 text-sm">
      Designed and built with love by{' '}
      <a
        href="https://github.com/bash-cyber"
        target="_blank"
        rel="noreferrer"
        className="text-white hover:underline"
      >
        Abdulrasaq Bashirat @bash-cyber
      </a>
    </footer>
  );
}

export default function App() {
  return (
    <BrowserRouter>
      <ToastProvider>
        <div className="min-h-screen bg-gray-50 flex flex-col">
          <Navbar />
          <main className="max-w-7xl mx-auto p-6 flex-1 w-full">
            <Routes>
              <Route path="/" element={<Dashboard />} />
              <Route path="/targets" element={<Targets />} />
              <Route path="/scans" element={<Scans />} />
              <Route path="/scans/:id" element={<ScanDetail />} />
              <Route path="/findings" element={<Findings />} />
            </Routes>
          </main>
          <Footer />
        </div>
      </ToastProvider>
    </BrowserRouter>
  );
}
