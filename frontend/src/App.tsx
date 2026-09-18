import { BrowserRouter, Routes, Route, Link } from 'react-router-dom';
import Dashboard from './pages/Dashboard';
import Targets from './pages/Targets';
import Scans from './pages/Scans';
import ScanDetail from './pages/ScanDetail';
import Findings from './pages/Findings';

function Navbar() {
  return (
    <nav className="bg-gray-900 text-white px-6 py-3 flex items-center gap-6">
      <Link to="/" className="font-bold text-lg">VulnScanner</Link>
      <Link to="/" className="hover:text-gray-300">Dashboard</Link>
      <Link to="/targets" className="hover:text-gray-300">Targets</Link>
      <Link to="/scans" className="hover:text-gray-300">Scans</Link>
      <Link to="/findings" className="hover:text-gray-300">Findings</Link>
    </nav>
  );
}

function Footer() {
  return (
    <footer className="bg-gray-900 text-gray-400 text-center py-4 text-sm">
      Designed and built by{' '}
      <a
        href="https://github.com/bash-cyber"
        target="_blank"
        rel="noreferrer"
        className="text-white hover:underline"
      >
        Abdulrasaq Bashheerat @bash-cyber
      </a>
    </footer>
  );
}

export default function App() {
  return (
    <BrowserRouter>
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
    </BrowserRouter>
  );
}
