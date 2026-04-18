import React, { useState } from 'react';
import './App.css';
import ScanForm from './components/ScanForm';
import ScanResults from './components/ScanResults';
import Dashboard from './components/Dashboard';

function App() {
  const [activeTab, setActiveTab] = useState('scan');
  const [scanResults, setScanResults] = useState(null);
  const [isScanning, setIsScanning] = useState(false);

  const handleScanComplete = (results) => {
    setScanResults(results);
    setActiveTab('results');
  };

  return (
    <div className="app-container">
      {/* Header */}
      <header className="app-header">
        <div className="header-content">
          <div className="header-left">
            <div className="header-icon">🔒</div>
            <div>
              <h1 className="header-title">Risk-Based API Scanner</h1>
              <p className="header-subtitle">
                AI-Driven Risk Prediction & Mitigation
              </p>
            </div>
          </div>
          <div className="header-right">
            <span className="status-badge">
              <span className="status-dot"></span>
              Online
            </span>
          </div>
        </div>
      </header>

      {/* Navigation Tabs */}
      <div className="nav-tabs-container">
        <div className="nav-tabs">
          <button
            onClick={() => setActiveTab('scan')}
            className={`nav-tab ${activeTab === 'scan' ? 'nav-tab-active' : ''}`}
          >
            <svg className="nav-icon" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z" />
            </svg>
            <span className="nav-text">New Scan</span>
          </button>
          
          <button
            onClick={() => setActiveTab('results')}
            className={`nav-tab ${activeTab === 'results' ? 'nav-tab-active' : ''}`}
            disabled={!scanResults}
          >
            <svg className="nav-icon" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 19v-6a2 2 0 00-2-2H5a2 2 0 00-2 2v6a2 2 0 002 2h2a2 2 0 002-2zm0 0V9a2 2 0 012-2h2a2 2 0 012 2v10m-6 0a2 2 0 002 2h2a2 2 0 002-2m0 0V5a2 2 0 012-2h2a2 2 0 012 2v14a2 2 0 01-2 2h-2a2 2 0 01-2-2z" />
            </svg>
            <span className="nav-text">Scan Results</span>
            {scanResults && (
              <span className="results-badge">
                {scanResults.summary.total_secrets}
              </span>
            )}
          </button>

          <button
            onClick={() => setActiveTab('dashboard')}
            className={`nav-tab ${activeTab === 'dashboard' ? 'nav-tab-active' : ''}`}
            disabled={!scanResults}
          >
            <svg className="nav-icon" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M4 5a1 1 0 011-1h14a1 1 0 011 1v2a1 1 0 01-1 1H5a1 1 0 01-1-1V5zM4 13a1 1 0 011-1h6a1 1 0 011 1v6a1 1 0 01-1 1H5a1 1 0 01-1-1v-6zM16 13a1 1 0 011-1h2a1 1 0 011 1v6a1 1 0 01-1 1h-2a1 1 0 01-1-1v-6z" />
            </svg>
            <span className="nav-text">Dashboard</span>
          </button>
        </div>
      </div>

      {/* Main Content */}
      <main className="main-content">
        {activeTab === 'scan' && (
          <ScanForm
            onScanComplete={handleScanComplete}
            isScanning={isScanning}
            setIsScanning={setIsScanning}
          />
        )}

        {activeTab === 'results' && scanResults && (
          <ScanResults results={scanResults} />
        )}

        {activeTab === 'dashboard' && scanResults && (
          <Dashboard results={scanResults} />
        )}

        {activeTab === 'results' && !scanResults && (
          <div className="no-results-container">
            <svg className="no-results-icon" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z" />
            </svg>
            <h3 className="no-results-title">No scan results</h3>
            <p className="no-results-text">Start a new scan to see results here</p>
          </div>
        )}
      </main>

      {/* Footer */}
      <footer className="app-footer">
        <div className="footer-content">
          <p className="footer-text">
            © 2025 Risk-Based API Scanner - Academic Project
          </p>
          <p className="footer-text">
            ISM Project - Milestone 1-4 Implementation
          </p>
        </div>
      </footer>
    </div>
  );
}

export default App;