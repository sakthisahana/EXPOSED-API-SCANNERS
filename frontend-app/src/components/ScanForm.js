import React, { useState } from 'react';
import axios from 'axios';
import './ScanForm.css';

const API_URL = 'http://localhost:8000';

function ScanForm({ onScanComplete, isScanning, setIsScanning }) {
  const [repoUrl, setRepoUrl] = useState('');
  const [validationResult, setValidationResult] = useState(null);
  const [error, setError] = useState(null);

  const handleValidate = async () => {
    setError(null);
    setValidationResult(null);

    if (!repoUrl.trim()) {
      setError('Please enter a repository URL');
      return;
    }

    try {
      const response = await axios.post(`${API_URL}/api/validate-repository`, {
        repository_url: repoUrl
      });
      setValidationResult(response.data);
    } catch (err) {
      setError(err.response?.data?.detail || 'Error validating repository');
    }
  };

  const handleScan = async () => {
    setError(null);
    setIsScanning(true);

    try {
      const response = await axios.post(`${API_URL}/api/scan`, {
        repository_url: repoUrl
      });
      onScanComplete(response.data);
    } catch (err) {
      setError(err.response?.data?.detail || 'Error scanning repository');
    } finally {
      setIsScanning(false);
    }
  };

  return (
    <div className="scan-form-container">
      <div className="scan-form-card">
        {/* Header */}
        <div className="form-header">
          <h2 className="form-title">
            Scan GitHub Repository
          </h2>
          <p className="form-subtitle">
            Enter a public GitHub repository URL to scan for exposed API keys and secrets
          </p>
        </div>

        {/* Input Section */}
        <div className="input-section">
          <label className="input-label">
            Repository URL
          </label>
          <div className="input-wrapper">
            <input
              type="text"
              value={repoUrl}
              onChange={(e) => setRepoUrl(e.target.value)}
              placeholder="https://github.com/owner/repository"
              className="url-input"
              disabled={isScanning}
            />
            <button
              onClick={handleValidate}
              disabled={isScanning}
              className="validate-button"
            >
              Validate
            </button>
          </div>
          <p className="url-helper">
            Example: https://github.com/username/repo-name
          </p>

          {/* Error Display */}
          {error && (
            <div className="error-alert">
              <div style={{display: 'flex', alignItems: 'flex-start'}}>
                <svg className="error-icon" fill="currentColor" viewBox="0 0 20 20">
                  <path fillRule="evenodd" d="M10 18a8 8 0 100-16 8 8 0 000 16zM8.707 7.293a1 1 0 00-1.414 1.414L8.586 10l-1.293 1.293a1 1 0 101.414 1.414L10 11.414l1.293 1.293a1 1 0 001.414-1.414L11.414 10l1.293-1.293a1 1 0 00-1.414-1.414L10 8.586 8.707 7.293z" clipRule="evenodd" />
                </svg>
                <div style={{flex: 1, marginLeft: '0.8rem'}}>
                  <h4 className="error-title">Error</h4>
                  <p className="error-message">{error}</p>
                </div>
              </div>
            </div>
          )}

          {/* Validation Result - Success */}
          {validationResult && validationResult.scan_allowed && (
            <div className="validation-success">
              <div style={{display: 'flex', alignItems: 'flex-start'}}>
                <svg className="success-icon" fill="currentColor" viewBox="0 0 20 20">
                  <path fillRule="evenodd" d="M10 18a8 8 0 100-16 8 8 0 000 16zm3.707-9.293a1 1 0 00-1.414-1.414L9 10.586 7.707 9.293a1 1 0 00-1.414 1.414l2 2a1 1 0 001.414 0l4-4z" clipRule="evenodd" />
                </svg>
                <div style={{flex: 1, marginLeft: '0.8rem'}}>
                  <h4 className="validation-title-success">
                    Repository Validated
                  </h4>
                  <div className="validation-info">
                    <div className="validation-info-item">
                      <p className="validation-info-label">Owner</p>
                      <p className="validation-info-value">{validationResult.owner}</p>
                    </div>
                    <div className="validation-info-item">
                      <p className="validation-info-label">Repository</p>
                      <p className="validation-info-value">{validationResult.repo_name}</p>
                    </div>
                    <div className="validation-info-item">
                      <p className="validation-info-label">Visibility</p>
                      <p className="validation-info-value">
                        {validationResult.is_public ? 'Public ✓' : 'Private ✗'}
                      </p>
                    </div>
                    <div className="validation-info-item">
                      <p className="validation-info-label">Language</p>
                      <p className="validation-info-value">{validationResult.language}</p>
                    </div>
                    {validationResult.description && (
                      <div className="validation-info-item" style={{gridColumn: '1 / -1'}}>
                        <p className="validation-info-label">Description</p>
                        <p className="validation-info-value">{validationResult.description}</p>
                      </div>
                    )}
                    <div className="validation-info-item" style={{gridColumn: '1 / -1'}}>
                      <p className="validation-info-label">Scan Allowed</p>
                      <p className="validation-status-allowed">
                        {validationResult.scan_allowed ? 'YES ✓' : 'NO - Repository is private'}
                      </p>
                    </div>
                  </div>
                </div>
              </div>
            </div>
          )}

          {/* Validation Result - Warning (Private Repo) */}
          {validationResult && !validationResult.scan_allowed && (
            <div className="validation-warning">
              <div style={{display: 'flex', alignItems: 'flex-start'}}>
                <svg className="warning-icon" fill="currentColor" viewBox="0 0 20 20">
                  <path fillRule="evenodd" d="M8.257 3.099c.765-1.36 2.722-1.36 3.486 0l5.58 9.92c.75 1.334-.213 2.98-1.742 2.98H4.42c-1.53 0-2.493-1.646-1.743-2.98l5.58-9.92zM11 13a1 1 0 11-2 0 1 1 0 012 0zm-1-8a1 1 0 00-1 1v3a1 1 0 002 0V6a1 1 0 00-1-1z" clipRule="evenodd" />
                </svg>
                <div style={{flex: 1, marginLeft: '0.8rem'}}>
                  <h4 className="validation-title-warning">
                    Repository Validated - Cannot Scan
                  </h4>
                  <div className="validation-info">
                    <div className="validation-info-item">
                      <p className="validation-info-label">Owner</p>
                      <p className="validation-info-value">{validationResult.owner}</p>
                    </div>
                    <div className="validation-info-item">
                      <p className="validation-info-label">Repository</p>
                      <p className="validation-info-value">{validationResult.repo_name}</p>
                    </div>
                    <div className="validation-info-item" style={{gridColumn: '1 / -1'}}>
                      <p className="validation-info-label">Scan Allowed</p>
                      <p className="validation-status-denied">
                        NO - Repository is private. Only public repositories can be scanned.
                      </p>
                    </div>
                  </div>
                </div>
              </div>
            </div>
          )}

          {/* Scan Button */}
          <div className="scan-button-wrapper">
            <button
              onClick={handleScan}
              disabled={!validationResult?.scan_allowed || isScanning}
              className="scan-button"
            >
              <span className="scan-button-content">
                {isScanning ? (
                  <>
                    <svg className="spinner" fill="none" viewBox="0 0 24 24">
                      <circle style={{opacity: 0.25}} cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4"></circle>
                      <path style={{opacity: 0.75}} fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"></path>
                    </svg>
                    Scanning Repository...
                  </>
                ) : (
                  'Start Security Scan'
                )}
              </span>
            </button>
          </div>
        </div>

        {/* Information Box */}
        <div className="info-box">
          <h4 className="info-title">What this scanner does:</h4>
          <ul className="info-list">
            <li className="info-list-item">Validates repository visibility (public only)</li>
            <li className="info-list-item">Scans source code for exposed API keys and secrets</li>
            <li className="info-list-item">Calculates risk scores based on ISM principles</li>
            <li className="info-list-item">Uses AI to predict exploitation likelihood</li>
            <li className="info-list-item">Provides mitigation recommendations</li>
            <li className="info-list-item">Maps findings to compliance frameworks (ISO, GDPR, PCI-DSS)</li>
          </ul>
        </div>

        {/* Example Section */}
        <div className="example-section">
          <h4 className="example-title">Example test repositories:</h4>
          <ul className="example-list">
            <li className="example-item">Create your own test repo with dummy API keys</li>
            <li className="example-item">Use format: sk_test_[random24chars] for Stripe test keys</li>
            <li className="example-item">Add keys in config files, .env files, or source code</li>
          </ul>
        </div>
      </div>
    </div>
  );
}

export default ScanForm;