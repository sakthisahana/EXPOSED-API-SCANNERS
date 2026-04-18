import React, { useState } from 'react';
import './ScanResults.css';

function ScanResults({ results }) {
  const [selectedSecret, setSelectedSecret] = useState(0);

  // No results - clean repository
  if (!results.exposed_secrets || results.exposed_secrets.length === 0) {
    return (
      <div className="scan-results-container">
        <div className="no-results-card">
          <svg className="success-icon-large" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z" />
          </svg>
          <h2 className="no-results-title">No Secrets Found!</h2>
          <p className="no-results-subtitle">
            The repository appears to be clean. No exposed API keys or secrets were detected.
          </p>
          <div className="clean-badge">
            <p className="clean-badge-text">
              ✓ Repository: {results.repository_info.full_name}
            </p>
          </div>
        </div>
      </div>
    );
  }

  const currentSecret = results.exposed_secrets[selectedSecret];
  const currentRisk = results.risk_scores[selectedSecret];

  return (
    <div className="scan-results-container">
      {/* Summary Cards */}
      <div className="summary-cards-grid">
        <div className="summary-card">
          <div className="summary-card-header">
            <div>
              <p className="summary-card-label">Total Secrets</p>
            </div>
            <div className="summary-card-icon icon-blue">
              <span>🔐</span>
            </div>
          </div>
          <p className="summary-card-value value-blue">{results.summary.total_secrets}</p>
        </div>

        <div className="summary-card">
          <div className="summary-card-header">
            <div>
              <p className="summary-card-label">Critical</p>
            </div>
            <div className="summary-card-icon icon-red">
              <span>⚠️</span>
            </div>
          </div>
          <p className="summary-card-value value-red">{results.summary.critical_count}</p>
        </div>

        <div className="summary-card">
          <div className="summary-card-header">
            <div>
              <p className="summary-card-label">High</p>
            </div>
            <div className="summary-card-icon icon-orange">
              <span>🔴</span>
            </div>
          </div>
          <p className="summary-card-value value-orange">{results.summary.high_count}</p>
        </div>

        <div className="summary-card">
          <div className="summary-card-header">
            <div>
              <p className="summary-card-label">Overall Risk</p>
            </div>
          </div>
          <p className="summary-card-value value-gradient">{results.summary.overall_risk}</p>
        </div>
      </div>

      {/* Main Content Grid */}
      <div className="results-grid">
        {/* Secrets List Sidebar */}
        <div className="secrets-list-card">
          <div className="secrets-list-header">
            <h3 className="secrets-list-title">
              Exposed Secrets ({results.exposed_secrets.length})
            </h3>
          </div>
          <div className="secrets-list-body">
            {results.exposed_secrets.map((secret, index) => (
              <div
                key={index}
                onClick={() => setSelectedSecret(index)}
                className={`secret-list-item ${selectedSecret === index ? 'active' : ''}`}
              >
                <div style={{position: 'relative', paddingRight: '80px'}}>
                  <p className="secret-provider-name">
                    {secret.provider}
                    {!secret.is_valid && (
                      <span style={{
                        marginLeft: '8px',
                        fontSize: '0.75rem',
                        color: '#f59e0b',
                        fontWeight: '600'
                      }}>
                        ⚠ Unverified
                      </span>
                    )}
                  </p>
                  <p className="secret-filename">{secret.file_name}</p>
                  <p className="secret-line-number">Line {secret.line_number}</p>
                  <span className={`severity-badge badge-${results.risk_scores[index].severity.toLowerCase()}`}>
                    {results.risk_scores[index].severity}
                  </span>
                </div>
              </div>
            ))}
          </div>
        </div>

        {/* Details Panel */}
        <div className="details-panel">
          {/* Secret Information Card */}
          <div className="secret-info-card">
            <div className="secret-info-header">
              <h3 className="secret-info-title">Secret Details</h3>
              <span className={`severity-badge-large badge-${currentRisk.severity.toLowerCase()}`}>
                {currentRisk.severity}
              </span>
            </div>

            {/* Validation Status */}
            {!currentSecret.is_valid && (
              <div style={{
                background: '#fef3c7',
                border: '1px solid #fbbf24',
                borderRadius: '8px',
                padding: '12px 16px',
                marginBottom: '16px',
                display: 'flex',
                alignItems: 'start',
                gap: '12px'
              }}>
                <span style={{fontSize: '1.25rem'}}>⚠️</span>
                <div>
                  <p style={{fontWeight: '600', color: '#92400e', marginBottom: '4px'}}>
                    Validation Warning
                  </p>
                  <p style={{fontSize: '0.875rem', color: '#78350f'}}>
                    {currentSecret.validation_result}. This may be an example or placeholder value, but should still be reviewed.
                  </p>
                </div>
              </div>
            )}

            {currentSecret.is_valid && (
              <div style={{
                background: '#fee2e2',
                border: '1px solid #ef4444',
                borderRadius: '8px',
                padding: '12px 16px',
                marginBottom: '16px',
                display: 'flex',
                alignItems: 'start',
                gap: '12px'
              }}>
                <span style={{fontSize: '1.25rem'}}>🚨</span>
                <div>
                  <p style={{fontWeight: '600', color: '#991b1b', marginBottom: '4px'}}>
                    Valid Secret Detected
                  </p>
                  <p style={{fontSize: '0.875rem', color: '#7f1d1d'}}>
                    This appears to be a legitimate secret. Immediate action required to rotate and remove this credential.
                  </p>
                </div>
              </div>
            )}

            <div className="details-grid">
              <div className="detail-item">
                <p className="detail-label">Provider</p>
                <p className="detail-value">{currentSecret.provider}</p>
              </div>
              <div className="detail-item">
                <p className="detail-label">Environment</p>
                <p className="detail-value">{currentSecret.environment}</p>
              </div>
              <div className="detail-item">
                <p className="detail-label">Privilege Level</p>
                <p className="detail-value">{currentSecret.privilege_level}</p>
              </div>
              <div className="detail-item">
                <p className="detail-label">Risk Score</p>
                <p className="detail-value">{currentRisk.total_score}/100</p>
              </div>
              <div className="detail-item">
                <p className="detail-label">Validation Status</p>
                <p className="detail-value">
                  {currentSecret.is_valid ? (
                    <span style={{color: '#dc2626', fontWeight: '700'}}>✓ Valid</span>
                  ) : (
                    <span style={{color: '#f59e0b', fontWeight: '700'}}>⚠ Unverified</span>
                  )}
                </p>
              </div>
            </div>

            <div style={{marginTop: '1.5rem'}}>
              <p className="detail-label">File Location</p>
              <p className="file-path-display">{currentSecret.file_path}</p>
              <p className="line-number-display">Line {currentSecret.line_number}</p>
            </div>

            <div style={{marginTop: '1.5rem'}}>
              <p className="detail-label">Masked Value</p>
              <code className="masked-value-display">
                {currentSecret.masked_value}
              </code>
            </div>

            <div style={{marginTop: '1.5rem'}}>
              <p className="detail-label">Code Context</p>
              <pre className="code-context-box">
                {currentSecret.context}
              </pre>
            </div>
          </div>

          {/* Risk Analysis Card */}
          <div className="risk-analysis-card">
            <h3 className="risk-analysis-title">Risk Analysis</h3>
            
            <div style={{display: 'flex', flexDirection: 'column', gap: '1.5rem'}}>
              {Object.entries(currentRisk.factors).map(([factor, score]) => (
                <div key={factor} className="risk-factor-item">
                  <div className="risk-factor-header">
                    <span className="risk-factor-label">
                      {factor.replace(/_/g, ' ')}
                    </span>
                    <span className="risk-factor-score">{score}</span>
                  </div>
                  <div className="risk-progress-bar">
                    <div
                      className="risk-progress-fill"
                      style={{ width: `${score}%` }}
                    ></div>
                  </div>
                </div>
              ))}
            </div>

            <div className="exploitation-probability-box">
              <span className="exploitation-label">Exploitation Probability</span>
              <span className="exploitation-value">
                {(currentRisk.exploitation_probability * 100).toFixed(1)}%
              </span>
            </div>
          </div>

          {/* AI Prediction Card */}
          {results.ai_predictions?.predictions?.[selectedSecret] && (
            <div className="ai-prediction-card">
              <h3 className="ai-prediction-title">🤖 AI Risk Prediction</h3>
              
              <div className="ai-risk-level-box">
                <p className="ai-risk-level-label">Predicted Risk Level</p>
                <p className="ai-risk-level-value">
                  {results.ai_predictions.predictions[selectedSecret].predicted_risk_level}
                </p>
              </div>

              <div className="confidence-distribution">
                <p className="confidence-title">Confidence Distribution</p>
                {Object.entries(results.ai_predictions.predictions[selectedSecret].probability_distribution).map(([level, prob]) => (
                  <div key={level} className="confidence-item">
                    <span className="confidence-level-name">{level}</span>
                    <div className="confidence-bar-container">
                      <div
                        className="confidence-bar-fill"
                        style={{ width: `${prob * 100}%` }}
                      ></div>
                    </div>
                    <span className="confidence-percentage">
                      {(prob * 100).toFixed(0)}%
                    </span>
                  </div>
                ))}
              </div>
            </div>
          )}
        </div>
      </div>

      {/* Mitigation Recommendations */}
      <div className="mitigation-card">
        <h3 className="mitigation-title">🛡️ Mitigation Recommendations</h3>
        <div style={{display: 'flex', flexDirection: 'column', gap: '1.5rem'}}>
          {results.mitigation_suggestions.slice(0, 5).map((suggestion, index) => (
            <div key={index} className="mitigation-item">
              <div className="mitigation-header">
                <span className={`priority-badge priority-${suggestion.priority.toLowerCase()}`}>
                  {suggestion.priority}
                </span>
                <div style={{flex: 1}}>
                  <h4 className="mitigation-action-title">{suggestion.action}</h4>
                  <p className="mitigation-description">{suggestion.description}</p>
                  {suggestion.steps && (
                    <ul className="mitigation-steps">
                      {suggestion.steps.map((step, i) => (
                        <li key={i} className="mitigation-step">{step}</li>
                      ))}
                    </ul>
                  )}
                  {suggestion.warning && (
                    <div className="mitigation-warning">
                      <p className="warning-text">⚠️ {suggestion.warning}</p>
                    </div>
                  )}
                </div>
              </div>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}

export default ScanResults;