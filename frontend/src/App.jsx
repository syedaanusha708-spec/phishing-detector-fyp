import React, { useState } from "react";
import { scanUrl, scanBulk } from "./api";

export default function App() {
  const [tab, setTab] = useState("url"); // "url" | "bulk"
  const [darkMode, setDarkMode] = useState(true);

  return (
    <div className={darkMode ? "page dark" : "page light"}>
      <header className="header">
        <div className="header-top">
          <div />
          <button className="theme-toggle" onClick={() => setDarkMode(!darkMode)}>
            {darkMode ? "☀️ Light Mode" : "🌙 Dark Mode"}
          </button>
        </div>
        <h1>🛡️ Phishing Website Detection Tool</h1>
      </header>

      <nav className="tabs">
        <button
          className={tab === "url" ? "tab active" : "tab"}
          onClick={() => setTab("url")}
        >
          URL Scanner
        </button>
        <button
          className={tab === "bulk" ? "tab active" : "tab"}
          onClick={() => setTab("bulk")}
        >
          Bulk Scanner
        </button>
      </nav>

      <main className="content">
        {tab === "url" && <UrlScanner />}
        {tab === "bulk" && <BulkScanner />}
      </main>
    </div>
  );
}

// Small reusable block that shows the 3 basic extra checks under a scan result
function ExtraChecks({ result }) {
  return (
    <div className="extra-checks">
      <div className="check-item">
        <strong>Domain Age:</strong>{" "}
        {result.domain_age?.available
          ? `${result.domain_age.age_days} days (since ${result.domain_age.creation_date})${
              result.domain_age.suspicious ? " ⚠️ Newly registered" : ""
            }`
          : "Not available"}
      </div>
      <div className="check-item">
        <strong>SSL Certificate:</strong>{" "}
        {result.ssl_certificate?.available
          ? result.ssl_certificate.valid
            ? `✅ Valid (expires ${result.ssl_certificate.expires})`
            : "⚠️ Invalid / Expired"
          : "❌ Not available"}
      </div>
      <div className="check-item">
        <strong>Typosquatting:</strong>{" "}
        {result.typosquatting?.is_typosquat
          ? `⚠️ Looks like a fake "${result.typosquatting.matched_brand}"`
          : "✅ No brand impersonation detected"}
      </div>
    </div>
  );
}

// Component to render DOM Structural Analysis with refined severity indicators
function DomInspector({ domData }) {
  if (!domData) return null;

  return (
    <div style={{
      marginTop: '20px',
      padding: '18px',
      backgroundColor: '#1e293b',
      borderRadius: '8px',
      border: '1px solid #334155',
      color: '#f8fafc',
      textAlign: 'left'
    }}>
      <h3 style={{ color: '#38bdf8', marginTop: 0, marginBottom: '12px', fontSize: '1.1rem' }}>
        🔍 Real-Time DOM & Web Structural Inspector
      </h3>

      <div style={{ marginBottom: '8px' }}>
        <strong>Scraped Webpage Title: </strong>
        <span style={{ color: '#cbd5e1' }}>{domData.scraped_title || "N/A"}</span>
      </div>

      {/* Neutral informational indicator for presence of a login form */}
      <div style={{ marginBottom: '8px' }}>
        <strong>Login Form: </strong>
        {domData.has_login_form ? (
          <span style={{ color: '#38bdf8' }}>ℹ️ Detected (Password Input Present)</span>
        ) : (
          <span style={{ color: '#22c55e' }}>✅ None Found</span>
        )}
      </div>

      {/* High-severity alert section reserved for genuine security violations */}
      {domData.dom_alerts && domData.dom_alerts.length > 0 ? (
        <div style={{
          marginTop: '12px',
          padding: '10px 14px',
          backgroundColor: 'rgba(239, 68, 68, 0.12)',
          borderRadius: '6px',
          borderLeft: '4px solid #ef4444'
        }}>
          <strong style={{ color: '#f87171' }}>⚠️ Security Violations Flagged:</strong>
          <ul style={{ margin: '6px 0 0 0', paddingLeft: '20px', color: '#fca5a5' }}>
            {domData.dom_alerts.map((alert, idx) => (
              <li key={idx}>{alert}</li>
            ))}
          </ul>
        </div>
      ) : (
        <div style={{
          marginTop: '12px',
          padding: '10px 14px',
          backgroundColor: 'rgba(34, 197, 94, 0.12)',
          borderRadius: '6px',
          borderLeft: '4px solid #22c55e',
          color: '#4ade80'
        }}>
          ✅ No brand impersonation, cross-domain credential harvesting, or malicious tags detected.
        </div>
      )}
    </div>
  );
}

function UrlScanner() {
  const [url, setUrl] = useState("");
  const [result, setResult] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");

  const handleScan = async () => {
    if (!url.trim()) return;
    setLoading(true);
    setError("");
    setResult(null);
    try {
      const data = await scanUrl(url.trim());
      setResult(data);
    } catch (e) {
      setError(e.message);
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="card">
      <h2>Scan a URL</h2>
      <div className="input-row">
        <input
          type="text"
          placeholder="Enter a URL, e.g. http://example.com"
          value={url}
          onChange={(e) => setUrl(e.target.value)}
          onKeyDown={(e) => e.key === "Enter" && handleScan()}
        />
        <button onClick={handleScan} disabled={loading}>
          {loading ? "Scanning..." : "Scan"}
        </button>
      </div>

      {error && <p className="error">{error}</p>}

      {result && (
        <div className={`result ${result.is_phishing ? "danger" : "safe"}`}>
          <p>
            <strong>Verdict:</strong>{" "}
            {result.is_phishing ? "Phishing" : "Safe"}
          </p>
          <p>
            <strong>Confidence:</strong> {result.confidence}%
          </p>
          <p>
            <strong>Risk Level:</strong> {result.risk_level}
          </p>

          <ExtraChecks result={result} />

          {/* New DOM Inspector Output Component */}
          <DomInspector domData={result.dom_inspection} />

          <details style={{ marginTop: '15px' }}>
            <summary>Extracted ML features</summary>
            <pre>{JSON.stringify(result.features, null, 2)}</pre>
          </details>
        </div>
      )}
    </div>
  );
}

function BulkScanner() {
  const [text, setText] = useState("");
  const [results, setResults] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");

  const handleScan = async () => {
    const urls = text
      .split("\n")
      .map((u) => u.trim())
      .filter(Boolean);

    if (urls.length === 0) return;

    setLoading(true);
    setError("");
    setResults(null);
    try {
      const data = await scanBulk(urls);
      setResults(data.results);
    } catch (e) {
      setError(e.message);
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="card">
      <h2>Bulk URL Scanner</h2>
      <p className="hint">Paste one URL per line (max 25 for this demo)</p>
      <textarea
        rows={6}
        placeholder={"http://example1.com\nhttp://example2.com\nhttps://example3.com"}
        value={text}
        onChange={(e) => setText(e.target.value)}
      />
      <button onClick={handleScan} disabled={loading}>
        {loading ? "Scanning..." : "Scan All"}
      </button>

      {error && <p className="error">{error}</p>}

      {results && (
        <table className="bulk-table">
          <thead>
            <tr>
              <th>URL</th>
              <th>Verdict</th>
              <th>Confidence</th>
              <th>Risk</th>
            </tr>
          </thead>
          <tbody>
            {results.map((r, i) => (
              <tr key={i} className={r.is_phishing ? "row-danger" : "row-safe"}>
                <td>{r.url}</td>
                <td>{r.error ? "Error" : r.is_phishing ? "Phishing" : "Safe"}</td>
                <td>{r.error ? "-" : `${r.confidence}%`}</td>
                <td>{r.error ? r.error : r.risk_level}</td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </div>
  );
}