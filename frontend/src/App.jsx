import React, { useState } from "react";
import { scanUrl, scanEmail, scanBulk } from "./api";

export default function App() {
  const [tab, setTab] = useState("url"); // "url" | "email" | "bulk"
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
        <p>AI-Powered URL &amp; Email Security Scanner</p>
      </header>

      <nav className="tabs">
        <button
          className={tab === "url" ? "tab active" : "tab"}
          onClick={() => setTab("url")}
        >
          URL Scanner
        </button>
        <button
          className={tab === "email" ? "tab active" : "tab"}
          onClick={() => setTab("email")}
        >
          Email Detector
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
        {tab === "email" && <EmailScanner />}
        {tab === "bulk" && <BulkScanner />}
      </main>

      {/* ------------------------------------------------------------
          FUTURE FEATURES: add more tabs/pages here later, e.g.
            <button onClick={() => setTab("history")}>Scan History</button>
         ------------------------------------------------------------ */}
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

          <details>
            <summary>Extracted features</summary>
            <pre>{JSON.stringify(result.features, null, 2)}</pre>
          </details>
        </div>
      )}
    </div>
  );
}

function EmailScanner() {
  const [text, setText] = useState("");
  const [result, setResult] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");

  const handleScan = async () => {
    if (!text.trim()) return;
    setLoading(true);
    setError("");
    setResult(null);
    try {
      const data = await scanEmail(text.trim());
      setResult(data);
    } catch (e) {
      setError(e.message);
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="card">
      <h2>Scan an Email</h2>
      <textarea
        rows={6}
        placeholder="Paste email text here..."
        value={text}
        onChange={(e) => setText(e.target.value)}
      />
      <button onClick={handleScan} disabled={loading}>
        {loading ? "Scanning..." : "Scan Email"}
      </button>

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
          {result.matched_keywords?.length > 0 && (
            <p>
              <strong>Matched keywords:</strong>{" "}
              {result.matched_keywords.join(", ")}
            </p>
          )}
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
