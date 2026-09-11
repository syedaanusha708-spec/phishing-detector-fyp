// Central place for all backend calls.
// Change BASE_URL here if you deploy the Flask API somewhere else.
const BASE_URL = "https://phishing-detector-v2-l6fp.onrender.com";

export async function scanUrl(url) {
  const res = await fetch(`${BASE_URL}/scan`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ url }),
  });
  if (!res.ok) {
    const err = await res.json().catch(() => ({}));
    throw new Error(err.error || "Failed to scan URL");
  }
  return res.json();
}

export async function scanEmail(emailText) {
  const res = await fetch(`${BASE_URL}/scan-email`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ email_text: emailText }),
  });
  if (!res.ok) {
    const err = await res.json().catch(() => ({}));
    throw new Error(err.error || "Failed to scan email");
  }
  return res.json();
}

export async function scanBulk(urls) {
  const res = await fetch(`${BASE_URL}/scan-bulk`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ urls }),
  });
  if (!res.ok) {
    const err = await res.json().catch(() => ({}));
    throw new Error(err.error || "Failed to run bulk scan");
  }
  return res.json();
}

// -----------------------------------------------------------------
// FUTURE FEATURES: add more API calls here as you build them, e.g.
//   export async function getScanHistory() { ... }
// -----------------------------------------------------------------
