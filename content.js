
(() => {
  "use strict";

  // ── Configuration ─────────────────────────────────────
  const API_URL = "http://127.0.0.1:5000/predict";

  const WHITELIST = [
    "google.com", "youtube.com", "github.com",
    "stackoverflow.com", "linkedin.com", "twitter.com",
    "facebook.com", "instagram.com", "wikipedia.org",
    "microsoft.com", "apple.com", "amazon.com",
    "flipkart.com", "zomato.com", "swiggy.com",
    "hotstar.com", "netflix.com", "spotify.com",
    "college.edu", "nptel.ac.in", "geeksforgeeks.org"
  ];

  const currentURL = window.location.href;

  // ── Whitelist check ───────────────────────────────────
  function isWhitelisted(url) {
    try {
      const hostname = new URL(url).hostname.toLowerCase();
      return WHITELIST.some(domain =>
        hostname === domain || hostname.endsWith("." + domain)
      );
    } catch {
      return false;
    }
  }

  // Do not scan browser-internal pages.
  if (!["http:", "https:"].includes(window.location.protocol)) {
    console.log("PhishGuard: unsupported page; skipping scan.");
    return;
  }

  if (isWhitelisted(currentURL)) {
    console.log("PhishGuard: trusted domain; skipping scan.");
    return;
  }

  console.log("PhishGuard scanning:", currentURL);

  // ── Ask the Flask API to scan this URL ─────────────────
  async function scanPage() {
    try {
      const response = await fetch(API_URL, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ url: currentURL })
      });

      if (!response.ok) {
        throw new Error(`API returned HTTP ${response.status}`);
      }

      const data = await response.json();
      console.log("PhishGuard API response:", data);

      if (typeof data.risk_score !== "number") {
        throw new Error(data.error || "API response has no valid risk_score");
      }

      showBar(data);
    } catch (error) {
      console.error("PhishGuard API error:", error);
      showErrorBar("Cannot connect to the phishing detection API.");
    }
  }

  // ── Display the risk result ────────────────────────────
  function showBar(data) {
    const score = Math.max(0, Math.min(100, Math.round(data.risk_score)));
    const isPhishing = data.is_phishing === true ||
                       data.prediction === "PHISHING";

    let color, title, message;

    if (score >= 80 || isPhishing) {
      color = "#991b1b";
      title = "🚨 POTENTIAL PHISHING DETECTED";
      message = `Risk score: ${score}% — Avoid entering sensitive information.`;
    } else if (score >= 50) {
      color = "#92400e";
      title = "⚠️ SUSPICIOUS WEBSITE";
      message = `Risk score: ${score}% — Proceed carefully.`;
    } else if (score >= 25) {
      color = "#1e40af";
      title = "🔵 LOW RISK";
      message = `Risk score: ${score}% — Continue with caution.`;
    } else {
      color = "#065f46";
      title = "✅ LOW RISK RESULT";
      message = `Risk score: ${score}% — No strong phishing signal detected.`;
    }

    const bar = makeBanner(title, message, color);
    document.documentElement.appendChild(bar);
  }

  function showErrorBar(message) {
    const bar = makeBanner(
      "⚠️ PHISHGUARD API OFFLINE",
      message,
      "#374151"
    );
    document.documentElement.appendChild(bar);
  }

  function makeBanner(title, message, color) {
    const old = document.getElementById("phish-bar");
    if (old) old.remove();

    const bar = document.createElement("div");
    bar.id = "phish-bar";

    Object.assign(bar.style, {
      position: "fixed",
      top: "0",
      left: "0",
      right: "0",
      zIndex: "2147483647",
      boxSizing: "border-box",
      padding: "12px 52px 12px 18px",
      background: color,
      color: "#fff",
      font: "13px Arial, sans-serif",
      boxShadow: "0 3px 15px rgba(0,0,0,.4)",
      borderBottom: "3px solid rgba(255,255,255,.35)"
    });

    const heading = document.createElement("strong");
    heading.textContent = title;

    const detail = document.createElement("div");
    detail.textContent = message;
    detail.style.marginTop = "4px";

    const dismiss = document.createElement("button");
    dismiss.type = "button";
    dismiss.textContent = "Dismiss";
    Object.assign(dismiss.style, {
      position: "absolute",
      right: "12px",
      top: "10px",
      padding: "6px 9px",
      color: "#fff",
      background: "rgba(255,255,255,.15)",
      border: "1px solid rgba(255,255,255,.5)",
      borderRadius: "5px",
      cursor: "pointer"
    });
    dismiss.addEventListener("click", () => bar.remove());

    bar.append(heading, detail, dismiss);
    return bar;
  }

  // Wait until the document root exists, then scan.
  if (document.documentElement) {
    scanPage();
  } else {
    document.addEventListener("DOMContentLoaded", scanPage, { once: true });
  }
})();
