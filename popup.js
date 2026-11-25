const API_URL = "http://127.0.0.1:8080/predict";

// Get current active tab
chrome.tabs.query({ active:true, currentWindow:true }, (tabs) => {
  const tab = tabs[0];
  if (!tab || !tab.url) return;

  const url = tab.url;

  // Show URL in popup
  document.getElementById("urlText").textContent = url;

  // Skip internal Chrome pages
  if (url.startsWith("chrome://") || url.startsWith("about:")) {
    document.getElementById("verdict").textContent = "N/A";
    document.getElementById("scoreNumber").textContent = "--";
    document.getElementById("footer").textContent =
      "Cannot scan Chrome internal pages";
    return;
  }

  // Check stored result first
  chrome.storage.local.get([`result_${tab.id}`], (stored) => {
    const saved = stored[`result_${tab.id}`];

    if (saved && saved.url === url) {
      displayResult(saved);
    } else {
      // Fresh scan
      document.getElementById("verdict").textContent = "Scanning...";
      fetchAndDisplay(url, tab.id);
    }
  });
});

function fetchAndDisplay(url, tabId) {
  fetch(API_URL, {
    method : "POST",
    headers: { "Content-Type": "application/json" },
    body   : JSON.stringify({ url })
  })
  .then(res => res.json())
  .then(data => {
    const result = {
      url        : url,
      risk_score : data.risk_score,
      risk_level : data.risk_level,
      risk_color : data.risk_color,
      is_phishing: data.is_phishing,
      top_reasons: data.top_reasons,
      prediction : data.prediction,
      checked_at : new Date().toLocaleTimeString()
    };
    chrome.storage.local.set({ [`result_${tabId}`]: result });
    displayResult(result);
  })
  .catch(() => {
    document.getElementById("verdict").textContent = "API Offline";
    document.getElementById("scoreNumber").textContent = "!";
    document.getElementById("footer").textContent =
      "Start Flask server: python api/app.py";
  });
}

function displayResult(result) {
  const score   = result.risk_score || 0;
  const circle  = document.getElementById("scoreCircle");
  const verdict = document.getElementById("verdict");
  const level   = document.getElementById("riskLevel");

  // Update score
  document.getElementById("scoreNumber").textContent =
    Math.round(score) + "%";

  // Color coding
  if (score >= 80) {
    circle.className  = "score-circle danger";
    verdict.textContent = "🔴 PHISHING";
    verdict.className   = "verdict danger";
  } else if (score >= 50) {
    circle.className  = "score-circle medium";
    verdict.textContent = "🟡 SUSPICIOUS";
    verdict.className   = "verdict";
  } else if (score >= 25) {
    circle.className  = "score-circle low";
    verdict.textContent = "🔵 LOW RISK";
    verdict.className   = "verdict safe";
  } else {
    circle.className  = "score-circle safe";
    verdict.textContent = "🟢 SAFE";
    verdict.className   = "verdict safe";
  }

  level.textContent = result.risk_level || "";

  // Show reasons if phishing
  if (result.is_phishing && result.top_reasons) {
    const box  = document.getElementById("reasonsBox");
    const list = document.getElementById("reasonsList");
    box.style.display = "block";
    list.innerHTML = result.top_reasons
      .map(r => `<span class="reason-tag">${r}</span>`)
      .join("");
  }

  // Footer
  document.getElementById("footer").textContent =
    `Last checked: ${result.checked_at || "just now"}`;
}