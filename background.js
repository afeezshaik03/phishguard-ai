const API_URL = "http://localhost:5000/predict";

// Called every time a tab finishes loading
chrome.tabs.onUpdated.addListener((tabId, changeInfo, tab) => {
  if (changeInfo.status === "complete" && tab.url) {

    // Skip Chrome internal pages
    if (tab.url.startsWith("chrome://") ||
        tab.url.startsWith("chrome-extension://") ||
        tab.url.startsWith("about:")) {
      return;
    }

    // Call Flask API with the URL
    fetch(API_URL, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ url: tab.url })
    })
    .then(res => res.json())
    .then(data => {
      if (data.risk_score >= 80) {
  chrome.notifications.create({
    type: "basic",
    iconUrl: "icons/icon128.png",
    title: "🚨 PHISHING SITE DETECTED!",
    message: `Risk: ${data.risk_score}% — ${tab.url.slice(0,60)}`,
    priority: 2,
    buttons: [
      { title: "Close Tab" },
      { title: "Dismiss" }
    ]
  });
}
      // Save result in Chrome storage (popup reads this)
      chrome.storage.local.set({
        [`result_${tabId}`]: {
          url        : tab.url,
          risk_score : data.risk_score,
          risk_level : data.risk_level,
          risk_color : data.risk_color,
          is_phishing: data.is_phishing,
          top_reasons: data.top_reasons,
          prediction : data.prediction,
          checked_at : new Date().toLocaleTimeString()
        }
      });

      // Change extension icon color based on risk
      const iconColor = data.is_phishing ? "red" : "green";
      chrome.action.setBadgeText({
        text  : data.is_phishing ? "⚠" : "✓",
        tabId : tabId
      });
      chrome.action.setBadgeBackgroundColor({
        color : data.is_phishing ? "#E24B4A" : "#1D9E75",
        tabId : tabId
      });
    })
    .catch(err => {
      console.log("API not reachable:", err);
      chrome.action.setBadgeText({ text: "?", tabId });
      chrome.action.setBadgeBackgroundColor({
        color: "#999999", tabId
      });
    });
  }
});
chrome.notifications.onButtonClicked.addListener(
  (notifId, btnIndex) => {

    if (btnIndex === 0) {
      chrome.tabs.query(
        { active: true, currentWindow: true },
        (tabs) => {
          if (tabs[0]) {
            chrome.tabs.remove(tabs[0].id);
          }
        }
      );
    }

    chrome.notifications.clear(notifId);
  }
);