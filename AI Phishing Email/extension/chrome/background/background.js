// AI Phishing Email Detector - Service Worker (Background)

let phishingCount = 0;

chrome.runtime.onMessage.addListener((message, sender) => {
  if (message.type === "SCAN_RESULT") {
    if (message.isPhishing) {
      phishingCount++;
      // Show red badge with count
      chrome.action.setBadgeText({ text: String(phishingCount), tabId: sender.tab?.id });
      chrome.action.setBadgeBackgroundColor({ color: "#d93025" });
    } else {
      // Show green check
      chrome.action.setBadgeText({ text: "✓", tabId: sender.tab?.id });
      chrome.action.setBadgeBackgroundColor({ color: "#34a853" });
    }
  }
});

// Clear badge when navigating away
chrome.tabs.onUpdated.addListener((tabId, changeInfo) => {
  if (changeInfo.status === "loading") {
    chrome.action.setBadgeText({ text: "", tabId });
  }
});
