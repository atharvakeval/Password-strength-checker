// AI Phishing Email Detector - Content Script
// Runs on Gmail and Outlook pages to detect phishing emails

const API_URL = "http://localhost:8000/predict";

// ─── Helpers ────────────────────────────────────────────────────────────────

function getEmailText() {
  // Gmail
  const gmailBody = document.querySelector(".a3s.aiL, .ii.gt .a3s");
  if (gmailBody) return gmailBody.innerText;

  // Outlook (live / office365)
  const outlookBody =
    document.querySelector('[role="main"] .wide-content-host') ||
    document.querySelector('[data-app-section="ConversationContainer"]') ||
    document.querySelector(".ReadingPaneContents");
  if (outlookBody) return outlookBody.innerText;

  return null;
}

function getEmailSubject() {
  const gmailSubject = document.querySelector("h2.hP");
  if (gmailSubject) return gmailSubject.innerText;
  const outlookSubject = document.querySelector('[data-testid="conversationHeaderSubject"], .subject');
  if (outlookSubject) return outlookSubject.innerText;
  return "";
}

function getSender() {
  const gmailSender = document.querySelector(".gD");
  if (gmailSender) return gmailSender.getAttribute("email") || gmailSender.innerText;
  const outlookSender = document.querySelector('[data-testid="senderContact"] span');
  if (outlookSender) return outlookSender.innerText;
  return "";
}

// ─── UI Elements ─────────────────────────────────────────────────────────────

function createScanButton() {
  if (document.getElementById("phish-scan-btn")) return;
  const btn = document.createElement("button");
  btn.id = "phish-scan-btn";
  btn.textContent = "🔍 Scan for Phishing";
  btn.title = "Analyse this email with AI Phishing Detector";
  btn.addEventListener("click", runScan);
  document.body.appendChild(btn);
}

function removeScanButton() {
  const btn = document.getElementById("phish-scan-btn");
  if (btn) btn.remove();
}

function showBanner(result) {
  removeBanner();
  const banner = document.createElement("div");
  banner.id = "phish-result-banner";
  const isPhishing = result.is_phishing;
  banner.className = isPhishing ? "phish-banner phish-danger" : "phish-banner phish-safe";
  const icon = isPhishing ? "🚨" : "✅";
  const title = isPhishing ? "Phishing Detected!" : "Email Looks Legitimate";
  const confidence = ((result.confidence || 0) * 100).toFixed(1);
  const indicatorsHTML = (result.indicators || []).length > 0
    ? `<ul class="phish-indicators">${result.indicators.map(i => `<li>${i}</li>`).join("")}</ul>` : "";
  banner.innerHTML = `
    <div class="phish-banner-header">
      <span class="phish-icon">${icon}</span>
      <strong>${title}</strong>
      <span class="phish-confidence">Confidence: ${confidence}%</span>
      <button class="phish-close" title="Dismiss">✕</button>
    </div>
    <p class="phish-explanation">${result.explanation || ""}</p>
    ${indicatorsHTML}`;
  banner.querySelector(".phish-close").addEventListener("click", removeBanner);
  const container = document.querySelector(".nH.bkK") || document.querySelector('[role="main"]') || document.body;
  container.insertBefore(banner, container.firstChild);
}

function removeBanner() {
  const banner = document.getElementById("phish-result-banner");
  if (banner) banner.remove();
}

function showLoading() {
  const btn = document.getElementById("phish-scan-btn");
  if (btn) { btn.textContent = "⏳ Scanning…"; btn.disabled = true; }
}

function resetButton() {
  const btn = document.getElementById("phish-scan-btn");
  if (btn) { btn.textContent = "🔍 Scan for Phishing"; btn.disabled = false; }
}

// ─── Core Scan ───────────────────────────────────────────────────────────────

async function runScan() {
  const emailText = getEmailText();
  if (!emailText || emailText.trim().length < 10) {
    alert("Could not extract email content. Please open an email first.");
    return;
  }
  showLoading();
  removeBanner();
  try {
    const response = await fetch(API_URL, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ text: emailText, sender: getSender(), subject: getEmailSubject() }),
    });
    if (!response.ok) {
      const err = await response.json().catch(() => ({}));
      throw new Error(err.detail || `Server error ${response.status}`);
    }
    const result = await response.json();
    showBanner(result);
    chrome.runtime.sendMessage({ type: "SCAN_RESULT", isPhishing: result.is_phishing, confidence: result.confidence });
  } catch (error) {
    showBanner({ is_phishing: false, confidence: 0, explanation: `❌ Scan failed: ${error.message}. Is the backend running on port 8000?`, indicators: [] });
  } finally {
    resetButton();
  }
}

// ─── Observer ────────────────────────────────────────────────────────────────

function checkForEmail() {
  if (getEmailText()) { createScanButton(); } else { removeScanButton(); removeBanner(); }
}

const observer = new MutationObserver(checkForEmail);
observer.observe(document.body, { childList: true, subtree: true });
checkForEmail();

chrome.runtime.onMessage.addListener((message, _sender, sendResponse) => {
  if (message.type === "SCAN_EMAIL") { runScan().then(() => sendResponse({ ok: true })); return true; }
  if (message.type === "GET_STATUS") { sendResponse({ emailOpen: !!getEmailText() }); }
});
