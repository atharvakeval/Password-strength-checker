// AI Phishing Email Detector - Popup Script

const API_URL = "http://localhost:8000";

const scanBtn = document.getElementById("scan-btn");
const apiStatus = document.getElementById("api-status");
const emailStatus = document.getElementById("email-status");
const resultBox = document.getElementById("result-box");
const resultTitle = document.getElementById("result-title");
const resultExplanation = document.getElementById("result-explanation");
const resultIndicators = document.getElementById("result-indicators");
const noEmailMsg = document.getElementById("no-email-msg");

// ─── Check API health ────────────────────────────────────────────────────────
async function checkAPI() {
  try {
    const resp = await fetch(`${API_URL}/health`, { signal: AbortSignal.timeout(3000) });
    if (resp.ok) {
      apiStatus.textContent = "Online ✓";
      apiStatus.className = "badge badge-ok";
      return true;
    }
  } catch (_) {}
  apiStatus.textContent = "Offline ✗";
  apiStatus.className = "badge badge-warn";
  return false;
}

// ─── Check if email is open in active tab ────────────────────────────────────
async function checkEmailStatus() {
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  if (!tab?.id) return false;

  const validHost = tab.url && (
    tab.url.includes("mail.google.com") ||
    tab.url.includes("outlook.live.com") ||
    tab.url.includes("outlook.office.com")
  );

  if (!validHost) {
    emailStatus.textContent = "Wrong page";
    emailStatus.className = "badge badge-gray";
    noEmailMsg.style.display = "block";
    return false;
  }

  try {
    const response = await chrome.tabs.sendMessage(tab.id, { type: "GET_STATUS" });
    if (response?.emailOpen) {
      emailStatus.textContent = "Detected ✓";
      emailStatus.className = "badge badge-ok";
      noEmailMsg.style.display = "none";
      return true;
    }
  } catch (_) {}

  emailStatus.textContent = "No email open";
  emailStatus.className = "badge badge-gray";
  noEmailMsg.style.display = "block";
  return false;
}

// ─── Show scan result ────────────────────────────────────────────────────────
function showResult(result) {
  const isPhishing = result.is_phishing;
  resultBox.style.display = "block";
  resultBox.className = `result-box ${isPhishing ? "result-danger" : "result-safe"}`;
  resultTitle.textContent = isPhishing ? "🚨 Phishing Detected!" : "✅ Looks Legitimate";
  resultExplanation.textContent = result.explanation || "";
  resultIndicators.innerHTML = (result.indicators || [])
    .map(i => `<li>${i}</li>`).join("");
}

// ─── Scan button click ───────────────────────────────────────────────────────
scanBtn.addEventListener("click", async () => {
  scanBtn.textContent = "⏳ Scanning…";
  scanBtn.disabled = true;
  resultBox.style.display = "none";

  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  if (!tab?.id) { scanBtn.textContent = "🔍 Scan Current Email"; scanBtn.disabled = false; return; }

  try {
    await chrome.tabs.sendMessage(tab.id, { type: "SCAN_EMAIL" });
  } catch (err) {
    resultBox.style.display = "block";
    resultBox.className = "result-box result-danger";
    resultTitle.textContent = "Error";
    resultExplanation.textContent = `Could not communicate with the page: ${err.message}`;
    resultIndicators.innerHTML = "";
  }

  scanBtn.textContent = "🔍 Scan Current Email";
  scanBtn.disabled = false;
});

// ─── Init ────────────────────────────────────────────────────────────────────
(async () => {
  const apiOk = await checkAPI();
  const emailOk = await checkEmailStatus();
  if (apiOk && emailOk) {
    scanBtn.disabled = false;
  }
})();
