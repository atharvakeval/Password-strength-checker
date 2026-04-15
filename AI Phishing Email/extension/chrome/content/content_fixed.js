// ============================================================
// content.js — Runs inside Gmail and Outlook
// Detects emails on hover and shows 🔴 🟡 🟢 risk badge
// ============================================================

var API_URL = "http://localhost:8000/predict";

// Store scan results so we don't scan same email twice
var scanResults = {};
var currentlyScanning = {};
var hoverTimer = null;


// ── RISK LEVEL HELPERS ────────────────────────────────────────

function getRiskLevel(result) {
    var prob = result.is_phishing ? result.confidence : (1 - result.confidence);
    if (prob >= 0.65) return "red";
    if (prob >= 0.30) return "yellow";
    return "green";
}

function getRiskIcon(level) {
    if (level == "red")    return "🔴";
    if (level == "yellow") return "🟡";
    if (level == "green")  return "🟢";
    return "⚪";
}

function getRiskText(level) {
    if (level == "red")    return "High Risk — Phishing!";
    if (level == "yellow") return "Moderate Risk — Suspicious";
    if (level == "green")  return "Safe — Looks Legitimate";
    return "Unknown";
}


// ── EMAIL KEY ─────────────────────────────────────────────────

function createEmailKey(sender, subject) {
    var combined = sender + "|" + subject;
    var hash = 0;
    for (var i = 0; i < combined.length; i++) {
        hash = hash + combined.charCodeAt(i);
    }
    return "email_" + Math.abs(hash);
}


// ── GMAIL ROW HELPERS ─────────────────────────────────────────

function getGmailRows() {
    return document.querySelectorAll("tr.zA");
}

function getGmailRowData(row) {
    var senderEl  = row.querySelector(".zF");
    var sender    = senderEl ? (senderEl.getAttribute("email") || senderEl.innerText || "") : "";

    var subjectEl = row.querySelector(".y6");
    var subject   = subjectEl ? subjectEl.innerText || "" : "";

    var snippetEl = row.querySelector(".y2");
    var snippet   = snippetEl ? snippetEl.innerText || "" : "";

    var fullText  = "Subject: " + subject + "\nFrom: " + sender + "\n" + snippet;

    return { sender: sender, subject: subject, text: fullText, key: createEmailKey(sender, subject) };
}


// ── OUTLOOK ROW HELPERS ───────────────────────────────────────

function getOutlookRows() {
    return document.querySelectorAll('[role="option"]');
}

function getOutlookRowData(row) {
    var senderEl  = row.querySelector(".ms-Persona-primaryText, [class*='senderName']");
    var sender    = senderEl ? senderEl.innerText || "" : "";

    var subjectEl = row.querySelector("[class*='subject']");
    var subject   = subjectEl ? subjectEl.innerText || "" : "";

    var previewEl = row.querySelector("[class*='preview']");
    var snippet   = previewEl ? previewEl.innerText || "" : "";

    var fullText  = "Subject: " + subject + "\nFrom: " + sender + "\n" + snippet;

    return { sender: sender, subject: subject, text: fullText, key: createEmailKey(sender, subject) };
}


// ── BADGE MANAGEMENT ──────────────────────────────────────────

function addBadge(row, key) {
    if (document.getElementById("badge-" + key)) return;

    var badge        = document.createElement("span");
    badge.id         = "badge-" + key;
    badge.className  = "phish-row-badge phish-badge-scanning";
    badge.setAttribute("data-key", key);
    badge.innerHTML  = "⏳";
    badge.title      = "Scanning...";

    if (row.tagName == "TR") {
        var td       = document.createElement("td");
        td.className = "phish-badge-td";
        td.appendChild(badge);
        row.appendChild(td);
    } else {
        badge.classList.add("phish-badge-overlay");
        row.appendChild(badge);
    }
}

function updateBadge(key, result) {
    var badge = document.getElementById("badge-" + key);
    if (!badge) return;

    if (result.error) {
        // Show the REAL error message so we can debug
        badge.className = "phish-row-badge";
        badge.innerHTML = "⚪";
        badge.title     = "Scan error: " + (result.message || "Unknown error") +
                          "\n\nMake sure:\n1. Python server is running (python main.py)\n2. Server is on port 8000\n3. Check terminal for error details";
        return;
    }

    var level         = getRiskLevel(result);
    badge.className   = "phish-row-badge phish-badge-" + level;
    badge.innerHTML   = getRiskIcon(level);
    var pct           = Math.round(result.confidence * 100);
    badge.title       = getRiskText(level) + " (" + pct + "% confidence)\n" + result.explanation;
}


// ── SCAN EMAIL VIA API ────────────────────────────────────────

async function scanEmail(emailData, row) {
    var key = emailData.key;

    if (scanResults[key] !== undefined) {
        addBadge(row, key);
        updateBadge(key, scanResults[key]);
        return;
    }

    if (currentlyScanning[key]) return;
    currentlyScanning[key] = true;

    addBadge(row, key);

    try {
        console.log("Phishing Detector: Scanning email...", emailData.subject);

        var response = await fetch(API_URL, {
            method:  "POST",
            headers: { "Content-Type": "application/json" },
            body:    JSON.stringify({
                text:    emailData.text,
                sender:  emailData.sender,
                subject: emailData.subject
            })
        });

        console.log("Server response status:", response.status);

        if (!response.ok) {
            var errorText = await response.text();
            throw new Error("Server returned " + response.status + ": " + errorText);
        }

        var result = await response.json();
        console.log("Scan result:", result);

        scanResults[key] = result;
        updateBadge(key, result);

        chrome.runtime.sendMessage({
            type:       "SCAN_RESULT",
            isPhishing: result.is_phishing,
            riskLevel:  result.risk_level
        });

    } catch (error) {
        console.error("Phishing Detector ERROR:", error.message);
        var errorResult = { error: true, message: error.message };
        scanResults[key] = errorResult;
        updateBadge(key, errorResult);
    }

    currentlyScanning[key] = false;
}


// ── HOVER BINDING ─────────────────────────────────────────────

function bindHover(row, getDataFn) {
    if (row.getAttribute("data-hover-added") == "true") return;
    row.setAttribute("data-hover-added", "true");

    row.addEventListener("mouseenter", function() {
        clearTimeout(hoverTimer);
        hoverTimer = setTimeout(function() {
            var data = getDataFn(row);
            if (data.text && data.text.trim().length > 10) {
                scanEmail(data, row);
            }
        }, 500);
    });

    row.addEventListener("mouseleave", function() {
        clearTimeout(hoverTimer);
    });
}


// ── PROCESS ALL ROWS ──────────────────────────────────────────

function processAllRows() {
    var hostname = window.location.hostname;

    if (hostname == "mail.google.com") {
        var rows = getGmailRows();
        for (var i = 0; i < rows.length; i++) {
            bindHover(rows[i], getGmailRowData);
        }
    } else {
        var rows = getOutlookRows();
        for (var i = 0; i < rows.length; i++) {
            bindHover(rows[i], getOutlookRowData);
        }
    }
}


// ── OPEN EMAIL SCAN ───────────────────────────────────────────

function getOpenEmailText() {
    var gmailBody = document.querySelector(".a3s.aiL");
    if (gmailBody) return gmailBody.innerText;
    var outlookBody = document.querySelector(".ReadingPaneContents");
    if (outlookBody) return outlookBody.innerText;
    return null;
}

function getOpenEmailSubject() {
    var g = document.querySelector("h2.hP");
    if (g) return g.innerText;
    var o = document.querySelector('[data-testid="conversationHeaderSubject"]');
    if (o) return o.innerText;
    return "";
}

function getOpenEmailSender() {
    var g = document.querySelector(".gD");
    if (g) return g.getAttribute("email") || g.innerText;
    var o = document.querySelector('[data-testid="senderContact"] span');
    if (o) return o.innerText;
    return "";
}

function showBanner(result) {
    removeBanner();
    var level  = result.error ? "yellow" : getRiskLevel(result);
    var banner = document.createElement("div");
    banner.id  = "phish-result-banner";

    if (level == "red")    banner.className = "phish-banner phish-danger";
    else if (level == "yellow") banner.className = "phish-banner phish-warn";
    else                   banner.className = "phish-banner phish-safe";

    var pct  = result.confidence ? Math.round(result.confidence * 100) : 0;
    var inds = "";
    if (result.indicators && result.indicators.length > 0) {
        inds = "<ul class='phish-indicators'>";
        for (var i = 0; i < result.indicators.length; i++) {
            inds += "<li>" + result.indicators[i] + "</li>";
        }
        inds += "</ul>";
    }

    banner.innerHTML =
        "<div class='phish-banner-header'>" +
            "<span class='phish-icon'>" + getRiskIcon(level) + "</span>" +
            "<strong>" + getRiskText(level) + "</strong>" +
            "<span class='phish-confidence'>Confidence: " + pct + "%</span>" +
            "<button class='phish-close'>✕</button>" +
        "</div>" +
        "<p class='phish-explanation'>" + (result.explanation || "") + "</p>" +
        inds;

    banner.querySelector(".phish-close").addEventListener("click", removeBanner);
    var container = document.querySelector('[role="main"]') || document.body;
    container.insertBefore(banner, container.firstChild);
}

function removeBanner() {
    var b = document.getElementById("phish-result-banner");
    if (b) b.remove();
}

function addScanButton() {
    if (document.getElementById("phish-scan-btn")) return;
    var btn       = document.createElement("button");
    btn.id        = "phish-scan-btn";
    btn.innerHTML = "🔍 Scan for Phishing";
    btn.addEventListener("click", runManualScan);
    document.body.appendChild(btn);
}

function removeScanButton() {
    var btn = document.getElementById("phish-scan-btn");
    if (btn) btn.remove();
}

async function runManualScan() {
    var emailText = getOpenEmailText();
    if (!emailText || emailText.trim().length < 10) {
        alert("Please open an email first.");
        return;
    }

    var btn = document.getElementById("phish-scan-btn");
    if (btn) { btn.innerHTML = "⏳ Scanning..."; btn.disabled = true; }

    var subject  = getOpenEmailSubject();
    var sender   = getOpenEmailSender();
    var fullText = "Subject: " + subject + "\n" + emailText;

    try {
        var response = await fetch(API_URL, {
            method:  "POST",
            headers: { "Content-Type": "application/json" },
            body:    JSON.stringify({ text: fullText, sender: sender, subject: subject })
        });

        if (!response.ok) throw new Error("Server error " + response.status);
        var result = await response.json();
        showBanner(result);

        chrome.runtime.sendMessage({
            type: "SCAN_RESULT",
            isPhishing: result.is_phishing,
            riskLevel:  result.risk_level
        });

    } catch (error) {
        showBanner({
            error: true,
            is_phishing: false,
            confidence: 0,
            risk_level: "yellow",
            explanation: "Scan failed: " + error.message,
            indicators: []
        });
    }

    if (btn) { btn.innerHTML = "🔍 Scan for Phishing"; btn.disabled = false; }
}

function checkEmailOpen() {
    if (getOpenEmailText()) addScanButton();
    else { removeScanButton(); removeBanner(); }
}


// ── OBSERVER — watch for Gmail loading new emails ─────────────

var observer = new MutationObserver(function() {
    checkEmailOpen();
    processAllRows();
});

observer.observe(document.body, { childList: true, subtree: true });

checkEmailOpen();
processAllRows();


// ── MESSAGE LISTENER ──────────────────────────────────────────

chrome.runtime.onMessage.addListener(function(message, sender, sendResponse) {
    if (message.type == "SCAN_EMAIL") {
        runManualScan().then(function() { sendResponse({ ok: true }); });
        return true;
    }
    if (message.type == "GET_STATUS") {
        sendResponse({ emailOpen: getOpenEmailText() != null });
    }
});
