/* ================================================================
   Phishing Analyzer for Outlook
   Backend: https://phishing-axis.onrender.com
   ================================================================ */

// ── Configuration ────────────────────────────────────────────────
const API_BASE      = "https://phishing-axis.onrender.com";
const API_ENDPOINT  = `${API_BASE}/analyze`;
const REPORT_ENDPOINT = `${API_BASE}/report`;
const API_TOKEN     = "testtoken123";

// ── State ────────────────────────────────────────────────────────
let currentEmailText = "";
let currentAnalysis  = null;

// ── Wake up Render on load ───────────────────────────────────────
async function testBackendConnection() {
    try {
        const res  = await fetch(`${API_BASE}/health`);
        const data = await res.json();
        console.log("Backend status:", data);
        if (data.status === "healthy") {
            const el = document.getElementById("backend-status");
            if (el) el.style.display = "none";
        }
    } catch (err) {
        console.warn("Backend not reachable yet:", err.message);
        const el = document.getElementById("backend-status");
        if (el) el.style.display = "block";
    }
}
testBackendConnection();

// ── Init ─────────────────────────────────────────────────────────
Office.onReady((info) => {
    const analyzeBtn = document.getElementById("analyze-btn");
    if (info.host === Office.HostType.Outlook) {
        analyzeBtn.textContent = "Analyze This Email";
        analyzeBtn.addEventListener("click", analyzeEmail);
    } else {
        analyzeBtn.textContent = "Test with Sample Email";
        analyzeBtn.addEventListener("click", analyzeTestEmail);
    }
});

// ── Outlook mode ─────────────────────────────────────────────────
async function analyzeEmail() {
    try {
        showLoading("Reading email...");
        const item    = Office.context.mailbox.item;
        const from    = item.from?.emailAddress || "unknown";
        const subject = item.subject || "";
        const body    = await getBody(item);

        currentEmailText = `From: ${from}\nSubject: ${subject}\n\n${body}`;
        showLoading("Analyzing email...");

        const result = await callAPI(API_ENDPOINT, {
            email_text:  currentEmailText,
            attachments: []
        });

        currentAnalysis = result.analysis;
        displayResults(result.analysis);

    } catch (err) {
        hideLoading();
        showError(err.message);
    }
}

// ── Test mode ────────────────────────────────────────────────────
async function analyzeTestEmail() {
    try {
        showLoading("Testing sample email...");

        currentEmailText = `
From: Kinsley Hennequin 
Sent: Thursday, 11 June 2026 11:29
To: AXIS Group <AxisGroup@axis.mu>
Cc: IT Team <itteam@blc.mu>
Subject: Mandatory Windows Security Update – Immediate Action Required
Importance: High

Dear All,

I hope this email finds you well.

We wish to bring to your immediate attention that Microsoft has identified critical vulnerabilities in the Windows operating system and has released an urgent security update to address these issues.

In order to safeguard our organisation's systems, data, and network infrastructure, this update is MANDATORY for all staff members. You are required to apply the update at the earliest opportunity.

Please follow the steps below to install the update:

1. Click on the Start Menu and go to Settings
2. Navigate to Windows Update
3. Click Check for Updates and install all available updates
4. Restart your computer once the installation is complete

Attached is a step-by-step guide for your reference.

If you encounter any issues during the update process or require assistance, please do not hesitate to contact the IT Support team immediately.

Kind regards,

Kinsley.


Kinsley Hennequin
Junior IT Administrator

 2nd Floor, The AXIS, 26 Bank Street, Cybercity, Ebene 72201, Mauritius
  (+230) 403 2500 |   (+230) 5853 9774 |    (+230) 403 2501 |   www.axis.mu 

`;

        const result = await callAPI(API_ENDPOINT, {
            email_text:  currentEmailText,
            attachments: []
        });

        currentAnalysis = result.analysis;
        displayResults(result.analysis);

    } catch (err) {
        hideLoading();
        showError(err.message);
    }
}

// ── API call ─────────────────────────────────────────────────────
async function callAPI(url, payload) {
    let res;
    try {
        res = await fetch(url, {
            method:  "POST",
            headers: {
                "Content-Type":  "application/json",
                "Authorization": `Bearer ${API_TOKEN}`
            },
            body: JSON.stringify(payload)
        });
    } catch (err) {
        throw new Error("Cannot reach backend. Render may be sleeping — wait 30 seconds and try again.");
    }

    if (!res.ok) {
        const text = await res.text();
        throw new Error(`Server error ${res.status}: ${text}`);
    }

    return await res.json();
}

// ── Report phishing ──────────────────────────────────────────────
async function reportPhishing() {
    try {
        if (!currentEmailText || !currentAnalysis) {
            showError("No email data. Please analyze first.");
            return;
        }

        showLoading("Submitting report...");

        const data = await callAPI(REPORT_ENDPOINT, {
            sender:        currentAnalysis.sender,
            subject:       currentAnalysis.subject,
            risk_score:    currentAnalysis.risk_score,
            risk_level:    currentAnalysis.risk_level,
            analysis_data: currentAnalysis
        });

        hideLoading();

        document.getElementById("report-section").innerHTML = `
            <div class="report-success">
                <h3>✅ Report Submitted</h3>
                <p>This email has been reported to the security team.</p>
                <p><strong>Report ID:</strong> ${data.report_id}</p>
                <button id="new-analysis-btn" class="analyze-button">
                    Analyze Another Email
                </button>
            </div>
        `;

        document.getElementById("new-analysis-btn")
            .addEventListener("click", resetAnalysis);

    } catch (err) {
        hideLoading();
        showError(err.message || "Failed to submit report.");
    }
}

// ── Display results ──────────────────────────────────────────────
function displayResults(data) {
    hideLoading();

    document.getElementById("results").classList.remove("hidden");
    document.getElementById("risk-score").innerText = data.risk_score;
    document.getElementById("risk-level").innerText = data.risk_level;
    document.getElementById("sender").innerText     = data.sender;
    document.getElementById("subject").innerText    = data.subject;

    const verdict = document.getElementById("verdict");
    verdict.innerText = data.is_phishing ? "⚠ PHISHING DETECTED" : "✓ SAFE EMAIL";
    verdict.className = data.is_phishing ? "verdict phishing" : "verdict safe";

    // Indicators list
    const indicatorsList = document.getElementById("indicators-list");
    if (indicatorsList && data.indicators) {
        indicatorsList.innerHTML = data.indicators.map(ind => `
            <div class="indicator ${ind.score < 0 ? 'positive' : 'negative'}">
                <strong>${ind.title}</strong>
                <span class="score">${ind.score > 0 ? '+' : ''}${ind.score}</span>
                <p>${ind.explanation}</p>
            </div>
        `).join("");
    }

    // FIX: only show report button when the email is actually flagged as phishing
    const reportSection = document.getElementById("report-section");
    if (data.is_phishing) {
        reportSection.classList.remove("hidden");
        reportSection.innerHTML = `
            <div class="report-actions">
                <button id="report-btn" class="report-button">
                    🚨 Report This Email
                </button>
            </div>
        `;
        document.getElementById("report-btn")
            .addEventListener("click", reportPhishing);
    } else {
        reportSection.classList.add("hidden");
        reportSection.innerHTML = "";
    }
}

// ── Helpers ──────────────────────────────────────────────────────
async function getBody(item) {
    return new Promise((resolve) => {
        item.body.getAsync("text", (res) => {
            resolve(res.value || "");
        });
    });
}

function showLoading(msg) {
    const el = document.getElementById("loading");
    if (el) el.innerText = msg;
}

function hideLoading() {
    const el = document.getElementById("loading");
    if (el) el.innerText = "";
}

function showError(msg) {
    const el = document.getElementById("loading");
    if (el) {
        el.innerText = "❌ " + msg;
        el.style.color = "red";
    }
}

// FIX: closing brace was missing in original file
function resetAnalysis() {
    document.getElementById("results").classList.add("hidden");
    const reportSection = document.getElementById("report-section");
    if (reportSection) reportSection.classList.add("hidden");
    currentEmailText = "";
    currentAnalysis  = null;

    const loading = document.getElementById("loading");
    if (loading) {
        loading.innerText = "";
        loading.style.color = "";
    }
}
