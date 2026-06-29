/* ================================================================
   Phishing Analyzer for Outlook
   Backend: https://phishing-axis.onrender.com
   ================================================================ */

// ── Configuration ────────────────────────────────────────────────
const API_BASE = "https://phishing-axis.onrender.com";

const API_ENDPOINT = `${API_BASE}/analyze`;
const REPORT_ENDPOINT = `${API_BASE}/report`;

const API_TOKEN = "testtoken123";

// ── State ────────────────────────────────────────────────────────
let currentEmailText = "";
let currentAnalysis = null;

// ── TEST BACKEND ON LOAD (SAFE) ──────────────────────────────────
async function testBackendConnection() {
    try {
        const res = await fetch(`${API_BASE}/health`);
        const data = await res.json();
        console.log("Backend status:", data);
    } catch (err) {
        console.warn("Backend not reachable yet:", err.message);
    }
}
testBackendConnection();

// ── INIT ─────────────────────────────────────────────────────────
Office.onReady((info) => {
    const analyzeBtn = document.getElementById("analyze-btn");
    const reportBtn = document.getElementById("report-btn");
    const cancelBtn = document.getElementById("cancel-report-btn");

    if (info.host === Office.HostType.Outlook) {
        analyzeBtn.addEventListener("click", analyzeEmail);
    } else {
        analyzeBtn.textContent = "Test with Sample Email";
        analyzeBtn.addEventListener("click", analyzeTestEmail);
    }

    if (reportBtn) reportBtn.addEventListener("click", reportPhishing);
    if (cancelBtn) cancelBtn.addEventListener("click", cancelReport);
});

// ────────────────────────────────────────────────────────────────
// OUTLOOK MODE
// ────────────────────────────────────────────────────────────────
async function analyzeEmail() {
    try {
        showLoading("Reading email...");

        const item = Office.context.mailbox.item;

        const from = item.from?.emailAddress || "unknown";
        const subject = item.subject || "";
        const body = await getBody(item);

        const emailText = `From: ${from}\nSubject: ${subject}\n\n${body}`;
        currentEmailText = emailText;

        showLoading("Analyzing email...");

        const result = await callAPI(API_ENDPOINT, {
            email_text: emailText,
            attachments: []
        });

        currentAnalysis = result.analysis;
        displayResults(result.analysis);

    } catch (err) {
        showError(err.message);
    }
}

// ────────────────────────────────────────────────────────────────
// TEST MODE
// ────────────────────────────────────────────────────────────────
async function analyzeTestEmail() {
    try {
        showLoading("Testing sample email...");

        const emailText = `
From: security@micr0soft-login.com
Subject: Urgent Account Verification

Click here immediately:
http://fake-login.xyz
`;

        currentEmailText = emailText;

        const result = await callAPI(API_ENDPOINT, {
            email_text: emailText,
            attachments: []
        });

        currentAnalysis = result.analysis;
        displayResults(result.analysis);

    } catch (err) {
        showError(err.message);
    }
}

// ────────────────────────────────────────────────────────────────
// API CALL (FIXED)
// ────────────────────────────────────────────────────────────────
async function callAPI(url, payload) {
    let res;

    try {
        res = await fetch(url, {
            method: "POST",
            headers: {
                "Content-Type": "application/json",
                "Authorization": `Bearer ${API_TOKEN}`
            },
            body: JSON.stringify(payload)
        });
    } catch (err) {
        throw new Error("Backend not reachable (Render may be sleeping)");
    }

    if (!res.ok) {
        const text = await res.text();
        throw new Error(`Server error ${res.status}: ${text}`);
    }

    return await res.json();
}

// ────────────────────────────────────────────────────────────────
// REPORT
// ────────────────────────────────────────────────────────────────
async function reportPhishing() {
    try {
        if (!currentAnalysis) {
            showError("No analysis available");
            return;
        }

        showLoading("Submitting report...");

        const res = await callAPI(REPORT_ENDPOINT, {
            sender: currentAnalysis.sender,
            subject: currentAnalysis.subject,
            risk_score: currentAnalysis.risk_score,
            risk_level: currentAnalysis.risk_level,
            analysis_data: currentAnalysis
        });

        hideLoading();

        document.getElementById("report-section").innerHTML = `
            <h3>✓ Report Submitted</h3>
            <p>Report ID: ${res.report_id}</p>
        `;

    } catch (err) {
        showError(err.message);
    }
}

function cancelReport() {
    document.getElementById("report-section").classList.add("hidden");
}

// ────────────────────────────────────────────────────────────────
// UI
// ────────────────────────────────────────────────────────────────
function displayResults(data) {
    hideLoading();

    document.getElementById("results").classList.remove("hidden");

    document.getElementById("risk-score").innerText = data.risk_score;
    document.getElementById("risk-level").innerText = data.risk_level;
    document.getElementById("sender").innerText = data.sender;
    document.getElementById("subject").innerText = data.subject;

    const verdict = document.getElementById("verdict");

    if (data.is_phishing) {
        verdict.innerText = "⚠ PHISHING DETECTED";
    } else {
        verdict.innerText = "✓ SAFE EMAIL";
    }
}

// ────────────────────────────────────────────────────────────────
// HELPERS
// ────────────────────────────────────────────────────────────────
async function getBody(item) {
    return new Promise((resolve) => {
        item.body.getAsync("text", (res) => {
            resolve(res.value || "");
        });
    });
}

function showLoading(msg) {
    document.getElementById("loading").innerText = msg;
}

function hideLoading() {
    document.getElementById("loading").innerText = "";
}

function showError(msg) {
    alert(msg);
}
