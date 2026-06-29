/* ================================================================
   taskpane.js — Phishing Analyzer for Outlook
   AXIS IT Security  ·  v1.0

   Frontend: https://github.com/Mohita-lab/phishing-analyzer/blob/main/frontend/taskpane.js
   Backend:  https://phishing-axis.onrender.com
   ================================================================ */

// ── Configuration ────────────────────────────────────────────────
const API_BASE        = 'https://phishing-axis.onrender.com';
const API_ENDPOINT    = `${API_BASE}/analyze`;
const REPORT_ENDPOINT = `${API_BASE}/report`;
const API_TOKEN = 'testtoken123';

fetch(`${API_BASE}/api/analytics/top-indicators`, {
    method: "GET",
    headers: {
        "Authorization": "Bearer testtoken123",
        "Content-Type": "application/json"
    }
})
.then(r => r.json())
.then(console.log)
.catch(console.error);

// ── State ────────────────────────────────────────────────────────
let currentEmailText = '';
let currentAnalysis  = null;

// ── Office.js Initialization ─────────────────────────────────────
Office.onReady((info) => {
    const analyzeBtn = document.getElementById('analyze-btn');
    const reportBtn  = document.getElementById('report-btn');
    const cancelBtn  = document.getElementById('cancel-report-btn');

    if (info.host === Office.HostType.Outlook) {
        analyzeBtn.addEventListener('click', analyzeEmail);
    } else {
        analyzeBtn.textContent = 'Test with Sample Email';
        analyzeBtn.addEventListener('click', analyzeTestEmail);
    }

    if (reportBtn) reportBtn.addEventListener('click', reportPhishing);
    if (cancelBtn) cancelBtn.addEventListener('click', cancelReport);
});

// ════════════════════════════════════════════════════════════════
// OUTLOOK MODE — reads the real open email via Office.js
// ════════════════════════════════════════════════════════════════
async function analyzeEmail() {
    try {
        showLoading('Reading email…');

        const item = Office.context.mailbox.item;

        const fromDisplay = item.from ? (item.from.displayName || '') : '';
        const fromEmail   = item.from ? (item.from.emailAddress  || '') : '';
        const fromField   = fromEmail
            ? `${fromDisplay} <${fromEmail}>`
            : fromDisplay || 'Unknown';

        const toField = item.to
            ? item.to.map(r => r.emailAddress
                ? `${r.displayName || ''} <${r.emailAddress}>`
                : r.displayName).join(', ')
            : '';

        const ccField = item.cc
            ? item.cc.map(r => r.emailAddress
                ? `${r.displayName || ''} <${r.emailAddress}>`
                : r.displayName).join(', ')
            : '';

        const subject     = item.subject    || '';
        const importance  = item.importance || 'normal';
        const body        = await getItemBody(item);
        const attachments = getAttachments(item);

        const emailText = buildEmailText({ fromField, toField, ccField, subject, importance, body });
        currentEmailText = emailText;

        showLoading('Analysing…');
        const result = await postToBackend(API_ENDPOINT, { email_text: emailText, attachments });
        currentAnalysis = result;
        displayResults(result);

    } catch (err) {
        console.error('analyzeEmail error:', err);
        showError(err.message || 'Failed to analyse the email. Please try again.');
    }
}

// ════════════════════════════════════════════════════════════════
// BROWSER TEST MODE
// ════════════════════════════════════════════════════════════════
async function analyzeTestEmail() {
    try {
        showLoading('Analysing sample email…');

        const emailText = `From: Microsoft Security no-reply@ms-security-alerts.com
To: Employee employee@company.com
Subject: Immediate Action Required: Account Will Be Suspended

Dear User,

We detected unusual sign-in activity on your Microsoft account.

To protect your data, your mailbox has been temporarily restricted.

Please verify your identity immediately to restore access:

🔗 http://login-microsoft-secureverify.com

If you do not complete verification within 24 hours, your account will be permanently suspended.

Microsoft Security Team
`;

        currentEmailText = emailText;
        const result = await postToBackend(API_ENDPOINT, {
            email_text:  emailText,
            attachments: []
        });
        currentAnalysis = result;
        displayResults(result);

    } catch (err) {
        console.error('analyzeTestEmail error:', err);
        showError(err.message);
    }
}

// ════════════════════════════════════════════════════════════════
// HELPERS
// ════════════════════════════════════════════════════════════════

function getItemBody(item) {
    return new Promise((resolve, reject) => {
        item.body.getAsync(Office.CoercionType.Text, result => {
            if (result.status === Office.AsyncResultStatus.Succeeded) {
                resolve(result.value);
            } else {
                reject(new Error('Could not read email body: ' + result.error.message));
            }
        });
    });
}

function getAttachments(item) {
    if (!item.attachments || item.attachments.length === 0) return [];
    return item.attachments.map(a => ({ name: a.name, size: a.size || 0 }));
}

function buildEmailText({ fromField, toField, ccField, subject, importance, body }) {
    return [
        `From: ${fromField}`,
        `Sent: ${new Date().toUTCString()}`,
        `To: ${toField}`,
        `Cc: ${ccField}`,
        `Subject: ${subject}`,
        `Importance: ${capitalise(importance)}`,
        '',
        body
    ].join('\n');
}

// ════════════════════════════════════════════════════════════════
// API CALLS
// ════════════════════════════════════════════════════════════════

async function postToBackend(url, payload) {
    let response;

    try {
        response = await fetch(url, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'Authorization': `Bearer ${API_TOKEN}`
            },
            body: JSON.stringify(payload)
        });
    } catch (networkErr) {
        throw new Error(
            'Cannot reach the backend server.\n\n' +
            'Note: Render free tier sleeps after inactivity.\n' +
            'Wait 30 seconds and try again.'
        );
    }

    if (response.status === 401) {
        const errorText = await response.text();
        console.error('Authentication Error:', errorText);

        throw new Error(
            'Authentication failed (401).\n' +
            'Verify that API_TOKEN in taskpane.js matches API_TOKENS on Render.'
        );
    }

    if (!response.ok) {
        const errorText = await response.text();
        console.error('Server Error:', errorText);

        throw new Error(
            `Server error ${response.status} — ${errorText}`
        );
    }

    const data = await response.json();

    if (!data.success) {
        throw new Error(data.error || 'Analysis failed.');
    }

    return data.analysis !== undefined ? data.analysis : data;
}

async function reportPhishing() {
    try {
        if (!currentEmailText || !currentAnalysis) {
            showError('No email data available. Please analyse the email first.');
            return;
        }

        showLoading('Submitting report…');

    const data = await postToBackend(REPORT_ENDPOINT, {
        sender: currentAnalysis.sender,
        subject: currentAnalysis.subject,
        risk_score: currentAnalysis.risk_score,
        risk_level: currentAnalysis.risk_level,
        analysis_data: currentAnalysis
    });

        hideLoading();

        document.getElementById('report-section').innerHTML = `
            <div class="report-success">
                <h3>✓ Report Submitted</h3>
                <p>This email has been reported to the security team.</p>
                <p class="report-id">Report ID: ${escHtml(data.report_id || '')}</p>
                <button id="new-analysis-btn" class="analyze-button">Analyse Another Email</button>
            </div>`;

        document.getElementById('new-analysis-btn')
            .addEventListener('click', resetAnalysis);

    } catch (err) {
        console.error('reportPhishing error:', err);
        showError(err.message || 'Failed to submit report.');
    }
}

function cancelReport() {
    document.getElementById('report-section').classList.add('hidden');
}

function resetAnalysis() {
    document.getElementById('results').classList.add('hidden');
    document.getElementById('initial-state').classList.remove('hidden');
    document.getElementById('error').classList.add('hidden');
    currentEmailText = '';
    currentAnalysis  = null;
}

// ════════════════════════════════════════════════════════════════
// UI — render results
// ════════════════════════════════════════════════════════════════

function displayResults(analysis) {
    hideLoading();
    document.getElementById('initial-state').classList.add('hidden');
    document.getElementById('error').classList.add('hidden');
    document.getElementById('results').classList.remove('hidden');

    const verdictEl = document.getElementById('verdict');
    if (analysis.is_phishing) {
        verdictEl.textContent = '⚠ LIKELY PHISHING';
        verdictEl.className   = 'verdict phishing';
    } else {
        verdictEl.textContent = '✓ LIKELY SAFE';
        verdictEl.className   = 'verdict safe';
    }

    document.getElementById('risk-score').textContent = analysis.risk_score;
    const levelEl = document.getElementById('risk-level');
    levelEl.textContent = analysis.risk_level;
    levelEl.className   = 'level ' + analysis.risk_level.toLowerCase();

    document.getElementById('sender').textContent     = analysis.sender     || '—';
    document.getElementById('subject').textContent    = analysis.subject    || '—';
    document.getElementById('importance').textContent = analysis.importance || '—';

    const reportSection = document.getElementById('report-section');
    if (analysis.is_phishing) {
        reportSection.classList.remove('hidden');
        reportSection.innerHTML = `
            <div class="report-warning">
                <h3>⚠ High Risk Detected</h3>
                <p>This email shows signs of being a phishing attempt.</p>
            </div>
            <div class="report-actions">
                <button id="report-btn" class="report-button">Report to Security</button>
                <button id="cancel-report-btn" class="cancel-button">Cancel</button>
            </div>`;
        document.getElementById('report-btn')
            .addEventListener('click', reportPhishing);
        document.getElementById('cancel-report-btn')
            .addEventListener('click', cancelReport);
    } else {
        reportSection.classList.add('hidden');
    }

    const list = document.getElementById('indicators-list');
    list.innerHTML = '';

    if (analysis.indicators && analysis.indicators.length > 0) {
        const sorted = [...analysis.indicators].sort((a, b) => b.score - a.score);
        sorted.forEach(ind => {
            const cls  = ind.score < 0 ? 'negative' : 'positive';
            const sign = ind.score >= 0 ? '+' : '';
            const el   = document.createElement('div');
            el.className = `indicator ${cls}`;
            el.innerHTML = `
                <div class="indicator-header">
                    <span class="indicator-title">${escHtml(ind.title)}</span>
                    <span class="indicator-score">${sign}${ind.score}</span>
                </div>
                <div class="indicator-explanation">${escHtml(ind.explanation)}</div>`;
            list.appendChild(el);
        });
    } else {
        list.innerHTML = '<p class="no-indicators">No phishing indicators detected.</p>';
    }

    displayAttachments(analysis.attachments);
}

function displayAttachments(attachmentAnalysis) {
    const section = document.getElementById('attachments-section');
    const list    = document.getElementById('attachments-list');

    if (!attachmentAnalysis || attachmentAnalysis.total_count === 0) {
        section.classList.add('hidden');
        return;
    }

    section.classList.remove('hidden');
    list.innerHTML = `
        <div class="attachments-summary">
            <span class="summary-text">
                Total: ${attachmentAnalysis.total_count} &nbsp;|&nbsp;
                Safe: ${attachmentAnalysis.safe_count} &nbsp;|&nbsp;
                Suspicious: <span class="suspicious-count">
                    ${attachmentAnalysis.suspicious_count}
                </span>
            </span>
        </div>`;

    attachmentAnalysis.details.forEach(att => {
        const cls      = att.is_suspicious ? 'suspicious' : 'safe';
        const sizeText = att.size > 0
            ? `${(att.size / 1024).toFixed(1)} KB`
            : 'Unknown size';
        const reasons  = att.reasons && att.reasons.length > 0
            ? '<div class="attachment-reasons">' +
              att.reasons.map(r =>
                  `<span class="reason">${escHtml(r)}</span>`
              ).join('') +
              '</div>'
            : '';

        const el = document.createElement('div');
        el.className = `attachment-item ${cls}`;
        el.innerHTML = `
            <div class="attachment-header">
                <span class="attachment-name">📎 ${escHtml(att.name)}</span>
                <span class="attachment-size">${sizeText}</span>
            </div>
            ${reasons}`;
        list.appendChild(el);
    });
}

// ════════════════════════════════════════════════════════════════
// UI STATE HELPERS
// ════════════════════════════════════════════════════════════════

function showLoading(msg = 'Loading…') {
    document.getElementById('initial-state').classList.add('hidden');
    document.getElementById('results').classList.add('hidden');
    document.getElementById('error').classList.add('hidden');
    document.getElementById('loading').classList.remove('hidden');
    const loadingText = document.getElementById('loading-text');
    if (loadingText) loadingText.textContent = msg;
}

function hideLoading() {
    document.getElementById('loading').classList.add('hidden');
}

function showError(message) {
    hideLoading();
    document.getElementById('initial-state').classList.remove('hidden');
    document.getElementById('error').classList.remove('hidden');
    document.getElementById('error-text').innerText = message;
}

// ════════════════════════════════════════════════════════════════
// UTILITIES
// ════════════════════════════════════════════════════════════════

function escHtml(str) {
    return String(str || '')
        .replace(/&/g,  '&amp;')
        .replace(/</g,  '&lt;')
        .replace(/>/g,  '&gt;')
        .replace(/"/g,  '&quot;');
}

function capitalise(str) {
    return str.charAt(0).toUpperCase() + str.slice(1).toLowerCase();
}
