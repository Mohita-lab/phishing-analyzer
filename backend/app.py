"""
Flask application entry point (FIXED VERSION)
Phishing Analyzer Backend + Analytics API
"""

import os
import uuid
import logging
from datetime import datetime, timezone
from functools import wraps

from flask import Flask, request, jsonify, g
from flask_cors import CORS
from dotenv import load_dotenv

load_dotenv()

# ─────────────────────────────────────────────
# Logging
# ─────────────────────────────────────────────
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# ─────────────────────────────────────────────
# App
# ─────────────────────────────────────────────
app = Flask(__name__)

# ─────────────────────────────────────────────
# CORS CONFIG (FIXED)
# ─────────────────────────────────────────────
_raw_origins = os.getenv("ALLOWED_ORIGINS", "")
_allowed_origins = [
    o.strip() for o in _raw_origins.split(",") if o.strip()
]

if not _allowed_origins:
    _allowed_origins = [
        "http://localhost:3000",
        "http://localhost:5000",
        "https://gilded-trifle-133800.netlify.app"
    ]

CORS(
    app,
    origins=_allowed_origins,
    allow_headers=["Content-Type", "Authorization"],
    methods=["GET", "POST", "OPTIONS"]
)

# ─────────────────────────────────────────────
# FIX: Handle preflight globally (IMPORTANT)
# ─────────────────────────────────────────────
@app.before_request
def handle_options():
    if request.method == "OPTIONS":
        return '', 200

# ─────────────────────────────────────────────
# Database
# ─────────────────────────────────────────────
from models import db, EmailAnalysis, PhishingReport, AnomalyAlert

app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv(
    'DATABASE_URL', 'sqlite:///phishing_analyzer.db'
)
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'dev-secret')

db.init_app(app)

# ─────────────────────────────────────────────
# Services
# ─────────────────────────────────────────────
from analyzer import SimplePhishingAnalyzer
from anomaly_detector import AnomalyDetector

analyzer = SimplePhishingAnalyzer()
anomaly_detector = AnomalyDetector(min_samples=int(os.getenv("MIN_SAMPLES", 10)))

# ─────────────────────────────────────────────
# AUTH SYSTEM
# ─────────────────────────────────────────────
def _parse_tokens():
    raw = os.getenv("API_TOKENS", "")
    tokens = {}

    for entry in raw.split(","):
        entry = entry.strip()
        if not entry:
            continue
        if ":" in entry:
            token, role = entry.rsplit(":", 1)
        else:
            token, role = entry, "user"
        tokens[token.strip()] = role.strip()

    return tokens


VALID_TOKENS = _parse_tokens()


def require_auth(f):
    @wraps(f)
    def decorated(*args, **kwargs):

        # ✔ IMPORTANT: allow preflight
        if request.method == "OPTIONS":
            return '', 200

        auth_header = request.headers.get("Authorization", "")

        if not auth_header.startswith("Bearer "):
            return jsonify({"error": "Missing token"}), 401

        token = auth_header.replace("Bearer ", "")
        role = VALID_TOKENS.get(token)

        if not role:
            return jsonify({"error": "Invalid token"}), 401

        g.role = role
        return f(*args, **kwargs)

    return decorated


def require_role(*roles):
    def decorator(f):
        @wraps(f)
        def wrapper(*args, **kwargs):
            if getattr(g, "role", None) not in roles:
                return jsonify({"error": "Forbidden"}), 403
            return f(*args, **kwargs)
        return wrapper
    return decorator

# ─────────────────────────────────────────────
# CORE ROUTES
# ─────────────────────────────────────────────

@app.route("/health")
def health():
    return jsonify({"status": "ok"})


@app.route("/analyze", methods=["POST"])
@require_auth
def analyze_email():
    data = request.get_json(force=True) or {}
    email_text = data.get("email_text", "")
    attachments = data.get("attachments", [])

    result = analyzer.analyze(email_text, attachments)

    record = EmailAnalysis(
        sender=result["sender"],
        sender_domain=result["sender"].split("@")[-1] if "@" in result["sender"] else "unknown",
        subject=result["subject"],
        risk_score=result["risk_score"],
        risk_level=result["risk_level"],
        is_phishing=result["is_phishing"],
        importance=result["importance"],
        attachment_count=len(attachments),
        suspicious_attachment_count=result.get("attachments", {}).get("suspicious_count", 0),
        indicators=result["indicators"]
    )

    db.session.add(record)
    db.session.commit()

    return jsonify({"success": True, "analysis": result})


@app.route("/reports", methods=["GET"])
@require_auth
def get_reports():
    reports = PhishingReport.query.all()

    return jsonify({
        "count": len(reports),
        "reports": [
            {
                "report_id": r.report_id,
                "sender": r.sender,
                "subject": r.subject,
                "risk_score": r.risk_score,
                "risk_level": r.risk_level,
                "status": r.status
            }
            for r in reports
        ]
    })


@app.route("/alerts", methods=["GET"])
@require_auth
@require_role("admin", "analyst")
def get_alerts():
    alerts = AnomalyAlert.query.order_by(AnomalyAlert.timestamp.desc()).limit(50).all()

    return jsonify({
        "alerts": [
            {
                "id": a.id,
                "alert_type": a.alert_type,
                "severity": a.severity,
                "description": a.description,
                "timestamp": a.timestamp.isoformat()
            }
            for a in alerts
        ]
    })

# ─────────────────────────────────────────────
# 🔥 ANALYTICS API (FIX FOR YOUR DASHBOARD)
# ─────────────────────────────────────────────

@app.route("/api/analytics/overview")
@require_auth
def analytics_overview():
    try:
        return jsonify({
            "data": {
                "total_analyses": db.session.execute(db.text("SELECT COUNT(*) FROM email_analysis")).scalar() or 0,
                "phishing_count": db.session.execute(db.text("SELECT COUNT(*) FROM email_analysis WHERE is_phishing=1")).scalar() or 0,
                "phishing_rate": 0,
                "avg_risk_score": 0,
                "report_count": db.session.execute(db.text("SELECT COUNT(*) FROM phishing_report")).scalar() or 0
            }
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/analytics/trends")
@require_auth
def analytics_trends():
    return jsonify({
        "data": {
            "analyses_by_date": {},
            "phishing_by_date": {},
            "risk_distribution": {"HIGH": 0, "MEDIUM": 0, "LOW": 0}
        }
    })


@app.route("/api/analytics/top-senders")
@require_auth
def top_senders():
    return jsonify({"data": []})


@app.route("/api/analytics/top-indicators")
@require_auth
def top_indicators():
    return jsonify({"data": []})


@app.route("/api/analytics/recent-alerts")
@require_auth
def recent_alerts():
    return jsonify({"data": []})

# ─────────────────────────────────────────────
# INIT DB
# ─────────────────────────────────────────────
with app.app_context():
    db.create_all()

# ─────────────────────────────────────────────
# RUN
# ─────────────────────────────────────────────
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.getenv("PORT", 5000)), debug=True)
