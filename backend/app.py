import os
import uuid
import logging
from datetime import datetime, timezone
from functools import wraps

from flask import Flask, request, jsonify, g
from flask_cors import CORS
from dotenv import load_dotenv
from sqlalchemy import text
from apscheduler.schedulers.background import BackgroundScheduler

from models import db, EmailAnalysis, PhishingReport, AnomalyAlert
from analyzer import SimplePhishingAnalyzer
from anomaly_detector import AnomalyDetector

load_dotenv()

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s: %(message)s")
logger = logging.getLogger(__name__)

app = Flask(__name__)

# ── CORS ──────────────────────────────────────────────────────────
origins = [o.strip() for o in os.getenv("ALLOWED_ORIGINS", "").split(",") if o.strip()]
if not origins:
    origins = ["http://localhost:3000", "https://gilded-trifle-133800.netlify.app"]
    logger.warning("ALLOWED_ORIGINS not set — using defaults.")

CORS(app, origins=origins, allow_headers=["Content-Type", "Authorization"], methods=["GET", "POST", "OPTIONS"])

# ── Database ──────────────────────────────────────────────────────
db_url = os.getenv("DATABASE_URL", "sqlite:///phishing_analyzer.db")
if db_url.startswith("postgres://"):
    db_url = db_url.replace("postgres://", "postgresql://", 1)

app.config["SQLALCHEMY_DATABASE_URI"] = db_url
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
app.config["SECRET_KEY"] = os.getenv("SECRET_KEY", "dev-secret-change-me")
db.init_app(app)

# ── Services ──────────────────────────────────────────────────────
analyzer = SimplePhishingAnalyzer()
anomaly_detector = AnomalyDetector(min_samples=int(os.getenv("MIN_SAMPLES", 10)))

# ── Auth ──────────────────────────────────────────────────────────
def _load_tokens():
    raw = os.getenv("API_TOKENS", "").strip()
    if not raw:
        logger.warning("API_TOKENS not set — all requests will be rejected.")
        return {}
    tokens = {}
    for entry in raw.split(","):
        entry = entry.strip()
        if ":" in entry:
            token, role = entry.rsplit(":", 1)
        else:
            token, role = entry, "user"
        tokens[token.strip()] = role.strip()
    logger.info(f"Loaded {len(tokens)} API token(s).")
    return tokens

VALID_TOKENS = _load_tokens()

def require_auth(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if request.method == "OPTIONS":
            return "", 200
        header = request.headers.get("Authorization", "")
        if not header.startswith("Bearer "):
            return jsonify({"error": "Missing Authorization header"}), 401
        token = header[len("Bearer "):]
        role = VALID_TOKENS.get(token)
        if not role:
            return jsonify({"error": "Invalid API token"}), 401
        g.role = role
        return f(*args, **kwargs)
    return decorated

def require_role(*roles):
    def decorator(f):
        @wraps(f)
        def decorated(*args, **kwargs):
            if g.get("role") not in roles:
                return jsonify({"error": "Insufficient permissions"}), 403
            return f(*args, **kwargs)
        return decorated
    return decorator

# ── Routes ────────────────────────────────────────────────────────
@app.route("/health")
def health():
    try:
        db.session.execute(text("SELECT 1"))
        return jsonify({"status": "healthy", "database": "connected"})
    except Exception:
        return jsonify({"status": "unhealthy", "database": "disconnected"}), 500


@app.route("/analyze", methods=["POST"])
@require_auth
def analyze_email():
    try:
        data = request.get_json(force=True) or {}
        email_text  = data.get("email_text")
        attachments = data.get("attachments", [])

        result = analyzer.analyze(email_text, attachments)
        domain = result["sender"].split("@")[-1] if "@" in result["sender"] else "unknown"

        record = EmailAnalysis(
            sender=result["sender"],
            sender_domain=domain,
            subject=result["subject"],
            risk_score=result["risk_score"],
            risk_level=result["risk_level"],
            is_phishing=result["is_phishing"],
            importance=result["importance"],
            attachment_count=len(attachments),
            suspicious_attachment_count=(result.get("attachments") or {}).get("suspicious_count", 0),
            indicators=result["indicators"],
        )
        db.session.add(record)
        db.session.commit()

        anomaly_detector.add_analysis({**result, "sender_domain": domain})
        anomalies = anomaly_detector.detect_anomalies(app=app)

        return jsonify({"success": True, "analysis": result, "anomalies": anomalies})

    except ValueError as e:
        return jsonify({"error": str(e)}), 400
    except Exception:
        logger.exception("Error in /analyze")
        return jsonify({"error": "Internal server error"}), 500


@app.route("/report", methods=["POST"])
@require_auth
def report_phishing():
    try:
        data = request.get_json(force=True) or {}
        missing = [f for f in ["sender", "subject", "risk_score", "risk_level"] if not data.get(f)]
        if missing:
            return jsonify({"error": f"Missing fields: {', '.join(missing)}"}), 400

        report_id = str(uuid.uuid4())
        db.session.add(PhishingReport(
            report_id=report_id,
            sender=data["sender"],
            subject=data["subject"],
            risk_score=int(data["risk_score"]),
            risk_level=data["risk_level"],
            analysis_data=data.get("analysis_data"),
            status="pending",
        ))

        if data.get("analysis_id"):
            rec = EmailAnalysis.query.get(data["analysis_id"])
            if rec:
                rec.was_reported = True
                rec.report_id = report_id

        db.session.commit()
        return jsonify({"success": True, "report_id": report_id, "status": "pending"})

    except Exception:
        logger.exception("Error in /report")
        return jsonify({"error": "Internal server error"}), 500


@app.route("/reports")
@require_auth
def get_reports():
    reports = PhishingReport.query.order_by(PhishingReport.timestamp.desc()).all()
    return jsonify({"count": len(reports), "reports": [
        {"report_id": r.report_id, "sender": r.sender, "subject": r.subject,
         "risk_score": r.risk_score, "risk_level": r.risk_level, "status": r.status}
        for r in reports
    ]})


@app.route("/alerts")
@require_auth
@require_role("admin", "analyst")
def get_alerts():
    alerts = AnomalyAlert.query.filter_by(acknowledged=False).order_by(AnomalyAlert.timestamp.desc()).limit(50).all()
    return jsonify({"alerts": [
        {"id": a.id, "alert_type": a.alert_type, "severity": a.severity,
         "description": a.description, "timestamp": a.timestamp.isoformat()}
        for a in alerts
    ]})


@app.route("/alerts/<int:alert_id>/acknowledge", methods=["POST"])
@require_auth
@require_role("admin", "analyst")
def acknowledge_alert(alert_id):
    alert = AnomalyAlert.query.get_or_404(alert_id)
    alert.acknowledged    = True
    alert.acknowledged_by = g.role
    alert.acknowledged_at = datetime.now(timezone.utc)
    db.session.commit()
    return jsonify({"success": True})


# ── Analytics routes (used by dashboard) ─────────────────────────
@app.route("/api/analytics/overview")
@require_auth
def analytics_overview():
    days      = int(request.args.get("days", 30))
    total     = EmailAnalysis.query.count()
    phishing  = EmailAnalysis.query.filter_by(is_phishing=True).count()
    avg_score = db.session.query(db.func.avg(EmailAnalysis.risk_score)).scalar() or 0
    reports   = PhishingReport.query.count()
    return jsonify({
        "total_analyzed": total,
        "phishing_count": phishing,
        "safe_count":     total - phishing,
        "avg_risk_score": float(round(avg_score, 1)),
        "report_count":   reports,          # dashboard reads report_count
        "days":           days,
    })


@app.route("/api/analytics/trends")
@require_auth
def analytics_trends():
    days    = int(request.args.get("days", 30))
    records = EmailAnalysis.query.order_by(EmailAnalysis.timestamp.desc()).limit(days * 10).all()

    analyses_by_date  = {}   # { "2026-06-24": 5 }
    phishing_by_date  = {}   # { "2026-06-24": 3 }
    risk_distribution = {"HIGH": 0, "MEDIUM": 0, "LOW": 0, "SAFE": 0}

    for r in records:
        date = r.timestamp.strftime("%Y-%m-%d")
        analyses_by_date[date] = analyses_by_date.get(date, 0) + 1
        if r.is_phishing:
            phishing_by_date[date] = phishing_by_date.get(date, 0) + 1
        level = r.risk_level if r.risk_level in risk_distribution else "SAFE"
        risk_distribution[level] += 1

    # dashboard reads: data.analyses_by_date, data.phishing_by_date, data.risk_distribution
    return jsonify({
        "analyses_by_date":  analyses_by_date,
        "phishing_by_date":  phishing_by_date,
        "risk_distribution": risk_distribution,
    })


@app.route("/api/analytics/top-senders")
@require_auth
def analytics_top_senders():
    records = EmailAnalysis.query.all()
    senders = {}
    for r in records:
        s = r.sender
        if s not in senders:
            senders[s] = {"sender": s, "email_count": 0, "total_score": 0, "phishing": 0}
        senders[s]["email_count"]  += 1
        senders[s]["total_score"]  += r.risk_score
        if r.is_phishing:
            senders[s]["phishing"] += 1
    result = []
    for s in senders.values():
        result.append({
            "sender":         s["sender"],
            "email_count":    s["email_count"],
            "avg_risk_score": round(s["total_score"] / s["email_count"], 1),
            "phishing_rate":  round(s["phishing"] / s["email_count"] * 100, 1),
        })
    result.sort(key=lambda x: x["email_count"], reverse=True)
    # Plain array — dashboard calls .forEach() directly
    return jsonify(result[:10])


@app.route("/api/analytics/top-indicators")
@require_auth
def analytics_top_indicators():
    records = EmailAnalysis.query.filter_by(is_phishing=True).all()
    counts  = {}
    for r in records:
        for ind in (r.indicators or []):
            title = ind.get("title", "Unknown")
            counts[title] = counts.get(title, 0) + 1
    sorted_ind = sorted(counts.items(), key=lambda x: x[1], reverse=True)[:10]
    # Plain array — dashboard calls .forEach() directly
    return jsonify([{"indicator": t, "count": c} for t, c in sorted_ind])


@app.route("/api/analytics/recent-alerts")
@require_auth
def analytics_recent_alerts():
    limit  = int(request.args.get("limit", 10))
    alerts = AnomalyAlert.query.order_by(AnomalyAlert.timestamp.desc()).limit(limit).all()
    # Plain array — dashboard calls .forEach() directly
    return jsonify([
        {"id": a.id, "alert_type": a.alert_type, "severity": a.severity,
         "description": a.description, "timestamp": a.timestamp.isoformat(),
         "acknowledged": a.acknowledged}
        for a in alerts
    ])


# ── CORS-safe 404 handler (prevents CORS errors on missing routes) ─
@app.errorhandler(404)
def not_found(e):
    return jsonify({"error": "Route not found"}), 404


# ── Startup ───────────────────────────────────────────────────────
with app.app_context():
    db.create_all()
    logger.info("Database tables ready.")
    try:
        anomaly_detector.load_history(app)
    except Exception as e:
        logger.warning(f"Could not load anomaly history: {e}")

# Start scheduler (once, not on Werkzeug reloader child)
if os.environ.get("WERKZEUG_RUN_MAIN") != "false":
    scheduler = BackgroundScheduler(daemon=True)
    scheduler.add_job(lambda: anomaly_detector.retrain(), "interval", minutes=30, id="retrain")
    scheduler.start()
    logger.info("Scheduler started.")

# ── Entry point ───────────────────────────────────────────────────
if __name__ == "__main__":
    app.run(
        host="0.0.0.0",
        port=int(os.getenv("PORT", 5000)),
        debug=os.getenv("DEBUG", "False").lower() == "true"
    )
