"""
"""
import os
import uuid
import logging
from datetime import datetime, timezone
from functools import wraps

from flask import Flask, request, jsonify, g
from flask_cors import CORS
from dotenv import load_dotenv
from sqlalchemy import text

load_dotenv()

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(name)s: %(message)s"
)

logger = logging.getLogger(__name__)

app = Flask(__name__)

# ------------------------------------------------------------------
# CORS
# ------------------------------------------------------------------

_raw_origins = os.getenv("ALLOWED_ORIGINS", "")
_allowed_origins = [
    origin.strip()
    for origin in _raw_origins.split(",")
    if origin.strip()
]

if not _allowed_origins:
    logger.warning(
        "ALLOWED_ORIGINS not set. Using development defaults."
    )

    _allowed_origins = [
        "http://localhost:3000",
        "http://localhost:5000",
        "https://gilded-trifle-133800.netlify.app"
    ]

CORS(
    app,
    origins=_allowed_origins,
    allow_headers=[
        "Content-Type",
        "Authorization"
    ],
    methods=[
        "GET",
        "POST",
        "OPTIONS"
    ]
)

# ------------------------------------------------------------------
# Database Configuration
# ------------------------------------------------------------------

database_url = os.getenv("DATABASE_URL")

if not database_url:
    raise ValueError(
        "DATABASE_URL environment variable is required"
    )

# Render compatibility
if database_url.startswith("postgres://"):
    database_url = database_url.replace(
        "postgres://",
        "postgresql://",
        1
    )

app.config["SQLALCHEMY_DATABASE_URI"] = database_url

app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

app.config["SQLALCHEMY_ENGINE_OPTIONS"] = {
    "pool_pre_ping": True,
    "pool_recycle": 300,
    "pool_size": 5,
    "max_overflow": 10
}

app.config["SECRET_KEY"] = os.getenv(
    "SECRET_KEY",
    "dev-secret-change-me"
)

# ------------------------------------------------------------------
# Models
# ------------------------------------------------------------------

from models import (
    db,
    EmailAnalysis,
    PhishingReport,
    AnomalyAlert
)

db.init_app(app)

# ------------------------------------------------------------------
# Services
# ------------------------------------------------------------------

from analyzer import SimplePhishingAnalyzer
from anomaly_detector import AnomalyDetector

analyzer = SimplePhishingAnalyzer()

min_samples = int(
    os.getenv("MIN_SAMPLES", 10)
)

anomaly_detector = AnomalyDetector(
    min_samples=min_samples
)

# ------------------------------------------------------------------
# Authentication
# ------------------------------------------------------------------

def _parse_tokens() -> dict:
    """
    Build token-role mapping.

    Format:
    API_TOKENS=token1:admin,token2:user
    """

    raw = os.getenv("API_TOKENS", "").strip()

    tokens = {}

    if not raw:
        logger.warning(
            "API_TOKENS not configured. "
            "Authenticated endpoints will reject requests."
        )
        return tokens

    for entry in raw.split(","):

        entry = entry.strip()

        if not entry:
            continue

        if ":" in entry:
            token, role = entry.rsplit(":", 1)
        else:
            token = entry
            role = "user"

        tokens[token.strip()] = role.strip()

    logger.info(
        f"Loaded {len(tokens)} API token(s)"
    )

    return tokens


VALID_TOKENS = _parse_tokens()


def require_auth(f):

    @wraps(f)
    def decorated(*args, **kwargs):

        if request.method == "OPTIONS":
            return "", 200

        auth_header = request.headers.get(
            "Authorization",
            ""
        )

        if not auth_header.startswith("Bearer "):
            return jsonify({
                "error":
                "Missing or malformed Authorization header"
            }), 401

        token = auth_header[len("Bearer "):]

        role = VALID_TOKENS.get(token)

        if role is None:
            return jsonify({
                "error": "Invalid API token"
            }), 401

        g.role = role

        return f(*args, **kwargs)

    return decorated


def require_role(*roles):

    def decorator(f):

        @wraps(f)
        def decorated(*args, **kwargs):

            if getattr(g, "role", None) not in roles:
                return jsonify({
                    "error":
                    "Insufficient permissions"
                }), 403

            return f(*args, **kwargs)

        return decorated

    return decorator

# ------------------------------------------------------------------
# Analyze Email
# ------------------------------------------------------------------

@app.route("/analyze", methods=["POST"])
@require_auth
def analyze_email():

    try:

        data = request.get_json(force=True) or {}

        email_text = data.get("email_text")

        attachments = data.get(
            "attachments",
            []
        )

        result = analyzer.analyze(
            email_text,
            attachments
        )

        sender_domain = (
            result["sender"].split("@")[-1]
            if "@" in result["sender"]
            else "unknown"
        )

        analysis_record = EmailAnalysis(
            sender=result["sender"],
            sender_domain=sender_domain,
            subject=result["subject"],
            risk_score=result["risk_score"],
            risk_level=result["risk_level"],
            is_phishing=result["is_phishing"],
            importance=result["importance"],
            attachment_count=len(
                attachments
            ),
            suspicious_attachment_count=(
                result.get("attachments") or {}
            ).get(
                "suspicious_count",
                0
            ),
            indicators=result["indicators"]
        )

        db.session.add(
            analysis_record
        )

        db.session.commit()

        anomaly_detector.add_analysis({
            **result,
            "sender_domain":
            sender_domain
        })

        anomalies = (
            anomaly_detector.detect_anomalies(
                app=app
            )
        )

        return jsonify({
            "success": True,
            "analysis": result,
            "anomalies": anomalies
        })

    except ValueError as e:

        return jsonify({
            "error": str(e)
        }), 400

    except Exception as e:

        logger.exception(
            "Unexpected error in /analyze"
        )

        return jsonify({
            "error":
            "Internal server error"
        }), 500


# ------------------------------------------------------------------
# Report Phishing
# ------------------------------------------------------------------

@app.route("/report", methods=["POST"])
@require_auth
def report_phishing():

    try:

        data = request.get_json(
            force=True
        ) or {}

        required = [
            "sender",
            "subject",
            "risk_score",
            "risk_level"
        ]

        missing = [
            field
            for field in required
            if not data.get(field)
        ]

        if missing:
            return jsonify({
                "error":
                f"Missing required fields: {', '.join(missing)}"
            }), 400

        report_id = str(
            uuid.uuid4()
        )

        report = PhishingReport(
            report_id=report_id,
            sender=data["sender"],
            subject=data["subject"],
            risk_score=int(
                data["risk_score"]
            ),
            risk_level=data[
                "risk_level"
            ],
            analysis_data=data.get(
                "analysis_data"
            ),
            status="pending"
        )

        db.session.add(report)

        analysis_id = data.get(
            "analysis_id"
        )

        if analysis_id:

            record = (
                EmailAnalysis.query.get(
                    analysis_id
                )
            )

            if record:
                record.was_reported = True
                record.report_id = report_id

        db.session.commit()

        return jsonify({
            "success": True,
            "report_id": report_id,
            "status": "pending"
        })

    except Exception:

        logger.exception(
            "Unexpected error in /report"
        )

        return jsonify({
            "error":
            "Internal server error"
        }), 500


# ------------------------------------------------------------------
# Alerts
# ------------------------------------------------------------------

@app.route("/alerts", methods=["GET"])
@require_auth
@require_role(
    "admin",
    "analyst"
)
def get_alerts():

    alerts = (
        AnomalyAlert.query
        .filter_by(
            acknowledged=False
        )
        .order_by(
            AnomalyAlert.timestamp.desc()
        )
        .limit(50)
        .all()
    )

    return jsonify({
        "alerts": [
            {
                "id": a.id,
                "alert_type":
                    a.alert_type,
                "severity":
                    a.severity,
                "description":
                    a.description,
                "timestamp":
                    a.timestamp.isoformat(),
                "metadata":
                    a.alert_metadata
            }
            for a in alerts
        ]
    })


@app.route(
    "/alerts/<int:alert_id>/acknowledge",
    methods=["POST"]
)
@require_auth
@require_role(
    "admin",
    "analyst"
)
def acknowledge_alert(alert_id):

    alert = (
        AnomalyAlert.query
        .get_or_404(alert_id)
    )

    alert.acknowledged = True

    alert.acknowledged_by = g.role

    alert.acknowledged_at = (
        datetime.now(
            timezone.utc
        )
    )

    db.session.commit()

    return jsonify({
        "success": True
    })

# ------------------------------------------------------------------
# Reports
# ------------------------------------------------------------------

@app.route("/reports", methods=["GET"])
@require_auth
def get_reports():

    reports = (
        PhishingReport.query.all()
    )

    return jsonify({
        "count": len(reports),
        "reports": [
            {
                "report_id":
                    r.report_id,
                "sender":
                    r.sender,
                "subject":
                    r.subject,
                "risk_score":
                    r.risk_score,
                "risk_level":
                    r.risk_level,
                "status":
                    r.status
            }
            for r in reports
        ]
    })


# ------------------------------------------------------------------
# Health Check
# ------------------------------------------------------------------

@app.route("/health", methods=["GET"])
def health():

    try:

        db.session.execute(
            text("SELECT 1")
        )

        return jsonify({
            "status": "healthy",
            "database":
            "connected"
        })

    except Exception as e:

        logger.exception(
            f"Health check failed: {e}"
        )

        return jsonify({
            "status":
            "unhealthy",
            "database":
            "disconnected"
        }), 500


# ------------------------------------------------------------------
# Scheduler
# ------------------------------------------------------------------

def _start_scheduler():

    try:

        from apscheduler.schedulers.background import (
            BackgroundScheduler
        )

        scheduler = (
            BackgroundScheduler(
                daemon=True
            )
        )

        def _retrain():

            with app.app_context():

                anomaly_detector.retrain()

                logger.info(
                    "AnomalyDetector retrained."
                )

        scheduler.add_job(
            _retrain,
            trigger="interval",
            minutes=30,
            id="retrain",
            replace_existing=True
        )

        scheduler.start()

        logger.info(
            "Scheduler started."
        )

        return scheduler

    except Exception as e:

        logger.warning(
            f"Scheduler disabled: {e}"
        )

        return None


# ------------------------------------------------------------------
# Startup
# ------------------------------------------------------------------

with app.app_context():

    try:

        logger.info(
            "Connecting to PostgreSQL..."
        )

        db.session.execute(
            text("SELECT 1")
        )

        logger.info(
            "PostgreSQL connection successful."
        )

        db.create_all()

        logger.info(
            "Database tables ready."
        )

    except Exception as e:

        logger.exception(
            f"Database startup failure: {e}"
        )

        raise

    try:

        anomaly_detector.load_history(
            app
        )

        logger.info(
            "Anomaly history loaded."
        )

    except Exception as e:

        logger.warning(
            f"Could not load anomaly history: {e}"
        )


# ------------------------------------------------------------------
# Start scheduler once
# ------------------------------------------------------------------

if os.environ.get(
    "WERKZEUG_RUN_MAIN"
) != "false":

    _scheduler = (
        _start_scheduler()
    )


# ------------------------------------------------------------------
# Entry Point
# ------------------------------------------------------------------

if __name__ == "__main__":

    port = int(
        os.getenv(
            "PORT",
            5000
        )
    )

    debug = (
        os.getenv(
            "DEBUG",
            "False"
        ).lower() == "true"
    )

    logger.info(
        f"Starting server on port {port}"
    )

    app.run(
        host="0.0.0.0",
        port=port,
        debug=debug
    )
