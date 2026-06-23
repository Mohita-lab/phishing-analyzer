"""
Flask application entry point.
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

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = Flask(__name__)

# ------------------------------------------------------------------
# CORS
# ------------------------------------------------------------------
_raw_origins = os.getenv('ALLOWED_ORIGINS', '')
_allowed_origins = [o.strip() for o in _raw_origins.split(',') if o.strip()]
# Fall back to permissive only in local dev (DEBUG=True)
if not _allowed_origins:
    logger.warning("ALLOWED_ORIGINS not set — defaulting to localhost only.")
    _allowed_origins = ['http://localhost:3000', 'http://localhost:5000','https://gilded-trifle-133800.netlify.app']

CORS(
    app,
    origins=_allowed_origins,
    allow_headers=["Content-Type", "Authorization"],
    methods=["GET", "POST", "OPTIONS"]
)
# ------------------------------------------------------------------
# Database
# ------------------------------------------------------------------
app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv(
    'DATABASE_URL', 'sqlite:///phishing_analyzer.db'
)
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'dev-secret-change-me')

from models import db, EmailAnalysis, PhishingReport, AnomalyAlert
db.init_app(app)

# ------------------------------------------------------------------
# Services (imported AFTER db to avoid circular issues)
# ------------------------------------------------------------------
from analyzer import SimplePhishingAnalyzer
from anomaly_detector import AnomalyDetector

analyzer         = SimplePhishingAnalyzer()
min_samples      = int(os.getenv('MIN_SAMPLES', 10))
anomaly_detector = AnomalyDetector(min_samples=min_samples)

# ------------------------------------------------------------------
# Authentication
# ------------------------------------------------------------------
def _parse_tokens() -> dict:
    """
    Build {token: role} from API_TOKENS env var.
    Format: token1:role1,token2:role2
    Returns empty dict (not an error) if unset — auth will reject all requests.
    """
    raw = os.getenv('API_TOKENS', '').strip()
    tokens = {}
    if not raw:
        logger.warning(
            "API_TOKENS is not set. All authenticated endpoints will return 401. "
            "Set API_TOKENS in your .env file."
        )
        return tokens
    for entry in raw.split(','):
        entry = entry.strip()
        if not entry:
            continue
        if ':' in entry:
            token, role = entry.rsplit(':', 1)
        else:
            token, role = entry, 'user'
        tokens[token.strip()] = role.strip()
    logger.info(f"Loaded {len(tokens)} API token(s).")
    return tokens

VALID_TOKENS = _parse_tokens()


def require_auth(f):
    @wraps(f)
    def decorated(*args, **kwargs):

        # ✅ ALLOW CORS PRELIGHT
        if request.method == "OPTIONS":
            return '', 200

        auth_header = request.headers.get('Authorization', '')
        if not auth_header.startswith('Bearer '):
            return jsonify({'error': 'Missing or malformed Authorization header'}), 401

        token = auth_header[len('Bearer '):]
        role  = VALID_TOKENS.get(token)
        if role is None:
            return jsonify({'error': 'Invalid API token'}), 401

        g.role = role
        return f(*args, **kwargs)

    return decorated


def require_role(*roles):
    """Decorator: restricts route to specific roles (apply after @require_auth)."""
    def decorator(f):
        @wraps(f)
        def decorated(*args, **kwargs):
            if getattr(g, 'role', None) not in roles:
                return jsonify({'error': 'Insufficient permissions'}), 403
            return f(*args, **kwargs)
        return decorated
    return decorator


# ------------------------------------------------------------------
# Routes
# ------------------------------------------------------------------
@app.route('/analyze', methods=['POST'])
@require_auth
def analyze_email():
    try:
        data        = request.get_json(force=True) or {}
        email_text  = data.get('email_text')
        attachments = data.get('attachments', [])

        result = analyzer.analyze(email_text, attachments)

        analysis_record = EmailAnalysis(
            sender=result['sender'],
            sender_domain=(
                result['sender'].split('@')[-1]
                if '@' in result['sender'] else 'unknown'
            ),
            subject=result['subject'],
            risk_score=result['risk_score'],
            risk_level=result['risk_level'],
            is_phishing=result['is_phishing'],
            importance=result['importance'],
            attachment_count=len(attachments),
            suspicious_attachment_count=(
                result.get('attachments') or {}
            ).get('suspicious_count', 0),
            indicators=result['indicators'],
        )
        db.session.add(analysis_record)
        db.session.commit()

        anomaly_detector.add_analysis({
            **result,
            'sender_domain': analysis_record.sender_domain,
        })
        anomalies = anomaly_detector.detect_anomalies(app=app)

        return jsonify({
            'success':   True,
            'analysis':  result,
            'anomalies': anomalies,
        })

    except ValueError as e:
        return jsonify({'error': str(e)}), 400
    except Exception as e:
        logger.exception("Unexpected error in /analyze")
        return jsonify({'error': 'Internal server error'}), 500


@app.route('/report', methods=['POST'])
@require_auth
def report_phishing():
    try:
        data = request.get_json(force=True) or {}

        required = ['sender', 'subject', 'risk_score', 'risk_level']
        missing  = [f for f in required if not data.get(f)]
        if missing:
            return jsonify({'error': f'Missing required fields: {", ".join(missing)}'}), 400

        report_id = str(uuid.uuid4())

        report = PhishingReport(
            report_id=report_id,
            sender=data['sender'],
            subject=data['subject'],
            risk_score=int(data['risk_score']),
            risk_level=data['risk_level'],
            analysis_data=data.get('analysis_data'),
            status='pending',
        )
        db.session.add(report)

        analysis_id = data.get('analysis_id')
        if analysis_id:
            record = EmailAnalysis.query.get(analysis_id)
            if record:
                record.was_reported = True
                record.report_id    = report_id

        db.session.commit()
        return jsonify({'success': True, 'report_id': report_id, 'status': 'pending'})

    except Exception as e:
        logger.exception("Unexpected error in /report")
        return jsonify({'error': 'Internal server error'}), 500


@app.route('/alerts', methods=['GET'])
@require_auth
@require_role('admin', 'analyst')
def get_alerts():
    alerts = (
        AnomalyAlert.query
        .filter_by(acknowledged=False)
        .order_by(AnomalyAlert.timestamp.desc())
        .limit(50)
        .all()
    )
    return jsonify({
        'alerts': [
            {
                'id':          a.id,
                'alert_type':  a.alert_type,
                'severity':    a.severity,
                'description': a.description,
                'timestamp':   a.timestamp.isoformat(),
                'metadata':    a.alert_metadata,
            }
            for a in alerts
        ]
    })


@app.route('/alerts/<int:alert_id>/acknowledge', methods=['POST'])
@require_auth
@require_role('admin', 'analyst')
def acknowledge_alert(alert_id: int):
    alert = AnomalyAlert.query.get_or_404(alert_id)
    alert.acknowledged    = True
    alert.acknowledged_by = g.role
    alert.acknowledged_at = datetime.now(timezone.utc)
    db.session.commit()
    return jsonify({'success': True})

@app.route('/reports', methods=['GET'])
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

@app.route('/health', methods=['GET'])
def health():
    return jsonify({'status': 'ok'})


# ------------------------------------------------------------------
# Startup — tables + history + scheduler
# ------------------------------------------------------------------
def _start_scheduler():
    """Start APScheduler only if not already running (avoids double-start in debug reload)."""
    try:
        from apscheduler.schedulers.background import BackgroundScheduler
        scheduler = BackgroundScheduler(daemon=True)

        def _retrain():
            with app.app_context():
                anomaly_detector.retrain()
                logger.info("AnomalyDetector retrained.")

        scheduler.add_job(_retrain, trigger='interval', minutes=30,
                          id='retrain', replace_existing=True)
        scheduler.start()
        logger.info("Scheduler started.")
        return scheduler
    except Exception as e:
        logger.warning(f"Scheduler could not start: {e}. Anomaly retraining disabled.")
        return None


with app.app_context():
    db.create_all()
    try:
        anomaly_detector.load_history(app)
    except Exception as e:
        logger.warning(f"Could not load anomaly history from DB: {e}. Starting fresh.")

# Only start scheduler once — not on Werkzeug's reloader child process
if os.environ.get('WERKZEUG_RUN_MAIN') != 'false':
    _scheduler = _start_scheduler()

# ------------------------------------------------------------------
# Entry point
# ------------------------------------------------------------------
if __name__ == '__main__':
    port  = int(os.getenv('PORT', 5000))
    debug = os.getenv('DEBUG', 'False').lower() == 'true'
    app.run(host='0.0.0.0', port=port, debug=debug)
