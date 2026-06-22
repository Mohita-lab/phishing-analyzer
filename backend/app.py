# ================================================================
#  app.py — Phishing Analyzer API
#  AXIS IT Security  ·  v1.0
#
#  Deployed on Render.com
#  Frontend is hosted separately on Netlify
# ================================================================

from flask import Flask, request, jsonify
from flask_cors import CORS
from analyzer import SimplePhishingAnalyzer
import os
import uuid

app = Flask(__name__)

# Allow requests from Netlify frontend only
CORS(app, origins=[
    'https://gilded-trifle-133800.netlify.app/',
    'http://localhost:5000',
    'http://127.0.0.1:5000'
])

analyzer = SimplePhishingAnalyzer()


# ── Health check ─────────────────────────────────────────────────
@app.route('/health', methods=['GET'])
def health_check():
    return jsonify({
        'status':  'healthy',
        'service': 'Phishing Email Analyzer API'
    }), 200


# ── Analyze endpoint ─────────────────────────────────────────────
@app.route('/analyze', methods=['POST'])
def analyze_email():
    """
    Expects JSON:
    {
        "email_text": "full email with headers",
        "attachments": [{"name": "file.exe", "size": 1024}]
    }
    """
    try:
        data = request.get_json()

        if not data or 'email_text' not in data:
            return jsonify({'error': 'Missing email_text'}), 400

        email_text = data['email_text']

        if not email_text or not email_text.strip():
            return jsonify({'error': 'Empty email text'}), 400

        attachments = data.get('attachments', None)

        result = analyzer.analyze(email_text, attachments)

        return jsonify({
            'success':  True,
            'analysis': result
        }), 200

    except Exception as e:
        return jsonify({'error': f'Analysis failed: {str(e)}'}), 500


# ── Report endpoint ───────────────────────────────────────────────
@app.route('/report', methods=['POST'])
def report_phishing():
    """
    Expects JSON:
    {
        "email_text": "full email content",
        "analysis":   { ...analysis object from /analyze... }
    }
    """
    try:
        data = request.get_json()

        if not data or 'email_text' not in data:
            return jsonify({'error': 'Missing email_text'}), 400

        analysis  = data.get('analysis', {})
        report_id = str(uuid.uuid4())

        # Log the report — in production connect this to your
        # security ticketing system (e.g. ServiceNow, Jira)
        print(f"[PHISHING REPORT] ID: {report_id}")
        print(f"  Sender:     {analysis.get('sender',     'Unknown')}")
        print(f"  Subject:    {analysis.get('subject',    'Unknown')}")
        print(f"  Risk Score: {analysis.get('risk_score', 0)}")
        print(f"  Risk Level: {analysis.get('risk_level', 'Unknown')}")

        return jsonify({
            'success':   True,
            'report_id': report_id,
            'message':   'Email reported to security team'
        }), 200

    except Exception as e:
        return jsonify({'error': f'Report failed: {str(e)}'}), 500


# ── Local development only ────────────────────────────────────────
if __name__ == '__main__':
    port  = int(os.environ.get('PORT', 5000))
    debug = os.environ.get('DEBUG', 'False').lower() == 'true'
    print(f"Starting Phishing Analyzer API on port {port}")
    app.run(host='0.0.0.0', port=port, debug=debug)
