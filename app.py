"""
PhishGuard AI — Flask Backend API
Routes: /analyze, /simulate, /health
"""
from flask import Flask, request, jsonify
from flask_cors import CORS
import os

from phishing_detector import PhishingDetector
from phishing_simulator import PhishingSimulator

app = Flask(__name__)
CORS(app)  # Enable CORS for frontend

detector = PhishingDetector()
simulator = PhishingSimulator()


@app.route('/health', methods=['GET'])
def health():
    return jsonify({'status': 'online', 'version': '1.0.0', 'engine': 'PhishGuard AI'})


@app.route('/analyze', methods=['POST'])
def analyze():
    """
    Analyze a message for phishing indicators.
    Body: { "message": "string" }
    Returns: { score, level, label, indicators, highlights, ai_explanation }
    """
    data = request.get_json()
    message = data.get('message', '').strip()

    if not message:
        return jsonify({'error': 'No message provided'}), 400
    if len(message) < 5:
        return jsonify({'error': 'Message too short'}), 400

    # Run NLP detection
    result = detector.analyze(message)

    # Get AI explanation
    ai_explanation = simulator.explain_analysis(message, result)
    result['ai_explanation'] = ai_explanation

    return jsonify(result)


@app.route('/simulate', methods=['POST'])
def simulate():
    """
    Generate a phishing simulation for a given scenario.
    Body: { "scenario": "bank|job|otp|parcel|prize|gov" }
    Returns: { message, tactics, breakdown }
    """
    data = request.get_json()
    scenario = data.get('scenario', 'bank')

    valid_scenarios = ['bank', 'job', 'otp', 'parcel', 'prize', 'gov']
    if scenario not in valid_scenarios:
        return jsonify({'error': f'Invalid scenario. Choose from: {", ".join(valid_scenarios)}'}), 400

    result = simulator.generate(scenario)
    return jsonify(result)


@app.route('/tips', methods=['GET'])
def tips():
    """Return all security awareness tips."""
    all_tips = [
        {'icon': '🔐', 'title': 'Never Share OTP or Passwords',
         'desc': 'No legitimate bank, company, or service will ever ask for your OTP, password, or PIN via email or SMS.'},
        {'icon': '🔍', 'title': 'Verify the Sender Domain',
         'desc': 'Check the actual email domain — suspicious TLDs and typosquatted domains are major red flags.'},
        {'icon': '🔗', 'title': 'Hover Before You Click',
         'desc': 'Hover over links to see the real URL. Shortened links can hide malicious destinations.'},
        {'icon': '📞', 'title': 'Call to Verify',
         'desc': 'If you receive an alert about your bank or service, call the official number from their website.'},
        {'icon': '⏱', 'title': "Don't Rush — Urgency = Red Flag",
         'desc': 'Artificial deadlines are a manipulation tactic. Take time to verify before acting.'},
        {'icon': '🛡', 'title': 'Enable Two-Factor Authentication',
         'desc': 'Use an authenticator app for 2FA — this protects you even if your password is stolen.'},
    ]
    return jsonify({'tips': all_tips})


if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    debug = os.environ.get('FLASK_DEBUG', 'false').lower() == 'true'
    print(f"🛡  PhishGuard AI Backend running on port {port}")
    app.run(host='0.0.0.0', port=port, debug=debug)
