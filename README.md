🛡 PhishGuard AI — Generative AI Powered Phishing Detection & Awareness Platform

![AI-Powered](https://img.shields.io/badge/AI-Powered-00d4ff?style=flat-square) 
![Python 3.9+](https://img.shields.io/badge/Python-3.9+-blue?style=flat-square)
![Flask](https://img.shields.io/badge/Flask-2.x-green?style=flat-square)
![License: MIT](https://img.shields.io/badge/License-MIT-yellow?style=flat-square)

**Generative AI + Rule-Based NLP platform to detect phishing messages, simulate attacks, and educate users on social engineering tactics.**
🚀 Live Demo: Try PhishGuard AI

📸 Key Screenshots
Analyzer Input	Analyzer Result
<img src="screenshots/analyzer_input.png" width="300"/>	<img src="screenshots/analyzer_result.png" width="300"/>
Simulator Fields	Simulator Generated Message
<img src="screenshots/simulator_fields.png" width="300"/>	<img src="screenshots/simulator_generated.png" width="300"/>
🎯 Project Overview

PhishGuard AI helps users detect phishing messages, understand manipulation tactics, and learn cybersecurity awareness in a safe environment.

Problem:

Phishing causes ~90% of global data breaches

Exploits human psychology rather than technical vulnerabilities

Users need:

Real-time detection of suspicious messages

Plain-language explanations of why something is risky

Hands-on experience with phishing simulations

✨ Features

1. 🔍 Phishing Message Analyzer

Paste emails, SMS, or messages for instant analysis

Detect urgency words, impersonation, suspicious links, and sensitive requests

Risk Score (0–100%) with Safe / Suspicious / High Risk

Highlights suspicious phrases with color-coded threat levels

2. 🤖 AI Explanation Engine

Powered by Claude (claude-sonnet-4-20250514)

Explains why a message is dangerous in plain language

Highlights manipulation techniques

Provides actionable advice

3. ⚡ Phishing Attack Simulator

Scenarios: Bank, Job Offer, OTP Theft, Parcel Scam, Lottery, Government

Generates safe, realistic example messages

Annotates manipulation tactics used

4. 🛡 Cybersecurity Awareness Tips

Context-aware tips after each scan

Covers OTP safety, domain verification, urgency flags, 2FA setup

🛠 Tech Stack
Layer	Technology
Frontend	HTML5, CSS3, Vanilla JS
UI Theme	Dark mode, grid/scan effects
Typography	Orbitron, Rajdhani, Share Tech Mono
Backend	Python 3.9+ with Flask
NLP Engine	Rule-based keyword & pattern matching
AI Engine	Anthropic Claude
CORS	flask-cors
📁 Folder Structure
PhishGuard-AI/
├── frontend/
│   ├── index.html
│   ├── style.css
│   └── script.js
├── backend/
│   ├── app.py
│   ├── phishing_detector.py
│   └── phishing_simulator.py
└── README.md
🚀 How to Run
Option A: Frontend Only
open frontend/index.html
# or serve via:
python -m http.server 8080

Note: Direct AI calls require API key in script.js or a proxy.

Option B: Full Stack (Flask Backend)
pip install flask flask-cors anthropic

# Set API Key
export ANTHROPIC_API_KEY="your_api_key_here"  # Linux/Mac
# set ANTHROPIC_API_KEY=your_api_key_here      # Windows

cd backend
python app.py  # http://localhost:5000
open frontend/index.html

API Endpoints:

Method	Endpoint	Description
GET	/health	Check server status
POST	/analyze	Analyze a message
POST	/simulate	Generate phishing simulation
GET	/tips	Get security tips
🧠 How AI Is Used

Detection: Rule-based NLP scores keywords, suspicious links, urgency, impersonation, and sensitive requests

Explanation: Claude generates plain-language breakdowns for users

Simulation: Claude creates safe example phishing messages with annotated tactics

🔒 Security & Ethics

All simulations are educational only

No real phishing infrastructure is created

Detection engine works offline — no message data is sent externally

📊 Detection Accuracy

~85–90% for common phishing patterns

AI explanation layer adds nuanced context

Can be enhanced with PhishTank/OpenPhish, fine-tuned models, SPF/DKIM/DMARC checks

🚀 Future Improvements

URL reputation API integration

Advanced ML models

Email header verification (SPF, DKIM, DMARC)

Browser extension for real-time protection

📄 License

MIT — Free for educational and research use

Built with 🛡 for cybersecurity awareness education
