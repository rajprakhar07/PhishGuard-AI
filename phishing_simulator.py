"""
PhishGuard AI — Phishing Simulator & AI Explanation Engine
Uses Anthropic Claude to generate educational simulations and explanations.
"""
import os
import json
import anthropic
from typing import Dict, Any


SCENARIO_PROMPTS = {
    'bank': 'Bank account suspension/verification phishing — attacker impersonates HDFC/SBI/Chase bank',
    'job': 'Fake job offer scam — attacker poses as a recruiter for a well-known company offering high salary',
    'otp': 'OTP theft attack — attacker tricks victim into sharing a one-time password via phone/SMS',
    'parcel': 'Parcel delivery scam — attacker impersonates FedEx/DHL/India Post about a failed delivery',
    'prize': 'Prize/lottery win scam — attacker claims victim has won a large cash prize',
    'gov': 'Government impersonation — attacker poses as tax authority/customs demanding payment',
}


class PhishingSimulator:
    """AI-powered phishing simulation and explanation engine."""

    def __init__(self):
        api_key = os.environ.get('ANTHROPIC_API_KEY')
        if api_key:
            self.client = anthropic.Anthropic(api_key=api_key)
        else:
            self.client = None
            print("⚠  ANTHROPIC_API_KEY not set — using fallback simulations")

    def generate(self, scenario: str) -> Dict[str, Any]:
        """Generate a realistic phishing simulation for the given scenario."""
        scenario_desc = SCENARIO_PROMPTS.get(scenario, SCENARIO_PROMPTS['bank'])

        if not self.client:
            return self._get_fallback_simulation(scenario)

        prompt = f"""You are a cybersecurity educator creating a realistic phishing simulation for awareness training.

Scenario: {scenario_desc}

Return ONLY valid JSON (no markdown, no preamble) in this exact format:
{{
  "message": "The full simulated phishing message (80-150 words, realistic)",
  "tactics": [
    {{"name": "Tactic Name", "description": "How this tactic manipulates the victim"}},
    {{"name": "Tactic Name", "description": "..."}},
    {{"name": "Tactic Name", "description": "..."}},
    {{"name": "Tactic Name", "description": "..."}}
  ],
  "breakdown": "2-3 paragraph plain-text explanation of how this attack works psychologically and how to spot it"
}}"""

        try:
            response = self.client.messages.create(
                model='claude-sonnet-4-20250514',
                max_tokens=1000,
                messages=[{'role': 'user', 'content': prompt}]
            )
            raw = response.content[0].text.strip()
            raw = raw.replace('```json', '').replace('```', '').strip()
            return json.loads(raw)
        except Exception as e:
            print(f"AI generation error: {e}")
            return self._get_fallback_simulation(scenario)

    def explain_analysis(self, message: str, analysis: Dict) -> str:
        """Generate AI explanation of why a message is/isn't phishing."""
        if not self.client:
            return self._fallback_explanation(analysis)

        indicators_text = '\n'.join([f"- {i['text']}" for i in analysis.get('indicators', [])])
        score = analysis.get('score', 0)
        label = analysis.get('label', 'UNKNOWN')

        prompt = f"""You are a cybersecurity expert. Analyze this message and explain it clearly to a non-technical user.

MESSAGE:
\"\"\"{message}\"\"\"

AUTOMATED SCAN:
- Risk Score: {score}%
- Risk Level: {label}
- Detected issues:
{indicators_text or '- No major indicators found'}

Write 2-3 paragraphs covering:
1. Whether this is phishing and why (or why it seems safe)
2. The specific manipulation techniques used (if any)  
3. What the user should do

Keep it under 180 words. Use plain text only, no markdown."""

        try:
            response = self.client.messages.create(
                model='claude-sonnet-4-20250514',
                max_tokens=600,
                messages=[{'role': 'user', 'content': prompt}]
            )
            return response.content[0].text.strip()
        except Exception as e:
            print(f"Explanation error: {e}")
            return self._fallback_explanation(analysis)

    def _fallback_explanation(self, analysis: Dict) -> str:
        level = analysis.get('level', 'safe')
        score = analysis.get('score', 0)
        if level == 'safe':
            return (f"This message scored {score}% on the phishing risk scale and appears relatively safe. "
                    "No major phishing indicators were detected. However, always stay alert — "
                    "sophisticated phishing can evade automated detection.\n\n"
                    "Remember to never share passwords, OTPs, or financial details with anyone, "
                    "and always verify unexpected requests through official channels.")
        return (f"This message scored {score}% and shows {level.replace('-', ' ')} signs of phishing. "
                "Key red flags include urgency tactics and requests for sensitive information.\n\n"
                "Phishing messages use fear, urgency, and impersonation to bypass rational thinking. "
                "The goal is to steal credentials, OTPs, or financial information.\n\n"
                "Do not click any links in this message. If it appears to be from a real organization, "
                "contact them directly through their official website or phone number.")

    def _get_fallback_simulation(self, scenario: str) -> Dict[str, Any]:
        fallbacks = {
            'bank': {
                'message': """URGENT SECURITY ALERT — HDFC Bank

Dear Valued Customer,

We have detected suspicious login activity on your account from an unrecognized device. Your account has been temporarily locked for your protection.

To restore full access, you MUST verify your identity within 24 hours:
🔗 Secure link: https://bit.ly/hdfc-verify-now

Please provide your Customer ID, NetBanking password, and the OTP sent to your registered mobile to complete verification.

Failure to verify will result in permanent account closure and any pending transactions will be reversed.

—HDFC Bank Security Team | Do not reply to this email""",
                'tactics': [
                    {'name': 'False Urgency', 'description': '24-hour deadline prevents rational thinking and forces panic'},
                    {'name': 'Authority Impersonation', 'description': 'Impersonates HDFC Bank to establish false trust'},
                    {'name': 'Fear of Loss', 'description': 'Threatens "permanent account closure" to force compliance'},
                    {'name': 'Multi-Factor Credential Theft', 'description': 'Requests both password AND OTP to fully compromise account'}
                ],
                'breakdown': ('This bank phishing attack uses three core psychological triggers: fear of financial loss, '
                              'time pressure, and authority. The attacker combines these to override the victim\'s critical thinking.\n\n'
                              'The most dangerous element is the simultaneous request for both password AND OTP. '
                              'The OTP system exists because banks don\'t know your OTP — requesting it proves this is a scam.\n\n'
                              'Real banks never send links asking for credentials. Always navigate directly to your bank\'s '
                              'official website by typing the URL, and call the number on the back of your card to verify alerts.')
            },
            'otp': {
                'message': """[SMS] Amazon: Your account has been flagged for suspicious purchases totaling ₹47,890. 
To cancel these charges and secure your account, call our fraud helpline: +91-9123456789. 
Have your registered OTP ready for identity verification. Case #AM-9934.""",
                'tactics': [
                    {'name': 'Financial Fear', 'description': 'Specific large amount (₹47,890) creates immediate panic'},
                    {'name': 'Fake Case Number', 'description': 'Case ID creates illusion of legitimacy and existing record'},
                    {'name': 'Voice Social Engineering', 'description': 'Phone call allows attacker to manipulate victim in real time'},
                    {'name': 'OTP Relay Attack', 'description': 'Attacker is simultaneously logging into real Amazon account and needs the OTP you receive'}
                ],
                'breakdown': ('This is an OTP relay attack combined with vishing (voice phishing). '
                              'The SMS creates panic about charges, then the phone call lets the attacker '
                              'request your OTP in real time while they\'re actually logging into your account.\n\n'
                              'The golden rule: Never share any OTP with anyone, even someone claiming to be from the company. '
                              'You receive OTPs to authenticate YOURSELF, not to prove your identity to customer service.')
            }
        }
        return fallbacks.get(scenario, fallbacks['bank'])
