"""
PhishGuard AI — Phishing Detection Engine
Rule-based NLP analyzer for phishing indicators.
"""
import re
from typing import Dict, List, Any


class PhishingDetector:
    """Multi-layer phishing detection using rule-based NLP."""

    PATTERNS = {
        'high': {
            'keywords': [
                'verify your account', 'confirm your identity', 'account suspended',
                'click here immediately', 'enter your otp', 'provide your password',
                'bank details required', 'credit card number', 'social security number',
                'you have been selected', 'winner', 'claim your prize',
                'account will be closed', 'unauthorized access detected',
                'verify now', 'immediate action required', 'last warning',
                'your account has been compromised', 'account will be terminated',
                'confirm your bank details', 'update payment information',
            ],
            'score': 25
        },
        'medium': {
            'keywords': [
                'urgent', 'act now', 'click here', 'click the link', 'verify',
                'confirm', 'update your information', 'suspended', 'locked',
                'security alert', 'unusual activity', 'login attempt',
                'free gift', 'congratulations', 'you have won',
                'otp', 'pin number', 'password',
                'dear customer', 'dear user', 'dear member',
                'your account', 'expires soon', 'limited time',
            ],
            'score': 15
        },
        'low': {
            'keywords': [
                'offer', 'limited', 'expire', 'expires', 'account', 'login',
                'link', 'download', 'attachment', 'invoice', 'payment',
                'billing', 'refund', 'claim', 'reward',
            ],
            'score': 8
        }
    }

    SUSPICIOUS_LINK_PATTERNS = [
        re.compile(r'bit\.ly|tinyurl|t\.co|goo\.gl|ow\.ly', re.I),
        re.compile(r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b'),  # IP address
        re.compile(r'paypa1|g00gle|arnazon|faceb00k|micros0ft|app1e|netfl1x', re.I),
        re.compile(r'secure-.*\.(com|net|org|xyz|tk|ml|ga|cf)', re.I),
        re.compile(r'\.(xyz|tk|ml|ga|cf|pw|top|click|link|buzz)\b', re.I),
    ]

    URGENCY_PATTERNS = [
        re.compile(r'\b(urgent|immediately|now|asap|expire[sd]?|24 hours?|48 hours?|limited time)\b', re.I),
        re.compile(r'\b(last chance|final notice|act now|do not delay|don\'t delay)\b', re.I),
    ]

    IMPERSONATION_PATTERNS = [
        re.compile(r'\b(amazon|paypal|google|microsoft|apple|netflix|facebook|instagram|'
                   r'bank of|chase|wells fargo|citibank|hdfc|sbi|icici|axis bank|kotak)\b', re.I),
        re.compile(r'\b(irs|income tax|customs|fedex|ups|dhl|usps|royal mail|india post)\b', re.I),
    ]

    SENSITIVE_DATA_PATTERN = re.compile(
        r'\b(otp|one.time.password|pin|cvv|password|passphrase|secret code|card number)\b', re.I
    )

    GENERIC_GREETING_PATTERN = re.compile(
        r'dear (customer|user|member|valued|account holder|sir|madam)', re.I
    )

    def analyze(self, text: str) -> Dict[str, Any]:
        lower = text.lower()
        score = 0
        indicators: List[Dict] = []
        highlights: List[Dict] = []
        seen_keywords: set = set()

        # ── Keyword Scoring ──────────────────────
        for level, data in self.PATTERNS.items():
            for kw in data['keywords']:
                if kw.lower() in lower and kw not in seen_keywords:
                    seen_keywords.add(kw)
                    score += min(data['score'], 30)
                    highlights.append({'word': kw, 'level': level})
                    if level == 'high':
                        indicators.append({'type': 'high', 'text': f'Critical phrase detected: "{kw}"'})
                    elif level == 'medium' and len([i for i in indicators if i['type'] == 'medium']) < 4:
                        indicators.append({'type': 'medium', 'text': f'Suspicious phrase: "{kw}"'})

        # ── Suspicious Links ─────────────────────
        for pattern in self.SUSPICIOUS_LINK_PATTERNS:
            if pattern.search(text):
                score += 20
                indicators.append({'type': 'high', 'text': 'Suspicious/shortened URL detected — potential redirect to malicious site'})
                break

        # ── Urgency Language ─────────────────────
        for pattern in self.URGENCY_PATTERNS:
            if pattern.search(text):
                score += 12
                indicators.append({'type': 'medium', 'text': 'Urgency tactics detected — designed to pressure you into acting without thinking'})
                break

        # ── Brand Impersonation ──────────────────
        impersonations = []
        for pattern in self.IMPERSONATION_PATTERNS:
            match = pattern.search(text)
            if match:
                impersonations.append(match.group(0))
                highlights.append({'word': match.group(0), 'level': 'high'})

        if impersonations:
            score += 18
            indicators.append({'type': 'high', 'text': f'Possible impersonation of: {", ".join(set(impersonations))}'})

        # ── Sensitive Data Request ───────────────
        if self.SENSITIVE_DATA_PATTERN.search(text):
            score += 25
            indicators.append({'type': 'high', 'text': 'Requesting OTP/PIN/password — legitimate services NEVER ask for these'})

        # ── Generic Greeting ─────────────────────
        if self.GENERIC_GREETING_PATTERN.search(text):
            score += 10
            indicators.append({'type': 'low', 'text': 'Generic greeting used — phishers send bulk messages without your name'})

        # ── Cap score ────────────────────────────
        score = min(score, 100)

        # ── Risk Classification ──────────────────
        if score >= 60:
            level, label = 'high-risk', 'HIGH RISK'
        elif score >= 30:
            level, label = 'suspicious', 'SUSPICIOUS'
        else:
            level, label = 'safe', 'SAFE'

        # Deduplicate indicators
        seen_texts: set = set()
        unique_indicators = []
        for ind in indicators:
            if ind['text'] not in seen_texts:
                seen_texts.add(ind['text'])
                unique_indicators.append(ind)

        return {
            'score': score,
            'level': level,
            'label': label,
            'indicators': unique_indicators[:8],
            'highlights': highlights
        }
