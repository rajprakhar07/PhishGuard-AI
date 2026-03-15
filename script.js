/* ═══════════════════════════════════════════
   PhishGuard AI — Frontend Logic
   Calls backend Flask API or Anthropic directly
   ═══════════════════════════════════════════ */

// ─── CONFIG ───────────────────────────────────
const BACKEND_URL = 'http://localhost:5000'; // Flask backend
const USE_DIRECT_AI = true; // Set false if using Flask

// ─── PHISHING DETECTION ENGINE (Rule-Based NLP) ───────────────────────────
const PHISHING_PATTERNS = {
  high: {
    keywords: [
      'verify your account', 'confirm your identity', 'suspended account',
      'click here immediately', 'enter your otp', 'provide your password',
      'bank details required', 'credit card number', 'social security',
      'you have been selected', 'winner', 'claim your prize',
      'account will be closed', 'unauthorized access detected',
      'verify now', 'immediate action required', 'last warning',
      'your account has been compromised', 'limited time offer',
    ],
    score: 25
  },
  medium: {
    keywords: [
      'urgent', 'act now', 'click here', 'click the link', 'verify',
      'confirm', 'update your information', 'suspended', 'locked',
      'security alert', 'unusual activity', 'login attempt',
      'free gift', 'congratulations', 'you have won',
      'otp', 'pin number', 'password',
      'dear customer', 'dear user', 'dear member',
    ],
    score: 15
  },
  low: {
    keywords: [
      'offer', 'limited', 'expire', 'expires', 'account', 'login',
      'link', 'http', 'https', 'click', 'download', 'attachment',
      'invoice', 'payment', 'billing', 'refund',
    ],
    score: 8
  }
};

const SUSPICIOUS_LINK_PATTERNS = [
  /bit\.ly|tinyurl|t\.co|goo\.gl|ow\.ly/i,
  /[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}/,
  /paypa1|g00gle|arnazon|faceb00k|micros0ft|app1e|netfl1x/i,
  /secure-.*\.(com|net|org|xyz|tk|ml|ga|cf)/i,
  /\.(xyz|tk|ml|ga|cf|pw|top|click|link|buzz)\b/i,
];

const URGENCY_PATTERNS = [
  /\b(urgent|immediately|now|asap|expire|expires|24 hours?|48 hours?|limited time)\b/i,
  /\b(last chance|final notice|act now|do not delay|don't delay)\b/i,
];

const IMPERSONATION_PATTERNS = [
  /\b(amazon|paypal|google|microsoft|apple|netflix|facebook|instagram|twitter|bank of|chase|wells fargo|citibank|hdfc|sbi|icici|axis bank)\b/i,
  /\b(irs|income tax|customs|fedex|ups|dhl|usps|royal mail|india post)\b/i,
];

function analyzeMessage(text) {
  const lower = text.toLowerCase();
  let score = 0;
  const indicators = [];
  const highlights = []; // {word, level}

  // Score keywords
  for (const [level, data] of Object.entries(PHISHING_PATTERNS)) {
    for (const kw of data.keywords) {
      if (lower.includes(kw.toLowerCase())) {
        const scoreAdd = Math.min(data.score, 30); // cap per hit
        score += scoreAdd;
        highlights.push({ word: kw, level });
        if (level === 'high') {
          indicators.push({ type: 'high', text: `Critical phrase detected: "${kw}"` });
        } else if (level === 'medium' && indicators.filter(i=>i.type==='medium').length < 4) {
          indicators.push({ type: 'medium', text: `Suspicious phrase: "${kw}"` });
        }
      }
    }
  }

  // Check for suspicious links
  for (const pattern of SUSPICIOUS_LINK_PATTERNS) {
    if (pattern.test(text)) {
      score += 20;
      indicators.push({ type: 'high', text: 'Suspicious/shortened URL detected — potential redirect to malicious site' });
      break;
    }
  }

  // Urgency language
  for (const pattern of URGENCY_PATTERNS) {
    if (pattern.test(text)) {
      score += 12;
      indicators.push({ type: 'medium', text: 'Urgency tactics detected — pressure to act without thinking' });
      break;
    }
  }

  // Impersonation
  const impersonationMatches = IMPERSONATION_PATTERNS.flatMap(p => {
    const m = text.match(p);
    return m ? [m[0]] : [];
  });
  if (impersonationMatches.length > 0) {
    score += 18;
    indicators.push({ type: 'high', text: `Possible impersonation of: ${impersonationMatches.join(', ')}` });
    impersonationMatches.forEach(w => highlights.push({ word: w, level: 'high' }));
  }

  // Requests for sensitive data
  if (/\b(otp|one.time.password|pin|cvv|password|passphrase|secret)\b/i.test(text)) {
    score += 25;
    indicators.push({ type: 'high', text: 'Requesting OTP/PIN/password — legitimate services NEVER ask for these' });
  }

  // Generic greeting (impersonal)
  if (/dear (customer|user|member|valued|account holder|sir|madam)/i.test(text)) {
    score += 10;
    indicators.push({ type: 'low', text: 'Generic greeting used — phishers send bulk messages without your name' });
  }

  // Cap score at 100
  score = Math.min(score, 100);

  // Determine risk level
  let level, label;
  if (score >= 60) { level = 'high-risk'; label = 'HIGH RISK'; }
  else if (score >= 30) { level = 'suspicious'; label = 'SUSPICIOUS'; }
  else { level = 'safe'; label = 'SAFE'; }

  // Deduplicate indicators
  const seen = new Set();
  const uniqueIndicators = indicators.filter(i => {
    if (seen.has(i.text)) return false;
    seen.add(i.text); return true;
  });

  return { score, level, label, indicators: uniqueIndicators, highlights };
}

// ─── HIGHLIGHT MESSAGE TEXT ───────────────────
function highlightMessage(text, highlights) {
  let result = text;
  // Sort by length descending to match longer phrases first
  const sorted = [...highlights].sort((a, b) => b.word.length - a.word.length);
  const classMap = { high: 'hl-red', medium: 'hl-orange', low: 'hl-yellow' };

  for (const { word, level } of sorted) {
    const cls = classMap[level] || 'hl-yellow';
    const escaped = word.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
    const regex = new RegExp(`(${escaped})`, 'gi');
    result = result.replace(regex, `<span class="${cls}">$1</span>`);
  }
  return result;
}

// ─── AI EXPLANATION (Claude API) ─────────────────
async function getAIExplanation(message, analysisResult) {
  const { score, level, label, indicators } = analysisResult;
  const indicatorTexts = indicators.map(i => `- ${i.text}`).join('\n');

  const prompt = `You are a cybersecurity expert and educator. Analyze this message for phishing indicators and explain it clearly to a non-technical user.

MESSAGE:
"""
${message}
"""

AUTOMATED ANALYSIS RESULT:
- Risk Score: ${score}%
- Risk Level: ${label}
- Detected Indicators:
${indicatorTexts || '- No major indicators found'}

Write a friendly, clear explanation (3-4 paragraphs) covering:
1. Whether this message is likely phishing and why (or why it seems safe)
2. The specific red flags or manipulation techniques used (if any)
3. What the attacker is trying to accomplish (if phishing)
4. What the user should do

Use <strong> tags for important terms. For dangerous elements use <span class="ai-warning"> and for reassuring points use <span class="ai-safe">. Keep it under 200 words. Start directly without "This message..." preamble.`;

  try {
    const response = await fetch('https://api.anthropic.com/v1/messages', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        model: 'claude-sonnet-4-20250514',
        max_tokens: 1000,
        messages: [{ role: 'user', content: prompt }]
      })
    });
    const data = await response.json();
    const rawText = data.content?.[0]?.text || '';
    // Convert newlines to paragraphs
    return rawText.split('\n\n').map(p => p.trim()).filter(Boolean).map(p => `<p>${p}</p>`).join('');
  } catch (err) {
    console.error('AI API error:', err);
    return generateFallbackExplanation(analysisResult);
  }
}

function generateFallbackExplanation(result) {
  const { score, level, indicators } = result;
  if (level === 'safe') {
    return `<p><span class="ai-safe">✓ This message appears relatively safe.</span> The automated scan found no major phishing indicators. However, always stay cautious — sophisticated phishing can evade automated detection.</p>
    <p>Remember: <strong>never share passwords, OTPs, or financial details</strong> with anyone, even if the message seems legitimate. Verify directly with the organization through official channels.</p>`;
  }
  const topIndicators = indicators.slice(0, 3).map(i => `<strong>${i.text}</strong>`).join(', ');
  return `<p><span class="ai-warning">⚠ Warning: This message shows ${level === 'high-risk' ? 'strong' : 'some'} signs of a phishing attack.</span> Key red flags include: ${topIndicators || 'suspicious patterns'}.</p>
  <p>Phishing messages use <strong>urgency, fear, and impersonation</strong> to bypass your rational thinking. The goal is to steal your credentials, OTP, or financial information.</p>
  <p><strong>Do not click any links</strong> in this message. Do not provide any personal information. If it claims to be from a bank or service you use, contact them directly through their official website or phone number.</p>`;
}

// ─── SIMULATION ENGINE ───────────────────────
const SCENARIO_DATA = {
  bank: { name: 'Bank Account Verification', tag: 'FINANCIAL PHISHING' },
  job: { name: 'Fake Job Offer', tag: 'EMPLOYMENT SCAM' },
  otp: { name: 'OTP Theft Attack', tag: 'CREDENTIAL THEFT' },
  parcel: { name: 'Parcel Delivery Scam', tag: 'LOGISTICS FRAUD' },
  prize: { name: 'Prize / Lottery Win', tag: 'ADVANCE FEE FRAUD' },
  gov: { name: 'Government Impersonation', tag: 'AUTHORITY SCAM' }
};

async function generateSimulation(scenario) {
  const scenarioName = SCENARIO_DATA[scenario]?.name || scenario;

  const prompt = `You are a cybersecurity educator creating a realistic but clearly educational phishing simulation. Generate a realistic phishing message for the scenario: "${scenarioName}".

Return ONLY valid JSON (no markdown fences) in this exact format:
{
  "message": "The full simulated phishing message text (realistic, 80-150 words)",
  "tactics": [
    {"name": "Tactic Name", "description": "Brief explanation of how this tactic manipulates the victim"},
    {"name": "Tactic Name", "description": "..."},
    {"name": "Tactic Name", "description": "..."},
    {"name": "Tactic Name", "description": "..."}
  ],
  "breakdown": "2-3 paragraph explanation of how this specific attack works, what psychological buttons it pushes, and how to spot and avoid it. Use <strong> tags for key terms."
}

Make the message realistic enough to educate, but clearly label psychological manipulation tactics. This is for cybersecurity awareness training.`;

  try {
    const response = await fetch('https://api.anthropic.com/v1/messages', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        model: 'claude-sonnet-4-20250514',
        max_tokens: 1000,
        messages: [{ role: 'user', content: prompt }]
      })
    });
    const data = await response.json();
    let raw = data.content?.[0]?.text || '{}';
    raw = raw.replace(/```json|```/g, '').trim();
    return JSON.parse(raw);
  } catch (err) {
    console.error('Simulation API error:', err);
    return getFallbackSimulation(scenario);
  }
}

function getFallbackSimulation(scenario) {
  const simulations = {
    bank: {
      message: `URGENT SECURITY ALERT — HDFC Bank
      
Dear Valued Customer,

We have detected suspicious login activity on your account. Your account has been temporarily locked for your security.

To restore access, you must verify your identity within 24 hours by clicking the secure link below:

🔗 https://secure-hdfcbank-verify.tk/login

You will need to provide your registered mobile number, net banking password, and the OTP sent to your phone.

Failure to verify within 24 hours will result in permanent account suspension.

—HDFC Bank Security Team`,
      tactics: [
        { name: 'False Urgency', description: '24-hour deadline creates panic, preventing rational thinking' },
        { name: 'Fear Trigger', description: 'Threat of "account suspension" forces immediate action' },
        { name: 'Brand Impersonation', description: 'Uses HDFC Bank branding to appear legitimate' },
        { name: 'Credential Harvesting', description: 'Asks for password + OTP to fully compromise account' }
      ],
      breakdown: '<p>This attack combines <strong>fear, urgency, and authority</strong> — the three pillars of financial phishing. The fake domain (hdfcbank-verify.tk) uses a legitimate-looking subdomain before a suspicious TLD (.tk is free and anonymous).</p><p>The request for both password AND OTP is the most dangerous red flag. <strong>Real banks never ask for your OTP over email</strong> — the OTP exists precisely because the bank doesn\'t know it. Providing both gives attackers full account access.</p>'
    },
    otp: {
      message: `[SMS] Amazon India: Your account has been locked due to suspicious activity. Verify your identity by sharing the OTP sent to your registered number with our verification agent. Your case ID: AM-7734. DO NOT ignore this message. Contact us at +91-9876543210.`,
      tactics: [
        { name: 'SMS Spoofing', description: 'Message appears to come from Amazon India number' },
        { name: 'Social Proof', description: 'Case ID number creates illusion of legitimacy' },
        { name: 'Agent Trick', description: '"Verification agent" tricks victim into sharing OTP verbally' },
        { name: 'Urgency', description: '"DO NOT ignore" creates anxiety about account security' }
      ],
      breakdown: '<p>This is a <strong>vishing + phishing hybrid</strong>. The SMS creates urgency, then directs victims to call a fake number where a "support agent" (the attacker) will request the OTP that was actually just triggered by the attacker logging in to the real account.</p><p><strong>Golden rule: Never share OTP with anyone</strong>, including people claiming to be from the company. The OTP is YOUR authentication factor — not the company\'s.</p>'
    }
  };
  return simulations[scenario] || simulations.bank;
}

// ─── SECURITY TIPS DATA ──────────────────────
const SECURITY_TIPS = [
  { icon: '🔐', title: 'Never Share OTP or Passwords', desc: 'No legitimate bank, company, or service will ever ask for your OTP, password, or PIN via email or SMS.' },
  { icon: '🔍', title: 'Verify the Sender Domain', desc: 'Check the actual email domain — "support@paypa1-secure.com" is NOT PayPal. Look for typos and suspicious TLDs.' },
  { icon: '🔗', title: 'Hover Before You Click', desc: 'Hover over links to see the real URL. Shortened links (bit.ly, tinyurl) can hide malicious destinations.' },
  { icon: '📞', title: 'Call to Verify', desc: 'If you receive an alert about your bank or service, call the official number from their website — not from the message.' },
  { icon: '⏱', title: "Don't Rush — Urgency = Red Flag", desc: 'Artificial deadlines are a manipulation tactic. Legitimate companies give you time to verify before taking action.' },
  { icon: '🛡', title: 'Enable Two-Factor Authentication', desc: 'Use an authenticator app (not SMS) for 2FA. This adds a critical layer even if your password is stolen.' },
  { icon: '📧', title: 'Generic Greetings = Warning', desc: '"Dear Customer" instead of your name? Phishing messages are mass-sent and don\'t know your name.' },
  { icon: '🔄', title: 'Keep Software Updated', desc: 'Many phishing attacks exploit browser and OS vulnerabilities. Regular updates patch security holes.' },
];

// ─── DOM HELPERS ──────────────────────────────
function showToast(msg, duration = 3000) {
  const t = document.getElementById('toast');
  t.textContent = msg;
  t.classList.remove('hidden');
  setTimeout(() => t.classList.add('hidden'), duration);
}

function setLoading(btnId, loading) {
  const btn = document.getElementById(btnId);
  const loader = btn.querySelector('.btn-loader');
  const text = btn.querySelector('.btn-text');
  if (loading) { loader.classList.remove('hidden'); text.style.opacity = '0.5'; btn.disabled = true; }
  else { loader.classList.add('hidden'); text.style.opacity = '1'; btn.disabled = false; }
}

// ─── PAGE NAVIGATION ─────────────────────────
function navigateTo(page) {
  document.querySelectorAll('.page').forEach(p => { p.classList.add('hidden'); p.classList.remove('active'); });
  document.querySelectorAll('.nav-link').forEach(l => l.classList.remove('active'));
  const target = document.getElementById(`page-${page}`);
  if (target) { target.classList.remove('hidden'); target.classList.add('active'); }
  const navEl = document.querySelector(`[data-page="${page}"]`);
  if (navEl) navEl.classList.add('active');
  window.scrollTo({ top: 0, behavior: 'smooth' });
}

// ─── ANALYZER FLOW ────────────────────────────
async function runAnalysis() {
  const input = document.getElementById('message-input').value.trim();
  if (!input) { showToast('⚠ Please paste a message to analyze'); return; }
  if (input.length < 10) { showToast('⚠ Message too short for analysis'); return; }

  setLoading('btn-analyze', true);

  // Run local NLP analysis
  const result = analyzeMessage(input);

  // Show results section
  const section = document.getElementById('results-section');
  section.classList.remove('hidden');
  section.scrollIntoView({ behavior: 'smooth', block: 'start' });

  // Animate risk score
  setTimeout(() => renderRiskScore(result), 100);

  // Highlight message
  const hl = highlightMessage(input, result.highlights);
  document.getElementById('highlighted-message').innerHTML = hl;

  // Indicators
  const indList = document.getElementById('indicators-list');
  indList.innerHTML = '';
  if (result.indicators.length === 0) {
    indList.innerHTML = '<div class="indicator-item low"><span>✓</span><span class="indicator-text">No major phishing indicators detected</span></div>';
  } else {
    result.indicators.slice(0, 6).forEach((ind, i) => {
      setTimeout(() => {
        const el = document.createElement('div');
        el.className = `indicator-item ${ind.type === 'high' ? 'high' : ind.type === 'medium' ? 'medium' : 'low'}`;
        const icons = { high: '🔴', medium: '🟠', low: '🟡' };
        el.innerHTML = `<span class="indicator-icon">${icons[ind.type] || '⚪'}</span><span class="indicator-text">${ind.text}</span>`;
        indList.appendChild(el);
      }, i * 80);
    });
  }

  // Render tips
  renderTips(result.level);

  // AI Explanation
  const aiLoading = document.getElementById('ai-loading');
  const aiContent = document.getElementById('ai-content');
  aiContent.innerHTML = '';
  aiLoading.classList.remove('hidden');

  const explanation = await getAIExplanation(input, result);
  aiLoading.classList.add('hidden');
  aiContent.innerHTML = explanation;

  setLoading('btn-analyze', false);
}

function renderRiskScore(result) {
  const pct = result.score;
  const circumference = 326.7;
  const offset = circumference - (pct / 100) * circumference;

  const circle = document.getElementById('risk-circle');
  circle.style.strokeDashoffset = offset;
  circle.className = `risk-fill ${result.level === 'high-risk' ? 'high-risk-color' : result.level === 'suspicious' ? 'suspicious-color' : ''}`;

  // Animate number
  let current = 0;
  const step = pct / 40;
  const interval = setInterval(() => {
    current = Math.min(current + step, pct);
    document.getElementById('risk-percent').textContent = Math.round(current);
    if (current >= pct) clearInterval(interval);
  }, 20);

  // Badge & label
  const badge = document.getElementById('risk-badge');
  badge.textContent = result.label;
  badge.className = `risk-badge ${result.level}`;

  const labelMap = { 'high-risk': 'HIGH RISK DETECTED', 'suspicious': 'SUSPICIOUS MESSAGE', 'safe': 'APPEARS SAFE' };
  document.getElementById('risk-label').textContent = labelMap[result.level];
}

function renderTips(riskLevel) {
  const tipsList = document.getElementById('tips-list');
  // Prioritize tips based on risk
  const tips = riskLevel === 'safe' ? SECURITY_TIPS.slice(4) : SECURITY_TIPS;
  tipsList.innerHTML = tips.slice(0, 6).map(t => `
    <div class="tip-item">
      <span class="tip-icon">${t.icon}</span>
      <div class="tip-content">
        <div class="tip-title">${t.title}</div>
        <div class="tip-desc">${t.desc}</div>
      </div>
    </div>`).join('');
}

// ─── SIMULATOR FLOW ────────────────────────────
let selectedScenario = 'bank';

function initSimulator() {
  document.querySelectorAll('.scenario-card').forEach(card => {
    card.addEventListener('click', () => {
      document.querySelectorAll('.scenario-card').forEach(c => c.classList.remove('active'));
      card.classList.add('active');
      selectedScenario = card.dataset.scenario;
    });
  });
}

async function runSimulation() {
  setLoading('btn-simulate', true);

  const output = document.getElementById('sim-output');
  output.classList.remove('hidden');
  output.scrollIntoView({ behavior: 'smooth', block: 'start' });

  // Clear previous
  document.getElementById('sim-message-box').innerHTML = '<div class="ai-loading"><div class="ai-dots"><span></span><span></span><span></span></div><p style="color:var(--text-muted);font-size:0.85rem">Generating simulation...</p></div>';
  document.getElementById('tactics-list').innerHTML = '';
  document.getElementById('sim-ai-content').innerHTML = '';

  const data = await generateSimulation(selectedScenario);

  // Scenario tag
  document.getElementById('sim-scenario-tag').textContent = SCENARIO_DATA[selectedScenario]?.tag || selectedScenario.toUpperCase();

  // Message
  document.getElementById('sim-message-box').textContent = data.message || '';

  // Tactics
  const tacticsList = document.getElementById('tactics-list');
  (data.tactics || []).forEach((t, i) => {
    setTimeout(() => {
      const el = document.createElement('div');
      el.className = 'tactic-item';
      el.innerHTML = `<span class="tactic-num">${String(i+1).padStart(2,'0')}</span>
        <span class="tactic-text"><span class="tactic-name">${t.name}:</span> ${t.description}</span>`;
      tacticsList.appendChild(el);
    }, i * 100);
  });

  // Breakdown
  const breakdown = data.breakdown || '';
  document.getElementById('sim-ai-content').innerHTML = breakdown.split('\n\n').map(p => `<p>${p}</p>`).join('');

  setLoading('btn-simulate', false);
}

// ─── SAMPLE MESSAGE ───────────────────────────
const SAMPLE_PHISHING = `Subject: URGENT: Your HDFC Bank Account Has Been Suspended!

Dear Valued Customer,

We have detected unauthorized access to your HDFC Bank NetBanking account. To protect your funds, your account has been temporarily suspended.

You MUST verify your identity within 24 hours to restore access:

👉 Click here: https://bit.ly/hdfc-secure-verify

You will need to:
1. Enter your customer ID and password
2. Provide the OTP sent to your registered mobile
3. Confirm your last 4 card digits

Failure to verify will result in permanent account closure and fund freeze.

This is an automated security alert. Do not reply to this email.

Regards,
HDFC Bank Security Team
helpdesk@hdfcbank-alerts-secure.tk`;

// ─── INIT ─────────────────────────────────────
document.addEventListener('DOMContentLoaded', () => {
  // Nav
  document.querySelectorAll('.nav-link').forEach(link => {
    link.addEventListener('click', e => {
      e.preventDefault();
      navigateTo(link.dataset.page);
    });
  });

  // Analyzer
  document.getElementById('btn-analyze').addEventListener('click', runAnalysis);
  document.getElementById('btn-clear').addEventListener('click', () => {
    document.getElementById('message-input').value = '';
    document.getElementById('char-count').textContent = '0';
    document.getElementById('results-section').classList.add('hidden');
  });
  document.getElementById('btn-paste').addEventListener('click', async () => {
    try {
      const text = await navigator.clipboard.readText();
      document.getElementById('message-input').value = text;
      document.getElementById('char-count').textContent = text.length;
    } catch { showToast('⚠ Clipboard access denied — paste manually'); }
  });
  document.getElementById('btn-load-sample').addEventListener('click', () => {
    document.getElementById('message-input').value = SAMPLE_PHISHING;
    document.getElementById('char-count').textContent = SAMPLE_PHISHING.length;
    showToast('✓ Sample phishing email loaded');
  });
  document.getElementById('message-input').addEventListener('input', e => {
    document.getElementById('char-count').textContent = e.target.value.length;
  });
  // Allow Enter+Ctrl to analyze
  document.getElementById('message-input').addEventListener('keydown', e => {
    if (e.ctrlKey && e.key === 'Enter') runAnalysis();
  });

  // Simulator
  initSimulator();
  document.getElementById('btn-simulate').addEventListener('click', runSimulation);
});
