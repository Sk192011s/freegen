// main.ts - Deno Deploy Entry Point

const kv = await Deno.openKv();

// ============== CONFIGURATION ==============
// Deno Deploy Environment Variables:
// VLESS_KEYS = "vless://key1,vless://key2,vless://key3"
// EXPIRE_HOURS = "24"  (key expire time in hours, e.g., 24 = 1 day, 72 = 3 days)
// MAX_GENERATES_PER_DAY = "2"

function getConfig() {
  const keysRaw = Deno.env.get("VLESS_KEYS") || "";
  const keys = keysRaw.split(",").map(k => k.trim()).filter(k => k.length > 0);
  const expireHours = parseInt(Deno.env.get("EXPIRE_HOURS") || "24");
  const maxPerDay = parseInt(Deno.env.get("MAX_GENERATES_PER_DAY") || "2");
  return { keys, expireHours, maxPerDay };
}

// ============== FINGERPRINT & RATE LIMITING ==============

async function hashSHA256(data: string): Promise<string> {
  const encoder = new TextEncoder();
  const dataBuffer = encoder.encode(data);
  const hashBuffer = await crypto.subtle.digest("SHA-256", dataBuffer);
  const hashArray = Array.from(new Uint8Array(hashBuffer));
  return hashArray.map(b => b.toString(16).padStart(2, "0")).join("");
}

async function generateServerFingerprint(ip: string, userAgent: string): Promise<string> {
  const raw = `${ip}||${userAgent}||pagaduu-salt-2024`;
  return await hashSHA256(raw);
}

async function checkRateLimit(fingerprint: string, maxPerDay: number): Promise<{ allowed: boolean; remaining: number; resetTime: string }> {
  const now = new Date();
  const todayKey = `${now.getUTCFullYear()}-${now.getUTCMonth()}-${now.getUTCDate()}`;
  const kvKey = ["rate_limit", fingerprint, todayKey];

  const entry = await kv.get<number>(kvKey);
  const count = entry.value || 0;

  if (count >= maxPerDay) {
    const tomorrow = new Date(now);
    tomorrow.setUTCDate(tomorrow.getUTCDate() + 1);
    tomorrow.setUTCHours(0, 0, 0, 0);
    const resetHours = Math.ceil((tomorrow.getTime() - now.getTime()) / (1000 * 60 * 60));
    return {
      allowed: false,
      remaining: 0,
      resetTime: `${resetHours} နာရီ အကြာမှာ ပြန်သုံးလို့ ရပါမယ်`
    };
  }

  return { allowed: true, remaining: maxPerDay - count, resetTime: "" };
}

async function incrementRateLimit(fingerprint: string): Promise<void> {
  const now = new Date();
  const todayKey = `${now.getUTCFullYear()}-${now.getUTCMonth()}-${now.getUTCDate()}`;
  const kvKey = ["rate_limit", fingerprint, todayKey];

  const entry = await kv.get<number>(kvKey);
  const count = entry.value || 0;

  // Expire after 48 hours to auto-cleanup
  await kv.set(kvKey, count + 1, { expireIn: 48 * 60 * 60 * 1000 });
}

// ============== KEY MANAGEMENT ==============

async function getRandomKey(config: ReturnType<typeof getConfig>): Promise<{ key: string; expireAt: string } | null> {
  if (config.keys.length === 0) return null;

  const randomIndex = Math.floor(Math.random() * config.keys.length);
  const key = config.keys[randomIndex];

  const expireAt = new Date();
  expireAt.setHours(expireAt.getHours() + config.expireHours);

  const expireFormatted = formatMyanmarDate(expireAt);

  return { key, expireAt: expireFormatted };
}

function formatMyanmarDate(date: Date): string {
  const myanmarMonths = ["ဇန်နဝါရီ", "ဖေဖော်ဝါရီ", "မတ်", "ဧပြီ", "မေ", "ဂျွန်",
    "ဂျူလိုင်", "ဩဂုတ်", "စက်တင်ဘာ", "အောက်တိုဘာ", "နိုဝင်ဘာ", "ဒီဇင်ဘာ"];
  const year = date.getFullYear();
  const month = myanmarMonths[date.getMonth()];
  const day = date.getDate();
  const hours = date.getHours().toString().padStart(2, "0");
  const minutes = date.getMinutes().toString().padStart(2, "0");
  return `${year} ${month} ${day} ရက်၊ ${hours}:${minutes}`;
}

// ============== API HANDLER ==============

async function handleGenerate(req: Request): Promise<Response> {
  if (req.method !== "POST") {
    return new Response(JSON.stringify({ error: "Method not allowed" }), { status: 405 });
  }

  const config = getConfig();
  const ip = req.headers.get("x-forwarded-for")?.split(",")[0]?.trim()
    || req.headers.get("cf-connecting-ip")
    || req.headers.get("x-real-ip")
    || "unknown";
  const userAgent = req.headers.get("user-agent") || "unknown";

  // Server-side fingerprint
  const fingerprint = await generateServerFingerprint(ip, userAgent);

  // Also check IP-only fingerprint to prevent VPN bypass
  const ipFingerprint = await hashSHA256(`ip-only-${ip}-pagaduu-salt`);

  // Check both fingerprints
  const fpCheck = await checkRateLimit(fingerprint, config.maxPerDay);
  const ipCheck = await checkRateLimit(ipFingerprint, config.maxPerDay);

  if (!fpCheck.allowed || !ipCheck.allowed) {
    const resetTime = !fpCheck.allowed ? fpCheck.resetTime : ipCheck.resetTime;
    return jsonResponse({
      success: false,
      error: "limit_reached",
      message: `ယနေ့အတွက် Generate လုပ်ခွင့် ကုန်သွားပါပြီ။ ${resetTime}`,
      remaining: 0
    }, 429);
  }

  const result = await getRandomKey(config);
  if (!result) {
    return jsonResponse({
      success: false,
      error: "no_keys",
      message: "လက်ရှိ Key မရှိပါ။ နောက်မှ ပြန်လာပါ။"
    }, 503);
  }

  // Increment both counters
  await incrementRateLimit(fingerprint);
  await incrementRateLimit(ipFingerprint);

  const remaining = Math.min(fpCheck.remaining, ipCheck.remaining) - 1;

  // Encrypt the key before sending
  const encryptedPayload = await encryptPayload(JSON.stringify({
    key: result.key,
    expireAt: result.expireAt,
    remaining,
    ts: Date.now()
  }));

  return jsonResponse({
    success: true,
    payload: encryptedPayload,
    remaining
  });
}

// ============== ENCRYPTION ==============

async function encryptPayload(plaintext: string): Promise<string> {
  const key = await crypto.subtle.generateKey(
    { name: "AES-GCM", length: 256 },
    true,
    ["encrypt", "decrypt"]
  );

  const iv = crypto.getRandomValues(new Uint8Array(12));
  const encoded = new TextEncoder().encode(plaintext);

  const ciphertext = await crypto.subtle.encrypt(
    { name: "AES-GCM", iv },
    key,
    encoded
  );

  const exportedKey = await crypto.subtle.exportKey("raw", key);

  // Combine: key(32) + iv(12) + ciphertext
  const combined = new Uint8Array(32 + 12 + new Uint8Array(ciphertext).length);
  combined.set(new Uint8Array(exportedKey), 0);
  combined.set(iv, 32);
  combined.set(new Uint8Array(ciphertext), 44);

  return btoa(String.fromCharCode(...combined));
}

function jsonResponse(data: unknown, status = 200): Response {
  return new Response(JSON.stringify(data), {
    status,
    headers: {
      "Content-Type": "application/json",
      "Cache-Control": "no-store, no-cache, must-revalidate",
      "X-Content-Type-Options": "nosniff",
    }
  });
}

// ============== CHECK REMAINING ==============

async function handleCheckRemaining(req: Request): Promise<Response> {
  const config = getConfig();
  const ip = req.headers.get("x-forwarded-for")?.split(",")[0]?.trim()
    || req.headers.get("cf-connecting-ip")
    || req.headers.get("x-real-ip")
    || "unknown";
  const userAgent = req.headers.get("user-agent") || "unknown";

  const fingerprint = await generateServerFingerprint(ip, userAgent);
  const ipFingerprint = await hashSHA256(`ip-only-${ip}-pagaduu-salt`);

  const fpCheck = await checkRateLimit(fingerprint, config.maxPerDay);
  const ipCheck = await checkRateLimit(ipFingerprint, config.maxPerDay);

  const remaining = Math.min(fpCheck.remaining, ipCheck.remaining);
  const allowed = fpCheck.allowed && ipCheck.allowed;

  return jsonResponse({
    remaining,
    allowed,
    maxPerDay: config.maxPerDay,
    expireHours: config.expireHours
  });
}

// ============== HTML PAGE ==============

function getHTML(): string {
  return `<!DOCTYPE html>
<html lang="my">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Pagaduu - VLESS Generator</title>

  <!-- Fonts -->
  <link rel="preconnect" href="https://fonts.googleapis.com">
  <link href="https://fonts.googleapis.com/css2?family=Padauk:wght@400;700&family=Inter:wght@300;400;500;600;700&display=swap" rel="stylesheet">

  <!-- Lucide Icons -->
  <script src="https://unpkg.com/lucide@latest/dist/umd/lucide.min.js"></script>

  <!-- AOS Animation -->
  <link href="https://unpkg.com/aos@2.3.4/dist/aos.css" rel="stylesheet">
  <script src="https://unpkg.com/aos@2.3.4/dist/aos.js"></script>

  <style>
    :root {
      --primary: #6366f1;
      --primary-dark: #4f46e5;
      --primary-light: #818cf8;
      --accent: #f59e0b;
      --bg-dark: #0f0f23;
      --bg-card: #1a1a3e;
      --bg-card-hover: #222255;
      --glass: rgba(255,255,255,0.05);
      --glass-border: rgba(255,255,255,0.1);
      --text: #e2e8f0;
      --text-dim: #94a3b8;
      --success: #10b981;
      --danger: #ef4444;
      --glow: 0 0 40px rgba(99,102,241,0.3);
    }

    * {
      margin: 0;
      padding: 0;
      box-sizing: border-box;
    }

    body {
      font-family: 'Padauk', 'Inter', sans-serif;
      background: var(--bg-dark);
      color: var(--text);
      min-height: 100vh;
      overflow-x: hidden;
    }

    /* Animated Background */
    .bg-animation {
      position: fixed;
      top: 0;
      left: 0;
      width: 100%;
      height: 100%;
      z-index: 0;
      overflow: hidden;
      pointer-events: none;
    }

    .bg-animation .orb {
      position: absolute;
      border-radius: 50%;
      filter: blur(80px);
      opacity: 0.15;
      animation: float 20s infinite ease-in-out;
    }

    .bg-animation .orb:nth-child(1) {
      width: 600px; height: 600px;
      background: var(--primary);
      top: -200px; left: -200px;
      animation-delay: 0s;
    }

    .bg-animation .orb:nth-child(2) {
      width: 500px; height: 500px;
      background: #8b5cf6;
      bottom: -200px; right: -200px;
      animation-delay: -7s;
    }

    .bg-animation .orb:nth-child(3) {
      width: 400px; height: 400px;
      background: var(--accent);
      top: 50%; left: 50%;
      animation-delay: -14s;
    }

    @keyframes float {
      0%, 100% { transform: translate(0, 0) scale(1); }
      25% { transform: translate(100px, -50px) scale(1.1); }
      50% { transform: translate(-50px, 100px) scale(0.9); }
      75% { transform: translate(80px, 50px) scale(1.05); }
    }

    /* Particles */
    .particles {
      position: fixed;
      top: 0; left: 0;
      width: 100%; height: 100%;
      z-index: 0;
      pointer-events: none;
    }

    .particle {
      position: absolute;
      width: 3px; height: 3px;
      background: var(--primary-light);
      border-radius: 50%;
      opacity: 0;
      animation: sparkle 4s infinite;
    }

    @keyframes sparkle {
      0% { opacity: 0; transform: translateY(0) scale(0); }
      50% { opacity: 0.8; transform: translateY(-40px) scale(1); }
      100% { opacity: 0; transform: translateY(-80px) scale(0); }
    }

    /* Layout */
    .container {
      position: relative;
      z-index: 1;
      max-width: 520px;
      margin: 0 auto;
      padding: 20px 16px;
      min-height: 100vh;
      display: flex;
      flex-direction: column;
    }

    /* Header */
    .header {
      display: flex;
      align-items: center;
      justify-content: space-between;
      padding: 16px 20px;
      background: var(--glass);
      backdrop-filter: blur(20px);
      border: 1px solid var(--glass-border);
      border-radius: 16px;
      margin-bottom: 24px;
    }

    .header-brand {
      display: flex;
      align-items: center;
      gap: 10px;
    }

    .header-brand .logo-icon {
      width: 40px; height: 40px;
      background: linear-gradient(135deg, var(--primary), var(--accent));
      border-radius: 12px;
      display: flex;
      align-items: center;
      justify-content: center;
      box-shadow: var(--glow);
    }

    .header-brand .logo-icon i {
      color: white;
      width: 22px; height: 22px;
    }

    .header-brand h1 {
      font-size: 18px;
      font-weight: 700;
      background: linear-gradient(135deg, var(--primary-light), var(--accent));
      -webkit-background-clip: text;
      -webkit-text-fill-color: transparent;
      background-clip: text;
      letter-spacing: 0.5px;
    }

    .header-brand span {
      font-size: 11px;
      color: var(--text-dim);
      display: block;
      margin-top: -2px;
    }

    .header-badge {
      padding: 6px 14px;
      background: linear-gradient(135deg, var(--primary), #8b5cf6);
      border-radius: 20px;
      font-size: 11px;
      font-weight: 600;
      color: white;
      letter-spacing: 0.5px;
      animation: pulse-badge 2s infinite;
    }

    @keyframes pulse-badge {
      0%, 100% { box-shadow: 0 0 0 0 rgba(99,102,241,0.4); }
      50% { box-shadow: 0 0 0 8px rgba(99,102,241,0); }
    }

    /* Stats Bar */
    .stats-bar {
      display: grid;
      grid-template-columns: repeat(3, 1fr);
      gap: 12px;
      margin-bottom: 24px;
    }

    .stat-card {
      background: var(--glass);
      backdrop-filter: blur(20px);
      border: 1px solid var(--glass-border);
      border-radius: 14px;
      padding: 16px 12px;
      text-align: center;
      transition: all 0.3s;
    }

    .stat-card:hover {
      border-color: var(--primary);
      transform: translateY(-2px);
      box-shadow: var(--glow);
    }

    .stat-card .stat-icon {
      width: 36px; height: 36px;
      margin: 0 auto 8px;
      border-radius: 10px;
      display: flex;
      align-items: center;
      justify-content: center;
    }

    .stat-card .stat-icon i { width: 18px; height: 18px; }

    .stat-card:nth-child(1) .stat-icon { background: rgba(99,102,241,0.2); color: var(--primary-light); }
    .stat-card:nth-child(2) .stat-icon { background: rgba(245,158,11,0.2); color: var(--accent); }
    .stat-card:nth-child(3) .stat-icon { background: rgba(16,185,129,0.2); color: var(--success); }

    .stat-card .stat-value {
      font-size: 20px;
      font-weight: 700;
      color: white;
    }

    .stat-card .stat-label {
      font-size: 11px;
      color: var(--text-dim);
      margin-top: 2px;
    }

    /* Main Card */
    .main-card {
      background: var(--glass);
      backdrop-filter: blur(20px);
      border: 1px solid var(--glass-border);
      border-radius: 20px;
      padding: 32px 24px;
      flex: 1;
    }

    .card-header {
      text-align: center;
      margin-bottom: 28px;
    }

    .card-header .icon-wrapper {
      width: 72px; height: 72px;
      margin: 0 auto 16px;
      border-radius: 20px;
      background: linear-gradient(135deg, var(--primary), #8b5cf6);
      display: flex;
      align-items: center;
      justify-content: center;
      box-shadow: 0 8px 32px rgba(99,102,241,0.4);
      animation: icon-float 3s ease-in-out infinite;
    }

    @keyframes icon-float {
      0%, 100% { transform: translateY(0); }
      50% { transform: translateY(-8px); }
    }

    .card-header .icon-wrapper i {
      color: white;
      width: 32px; height: 32px;
    }

    .card-header h2 {
      font-size: 22px;
      font-weight: 700;
      color: white;
      margin-bottom: 6px;
    }

    .card-header p {
      font-size: 14px;
      color: var(--text-dim);
    }

    /* Generate Button */
    .generate-btn {
      width: 100%;
      padding: 16px;
      border: none;
      border-radius: 14px;
      background: linear-gradient(135deg, var(--primary), #8b5cf6);
      color: white;
      font-family: 'Padauk', sans-serif;
      font-size: 16px;
      font-weight: 700;
      cursor: pointer;
      transition: all 0.3s;
      display: flex;
      align-items: center;
      justify-content: center;
      gap: 10px;
      position: relative;
      overflow: hidden;
    }

    .generate-btn::before {
      content: '';
      position: absolute;
      top: 0; left: -100%;
      width: 100%; height: 100%;
      background: linear-gradient(90deg, transparent, rgba(255,255,255,0.2), transparent);
      transition: left 0.5s;
    }

    .generate-btn:hover::before {
      left: 100%;
    }

    .generate-btn:hover {
      transform: translateY(-2px);
      box-shadow: 0 8px 25px rgba(99,102,241,0.5);
    }

    .generate-btn:active {
      transform: translateY(0);
    }

    .generate-btn:disabled {
      opacity: 0.5;
      cursor: not-allowed;
      transform: none !important;
      box-shadow: none !important;
    }

    .generate-btn:disabled::before { display: none; }

    .generate-btn i { width: 20px; height: 20px; }

    /* Spinner */
    .spinner {
      width: 20px; height: 20px;
      border: 2px solid rgba(255,255,255,0.3);
      border-top: 2px solid white;
      border-radius: 50%;
      animation: spin 0.8s linear infinite;
      display: none;
    }

    @keyframes spin { to { transform: rotate(360deg); } }

    /* Result Area */
    .result-area {
      margin-top: 24px;
      display: none;
    }

    .result-area.show { display: block; }

    .result-box {
      background: rgba(0,0,0,0.3);
      border: 1px solid var(--glass-border);
      border-radius: 14px;
      padding: 20px;
      position: relative;
      animation: slideUp 0.5s ease;
    }

    @keyframes slideUp {
      from { opacity: 0; transform: translateY(20px); }
      to { opacity: 1; transform: translateY(0); }
    }

    .result-label {
      display: flex;
      align-items: center;
      gap: 8px;
      margin-bottom: 12px;
      font-size: 12px;
      color: var(--success);
      font-weight: 600;
    }

    .result-label i { width: 16px; height: 16px; }

    .result-key {
      background: rgba(0,0,0,0.4);
      border: 1px solid var(--glass-border);
      border-radius: 10px;
      padding: 14px;
      font-family: 'JetBrains Mono', monospace;
      font-size: 11px;
      color: var(--primary-light);
      word-break: break-all;
      line-height: 1.6;
      max-height: 120px;
      overflow-y: auto;
      user-select: all;
    }

    .result-meta {
      display: flex;
      align-items: center;
      justify-content: space-between;
      margin-top: 14px;
      padding-top: 14px;
      border-top: 1px solid var(--glass-border);
    }

    .expire-info {
      display: flex;
      align-items: center;
      gap: 6px;
      font-size: 12px;
      color: var(--accent);
    }

    .expire-info i { width: 14px; height: 14px; }

    .copy-btn {
      display: flex;
      align-items: center;
      gap: 6px;
      padding: 8px 18px;
      border: 1px solid var(--primary);
      border-radius: 10px;
      background: rgba(99,102,241,0.15);
      color: var(--primary-light);
      font-family: 'Padauk', sans-serif;
      font-size: 13px;
      font-weight: 600;
      cursor: pointer;
      transition: all 0.3s;
    }

    .copy-btn:hover {
      background: var(--primary);
      color: white;
    }

    .copy-btn i { width: 14px; height: 14px; }

    /* Remaining Badge */
    .remaining-bar {
      margin-top: 20px;
      padding: 14px 18px;
      background: rgba(0,0,0,0.2);
      border: 1px solid var(--glass-border);
      border-radius: 12px;
      display: flex;
      align-items: center;
      justify-content: space-between;
    }

    .remaining-bar .label {
      font-size: 13px;
      color: var(--text-dim);
      display: flex;
      align-items: center;
      gap: 6px;
    }

    .remaining-bar .label i { width: 16px; height: 16px; }

    .remaining-bar .count {
      font-size: 18px;
      font-weight: 700;
      color: var(--accent);
    }

    /* Error Message */
    .error-msg {
      margin-top: 16px;
      padding: 14px 18px;
      background: rgba(239,68,68,0.1);
      border: 1px solid rgba(239,68,68,0.3);
      border-radius: 12px;
      color: #fca5a5;
      font-size: 14px;
      display: none;
      align-items: center;
      gap: 8px;
      animation: shake 0.5s ease;
    }

    .error-msg.show { display: flex; }

    .error-msg i { width: 18px; height: 18px; flex-shrink: 0; }

    @keyframes shake {
      0%, 100% { transform: translateX(0); }
      25% { transform: translateX(-5px); }
      75% { transform: translateX(5px); }
    }

    /* Footer */
    .footer {
      text-align: center;
      padding: 24px 0 12px;
      font-size: 12px;
      color: var(--text-dim);
    }

    .footer a {
      color: var(--primary-light);
      text-decoration: none;
    }

    /* Success animation */
    .success-overlay {
      position: fixed;
      top: 0; left: 0;
      width: 100%; height: 100%;
      z-index: 100;
      display: none;
      align-items: center;
      justify-content: center;
      background: rgba(0,0,0,0.5);
      backdrop-filter: blur(4px);
    }

    .success-overlay.show {
      display: flex;
      animation: fadeIn 0.3s ease;
    }

    @keyframes fadeIn {
      from { opacity: 0; }
      to { opacity: 1; }
    }

    .success-popup {
      background: var(--bg-card);
      border: 1px solid var(--success);
      border-radius: 20px;
      padding: 32px;
      text-align: center;
      animation: popIn 0.5s cubic-bezier(0.68, -0.55, 0.265, 1.55);
      max-width: 300px;
    }

    @keyframes popIn {
      from { transform: scale(0.5); opacity: 0; }
      to { transform: scale(1); opacity: 1; }
    }

    .success-popup .check-circle {
      width: 60px; height: 60px;
      background: rgba(16,185,129,0.2);
      border-radius: 50%;
      display: flex;
      align-items: center;
      justify-content: center;
      margin: 0 auto 16px;
    }

    .success-popup .check-circle i {
      color: var(--success);
      width: 28px; height: 28px;
    }

    .success-popup h3 {
      color: white;
      margin-bottom: 6px;
    }

    .success-popup p {
      color: var(--text-dim);
      font-size: 13px;
    }

    /* Scrollbar */
    ::-webkit-scrollbar { width: 4px; }
    ::-webkit-scrollbar-track { background: transparent; }
    ::-webkit-scrollbar-thumb { background: var(--primary); border-radius: 4px; }

    /* Copy toast */
    .toast {
      position: fixed;
      bottom: 30px;
      left: 50%;
      transform: translateX(-50%) translateY(100px);
      background: var(--success);
      color: white;
      padding: 12px 24px;
      border-radius: 12px;
      font-size: 14px;
      font-weight: 600;
      z-index: 200;
      transition: transform 0.3s cubic-bezier(0.68, -0.55, 0.265, 1.55);
      display: flex;
      align-items: center;
      gap: 8px;
    }

    .toast.show {
      transform: translateX(-50%) translateY(0);
    }

    .toast i { width: 16px; height: 16px; }

    @media (max-width: 400px) {
      .container { padding: 12px; }
      .main-card { padding: 24px 16px; }
      .header { padding: 12px 16px; }
      .header-brand h1 { font-size: 15px; }
    }
  </style>
</head>
<body>

  <!-- Animated Background -->
  <div class="bg-animation">
    <div class="orb"></div>
    <div class="orb"></div>
    <div class="orb"></div>
  </div>

  <!-- Particles -->
  <div class="particles" id="particles"></div>

  <div class="container">
    <!-- Header -->
    <div class="header" data-aos="fade-down">
      <div class="header-brand">
        <div class="logo-icon">
          <i data-lucide="zap"></i>
        </div>
        <div>
          <h1>Pagaduu Generate Vless</h1>
          <span>Premium Key Generator</span>
        </div>
      </div>
      <div class="header-badge">PRO</div>
    </div>

    <!-- Stats -->
    <div class="stats-bar" data-aos="fade-up" data-aos-delay="100">
      <div class="stat-card">
        <div class="stat-icon"><i data-lucide="shield-check"></i></div>
        <div class="stat-value" id="statRemaining">-</div>
        <div class="stat-label">ကျန်ရှိ</div>
      </div>
      <div class="stat-card">
        <div class="stat-icon"><i data-lucide="clock"></i></div>
        <div class="stat-value" id="statExpire">-</div>
        <div class="stat-label">နာရီ</div>
      </div>
      <div class="stat-card">
        <div class="stat-icon"><i data-lucide="activity"></i></div>
        <div class="stat-value">Online</div>
        <div class="stat-label">Status</div>
      </div>
    </div>

    <!-- Main Card -->
    <div class="main-card" data-aos="fade-up" data-aos-delay="200">
      <div class="card-header">
        <div class="icon-wrapper">
          <i data-lucide="key-round"></i>
        </div>
        <h2>VLESS Key ရယူမည်</h2>
        <p>Generate ကိုနှိပ်၍ Key အသစ် ရယူပါ</p>
      </div>

      <button class="generate-btn" id="generateBtn" onclick="handleGenerate()">
        <i data-lucide="sparkles"></i>
        <span id="btnText">Generate Key</span>
        <div class="spinner" id="spinner"></div>
      </button>

      <!-- Error -->
      <div class="error-msg" id="errorMsg">
        <i data-lucide="alert-circle"></i>
        <span id="errorText"></span>
      </div>

      <!-- Result -->
      <div class="result-area" id="resultArea">
        <div class="result-box">
          <div class="result-label">
            <i data-lucide="check-circle-2"></i>
            VLESS Key Generated Successfully
          </div>
          <div class="result-key" id="resultKey"></div>
          <div class="result-meta">
            <div class="expire-info">
              <i data-lucide="timer"></i>
              <span id="expireText"></span>
            </div>
            <button class="copy-btn" onclick="copyKey()">
              <i data-lucide="copy"></i>
              Copy
            </button>
          </div>
        </div>
      </div>

      <!-- Remaining -->
      <div class="remaining-bar">
        <div class="label">
          <i data-lucide="info"></i>
          ယနေ့ ကျန်ရှိသော အကြိမ်
        </div>
        <div class="count" id="remainingCount">-</div>
      </div>
    </div>

    <div class="footer">
      Powered by <a href="#">Pagaduu</a> &copy; 2025
    </div>
  </div>

  <!-- Success Overlay -->
  <div class="success-overlay" id="successOverlay">
    <div class="success-popup">
      <div class="check-circle"><i data-lucide="check"></i></div>
      <h3>အောင်မြင်ပါသည်!</h3>
      <p>Key ကို Copy ယူ၍ အသုံးပြုပါ</p>
    </div>
  </div>

  <!-- Toast -->
  <div class="toast" id="toast">
    <i data-lucide="check-circle-2"></i>
    Copy ကူးယူပြီးပါပြီ!
  </div>

<script>
  // Initialize
  document.addEventListener('DOMContentLoaded', () => {
    lucide.createIcons();
    AOS.init({ once: true, duration: 600 });
    createParticles();
    checkRemaining();
    protectDevTools();
  });

  // Create particles
  function createParticles() {
    const container = document.getElementById('particles');
    for (let i = 0; i < 30; i++) {
      const particle = document.createElement('div');
      particle.className = 'particle';
      particle.style.left = Math.random() * 100 + '%';
      particle.style.top = Math.random() * 100 + '%';
      particle.style.animationDelay = Math.random() * 4 + 's';
      particle.style.animationDuration = (3 + Math.random() * 3) + 's';
      container.appendChild(particle);
    }
  }

  // DevTools protection & anti-debug
  function protectDevTools() {
    // Disable right-click
    document.addEventListener('contextmenu', e => e.preventDefault());

    // Disable common dev shortcuts
    document.addEventListener('keydown', e => {
      if (e.key === 'F12' ||
          (e.ctrlKey && e.shiftKey && (e.key === 'I' || e.key === 'J' || e.key === 'C')) ||
          (e.ctrlKey && e.key === 'U') ||
          (e.ctrlKey && e.key === 'S')) {
        e.preventDefault();
      }
    });

    // Anti-debug: detect DevTools via timing
    (function antiDebug() {
      const threshold = 160;
      setInterval(() => {
        const start = performance.now();
        debugger;
        const end = performance.now();
        if (end - start > threshold) {
          document.body.innerHTML = '<div style="display:flex;align-items:center;justify-content:center;height:100vh;color:#ef4444;font-size:24px;font-family:Padauk,sans-serif;text-align:center;padding:20px;">ခွင့်မပြုပါ။<br>Developer Tools ပိတ်ပါ။</div>';
        }
      }, 1000);
    })();
  }

  let currentKey = '';

  async function checkRemaining() {
    try {
      const res = await fetch('/api/check', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' }
      });
      const data = await res.json();
      document.getElementById('statRemaining').textContent = data.remaining + '/' + data.maxPerDay;
      document.getElementById('statExpire').textContent = data.expireHours;
      document.getElementById('remainingCount').textContent = data.remaining + ' ကြိမ်';

      if (!data.allowed) {
        document.getElementById('generateBtn').disabled = true;
        document.getElementById('btnText').textContent = 'ယနေ့ ကုန်သွားပါပြီ';
      }
    } catch (e) {
      console.log('Check failed');
    }
  }

  // Decrypt payload
  async function decryptPayload(base64Data) {
    const binaryStr = atob(base64Data);
    const bytes = new Uint8Array(binaryStr.length);
    for (let i = 0; i < binaryStr.length; i++) {
      bytes[i] = binaryStr.charCodeAt(i);
    }

    const keyData = bytes.slice(0, 32);
    const iv = bytes.slice(32, 44);
    const ciphertext = bytes.slice(44);

    const key = await crypto.subtle.importKey(
      'raw', keyData, { name: 'AES-GCM' }, false, ['decrypt']
    );

    const decrypted = await crypto.subtle.decrypt(
      { name: 'AES-GCM', iv }, key, ciphertext
    );

    return JSON.parse(new TextDecoder().decode(decrypted));
  }

  async function handleGenerate() {
    const btn = document.getElementById('generateBtn');
    const spinner = document.getElementById('spinner');
    const btnText = document.getElementById('btnText');
    const errorMsg = document.getElementById('errorMsg');
    const resultArea = document.getElementById('resultArea');

    // Reset
    errorMsg.classList.remove('show');
    resultArea.classList.remove('show');

    // Loading state
    btn.disabled = true;
    spinner.style.display = 'block';
    btnText.textContent = 'Generating...';

    try {
      const res = await fetch('/api/generate', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' }
      });

      const data = await res.json();

      if (!data.success) {
        document.getElementById('errorText').textContent = data.message;
        errorMsg.classList.add('show');

        if (data.error === 'limit_reached') {
          btn.disabled = true;
          btnText.textContent = 'ယနေ့ ကုန်သွားပါပြီ';
          spinner.style.display = 'none';
          return;
        }
      } else {
        // Decrypt the payload
        const decrypted = await decryptPayload(data.payload);
        currentKey = decrypted.key;

        document.getElementById('resultKey').textContent = currentKey;
        document.getElementById('expireText').textContent = 'သက်တမ်း - ' + decrypted.expireAt + ' ထိ';
        resultArea.classList.add('show');

        // Update remaining
        const remaining = decrypted.remaining;
        document.getElementById('remainingCount').textContent = remaining + ' ကြိမ်';
        document.getElementById('statRemaining').textContent = remaining + '/' + document.getElementById('statRemaining').textContent.split('/')[1];

        if (remaining <= 0) {
          btn.disabled = true;
          btnText.textContent = 'ယနေ့ ကုန်သွားပါပြီ';
          spinner.style.display = 'none';
          showSuccess();
          return;
        }

        showSuccess();
      }
    } catch (e) {
      document.getElementById('errorText').textContent = 'ချိတ်ဆက်မှု မအောင်မြင်ပါ။ ထပ်ကြိုးစားပါ။';
      errorMsg.classList.add('show');
    }

    // Reset button
    spinner.style.display = 'none';
    btnText.textContent = 'Generate Key';
    // Re-enable only if not at limit
    if (!btn.textContent.includes('ကုန်သွားပါပြီ')) {
      btn.disabled = false;
    }
    lucide.createIcons();
  }

  function showSuccess() {
    const overlay = document.getElementById('successOverlay');
    overlay.classList.add('show');
    lucide.createIcons();
    setTimeout(() => overlay.classList.remove('show'), 2000);
  }

  function copyKey() {
    if (!currentKey) return;
    navigator.clipboard.writeText(currentKey).then(() => {
      const toast = document.getElementById('toast');
      toast.classList.add('show');
      setTimeout(() => toast.classList.remove('show'), 2500);
    });
  }
</script>

</body>
</html>`;
}

// ============== ROUTER ==============

Deno.serve(async (req) => {
  const url = new URL(req.url);

  if (url.pathname === "/api/generate") {
    return await handleGenerate(req);
  }

  if (url.pathname === "/api/check") {
    return await handleCheckRemaining(req);
  }

  // Serve HTML
  return new Response(getHTML(), {
    headers: {
      "Content-Type": "text/html; charset=utf-8",
      "Cache-Control": "no-store",
      "X-Frame-Options": "DENY",
      "X-Content-Type-Options": "nosniff",
      "Content-Security-Policy": "default-src 'self' 'unsafe-inline' 'unsafe-eval' https://fonts.googleapis.com https://fonts.gstatic.com https://unpkg.com;",
    }
  });
});
