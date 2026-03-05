// main.ts - Deno Deploy Entry Point (Full Secure Version)

const kv = await Deno.openKv();

// ============== CONFIGURATION ==============
function getConfig() {
  const keysRaw = Deno.env.get("VLESS_KEYS") || "";
  const keys = keysRaw.split(",").map(k => k.trim()).filter(k => k.length > 0);
  const expireHours = parseInt(Deno.env.get("EXPIRE_HOURS") || "24");
  const maxPerDay = parseInt(Deno.env.get("MAX_GENERATES_PER_DAY") || "2");
  return { keys, expireHours, maxPerDay };
}

// ============== SECURITY: CSRF TOKEN ==============

async function generateCSRFToken(ip: string): Promise<string> {
  const secret = Deno.env.get("CSRF_SECRET") || "pagaduu-csrf-default-secret-2024";
  const hour = Math.floor(Date.now() / (1000 * 60 * 60)); // Rotate hourly
  const raw = `${ip}||${hour}||${secret}`;
  return await hashSHA256(raw);
}

async function validateCSRFToken(token: string, ip: string): Promise<boolean> {
  const secret = Deno.env.get("CSRF_SECRET") || "pagaduu-csrf-default-secret-2024";
  const hour = Math.floor(Date.now() / (1000 * 60 * 60));
  // Check current hour and previous hour (for edge cases)
  const current = await hashSHA256(`${ip}||${hour}||${secret}`);
  const previous = await hashSHA256(`${ip}||${hour - 1}||${secret}`);
  return token === current || token === previous;
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

async function incrementRateLimitAtomic(fingerprint: string, ipFingerprint: string): Promise<boolean> {
  const now = new Date();
  const todayKey = `${now.getUTCFullYear()}-${now.getUTCMonth()}-${now.getUTCDate()}`;
  const fpKey = ["rate_limit", fingerprint, todayKey];
  const ipKey = ["rate_limit", ipFingerprint, todayKey];

  const maxRetries = 5;
  for (let i = 0; i < maxRetries; i++) {
    const fpEntry = await kv.get<number>(fpKey);
    const ipEntry = await kv.get<number>(ipKey);
    const fpCount = fpEntry.value || 0;
    const ipCount = ipEntry.value || 0;

    const expireIn = 48 * 60 * 60 * 1000; // 48 hours

    // Atomic transaction: both counters must succeed together
    const result = await kv.atomic()
      .check(fpEntry) // Ensure fpEntry hasn't changed
      .check(ipEntry) // Ensure ipEntry hasn't changed
      .set(fpKey, fpCount + 1, { expireIn })
      .set(ipKey, ipCount + 1, { expireIn })
      .commit();

    if (result.ok) {
      return true;
    }
    // If commit failed (conflict), retry
    await new Promise(resolve => setTimeout(resolve, 50 * (i + 1)));
  }
  return false; // All retries failed
}

// ============== KEY MANAGEMENT ==============

async function getRandomKey(config: ReturnType<typeof getConfig>): Promise<{ key: string; expireAt: string } | null> {
  if (config.keys.length === 0) return null;

  // Use crypto.getRandomValues for better randomness
  const randomBytes = new Uint32Array(1);
  crypto.getRandomValues(randomBytes);
  const randomIndex = randomBytes[0] % config.keys.length;
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

  const combined = new Uint8Array(32 + 12 + new Uint8Array(ciphertext).length);
  combined.set(new Uint8Array(exportedKey), 0);
  combined.set(iv, 32);
  combined.set(new Uint8Array(ciphertext), 44);

  return btoa(String.fromCharCode(...combined));
}

// ============== RESPONSE HELPERS ==============

function jsonResponse(data: unknown, status = 200, extraHeaders: Record<string, string> = {}): Response {
  return new Response(JSON.stringify(data), {
    status,
    headers: {
      "Content-Type": "application/json",
      "Cache-Control": "no-store, no-cache, must-revalidate, proxy-revalidate",
      "Pragma": "no-cache",
      "Expires": "0",
      "X-Content-Type-Options": "nosniff",
      "X-Frame-Options": "DENY",
      "X-XSS-Protection": "1; mode=block",
      "Referrer-Policy": "no-referrer",
      ...extraHeaders,
    }
  });
}

function getClientIP(req: Request): string {
  return req.headers.get("x-forwarded-for")?.split(",")[0]?.trim()
    || req.headers.get("cf-connecting-ip")
    || req.headers.get("x-real-ip")
    || "unknown";
}

// ============== REQUEST VALIDATION ==============

function validateRequest(req: Request): { valid: boolean; error?: string } {
  const contentType = req.headers.get("content-type") || "";
  const origin = req.headers.get("origin") || "";
  const referer = req.headers.get("referer") || "";

  // Must have a user-agent (basic bot filtering)
  const ua = req.headers.get("user-agent") || "";
  if (!ua || ua.length < 10) {
    return { valid: false, error: "Invalid request" };
  }

  return { valid: true };
}

// ============== API HANDLERS ==============

async function handleGenerate(req: Request): Promise<Response> {
  if (req.method !== "POST") {
    return jsonResponse({ error: "Method not allowed" }, 405);
  }

  // Validate request
  const validation = validateRequest(req);
  if (!validation.valid) {
    return jsonResponse({ success: false, error: "invalid_request", message: "ခွင့်မပြုပါ။" }, 403);
  }

  // Parse body & check honeypot + CSRF
  try {
    const body = await req.json();

    // Honeypot check: if the hidden field is filled, it's a bot
    if (body.website && body.website.length > 0) {
      // Bot detected - return fake success to confuse
      return jsonResponse({
        success: true,
        payload: btoa("bot-detected-fake-payload"),
        remaining: 0
      });
    }

    // CSRF token validation
    const ip = getClientIP(req);
    if (!body.csrf_token || !(await validateCSRFToken(body.csrf_token, ip))) {
      return jsonResponse({ success: false, error: "invalid_token", message: "Session သက်တမ်းကုန်ပါပြီ။ Page ကို Refresh လုပ်ပါ။" }, 403);
    }
  } catch {
    return jsonResponse({ success: false, error: "invalid_body", message: "ခွင့်မပြုပါ။" }, 400);
  }

  const config = getConfig();
  const ip = getClientIP(req);
  const userAgent = req.headers.get("user-agent") || "unknown";

  const fingerprint = await generateServerFingerprint(ip, userAgent);
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

  // Atomic increment - handles concurrent users safely
  const incrementSuccess = await incrementRateLimitAtomic(fingerprint, ipFingerprint);
  if (!incrementSuccess) {
    return jsonResponse({
      success: false,
      error: "server_busy",
      message: "Server အလုပ်များနေပါသည်။ ခဏစောင့်၍ ထပ်ကြိုးစားပါ။"
    }, 503);
  }

  const remaining = Math.min(fpCheck.remaining, ipCheck.remaining) - 1;

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

async function handleCheckRemaining(req: Request): Promise<Response> {
  if (req.method !== "POST") {
    return jsonResponse({ error: "Method not allowed" }, 405);
  }

  const config = getConfig();
  const ip = getClientIP(req);
  const userAgent = req.headers.get("user-agent") || "unknown";

  const fingerprint = await generateServerFingerprint(ip, userAgent);
  const ipFingerprint = await hashSHA256(`ip-only-${ip}-pagaduu-salt`);

  const fpCheck = await checkRateLimit(fingerprint, config.maxPerDay);
  const ipCheck = await checkRateLimit(ipFingerprint, config.maxPerDay);

  const remaining = Math.min(fpCheck.remaining, ipCheck.remaining);
  const allowed = fpCheck.allowed && ipCheck.allowed;

  // Generate CSRF token for this session
  const csrfToken = await generateCSRFToken(ip);

  return jsonResponse({
    remaining,
    allowed,
    maxPerDay: config.maxPerDay,
    expireHours: config.expireHours,
    csrf_token: csrfToken
  });
}

// ============== HTML PAGE ==============

function getHTML(): string {
  return `<!DOCTYPE html>
<html lang="my">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0, maximum-scale=1.0, user-scalable=no">
  <title>Pagaduu - VLESS Key Generator</title>

  <!-- Fonts -->
  <link rel="preconnect" href="https://fonts.googleapis.com">
  <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
  <link href="https://fonts.googleapis.com/css2?family=Padauk:wght@400;700&family=Inter:wght@300;400;500;600;700&family=JetBrains+Mono:wght@400;500&display=swap" rel="stylesheet">

  <!-- Lucide Icons -->
  <script src="https://unpkg.com/lucide@latest/dist/umd/lucide.min.js"></script>

  <!-- AOS Animation -->
  <link href="https://unpkg.com/aos@2.3.4/dist/aos.css" rel="stylesheet">
  <script src="https://unpkg.com/aos@2.3.4/dist/aos.js"></script>

  <!-- QR Code Library -->
  <script src="https://unpkg.com/qrcode-generator@1.4.4/qrcode.js"></script>

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
      --warning: #f59e0b;
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
      top: 0; left: 0;
      width: 100%; height: 100%;
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

    .header-right {
      display: flex;
      align-items: center;
      gap: 10px;
    }

    .tg-btn {
      display: flex;
      align-items: center;
      gap: 5px;
      padding: 6px 12px;
      background: rgba(0, 136, 204, 0.2);
      border: 1px solid rgba(0, 136, 204, 0.4);
      border-radius: 10px;
      color: #38bdf8;
      font-size: 11px;
      font-weight: 600;
      text-decoration: none;
      transition: all 0.3s;
      font-family: 'Padauk', sans-serif;
    }

    .tg-btn:hover {
      background: rgba(0, 136, 204, 0.35);
      border-color: #38bdf8;
      transform: translateY(-1px);
    }

    .tg-btn i { width: 14px; height: 14px; }

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

    /* Compatible Apps Notice */
    .compat-notice {
      margin-bottom: 20px;
      padding: 14px 16px;
      background: rgba(99, 102, 241, 0.08);
      border: 1px solid rgba(99, 102, 241, 0.2);
      border-radius: 12px;
    }

    .compat-notice .compat-title {
      font-size: 12px;
      font-weight: 700;
      color: var(--primary-light);
      margin-bottom: 8px;
      display: flex;
      align-items: center;
      gap: 6px;
    }

    .compat-notice .compat-title i { width: 14px; height: 14px; }

    .compat-apps {
      display: flex;
      flex-wrap: wrap;
      gap: 6px;
      margin-bottom: 10px;
    }

    .compat-app {
      padding: 4px 10px;
      background: rgba(16, 185, 129, 0.15);
      border: 1px solid rgba(16, 185, 129, 0.3);
      border-radius: 8px;
      font-size: 11px;
      color: var(--success);
      font-weight: 600;
    }

    .compat-warning {
      display: flex;
      align-items: center;
      gap: 6px;
      padding: 8px 12px;
      background: rgba(239, 68, 68, 0.1);
      border: 1px solid rgba(239, 68, 68, 0.25);
      border-radius: 8px;
      font-size: 11px;
      color: #fca5a5;
      margin-top: 8px;
    }

    .compat-warning i { width: 14px; height: 14px; flex-shrink: 0; color: var(--danger); }

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

    .generate-btn:hover::before { left: 100%; }

    .generate-btn:hover {
      transform: translateY(-2px);
      box-shadow: 0 8px 25px rgba(99,102,241,0.5);
    }

    .generate-btn:active { transform: translateY(0); }

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

    .action-buttons {
      display: flex;
      gap: 8px;
    }

    .copy-btn, .qr-btn {
      display: flex;
      align-items: center;
      gap: 6px;
      padding: 8px 14px;
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

    .copy-btn:hover, .qr-btn:hover {
      background: var(--primary);
      color: white;
    }

    .copy-btn i, .qr-btn i { width: 14px; height: 14px; }

    /* QR Modal */
    .qr-modal {
      position: fixed;
      top: 0; left: 0;
      width: 100%; height: 100%;
      z-index: 150;
      display: none;
      align-items: center;
      justify-content: center;
      background: rgba(0,0,0,0.6);
      backdrop-filter: blur(6px);
    }

    .qr-modal.show {
      display: flex;
      animation: fadeIn 0.3s ease;
    }

    .qr-modal-content {
      background: var(--bg-card);
      border: 1px solid var(--glass-border);
      border-radius: 20px;
      padding: 28px;
      text-align: center;
      animation: popIn 0.4s cubic-bezier(0.68, -0.55, 0.265, 1.55);
      max-width: 320px;
      width: 90%;
    }

    .qr-modal-content h3 {
      color: white;
      margin-bottom: 6px;
      font-size: 16px;
    }

    .qr-modal-content p {
      color: var(--text-dim);
      font-size: 12px;
      margin-bottom: 16px;
    }

    .qr-code-container {
      background: white;
      border-radius: 12px;
      padding: 16px;
      display: inline-block;
      margin-bottom: 16px;
    }

    .qr-code-container canvas, .qr-code-container img {
      display: block;
    }

    .qr-close-btn {
      padding: 10px 28px;
      background: var(--glass);
      border: 1px solid var(--glass-border);
      border-radius: 10px;
      color: var(--text);
      font-family: 'Padauk', sans-serif;
      font-size: 14px;
      cursor: pointer;
      transition: all 0.3s;
    }

    .qr-close-btn:hover {
      background: rgba(255,255,255,0.1);
    }

    /* How to use section */
    .howto-section {
      margin-top: 20px;
      padding: 16px;
      background: rgba(0,0,0,0.2);
      border: 1px solid var(--glass-border);
      border-radius: 12px;
    }

    .howto-toggle {
      display: flex;
      align-items: center;
      justify-content: space-between;
      cursor: pointer;
      user-select: none;
    }

    .howto-toggle .label {
      font-size: 13px;
      color: var(--text-dim);
      display: flex;
      align-items: center;
      gap: 6px;
      font-weight: 600;
    }

    .howto-toggle .label i { width: 16px; height: 16px; }

    .howto-toggle .arrow {
      color: var(--text-dim);
      transition: transform 0.3s;
    }

    .howto-toggle .arrow i { width: 16px; height: 16px; }

    .howto-toggle.open .arrow { transform: rotate(180deg); }

    .howto-content {
      max-height: 0;
      overflow: hidden;
      transition: max-height 0.4s ease;
    }

    .howto-content.open {
      max-height: 600px;
    }

    .howto-steps {
      padding-top: 14px;
      font-size: 12.5px;
      color: var(--text-dim);
      line-height: 1.8;
    }

    .howto-steps .step {
      display: flex;
      gap: 10px;
      margin-bottom: 10px;
    }

    .howto-steps .step-num {
      width: 22px; height: 22px;
      background: rgba(99,102,241,0.2);
      border-radius: 6px;
      display: flex;
      align-items: center;
      justify-content: center;
      font-size: 11px;
      font-weight: 700;
      color: var(--primary-light);
      flex-shrink: 0;
      margin-top: 2px;
    }

    .howto-steps .app-name {
      color: var(--primary-light);
      font-weight: 600;
    }

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

    /* Telegram Contact Bar */
    .tg-contact-bar {
      margin-top: 20px;
      padding: 14px 18px;
      background: rgba(0, 136, 204, 0.08);
      border: 1px solid rgba(0, 136, 204, 0.2);
      border-radius: 12px;
      display: flex;
      align-items: center;
      justify-content: space-between;
    }

    .tg-contact-bar .tg-info {
      display: flex;
      align-items: center;
      gap: 10px;
    }

    .tg-contact-bar .tg-icon {
      width: 36px; height: 36px;
      background: rgba(0, 136, 204, 0.2);
      border-radius: 10px;
      display: flex;
      align-items: center;
      justify-content: center;
      color: #38bdf8;
    }

    .tg-contact-bar .tg-icon i { width: 18px; height: 18px; }

    .tg-contact-bar .tg-text {
      font-size: 12px;
      color: var(--text-dim);
    }

    .tg-contact-bar .tg-text strong {
      display: block;
      color: #38bdf8;
      font-size: 13px;
    }

    .tg-contact-bar .tg-link {
      padding: 8px 16px;
      background: rgba(0, 136, 204, 0.2);
      border: 1px solid rgba(0, 136, 204, 0.3);
      border-radius: 10px;
      color: #38bdf8;
      font-family: 'Padauk', sans-serif;
      font-size: 12px;
      font-weight: 600;
      text-decoration: none;
      transition: all 0.3s;
    }

    .tg-contact-bar .tg-link:hover {
      background: rgba(0, 136, 204, 0.35);
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

    /* Toast */
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

    /* Scrollbar */
    ::-webkit-scrollbar { width: 4px; }
    ::-webkit-scrollbar-track { background: transparent; }
    ::-webkit-scrollbar-thumb { background: var(--primary); border-radius: 4px; }

    /* Honeypot - hidden from real users */
    .hp-field {
      position: absolute;
      left: -9999px;
      top: -9999px;
      opacity: 0;
      height: 0;
      width: 0;
      overflow: hidden;
      pointer-events: none;
      tab-index: -1;
    }

    @media (max-width: 400px) {
      .container { padding: 12px; }
      .main-card { padding: 24px 16px; }
      .header { padding: 12px 16px; }
      .header-brand h1 { font-size: 15px; }
      .action-buttons { flex-direction: column; }
      .action-buttons .copy-btn, .action-buttons .qr-btn { width: 100%; justify-content: center; }
      .result-meta { flex-direction: column; gap: 12px; align-items: flex-start; }
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
          <h1>Pagaduu VPN</h1>
          <span>VLESS Key Generator</span>
        </div>
      </div>
      <div class="header-right">
        <a href="https://t.me/iqowoq" target="_blank" rel="noopener" class="tg-btn">
          <i data-lucide="send"></i>
          TG
        </a>
        <div class="header-badge">PRO</div>
      </div>
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

      <!-- Compatible Apps -->
      <div class="compat-notice">
        <div class="compat-title">
          <i data-lucide="smartphone"></i>
          အသုံးပြုနိုင်သော Apps များ
        </div>
        <div class="compat-apps">
          <span class="compat-app">V2rayNG</span>
          <span class="compat-app">V2Box</span>
          <span class="compat-app">Nekoray</span>
          <span class="compat-app">V2rayN</span>
          <span class="compat-app">Streisand</span>
          <span class="compat-app">Shadowrocket</span>
        </div>
        <div class="compat-warning">
          <i data-lucide="alert-triangle"></i>
          <span><strong>Hiddify App တွင် သုံး၍ မရနိုင်ပါ။</strong> V2rayNG (သို့) V2Box ကို အသုံးပြုပါ။</span>
        </div>
      </div>

      <!-- Honeypot (hidden from real users, bots will fill this) -->
      <div class="hp-field" aria-hidden="true">
        <input type="text" id="hpWebsite" name="website" tabindex="-1" autocomplete="off">
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
            <div class="action-buttons">
              <button class="copy-btn" onclick="copyKey()">
                <i data-lucide="copy"></i>
                Copy
              </button>
              <button class="qr-btn" onclick="showQR()">
                <i data-lucide="qr-code"></i>
                QR
              </button>
            </div>
          </div>
        </div>
      </div>

      <!-- How to use -->
      <div class="howto-section">
        <div class="howto-toggle" id="howtoToggle" onclick="toggleHowto()">
          <div class="label">
            <i data-lucide="help-circle"></i>
            Key အသုံးပြုနည်း
          </div>
          <div class="arrow">
            <i data-lucide="chevron-down"></i>
          </div>
        </div>
        <div class="howto-content" id="howtoContent">
          <div class="howto-steps">
            <div class="step">
              <div class="step-num">1</div>
              <div>Generate Key ခလုတ်နှိပ်ပြီး Key ကို <strong>Copy</strong> ယူပါ (သို့) <strong>QR Code</strong> ကို Scan ဖတ်ပါ။</div>
            </div>
            <div class="step">
              <div class="step-num">2</div>
              <div><span class="app-name">V2rayNG</span> - ညာဘက်အပေါ် <strong>+</strong> နှိပ် → "Import config from clipboard" ကိုရွေးပါ။</div>
            </div>
            <div class="step">
              <div class="step-num">3</div>
              <div><span class="app-name">V2Box</span> - ညာဘက်အပေါ် <strong>+</strong> နှိပ် → "Import from clipboard" ကိုရွေးပါ။ QR scan လည်း ရပါသည်။</div>
            </div>
            <div class="step">
              <div class="step-num">4</div>
              <div>ချိတ်ဆက်ပြီး ယခု ပြထားသော <strong>သက်တမ်းကုန်ဆုံးချိန်</strong>ထိ အသုံးပြုနိုင်ပါသည်။</div>
            </div>
            <div class="step" style="margin-top: 6px;">
              <div class="step-num" style="background: rgba(239,68,68,0.2); color: var(--danger);">!</div>
              <div style="color: #fca5a5;"><strong>Hiddify App</strong> တွင် ဤ Key ကို သုံး၍ <strong>မရနိုင်ပါ</strong>။ V2rayNG (သို့) V2Box ကို အသုံးပြုပါ။</div>
            </div>
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

      <!-- Telegram Contact -->
      <div class="tg-contact-bar">
        <div class="tg-info">
          <div class="tg-icon">
            <i data-lucide="send"></i>
          </div>
          <div class="tg-text">
            အကူအညီ / ဆက်သွယ်ရန်
            <strong>@iqowoq</strong>
          </div>
        </div>
        <a href="https://t.me/iqowoq" target="_blank" rel="noopener" class="tg-link">
          Message
        </a>
      </div>
    </div>

    <div class="footer">
      Powered by <a href="https://t.me/iqowoq" target="_blank" rel="noopener">Pagaduu</a> &copy; 2025 | <a href="https://t.me/iqowoq" target="_blank" rel="noopener">Telegram</a>
    </div>
  </div>

  <!-- Success Overlay -->
  <div class="success-overlay" id="successOverlay">
    <div class="success-popup">
      <div class="check-circle"><i data-lucide="check"></i></div>
      <h3>အောင်မြင်ပါသည်!</h3>
      <p>Key ကို Copy ယူ၍ V2rayNG / V2Box တွင် အသုံးပြုပါ</p>
    </div>
  </div>

  <!-- QR Modal -->
  <div class="qr-modal" id="qrModal">
    <div class="qr-modal-content">
      <h3>QR Code Scan ဖတ်ပါ</h3>
      <p>V2rayNG / V2Box App ဖြင့် Scan ဖတ်ပါ</p>
      <div class="qr-code-container" id="qrCodeContainer"></div>
      <br>
      <button class="qr-close-btn" onclick="closeQR()">ပိတ်မည်</button>
    </div>
  </div>

  <!-- Toast -->
  <div class="toast" id="toast">
    <i data-lucide="check-circle-2"></i>
    Copy ကူးယူပြီးပါပြီ!
  </div>

<script>
  // ====== INITIALIZATION ======
  let csrfToken = '';
  let currentKey = '';
  let isGenerating = false;

  document.addEventListener('DOMContentLoaded', () => {
    lucide.createIcons();
    AOS.init({ once: true, duration: 600 });
    createParticles();
    checkRemaining();
    protectDevTools();
  });

  // ====== PARTICLES ======
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

  // ====== DEVTOOLS PROTECTION ======
  function protectDevTools() {
    document.addEventListener('contextmenu', e => e.preventDefault());

    document.addEventListener('keydown', e => {
      if (e.key === 'F12' ||
          (e.ctrlKey && e.shiftKey && (e.key === 'I' || e.key === 'J' || e.key === 'C')) ||
          (e.ctrlKey && e.key === 'U') ||
          (e.ctrlKey && e.key === 'S')) {
        e.preventDefault();
      }
    });

    // Anti-debug
    (function antiDebug() {
      const threshold = 160;
      setInterval(() => {
        const start = performance.now();
        debugger;
        const end = performance.now();
        if (end - start > threshold) {
          document.body.innerHTML = '<div style="display:flex;align-items:center;justify-content:center;height:100vh;color:#ef4444;font-size:24px;font-family:Padauk,sans-serif;text-align:center;padding:20px;">ခွင့်မပြုပါ။<br>Developer Tools ပိတ်ပါ။</div>';
        }
      }, 2000);
    })();
  }

  // ====== CHECK REMAINING ======
  async function checkRemaining() {
    try {
      const res = await fetch('/api/check', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({})
      });
      const data = await res.json();

      // Store CSRF token
      csrfToken = data.csrf_token || '';

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

  // ====== DECRYPT PAYLOAD ======
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

  // ====== GENERATE KEY ======
  async function handleGenerate() {
    if (isGenerating) return;
    isGenerating = true;

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
      // Honeypot value
      const hpValue = document.getElementById('hpWebsite')?.value || '';

      const res = await fetch('/api/generate', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          csrf_token: csrfToken,
          website: hpValue, // Honeypot field
          t: Date.now()
        })
      });

      const data = await res.json();

      if (!data.success) {
        document.getElementById('errorText').textContent = data.message;
        errorMsg.classList.add('show');

        if (data.error === 'limit_reached') {
          btn.disabled = true;
          btnText.textContent = 'ယနေ့ ကုန်သွားပါပြီ';
          spinner.style.display = 'none';
          isGenerating = false;
          return;
        }

        if (data.error === 'invalid_token') {
          // Refresh CSRF token
          await checkRemaining();
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
          // Refresh CSRF for next session
          await checkRemaining();
          isGenerating = false;
          return;
        }

        showSuccess();
        // Refresh CSRF token after successful generate
        await checkRemaining();
      }
    } catch (e) {
      document.getElementById('errorText').textContent = 'ချိတ်ဆက်မှု မအောင်မြင်ပါ။ ထပ်ကြိုးစားပါ။';
      errorMsg.classList.add('show');
    }

    // Reset button
    spinner.style.display = 'none';
    btnText.textContent = 'Generate Key';
    if (btn.textContent && !btn.querySelector('#btnText').textContent.includes('ကုန်သွားပါပြီ')) {
      btn.disabled = false;
    }
    lucide.createIcons();
    isGenerating = false;
  }

  // ====== SUCCESS OVERLAY ======
  function showSuccess() {
    const overlay = document.getElementById('successOverlay');
    overlay.classList.add('show');
    lucide.createIcons();
    setTimeout(() => overlay.classList.remove('show'), 2000);
  }

  // ====== COPY KEY ======
  function copyKey() {
    if (!currentKey) return;
    navigator.clipboard.writeText(currentKey).then(() => {
      showToast('Copy ကူးယူပြီးပါပြီ!');
    }).catch(() => {
      // Fallback for older browsers
      const textarea = document.createElement('textarea');
      textarea.value = currentKey;
      textarea.style.position = 'fixed';
      textarea.style.opacity = '0';
      document.body.appendChild(textarea);
      textarea.select();
      document.execCommand('copy');
      document.body.removeChild(textarea);
      showToast('Copy ကူးယူပြီးပါပြီ!');
    });
  }

  function showToast(message) {
    const toast = document.getElementById('toast');
    toast.querySelector('span') || (toast.innerHTML = '<i data-lucide="check-circle-2"></i>' + message);
    toast.classList.add('show');
    lucide.createIcons();
    setTimeout(() => toast.classList.remove('show'), 2500);
  }

  // ====== QR CODE ======
  function showQR() {
    if (!currentKey) return;

    const modal = document.getElementById('qrModal');
    const container = document.getElementById('qrCodeContainer');

    // Clear previous QR
    container.innerHTML = '';

    try {
      // Generate QR code
      const qr = qrcode(0, 'L');
      qr.addData(currentKey);
      qr.make();

      // Create image
      const size = 200;
      const cellSize = Math.floor(size / qr.getModuleCount());
      container.innerHTML = qr.createImgTag(cellSize, 0);
    } catch (e) {
      // If QR generation fails for long keys, show message
      container.innerHTML = '<p style="color:#666;font-size:12px;padding:20px;">Key ရှည်လွန်းသဖြင့် QR ဖန်တီး၍ မရပါ။<br>Copy ယူ၍ အသုံးပြုပါ။</p>';
    }

    modal.classList.add('show');
  }

  function closeQR() {
    document.getElementById('qrModal').classList.remove('show');
  }

  // Close QR modal on backdrop click
  document.addEventListener('click', (e) => {
    const modal = document.getElementById('qrModal');
    if (e.target === modal) {
      closeQR();
    }
  });

  // ====== HOW TO USE TOGGLE ======
  function toggleHowto() {
    const toggle = document.getElementById('howtoToggle');
    const content = document.getElementById('howtoContent');
    toggle.classList.toggle('open');
    content.classList.toggle('open');
  }
</script>

</body>
</html>`;
}

// ============== ROUTER ==============

Deno.serve(async (req) => {
  const url = new URL(req.url);

  // Security headers for all responses
  const securityHeaders: Record<string, string> = {
    "X-Frame-Options": "DENY",
    "X-Content-Type-Options": "nosniff",
    "X-XSS-Protection": "1; mode=block",
    "Referrer-Policy": "no-referrer",
    "Permissions-Policy": "camera=(), microphone=(), geolocation=()",
    "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
  };

  if (url.pathname === "/api/generate") {
    return await handleGenerate(req);
  }

  if (url.pathname === "/api/check") {
    return await handleCheckRemaining(req);
  }

  // Block common attack paths
  const blockedPaths = ["/wp-admin", "/wp-login", "/.env", "/config", "/admin", "/.git"];
  if (blockedPaths.some(p => url.pathname.toLowerCase().startsWith(p))) {
    return new Response("Not found", { status: 404 });
  }

  // Serve HTML
  return new Response(getHTML(), {
    headers: {
      "Content-Type": "text/html; charset=utf-8",
      "Cache-Control": "no-store, no-cache, must-revalidate",
      "Content-Security-Policy": "default-src 'self'; script-src 'self' 'unsafe-inline' 'unsafe-eval' https://unpkg.com; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com https://unpkg.com; font-src https://fonts.gstatic.com; img-src 'self' data:; connect-src 'self';",
      ...securityHeaders,
    }
  });
});
