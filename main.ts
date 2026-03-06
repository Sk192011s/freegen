// main.ts - Deno Deploy Entry Point (Full Secure Version - Fixed Expiry System V2)

const kv = await Deno.openKv();

// ============== CONFIGURATION ==============
function getConfig() {
  const keysRaw = Deno.env.get("VLESS_KEYS") || "";
  const keys = keysRaw.split(",").map(k => k.trim()).filter(k => k.length > 0);

  // Fixed validity period - all users see the same dates
  const validFrom = Deno.env.get("VALID_FROM") || "2026-03-05";
  const validUntil = Deno.env.get("VALID_UNTIL") || "2026-03-12";

  // Custom display text for validity period
  const validityText = Deno.env.get("VALIDITY_TEXT") || "၅ ရက် မတ်လ ၂၀၂၆ မှ ၁၂ ရက် မတ်လ ၂၀၂၆ ထိ";

  // Max generates per validity period (not per day)
  const maxPerPeriod = parseInt(Deno.env.get("MAX_GENERATES_PER_PERIOD") || "2");

  // Key version - MUST change this when you update keys or dates to reset rate limits
  const keyVersion = Deno.env.get("KEY_VERSION") || "v2";

  // Timezone offset in minutes for Myanmar (UTC+6:30 = 390 minutes)
  const tzOffset = parseInt(Deno.env.get("TZ_OFFSET_MINUTES") || "390");

  return { keys, validFrom, validUntil, validityText, maxPerPeriod, keyVersion, tzOffset };
}

// ============== SECURITY: CSRF TOKEN ==============

async function generateCSRFToken(ip: string): Promise<string> {
  const secret = Deno.env.get("CSRF_SECRET") || "pagaduu-csrf-default-secret-2024";
  const hour = Math.floor(Date.now() / (1000 * 60 * 60));
  const raw = `${ip}||${hour}||${secret}`;
  return await hashSHA256(raw);
}

async function validateCSRFToken(token: string, ip: string): Promise<boolean> {
  const secret = Deno.env.get("CSRF_SECRET") || "pagaduu-csrf-default-secret-2024";
  const hour = Math.floor(Date.now() / (1000 * 60 * 60));
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

/**
 * Check if current time is within the valid period.
 * Uses timezone offset to compare dates in the configured local timezone.
 */
function isWithinValidPeriod(config: ReturnType<typeof getConfig>): boolean {
  const now = Date.now();
  // Convert validFrom/validUntil from local timezone to UTC
  // validFrom "2026-03-05" means start of that day in local timezone
  // validUntil "2026-03-12" means end of that day in local timezone
  const fromLocal = new Date(config.validFrom + "T00:00:00");
  const untilLocal = new Date(config.validUntil + "T23:59:59");

  // Adjust from local timezone to UTC by subtracting the offset
  const fromUTC = fromLocal.getTime() - (config.tzOffset * 60 * 1000);
  const untilUTC = untilLocal.getTime() - (config.tzOffset * 60 * 1000);

  return now >= fromUTC && now <= untilUTC;
}

/**
 * Get the UTC timestamp for when the valid period ends (used for KV expiry).
 */
function getValidUntilUTC(config: ReturnType<typeof getConfig>): number {
  const untilLocal = new Date(config.validUntil + "T23:59:59");
  return untilLocal.getTime() - (config.tzOffset * 60 * 1000);
}

async function checkRateLimit(
  fingerprint: string,
  config: ReturnType<typeof getConfig>
): Promise<{ allowed: boolean; remaining: number; message: string }> {
  // First check if within valid period - no need to check KV if expired
  if (!isWithinValidPeriod(config)) {
    return {
      allowed: false,
      remaining: 0,
      message: "လက်ရှိ Key သက်တမ်း ကုန်ဆုံးနေပါသည်။ Key အသစ်ထွက်လာရင် ပြန်လာပါ။"
    };
  }

  // Rate limit key includes keyVersion + validFrom + validUntil so it resets when config changes
  const periodKey = `${config.keyVersion}_${config.validFrom}_${config.validUntil}`;
  const kvKey = ["rate_limit_period", fingerprint, periodKey];

  const entry = await kv.get<number>(kvKey);
  const count = entry.value || 0;

  if (count >= config.maxPerPeriod) {
    return {
      allowed: false,
      remaining: 0,
      message: `ဤ Key သက်တမ်းအတွင်း Generate လုပ်ခွင့် (${config.maxPerPeriod} ကြိမ်) ကုန်သွားပါပြီ။ Key အသစ်ထွက်လာရင် ပြန်သုံးလို့ ရပါမယ်။`
    };
  }

  return {
    allowed: true,
    remaining: config.maxPerPeriod - count,
    message: ""
  };
}

async function incrementRateLimitAtomic(
  fingerprint: string,
  ipFingerprint: string,
  config: ReturnType<typeof getConfig>
): Promise<boolean> {
  const periodKey = `${config.keyVersion}_${config.validFrom}_${config.validUntil}`;
  const fpKey = ["rate_limit_period", fingerprint, periodKey];
  const ipKey = ["rate_limit_period", ipFingerprint, periodKey];

  // Calculate expiry: time until validUntil + 1 day buffer (in local timezone)
  const untilUTC = getValidUntilUTC(config);
  const expireIn = Math.max(untilUTC - Date.now() + 86400000, 86400000);

  const maxRetries = 5;
  for (let i = 0; i < maxRetries; i++) {
    const fpEntry = await kv.get<number>(fpKey);
    const ipEntry = await kv.get<number>(ipKey);
    const fpCount = fpEntry.value || 0;
    const ipCount = ipEntry.value || 0;

    const result = await kv.atomic()
      .check(fpEntry)
      .check(ipEntry)
      .set(fpKey, fpCount + 1, { expireIn })
      .set(ipKey, ipCount + 1, { expireIn })
      .commit();

    if (result.ok) return true;
    await new Promise(resolve => setTimeout(resolve, 50 * (i + 1)));
  }
  return false;
}

// ============== TOTAL GENERATE COUNTER ==============

async function incrementTotalCount(): Promise<number> {
  const key = ["stats", "total_generates"];
  const maxRetries = 5;
  for (let i = 0; i < maxRetries; i++) {
    const entry = await kv.get<number>(key);
    const count = entry.value || 0;
    const result = await kv.atomic()
      .check(entry)
      .set(key, count + 1)
      .commit();
    if (result.ok) return count + 1;
    await new Promise(resolve => setTimeout(resolve, 50 * (i + 1)));
  }
  return -1;
}

async function getTotalCount(): Promise<number> {
  const entry = await kv.get<number>(["stats", "total_generates"]);
  return entry.value || 0;
}

// ============== KEY MANAGEMENT ==============

function getRandomKey(config: ReturnType<typeof getConfig>): { key: string } | null {
  if (config.keys.length === 0) return null;

  const randomBytes = new Uint32Array(1);
  crypto.getRandomValues(randomBytes);
  const randomIndex = randomBytes[0] % config.keys.length;
  const key = config.keys[randomIndex];

  return { key };
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

  const validation = validateRequest(req);
  if (!validation.valid) {
    return jsonResponse({ success: false, error: "invalid_request", message: "ခွင့်မပြုပါ။" }, 403);
  }

  const ip = getClientIP(req);
  const userAgent = req.headers.get("user-agent") || "unknown";

  try {
    const body = await req.json();

    // Honeypot check
    if (body.website && body.website.length > 0) {
      return jsonResponse({
        success: true,
        payload: btoa("bot-detected-fake-payload"),
        remaining: 0
      });
    }

    // CSRF check
    if (!body.csrf_token || !(await validateCSRFToken(body.csrf_token, ip))) {
      return jsonResponse({
        success: false,
        error: "invalid_token",
        message: "Session သက်တမ်းကုန်ပါပြီ။ Page ကို Refresh လုပ်ပါ။"
      }, 403);
    }
  } catch {
    return jsonResponse({ success: false, error: "invalid_body", message: "ခွင့်မပြုပါ။" }, 400);
  }

  const config = getConfig();

  // Check if within valid period first
  if (!isWithinValidPeriod(config)) {
    return jsonResponse({
      success: false,
      error: "expired",
      message: "လက်ရှိ Key သက်တမ်း ကုန်ဆုံးနေပါသည်။ Key အသစ်ထွက်လာရင် ပြန်လာပါ။"
    }, 403);
  }

  const fingerprint = await generateServerFingerprint(ip, userAgent);
  const ipFingerprint = await hashSHA256(`ip-only-${ip}-pagaduu-salt`);

  const fpCheck = await checkRateLimit(fingerprint, config);
  const ipCheck = await checkRateLimit(ipFingerprint, config);

  if (!fpCheck.allowed || !ipCheck.allowed) {
    const message = !fpCheck.allowed ? fpCheck.message : ipCheck.message;
    return jsonResponse({
      success: false,
      error: "limit_reached",
      message,
      remaining: 0
    }, 429);
  }

  const result = getRandomKey(config);
  if (!result) {
    return jsonResponse({
      success: false,
      error: "no_keys",
      message: "လက်ရှိ Key မရှိပါ။ နောက်မှ ပြန်လာပါ။"
    }, 503);
  }

  const incrementSuccess = await incrementRateLimitAtomic(fingerprint, ipFingerprint, config);
  if (!incrementSuccess) {
    return jsonResponse({
      success: false,
      error: "server_busy",
      message: "Server အလုပ်များနေပါသည်။ ခဏစောင့်၍ ထပ်ကြိုးစားပါ။"
    }, 503);
  }

  const totalCount = await incrementTotalCount();
  const remaining = Math.min(fpCheck.remaining, ipCheck.remaining) - 1;

  const encryptedPayload = await encryptPayload(JSON.stringify({
    key: result.key,
    validityText: config.validityText,
    remaining,
    totalGenerated: totalCount,
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

  const withinPeriod = isWithinValidPeriod(config);

  let remaining = 0;
  let allowed = false;

  if (withinPeriod) {
    const fpCheck = await checkRateLimit(fingerprint, config);
    const ipCheck = await checkRateLimit(ipFingerprint, config);
    remaining = Math.min(fpCheck.remaining, ipCheck.remaining);
    allowed = fpCheck.allowed && ipCheck.allowed;
  }

  const csrfToken = await generateCSRFToken(ip);
  const totalGenerated = await getTotalCount();

  return jsonResponse({
    remaining,
    allowed,
    maxPerPeriod: config.maxPerPeriod,
    validityText: config.validityText,
    validFrom: config.validFrom,
    validUntil: config.validUntil,
    withinPeriod,
    keyVersion: config.keyVersion,
    totalGenerated,
    csrf_token: csrfToken
  });
}

// ============== DEBUG ENDPOINT (remove in production or protect with auth) ==============

async function handleDebug(req: Request): Promise<Response> {
  const authKey = Deno.env.get("DEBUG_AUTH_KEY") || "";
  const url = new URL(req.url);
  const providedKey = url.searchParams.get("key") || "";

  // Only allow if DEBUG_AUTH_KEY env var is set and matches
  if (!authKey || providedKey !== authKey) {
    return new Response("Not found", { status: 404 });
  }

  const config = getConfig();
  const now = new Date();
  const nowUTC = now.toISOString();
  const myanmarTime = new Date(now.getTime() + config.tzOffset * 60 * 1000).toISOString();

  const fromLocal = new Date(config.validFrom + "T00:00:00");
  const untilLocal = new Date(config.validUntil + "T23:59:59");
  const fromUTC = fromLocal.getTime() - (config.tzOffset * 60 * 1000);
  const untilUTC = untilLocal.getTime() - (config.tzOffset * 60 * 1000);

  return jsonResponse({
    currentTimeUTC: nowUTC,
    currentTimeMM: myanmarTime,
    config: {
      validFrom: config.validFrom,
      validUntil: config.validUntil,
      keyVersion: config.keyVersion,
      maxPerPeriod: config.maxPerPeriod,
      tzOffset: config.tzOffset,
      keysCount: config.keys.length,
      validityText: config.validityText
    },
    computed: {
      fromUTC: new Date(fromUTC).toISOString(),
      untilUTC: new Date(untilUTC).toISOString(),
      isWithinPeriod: isWithinValidPeriod(config),
      nowTimestamp: Date.now(),
      fromTimestamp: fromUTC,
      untilTimestamp: untilUTC
    }
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

  <link rel="preconnect" href="https://fonts.googleapis.com">
  <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
  <link href="https://fonts.googleapis.com/css2?family=Padauk:wght@400;700&family=Inter:wght@300;400;500;600;700&family=JetBrains+Mono:wght@400;500&display=swap" rel="stylesheet">

  <script src="https://unpkg.com/lucide@latest/dist/umd/lucide.min.js"><\/script>

  <link href="https://unpkg.com/aos@2.3.4/dist/aos.css" rel="stylesheet">
  <script src="https://unpkg.com/aos@2.3.4/dist/aos.js"><\/script>

  <script src="https://unpkg.com/qrcode-generator@1.4.4/qrcode.js"><\/script>

  <style>
    :root {
      --primary: #6366f1;
      --primary-dark: #4f46e5;
      --primary-light: #818cf8;
      --primary-glow: rgba(99,102,241,0.4);
      --accent: #f59e0b;
      --accent-light: #fbbf24;
      --bg-dark: #050510;
      --bg-card: #0d0d2b;
      --bg-card-alt: #111138;
      --glass: rgba(255,255,255,0.03);
      --glass-hover: rgba(255,255,255,0.06);
      --glass-border: rgba(255,255,255,0.08);
      --glass-border-hover: rgba(255,255,255,0.15);
      --text: #e2e8f0;
      --text-dim: #64748b;
      --text-muted: #475569;
      --success: #10b981;
      --success-light: #34d399;
      --danger: #ef4444;
      --warning: #f59e0b;
      --cyan: #06b6d4;
      --purple: #a855f7;
      --pink: #ec4899;
      --glow-sm: 0 0 20px rgba(99,102,241,0.2);
      --glow-md: 0 0 40px rgba(99,102,241,0.3);
      --glow-lg: 0 4px 60px rgba(99,102,241,0.4);
      --radius-sm: 10px;
      --radius-md: 14px;
      --radius-lg: 20px;
      --radius-xl: 24px;
    }

    * { margin: 0; padding: 0; box-sizing: border-box; }

    body {
      font-family: 'Padauk', 'Inter', sans-serif;
      background: var(--bg-dark);
      color: var(--text);
      min-height: 100vh;
      overflow-x: hidden;
    }

    .bg-animation {
      position: fixed;
      top: 0; left: 0;
      width: 100%; height: 100%;
      z-index: 0;
      overflow: hidden;
      pointer-events: none;
    }

    .bg-grid {
      position: absolute;
      top: 0; left: 0;
      width: 100%; height: 100%;
      background-image:
        linear-gradient(rgba(99,102,241,0.03) 1px, transparent 1px),
        linear-gradient(90deg, rgba(99,102,241,0.03) 1px, transparent 1px);
      background-size: 60px 60px;
    }

    .bg-animation .orb {
      position: absolute;
      border-radius: 50%;
      filter: blur(100px);
      opacity: 0.12;
      animation: orbFloat 25s infinite ease-in-out;
    }

    .bg-animation .orb:nth-child(2) {
      width: 700px; height: 700px;
      background: linear-gradient(135deg, #6366f1, #8b5cf6);
      top: -300px; left: -200px;
      animation-delay: 0s;
    }

    .bg-animation .orb:nth-child(3) {
      width: 500px; height: 500px;
      background: linear-gradient(135deg, #06b6d4, #3b82f6);
      bottom: -200px; right: -200px;
      animation-delay: -8s;
    }

    .bg-animation .orb:nth-child(4) {
      width: 400px; height: 400px;
      background: linear-gradient(135deg, #a855f7, #ec4899);
      top: 40%; left: 60%;
      animation-delay: -16s;
    }

    @keyframes orbFloat {
      0%, 100% { transform: translate(0, 0) scale(1) rotate(0deg); }
      25% { transform: translate(80px, -60px) scale(1.1) rotate(90deg); }
      50% { transform: translate(-40px, 80px) scale(0.9) rotate(180deg); }
      75% { transform: translate(60px, 40px) scale(1.05) rotate(270deg); }
    }

    .particles {
      position: fixed;
      top: 0; left: 0;
      width: 100%; height: 100%;
      z-index: 0;
      pointer-events: none;
    }

    .particle {
      position: absolute;
      width: 2px; height: 2px;
      background: var(--primary-light);
      border-radius: 50%;
      opacity: 0;
      animation: sparkle 5s infinite;
    }

    @keyframes sparkle {
      0% { opacity: 0; transform: translateY(0) scale(0); }
      30% { opacity: 0.6; transform: translateY(-30px) scale(1); }
      100% { opacity: 0; transform: translateY(-80px) scale(0); }
    }

    .container {
      position: relative;
      z-index: 1;
      max-width: 480px;
      margin: 0 auto;
      padding: 16px 14px;
      min-height: 100vh;
      display: flex;
      flex-direction: column;
    }

    .header {
      display: flex;
      align-items: center;
      justify-content: space-between;
      padding: 14px 18px;
      background: var(--glass);
      backdrop-filter: blur(24px);
      -webkit-backdrop-filter: blur(24px);
      border: 1px solid var(--glass-border);
      border-radius: var(--radius-lg);
      margin-bottom: 16px;
    }

    .header-brand {
      display: flex;
      align-items: center;
      gap: 10px;
    }

    .logo-icon {
      width: 38px; height: 38px;
      background: linear-gradient(135deg, var(--primary), var(--purple));
      border-radius: var(--radius-sm);
      display: flex;
      align-items: center;
      justify-content: center;
      box-shadow: 0 0 20px rgba(99,102,241,0.3);
      position: relative;
    }

    .logo-icon::after {
      content: '';
      position: absolute;
      inset: -2px;
      border-radius: 12px;
      background: linear-gradient(135deg, var(--primary), var(--purple));
      z-index: -1;
      opacity: 0.4;
      filter: blur(8px);
    }

    .logo-icon i { color: white; width: 20px; height: 20px; }

    .header-brand h1 {
      font-size: 17px;
      font-weight: 700;
      background: linear-gradient(135deg, #c7d2fe, var(--primary-light));
      -webkit-background-clip: text;
      -webkit-text-fill-color: transparent;
      background-clip: text;
    }

    .header-brand span {
      font-size: 10px;
      color: var(--text-muted);
      display: block;
      margin-top: -1px;
      letter-spacing: 1px;
      text-transform: uppercase;
    }

    .header-right { display: flex; align-items: center; gap: 8px; }

    .tg-btn {
      display: flex;
      align-items: center;
      gap: 5px;
      padding: 6px 12px;
      background: rgba(56, 189, 248, 0.08);
      border: 1px solid rgba(56, 189, 248, 0.2);
      border-radius: var(--radius-sm);
      color: #38bdf8;
      font-size: 11px;
      font-weight: 600;
      text-decoration: none;
      transition: all 0.3s;
      font-family: 'Inter', sans-serif;
    }

    .tg-btn:hover {
      background: rgba(56, 189, 248, 0.15);
      border-color: rgba(56, 189, 248, 0.4);
      transform: translateY(-1px);
    }

    .tg-btn i { width: 13px; height: 13px; }

    .header-badge {
      padding: 5px 12px;
      background: linear-gradient(135deg, var(--primary), var(--purple));
      border-radius: 20px;
      font-size: 10px;
      font-weight: 700;
      color: white;
      letter-spacing: 1.5px;
      text-transform: uppercase;
    }

    .validity-notice {
      margin-bottom: 16px;
      padding: 14px 16px;
      background: linear-gradient(135deg, rgba(6,182,212,0.06), rgba(99,102,241,0.06));
      border: 1px solid rgba(6,182,212,0.15);
      border-radius: var(--radius-md);
      display: flex;
      align-items: center;
      gap: 12px;
    }

    .validity-notice .vn-icon {
      width: 40px; height: 40px;
      background: rgba(6,182,212,0.12);
      border-radius: var(--radius-sm);
      display: flex;
      align-items: center;
      justify-content: center;
      flex-shrink: 0;
    }

    .validity-notice .vn-icon i { width: 20px; height: 20px; color: var(--cyan); }

    .validity-notice .vn-text {
      font-size: 12.5px;
      color: var(--text-dim);
      line-height: 1.6;
    }

    .validity-notice .vn-text strong {
      color: var(--cyan);
      font-weight: 700;
      display: block;
      font-size: 13px;
    }

    .validity-expired {
      border-color: rgba(239,68,68,0.2) !important;
      background: linear-gradient(135deg, rgba(239,68,68,0.06), rgba(239,68,68,0.03)) !important;
    }

    .validity-expired .vn-icon {
      background: rgba(239,68,68,0.12) !important;
    }

    .validity-expired .vn-icon i { color: var(--danger) !important; }
    .validity-expired .vn-text strong { color: #fca5a5 !important; }

    .stats-bar {
      display: grid;
      grid-template-columns: repeat(4, 1fr);
      gap: 10px;
      margin-bottom: 16px;
    }

    .stat-card {
      background: var(--glass);
      backdrop-filter: blur(20px);
      -webkit-backdrop-filter: blur(20px);
      border: 1px solid var(--glass-border);
      border-radius: var(--radius-md);
      padding: 14px 8px;
      text-align: center;
      transition: all 0.3s;
      position: relative;
      overflow: hidden;
    }

    .stat-card::before {
      content: '';
      position: absolute;
      top: 0; left: 0;
      width: 100%; height: 2px;
      border-radius: 2px 2px 0 0;
    }

    .stat-card:nth-child(1)::before { background: linear-gradient(90deg, var(--primary), var(--purple)); }
    .stat-card:nth-child(2)::before { background: linear-gradient(90deg, var(--cyan), #3b82f6); }
    .stat-card:nth-child(3)::before { background: linear-gradient(90deg, var(--accent), #f97316); }
    .stat-card:nth-child(4)::before { background: linear-gradient(90deg, var(--success), #06b6d4); }

    .stat-card:hover {
      border-color: var(--glass-border-hover);
      transform: translateY(-2px);
      background: var(--glass-hover);
    }

    .stat-card .stat-icon {
      width: 32px; height: 32px;
      margin: 0 auto 6px;
      border-radius: 8px;
      display: flex;
      align-items: center;
      justify-content: center;
    }

    .stat-card .stat-icon i { width: 16px; height: 16px; }

    .stat-card:nth-child(1) .stat-icon { background: rgba(99,102,241,0.15); color: var(--primary-light); }
    .stat-card:nth-child(2) .stat-icon { background: rgba(6,182,212,0.15); color: var(--cyan); }
    .stat-card:nth-child(3) .stat-icon { background: rgba(245,158,11,0.15); color: var(--accent); }
    .stat-card:nth-child(4) .stat-icon { background: rgba(16,185,129,0.15); color: var(--success); }

    .stat-card .stat-value {
      font-size: 17px;
      font-weight: 700;
      color: white;
      font-family: 'Inter', sans-serif;
    }

    .stat-card .stat-label {
      font-size: 10px;
      color: var(--text-muted);
      margin-top: 2px;
      letter-spacing: 0.3px;
    }

    .main-card {
      background: var(--glass);
      backdrop-filter: blur(24px);
      -webkit-backdrop-filter: blur(24px);
      border: 1px solid var(--glass-border);
      border-radius: var(--radius-xl);
      padding: 28px 20px;
      flex: 1;
      position: relative;
      overflow: hidden;
    }

    .main-card::before {
      content: '';
      position: absolute;
      top: 0; left: 0;
      width: 100%; height: 100%;
      background: radial-gradient(ellipse at top, rgba(99,102,241,0.04), transparent 60%);
      pointer-events: none;
    }

    .card-header {
      text-align: center;
      margin-bottom: 24px;
      position: relative;
    }

    .card-header .icon-wrapper {
      width: 68px; height: 68px;
      margin: 0 auto 14px;
      border-radius: 18px;
      background: linear-gradient(135deg, var(--primary), var(--purple));
      display: flex;
      align-items: center;
      justify-content: center;
      box-shadow: 0 8px 40px rgba(99,102,241,0.35);
      animation: iconPulse 3s ease-in-out infinite;
      position: relative;
    }

    .card-header .icon-wrapper::after {
      content: '';
      position: absolute;
      inset: -4px;
      border-radius: 22px;
      background: linear-gradient(135deg, var(--primary), var(--purple));
      z-index: -1;
      opacity: 0.2;
      filter: blur(12px);
      animation: iconGlow 3s ease-in-out infinite;
    }

    @keyframes iconPulse {
      0%, 100% { transform: translateY(0) scale(1); }
      50% { transform: translateY(-6px) scale(1.02); }
    }

    @keyframes iconGlow {
      0%, 100% { opacity: 0.2; }
      50% { opacity: 0.4; }
    }

    .card-header .icon-wrapper i { color: white; width: 30px; height: 30px; }

    .card-header h2 {
      font-size: 20px;
      font-weight: 700;
      color: white;
      margin-bottom: 4px;
    }

    .card-header p { font-size: 13px; color: var(--text-dim); }

    .compat-notice {
      margin-bottom: 18px;
      padding: 14px 16px;
      background: rgba(99, 102, 241, 0.04);
      border: 1px solid rgba(99, 102, 241, 0.12);
      border-radius: var(--radius-md);
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

    .compat-apps { display: flex; flex-wrap: wrap; gap: 5px; margin-bottom: 10px; }

    .compat-app {
      padding: 3px 10px;
      background: rgba(16, 185, 129, 0.08);
      border: 1px solid rgba(16, 185, 129, 0.2);
      border-radius: 6px;
      font-size: 11px;
      color: var(--success-light);
      font-weight: 600;
      font-family: 'Inter', sans-serif;
    }

    .compat-warning {
      display: flex;
      align-items: center;
      gap: 6px;
      padding: 8px 12px;
      background: rgba(239, 68, 68, 0.06);
      border: 1px solid rgba(239, 68, 68, 0.15);
      border-radius: 8px;
      font-size: 11px;
      color: #fca5a5;
      margin-top: 8px;
    }

    .compat-warning i { width: 14px; height: 14px; flex-shrink: 0; color: var(--danger); }

    .generate-btn {
      width: 100%;
      padding: 15px;
      border: none;
      border-radius: var(--radius-md);
      background: linear-gradient(135deg, var(--primary), var(--purple));
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
      letter-spacing: 0.3px;
    }

    .generate-btn::before {
      content: '';
      position: absolute;
      top: 0; left: -100%;
      width: 100%; height: 100%;
      background: linear-gradient(90deg, transparent, rgba(255,255,255,0.15), transparent);
      transition: left 0.6s;
    }

    .generate-btn:hover::before { left: 100%; }

    .generate-btn:hover {
      transform: translateY(-2px);
      box-shadow: var(--glow-lg);
    }

    .generate-btn:active { transform: translateY(0); }

    .generate-btn:disabled {
      opacity: 0.4;
      cursor: not-allowed;
      transform: none !important;
      box-shadow: none !important;
    }

    .generate-btn:disabled::before { display: none; }
    .generate-btn i { width: 20px; height: 20px; }

    .spinner {
      width: 20px; height: 20px;
      border: 2px solid rgba(255,255,255,0.3);
      border-top: 2px solid white;
      border-radius: 50%;
      animation: spin 0.8s linear infinite;
      display: none;
    }

    @keyframes spin { to { transform: rotate(360deg); } }

    .result-area { margin-top: 20px; display: none; }
    .result-area.show { display: block; }

    .result-box {
      background: rgba(0,0,0,0.2);
      border: 1px solid rgba(16,185,129,0.15);
      border-radius: var(--radius-md);
      padding: 18px;
      position: relative;
      animation: slideUp 0.5s ease;
    }

    .result-box::before {
      content: '';
      position: absolute;
      top: 0; left: 0;
      width: 100%; height: 2px;
      background: linear-gradient(90deg, var(--success), var(--cyan));
      border-radius: 2px 2px 0 0;
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
      color: var(--success-light);
      font-weight: 600;
    }

    .result-label i { width: 16px; height: 16px; }

    .result-key {
      background: rgba(0,0,0,0.3);
      border: 1px solid var(--glass-border);
      border-radius: var(--radius-sm);
      padding: 14px;
      font-family: 'JetBrains Mono', monospace;
      font-size: 10.5px;
      color: var(--primary-light);
      word-break: break-all;
      line-height: 1.6;
      max-height: 110px;
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
      flex-wrap: wrap;
      gap: 10px;
    }

    .expire-info {
      display: flex;
      align-items: center;
      gap: 6px;
      font-size: 11.5px;
      color: var(--cyan);
    }

    .expire-info i { width: 14px; height: 14px; }

    .action-buttons { display: flex; gap: 8px; }

    .copy-btn, .qr-btn {
      display: flex;
      align-items: center;
      gap: 5px;
      padding: 7px 14px;
      border: 1px solid rgba(99,102,241,0.3);
      border-radius: var(--radius-sm);
      background: rgba(99,102,241,0.08);
      color: var(--primary-light);
      font-family: 'Inter', sans-serif;
      font-size: 12px;
      font-weight: 600;
      cursor: pointer;
      transition: all 0.3s;
    }

    .copy-btn:hover, .qr-btn:hover {
      background: var(--primary);
      color: white;
      border-color: var(--primary);
    }

    .copy-btn i, .qr-btn i { width: 14px; height: 14px; }

    .qr-modal {
      position: fixed;
      top: 0; left: 0;
      width: 100%; height: 100%;
      z-index: 150;
      display: none;
      align-items: center;
      justify-content: center;
      background: rgba(0,0,0,0.7);
      backdrop-filter: blur(8px);
    }

    .qr-modal.show { display: flex; animation: fadeIn 0.3s ease; }

    .qr-modal-content {
      background: var(--bg-card);
      border: 1px solid var(--glass-border);
      border-radius: var(--radius-xl);
      padding: 28px;
      text-align: center;
      animation: popIn 0.4s cubic-bezier(0.68, -0.55, 0.265, 1.55);
      max-width: 300px;
      width: 90%;
    }

    .qr-modal-content h3 { color: white; margin-bottom: 4px; font-size: 16px; }
    .qr-modal-content p { color: var(--text-dim); font-size: 12px; margin-bottom: 16px; }

    .qr-code-container {
      background: white;
      border-radius: var(--radius-md);
      padding: 16px;
      display: inline-block;
      margin-bottom: 16px;
    }

    .qr-code-container canvas, .qr-code-container img { display: block; }

    .qr-close-btn {
      padding: 10px 28px;
      background: var(--glass);
      border: 1px solid var(--glass-border);
      border-radius: var(--radius-sm);
      color: var(--text);
      font-family: 'Padauk', sans-serif;
      font-size: 14px;
      cursor: pointer;
      transition: all 0.3s;
    }

    .qr-close-btn:hover { background: var(--glass-hover); }

    .howto-section {
      margin-top: 18px;
      padding: 14px 16px;
      background: rgba(0,0,0,0.15);
      border: 1px solid var(--glass-border);
      border-radius: var(--radius-md);
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

    .howto-toggle .label i { width: 15px; height: 15px; }

    .howto-toggle .arrow { color: var(--text-muted); transition: transform 0.3s; }
    .howto-toggle .arrow i { width: 15px; height: 15px; }
    .howto-toggle.open .arrow { transform: rotate(180deg); }

    .howto-content { max-height: 0; overflow: hidden; transition: max-height 0.4s ease; }
    .howto-content.open { max-height: 600px; }

    .howto-steps { padding-top: 14px; font-size: 12.5px; color: var(--text-dim); line-height: 1.8; }

    .howto-steps .step { display: flex; gap: 10px; margin-bottom: 10px; }

    .howto-steps .step-num {
      width: 22px; height: 22px;
      background: rgba(99,102,241,0.12);
      border-radius: 6px;
      display: flex;
      align-items: center;
      justify-content: center;
      font-size: 11px;
      font-weight: 700;
      color: var(--primary-light);
      flex-shrink: 0;
      margin-top: 2px;
      font-family: 'Inter', sans-serif;
    }

    .howto-steps .app-name { color: var(--primary-light); font-weight: 600; }

    .remaining-bar {
      margin-top: 18px;
      padding: 13px 16px;
      background: rgba(0,0,0,0.15);
      border: 1px solid var(--glass-border);
      border-radius: var(--radius-md);
      display: flex;
      align-items: center;
      justify-content: space-between;
    }

    .remaining-bar .label {
      font-size: 12.5px;
      color: var(--text-dim);
      display: flex;
      align-items: center;
      gap: 6px;
    }

    .remaining-bar .label i { width: 15px; height: 15px; }

    .remaining-bar .count {
      font-size: 17px;
      font-weight: 700;
      color: var(--accent-light);
      font-family: 'Inter', sans-serif;
    }

    .total-bar {
      margin-top: 10px;
      padding: 13px 16px;
      background: rgba(0,0,0,0.15);
      border: 1px solid var(--glass-border);
      border-radius: var(--radius-md);
      display: flex;
      align-items: center;
      justify-content: space-between;
    }

    .total-bar .label {
      font-size: 12.5px;
      color: var(--text-dim);
      display: flex;
      align-items: center;
      gap: 6px;
    }

    .total-bar .label i { width: 15px; height: 15px; }

    .total-bar .count {
      font-size: 17px;
      font-weight: 700;
      background: linear-gradient(135deg, var(--success-light), var(--cyan));
      -webkit-background-clip: text;
      -webkit-text-fill-color: transparent;
      background-clip: text;
      font-family: 'Inter', sans-serif;
    }

    .error-msg {
      margin-top: 14px;
      padding: 13px 16px;
      background: rgba(239,68,68,0.06);
      border: 1px solid rgba(239,68,68,0.2);
      border-radius: var(--radius-md);
      color: #fca5a5;
      font-size: 13px;
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

    .tg-contact-bar {
      margin-top: 18px;
      padding: 13px 16px;
      background: rgba(56, 189, 248, 0.04);
      border: 1px solid rgba(56, 189, 248, 0.12);
      border-radius: var(--radius-md);
      display: flex;
      align-items: center;
      justify-content: space-between;
    }

    .tg-contact-bar .tg-info { display: flex; align-items: center; gap: 10px; }

    .tg-contact-bar .tg-icon {
      width: 34px; height: 34px;
      background: rgba(56, 189, 248, 0.1);
      border-radius: var(--radius-sm);
      display: flex;
      align-items: center;
      justify-content: center;
      color: #38bdf8;
    }

    .tg-contact-bar .tg-icon i { width: 17px; height: 17px; }

    .tg-contact-bar .tg-text { font-size: 11px; color: var(--text-muted); }
    .tg-contact-bar .tg-text strong { display: block; color: #38bdf8; font-size: 12px; }

    .tg-contact-bar .tg-link {
      padding: 7px 14px;
      background: rgba(56, 189, 248, 0.08);
      border: 1px solid rgba(56, 189, 248, 0.2);
      border-radius: var(--radius-sm);
      color: #38bdf8;
      font-family: 'Inter', sans-serif;
      font-size: 12px;
      font-weight: 600;
      text-decoration: none;
      transition: all 0.3s;
    }

    .tg-contact-bar .tg-link:hover { background: rgba(56, 189, 248, 0.18); }

    .footer {
      text-align: center;
      padding: 20px 0 10px;
      font-size: 11px;
      color: var(--text-muted);
    }

    .footer a { color: var(--primary-light); text-decoration: none; }

    .success-overlay {
      position: fixed;
      top: 0; left: 0;
      width: 100%; height: 100%;
      z-index: 100;
      display: none;
      align-items: center;
      justify-content: center;
      background: rgba(0,0,0,0.6);
      backdrop-filter: blur(6px);
    }

    .success-overlay.show { display: flex; animation: fadeIn 0.3s ease; }

    @keyframes fadeIn { from { opacity: 0; } to { opacity: 1; } }

    .success-popup {
      background: var(--bg-card);
      border: 1px solid rgba(16,185,129,0.3);
      border-radius: var(--radius-xl);
      padding: 32px;
      text-align: center;
      animation: popIn 0.5s cubic-bezier(0.68, -0.55, 0.265, 1.55);
      max-width: 280px;
    }

    @keyframes popIn {
      from { transform: scale(0.5); opacity: 0; }
      to { transform: scale(1); opacity: 1; }
    }

    .success-popup .check-circle {
      width: 56px; height: 56px;
      background: rgba(16,185,129,0.15);
      border-radius: 50%;
      display: flex;
      align-items: center;
      justify-content: center;
      margin: 0 auto 14px;
    }

    .success-popup .check-circle i { color: var(--success); width: 26px; height: 26px; }
    .success-popup h3 { color: white; margin-bottom: 4px; font-size: 16px; }
    .success-popup p { color: var(--text-dim); font-size: 12px; }

    .toast {
      position: fixed;
      bottom: 30px;
      left: 50%;
      transform: translateX(-50%) translateY(100px);
      background: linear-gradient(135deg, var(--success), #059669);
      color: white;
      padding: 11px 22px;
      border-radius: var(--radius-sm);
      font-size: 13px;
      font-weight: 600;
      z-index: 200;
      transition: transform 0.3s cubic-bezier(0.68, -0.55, 0.265, 1.55);
      display: flex;
      align-items: center;
      gap: 8px;
      box-shadow: 0 4px 20px rgba(16,185,129,0.4);
    }

    .toast.show { transform: translateX(-50%) translateY(0); }
    .toast i { width: 15px; height: 15px; }

    ::-webkit-scrollbar { width: 3px; }
    ::-webkit-scrollbar-track { background: transparent; }
    ::-webkit-scrollbar-thumb { background: var(--primary); border-radius: 3px; }

    .hp-field {
      position: absolute;
      left: -9999px; top: -9999px;
      opacity: 0; height: 0; width: 0;
      overflow: hidden; pointer-events: none;
    }

    /* Version badge */
    .version-badge {
      margin-top: 10px;
      padding: 10px 16px;
      background: rgba(99,102,241,0.04);
      border: 1px solid rgba(99,102,241,0.1);
      border-radius: var(--radius-md);
      display: flex;
      align-items: center;
      justify-content: space-between;
    }

    .version-badge .label {
      font-size: 11px;
      color: var(--text-muted);
      display: flex;
      align-items: center;
      gap: 6px;
    }

    .version-badge .label i { width: 13px; height: 13px; }

    .version-badge .value {
      font-size: 12px;
      font-weight: 700;
      color: var(--primary-light);
      font-family: 'Inter', sans-serif;
      text-transform: uppercase;
    }

    @media (max-width: 420px) {
      .container { padding: 10px; }
      .main-card { padding: 22px 16px; }
      .header { padding: 12px 14px; }
      .header-brand h1 { font-size: 15px; }
      .stats-bar { grid-template-columns: repeat(2, 1fr); }
      .action-buttons { flex-direction: column; width: 100%; }
      .action-buttons .copy-btn, .action-buttons .qr-btn { width: 100%; justify-content: center; }
      .result-meta { flex-direction: column; align-items: flex-start; }
    }
  </style>
</head>
<body>

  <div class="bg-animation">
    <div class="bg-grid"></div>
    <div class="orb"></div>
    <div class="orb"></div>
    <div class="orb"></div>
  </div>

  <div class="particles" id="particles"></div>

  <div class="container">
    <div class="header" data-aos="fade-down">
      <div class="header-brand">
        <div class="logo-icon"><i data-lucide="zap"></i></div>
        <div>
          <h1>Pagaduu VPN</h1>
          <span>VLESS Key Generator</span>
        </div>
      </div>
      <div class="header-right">
        <a href="https://t.me/iqowoq" target="_blank" rel="noopener" class="tg-btn">
          <i data-lucide="send"></i> TG
        </a>
        <div class="header-badge">PRO</div>
      </div>
    </div>

    <div class="validity-notice" id="validityNotice" data-aos="fade-up" data-aos-delay="50">
      <div class="vn-icon"><i data-lucide="calendar-check"></i></div>
      <div class="vn-text">
        <strong id="validityText">Loading...</strong>
        <span id="validityStatus">Key သက်တမ်း စစ်ဆေးနေပါသည်...</span>
      </div>
    </div>

    <div class="stats-bar" data-aos="fade-up" data-aos-delay="100">
      <div class="stat-card">
        <div class="stat-icon"><i data-lucide="shield-check"></i></div>
        <div class="stat-value" id="statRemaining">-</div>
        <div class="stat-label">ကျန်ရှိ</div>
      </div>
      <div class="stat-card">
        <div class="stat-icon"><i data-lucide="repeat"></i></div>
        <div class="stat-value" id="statMaxPeriod">-</div>
        <div class="stat-label">ခွင့်ပြု</div>
      </div>
      <div class="stat-card">
        <div class="stat-icon"><i data-lucide="users"></i></div>
        <div class="stat-value" id="statTotal">-</div>
        <div class="stat-label">စုစုပေါင်း</div>
      </div>
      <div class="stat-card">
        <div class="stat-icon"><i data-lucide="activity"></i></div>
        <div class="stat-value" id="statStatus">-</div>
        <div class="stat-label">Status</div>
      </div>
    </div>

    <div class="main-card" data-aos="fade-up" data-aos-delay="200">
      <div class="card-header">
        <div class="icon-wrapper"><i data-lucide="key-round"></i></div>
        <h2>VLESS Key ရယူမည်</h2>
        <p>Generate ကိုနှိပ်၍ Key အသစ် ရယူပါ</p>
      </div>

      <div class="compat-notice">
        <div class="compat-title">
          <i data-lucide="smartphone"></i> အသုံးပြုနိုင်သော Apps များ
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

      <div class="hp-field" aria-hidden="true">
        <input type="text" id="hpWebsite" name="website" tabindex="-1" autocomplete="off">
      </div>

      <button class="generate-btn" id="generateBtn" onclick="handleGenerate()">
        <i data-lucide="sparkles"></i>
        <span id="btnText">Generate Key</span>
        <div class="spinner" id="spinner"></div>
      </button>

      <div class="error-msg" id="errorMsg">
        <i data-lucide="alert-circle"></i>
        <span id="errorText"></span>
      </div>

      <div class="result-area" id="resultArea">
        <div class="result-box">
          <div class="result-label">
            <i data-lucide="check-circle-2"></i> VLESS Key Generated Successfully
          </div>
          <div class="result-key" id="resultKey"></div>
          <div class="result-meta">
            <div class="expire-info">
              <i data-lucide="calendar-range"></i>
              <span id="expireText"></span>
            </div>
            <div class="action-buttons">
              <button class="copy-btn" onclick="copyKey()">
                <i data-lucide="copy"></i> Copy
              </button>
              <button class="qr-btn" onclick="showQR()">
                <i data-lucide="qr-code"></i> QR
              </button>
            </div>
          </div>
        </div>
      </div>

      <div class="howto-section">
        <div class="howto-toggle" id="howtoToggle" onclick="toggleHowto()">
          <div class="label"><i data-lucide="help-circle"></i> Key အသုံးပြုနည်း</div>
          <div class="arrow"><i data-lucide="chevron-down"></i></div>
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
              <div>ချိတ်ဆက်ပြီး ပြထားသော <strong>သက်တမ်းကုန်ဆုံးရက်</strong>ထိ အသုံးပြုနိုင်ပါသည်။</div>
            </div>
            <div class="step" style="margin-top: 6px;">
              <div class="step-num" style="background: rgba(239,68,68,0.12); color: var(--danger);">!</div>
              <div style="color: #fca5a5;"><strong>Hiddify App</strong> တွင် ဤ Key ကို သုံး၍ <strong>မရနိုင်ပါ</strong>။ V2rayNG (သို့) V2Box ကို အသုံးပြုပါ။</div>
            </div>
          </div>
        </div>
      </div>

      <div class="remaining-bar">
        <div class="label"><i data-lucide="gauge"></i> ဤသက်တမ်းအတွင်း ကျန်ရှိအကြိမ်</div>
        <div class="count" id="remainingCount">-</div>
      </div>

      <div class="total-bar">
        <div class="label"><i data-lucide="bar-chart-3"></i> စုစုပေါင်း Generate ပြုလုပ်ပြီး</div>
        <div class="count" id="totalCount">-</div>
      </div>

      <div class="version-badge">
        <div class="label"><i data-lucide="tag"></i> Key Version</div>
        <div class="value" id="keyVersionText">-</div>
      </div>

      <div class="tg-contact-bar">
        <div class="tg-info">
          <div class="tg-icon"><i data-lucide="send"></i></div>
          <div class="tg-text">
            အကူအညီ / ဆက်သွယ်ရန်
            <strong>@iqowoq</strong>
          </div>
        </div>
        <a href="https://t.me/iqowoq" target="_blank" rel="noopener" class="tg-link">Message</a>
      </div>
    </div>

    <div class="footer">
      Powered by <a href="https://t.me/iqowoq" target="_blank" rel="noopener">Pagaduu</a> &copy; 2026 | <a href="https://t.me/iqowoq" target="_blank" rel="noopener">Telegram</a>
    </div>
  </div>

  <div class="success-overlay" id="successOverlay">
    <div class="success-popup">
      <div class="check-circle"><i data-lucide="check"></i></div>
      <h3>အောင်မြင်ပါသည်!</h3>
      <p>Key ကို Copy ယူ၍ V2rayNG / V2Box တွင် အသုံးပြုပါ</p>
    </div>
  </div>

  <div class="qr-modal" id="qrModal">
    <div class="qr-modal-content">
      <h3>QR Code Scan ဖတ်ပါ</h3>
      <p>V2rayNG / V2Box App ဖြင့် Scan ဖတ်ပါ</p>
      <div class="qr-code-container" id="qrCodeContainer"></div>
      <br>
      <button class="qr-close-btn" onclick="closeQR()">ပိတ်မည်</button>
    </div>
  </div>

  <div class="toast" id="toast">
    <i data-lucide="check-circle-2"></i>
    <span>Copy ကူးယူပြီးပါပြီ!</span>
  </div>

<script>
  let csrfToken = '';
  let currentKey = '';
  let isGenerating = false;

  document.addEventListener('DOMContentLoaded', () => {
    lucide.createIcons();
    AOS.init({ once: true, duration: 600 });
    createParticles();
    checkRemaining();
  });

  function createParticles() {
    const container = document.getElementById('particles');
    for (let i = 0; i < 25; i++) {
      const particle = document.createElement('div');
      particle.className = 'particle';
      particle.style.left = Math.random() * 100 + '%';
      particle.style.top = Math.random() * 100 + '%';
      particle.style.animationDelay = Math.random() * 5 + 's';
      particle.style.animationDuration = (4 + Math.random() * 4) + 's';
      container.appendChild(particle);
    }
  }

  async function checkRemaining() {
    try {
      const res = await fetch('/api/check', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({})
      });
      const data = await res.json();

      csrfToken = data.csrf_token || '';

      const validityNotice = document.getElementById('validityNotice');
      const validityTextEl = document.getElementById('validityText');
      const validityStatus = document.getElementById('validityStatus');

      validityTextEl.textContent = data.validityText || 'N/A';

      if (data.withinPeriod) {
        validityStatus.textContent = 'အသုံးပြုနိုင်ပါသည်';
        validityNotice.classList.remove('validity-expired');
      } else {
        validityStatus.textContent = 'Key သက်တမ်း ကုန်ဆုံးနေပါသည်';
        validityNotice.classList.add('validity-expired');
      }

      document.getElementById('statRemaining').textContent = data.remaining + '/' + data.maxPerPeriod;
      document.getElementById('statMaxPeriod').textContent = data.maxPerPeriod + ' \\u1000\\u103c\\u102d\\u1019\\u103a';
      document.getElementById('statTotal').textContent = data.totalGenerated || 0;

      const statusEl = document.getElementById('statStatus');
      if (data.withinPeriod) {
        statusEl.textContent = 'Active';
        statusEl.style.color = 'var(--success-light)';
      } else {
        statusEl.textContent = 'Expired';
        statusEl.style.color = '#fca5a5';
      }

      document.getElementById('remainingCount').textContent = data.remaining + ' \\u1000\\u103c\\u102d\\u1019\\u103a';
      document.getElementById('totalCount').textContent = (data.totalGenerated || 0) + ' \\u1000\\u103c\\u102d\\u1019\\u103a';
      document.getElementById('keyVersionText').textContent = data.keyVersion || '-';

      const btn = document.getElementById('generateBtn');
      const btnText = document.getElementById('btnText');

      if (!data.allowed) {
        btn.disabled = true;
        if (!data.withinPeriod) {
          btnText.textContent = 'Key \\u101e\\u1000\\u103a\\u1010\\u1019\\u103a\\u1038 \\u1000\\u102f\\u1014\\u103a\\u1006\\u102f\\u1036\\u1038\\u1014\\u1031\\u1015\\u102b\\u101e\\u100a\\u103a';
        } else {
          btnText.textContent = 'Generate \\u1001\\u103d\\u1004\\u103a\\u1037 \\u1000\\u102f\\u1014\\u103a\\u101e\\u103d\\u102c\\u1038\\u1015\\u102b\\u1015\\u103c\\u102e';
        }
      } else {
        btn.disabled = false;
        btnText.textContent = 'Generate Key';
      }
    } catch (e) {
      console.log('Check failed:', e);
    }
  }

  async function decryptPayload(base64Data) {
    const binaryStr = atob(base64Data);
    const bytes = new Uint8Array(binaryStr.length);
    for (let i = 0; i < binaryStr.length; i++) {
      bytes[i] = binaryStr.charCodeAt(i);
    }
    const keyData = bytes.slice(0, 32);
    const iv = bytes.slice(32, 44);
    const ciphertext = bytes.slice(44);
    const key = await crypto.subtle.importKey('raw', keyData, { name: 'AES-GCM' }, false, ['decrypt']);
    const decrypted = await crypto.subtle.decrypt({ name: 'AES-GCM', iv }, key, ciphertext);
    return JSON.parse(new TextDecoder().decode(decrypted));
  }

  async function handleGenerate() {
    if (isGenerating) return;
    isGenerating = true;

    const btn = document.getElementById('generateBtn');
    const spinner = document.getElementById('spinner');
    const btnText = document.getElementById('btnText');
    const errorMsg = document.getElementById('errorMsg');
    const resultArea = document.getElementById('resultArea');

    errorMsg.classList.remove('show');
    resultArea.classList.remove('show');

    btn.disabled = true;
    spinner.style.display = 'block';
    btnText.textContent = 'Generating...';

    try {
      const hpValue = document.getElementById('hpWebsite')?.value || '';

      const res = await fetch('/api/generate', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          csrf_token: csrfToken,
          website: hpValue,
          t: Date.now()
        })
      });

      const data = await res.json();

      if (!data.success) {
        document.getElementById('errorText').textContent = data.message;
        errorMsg.classList.add('show');

        if (data.error === 'limit_reached' || data.error === 'expired') {
          btn.disabled = true;
          btnText.textContent = data.error === 'expired'
            ? 'Key \\u101e\\u1000\\u103a\\u1010\\u1019\\u103a\\u1038 \\u1000\\u102f\\u1014\\u103a\\u1006\\u102f\\u1036\\u1038\\u1014\\u1031\\u1015\\u102b\\u101e\\u100a\\u103a'
            : 'Generate \\u1001\\u103d\\u1004\\u103a\\u1037 \\u1000\\u102f\\u1014\\u103a\\u101e\\u103d\\u102c\\u1038\\u1015\\u102b\\u1015\\u103c\\u102e';
          spinner.style.display = 'none';
          isGenerating = false;
          return;
        }

        if (data.error === 'invalid_token') {
          await checkRemaining();
        }

        spinner.style.display = 'none';
        btnText.textContent = 'Generate Key';
        btn.disabled = false;
        isGenerating = false;
        return;
      }

      // Success
      const decrypted = await decryptPayload(data.payload);
      currentKey = decrypted.key;

      document.getElementById('resultKey').textContent = currentKey;
      document.getElementById('expireText').textContent = '\\u101e\\u1000\\u103a\\u1010\\u1019\\u103a\\u1038: ' + decrypted.validityText;
      resultArea.classList.add('show');

      const remaining = decrypted.remaining;
      document.getElementById('remainingCount').textContent = remaining + ' \\u1000\\u103c\\u102d\\u1019\\u103a';
      document.getElementById('statRemaining').textContent = remaining + '/' + document.getElementById('statRemaining').textContent.split('/')[1];

      if (decrypted.totalGenerated) {
        document.getElementById('statTotal').textContent = decrypted.totalGenerated;
        document.getElementById('totalCount').textContent = decrypted.totalGenerated + ' \\u1000\\u103c\\u102d\\u1019\\u103a';
      }

      showSuccess();

      // Refresh CSRF token and state
      await checkRemaining();

      if (remaining <= 0) {
        btn.disabled = true;
        btnText.textContent = 'Generate \\u1001\\u103d\\u1004\\u103a\\u1037 \\u1000\\u102f\\u1014\\u103a\\u101e\\u103d\\u102c\\u1038\\u1015\\u102b\\u1015\\u103c\\u102e';
        spinner.style.display = 'none';
        isGenerating = false;
        return;
      }

      spinner.style.display = 'none';
      btnText.textContent = 'Generate Key';
      btn.disabled = false;
      lucide.createIcons();

    } catch (e) {
      document.getElementById('errorText').textContent = '\\u1001\\u103b\\u102d\\u1010\\u103a\\u1006\\u1000\\u103a\\u1019\\u103e\\u102f \\u1019\\u1021\\u1031\\u102c\\u1004\\u103a\\u1019\\u103c\\u1004\\u103a\\u1015\\u102b\\u104b \\u1011\\u1015\\u103a\\u1000\\u103c\\u102d\\u102f\\u1038\\u1005\\u102c\\u1038\\u1015\\u102b\\u104b';
      errorMsg.classList.add('show');
      spinner.style.display = 'none';
      btnText.textContent = 'Generate Key';
      btn.disabled = false;
    }

    isGenerating = false;
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
      showToast();
    }).catch(() => {
      const textarea = document.createElement('textarea');
      textarea.value = currentKey;
      textarea.style.position = 'fixed';
      textarea.style.opacity = '0';
      document.body.appendChild(textarea);
      textarea.select();
      document.execCommand('copy');
      document.body.removeChild(textarea);
      showToast();
    });
  }

  function showToast() {
    const toast = document.getElementById('toast');
    toast.classList.add('show');
    setTimeout(() => toast.classList.remove('show'), 2500);
  }

  function showQR() {
    if (!currentKey) return;
    const modal = document.getElementById('qrModal');
    const container = document.getElementById('qrCodeContainer');
    container.innerHTML = '';
    try {
      const qr = qrcode(0, 'L');
      qr.addData(currentKey);
      qr.make();
      const size = 200;
      const cellSize = Math.floor(size / qr.getModuleCount());
      container.innerHTML = qr.createImgTag(cellSize, 0);
    } catch (e) {
      container.innerHTML = '<p style="color:#666;font-size:12px;padding:20px;">Key \\u101b\\u103e\\u100a\\u103a\\u101c\\u103d\\u1014\\u103a\\u1038\\u101e\\u1016\\u1004\\u103a\\u1037 QR \\u1016\\u1014\\u103a\\u1010\\u102e\\u1038\\u�EB \\u1019\\u101b\\u1015\\u102b\\u104b<br>Copy \\u101a\\u1030\\u�EB \\u1021\\u101e\\u102f\\u1036\\u1038\\u1015\\u103c\\u102f\\u1015\\u102b\\u104b</p>';
    }
    modal.classList.add('show');
  }

  function closeQR() { document.getElementById('qrModal').classList.remove('show'); }

  document.addEventListener('click', (e) => {
    if (e.target === document.getElementById('qrModal')) closeQR();
  });

  function toggleHowto() {
    document.getElementById('howtoToggle').classList.toggle('open');
    document.getElementById('howtoContent').classList.toggle('open');
  }
<\/script>

</body>
</html>`;
}

// ============== ROUTER ==============

Deno.serve(async (req) => {
  const url = new URL(req.url);

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

  if (url.pathname === "/api/debug") {
    return await handleDebug(req);
  }

  const blockedPaths = ["/wp-admin", "/wp-login", "/.env", "/config", "/admin", "/.git"];
  if (blockedPaths.some(p => url.pathname.toLowerCase().startsWith(p))) {
    return new Response("Not found", { status: 404 });
  }

  return new Response(getHTML(), {
    headers: {
      "Content-Type": "text/html; charset=utf-8",
      "Cache-Control": "no-store, no-cache, must-revalidate",
      "Content-Security-Policy": "default-src 'self'; script-src 'self' 'unsafe-inline' 'unsafe-eval' https://unpkg.com; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com https://unpkg.com; font-src https://fonts.gstatic.com; img-src 'self' data:; connect-src 'self';",
      ...securityHeaders,
    }
  });
});
