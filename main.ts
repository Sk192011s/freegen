// main.ts - Deno Deploy Entry Point (Patgaduu Secure V4 - Light Theme)
// Fixed: Total count is now ALL users combined (global), with proper atomic concurrency

const kv = await Deno.openKv();

// ============== CONFIGURATION ==============
function getConfig() {
  const keysRaw = Deno.env.get("VLESS_KEYS") || "";
  const keys = keysRaw.split(",").map(k => k.trim()).filter(k => k.length > 0);

  const validFrom = Deno.env.get("VALID_FROM") || "2026-03-05";
  const validUntil = Deno.env.get("VALID_UNTIL") || "2026-03-12";

  const validityText = Deno.env.get("VALIDITY_TEXT") || "၅ရက် မတ်လ ၂၀၂၆ မှ ၁၂ ရက် မတ်လ ၂၀၂၆ ထိ";

  const maxPerPeriod = parseInt(Deno.env.get("MAX_GENERATES_PER_PERIOD") || "2");
  const keyVersion = Deno.env.get("KEY_VERSION") || "v2";
  const tzOffset = parseInt(Deno.env.get("TZ_OFFSET_MINUTES") || "390");

  const adminTgLink = Deno.env.get("ADMIN_TG_LINK") || "https://t.me/iqowoq";
  const adminTgHandle = Deno.env.get("ADMIN_TG_HANDLE") || "@iqowoq";
  const adminNotice = Deno.env.get("ADMIN_NOTICE") || "";

  return { keys, validFrom, validUntil, validityText, maxPerPeriod, keyVersion, tzOffset, adminTgLink, adminTgHandle, adminNotice };
}

// ============== SECURITY: CSRF TOKEN ==============

async function generateCSRFToken(ip: string): Promise<string> {
  const secret = Deno.env.get("CSRF_SECRET") || "patgaduu-csrf-default-secret-2024";
  const hour = Math.floor(Date.now() / (1000 * 60 * 60));
  const raw = `${ip}||${hour}||${secret}`;
  return await hashSHA256(raw);
}

async function validateCSRFToken(token: string, ip: string): Promise<boolean> {
  const secret = Deno.env.get("CSRF_SECRET") || "patgaduu-csrf-default-secret-2024";
  const hour = Math.floor(Date.now() / (1000 * 60 * 60));
  const current = await hashSHA256(`${ip}||${hour}||${secret}`);
  const previous = await hashSHA256(`${ip}||${hour - 1}||${secret}`);
  return token === current || token === previous;
}

// ============== SECURITY: PROOF-OF-WORK ==============

async function generateChallenge(ip: string): Promise<{ challenge: string; difficulty: number }> {
  const secret = Deno.env.get("CSRF_SECRET") || "patgaduu-csrf-default-secret-2024";
  const timestamp = Math.floor(Date.now() / (1000 * 60 * 5)); // 5 min window
  const challenge = await hashSHA256(`${ip}||${timestamp}||pow||${secret}`);
  return { challenge, difficulty: 4 }; // must find nonce where hash starts with 4 zeros
}

async function verifyPoW(ip: string, challenge: string, nonce: string): Promise<boolean> {
  const secret = Deno.env.get("CSRF_SECRET") || "patgaduu-csrf-default-secret-2024";
  const timestamp = Math.floor(Date.now() / (1000 * 60 * 5));
  const expectedChallenge = await hashSHA256(`${ip}||${timestamp}||pow||${secret}`);
  const prevTimestamp = Math.floor(Date.now() / (1000 * 60 * 5)) - 1;
  const prevChallenge = await hashSHA256(`${ip}||${prevTimestamp}||pow||${secret}`);

  if (challenge !== expectedChallenge && challenge !== prevChallenge) return false;

  const hash = await hashSHA256(`${challenge}||${nonce}`);
  return hash.startsWith("0000"); // 4 zeros difficulty
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
  const raw = `${ip}||${userAgent}||patgaduu-salt-2024`;
  return await hashSHA256(raw);
}

function isWithinValidPeriod(config: ReturnType<typeof getConfig>): boolean {
  const now = Date.now();
  const fromLocal = new Date(config.validFrom + "T00:00:00");
  const untilLocal = new Date(config.validUntil + "T23:59:59");

  const fromUTC = fromLocal.getTime() - (config.tzOffset * 60 * 1000);
  const untilUTC = untilLocal.getTime() - (config.tzOffset * 60 * 1000);

  return now >= fromUTC && now <= untilUTC;
}

function getValidUntilUTC(config: ReturnType<typeof getConfig>): number {
  const untilLocal = new Date(config.validUntil + "T23:59:59");
  return untilLocal.getTime() - (config.tzOffset * 60 * 1000);
}

async function checkRateLimit(
  fingerprint: string,
  config: ReturnType<typeof getConfig>
): Promise<{ allowed: boolean; remaining: number; message: string }> {
  if (!isWithinValidPeriod(config)) {
    return {
      allowed: false,
      remaining: 0,
      message: "လက်ရှိ Key သက်တမ်း ကုန်ဆုံးနေပါသည်။ Key အသစ်ထွက်လာရင် ပြန်လာပါ။"
    };
  }

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

// ============== ATOMIC INCREMENT: Rate Limit + Global Total (single transaction) ==============

async function incrementAllAtomic(
  fingerprint: string,
  ipFingerprint: string,
  config: ReturnType<typeof getConfig>
): Promise<{ success: boolean; totalCount: number }> {
  const periodKey = `${config.keyVersion}_${config.validFrom}_${config.validUntil}`;
  const fpKey = ["rate_limit_period", fingerprint, periodKey];
  const ipKey = ["rate_limit_period", ipFingerprint, periodKey];
  const totalKey = ["stats", "total_generates"];

  const untilUTC = getValidUntilUTC(config);
  const expireIn = Math.max(untilUTC - Date.now() + 86400000, 86400000);

  const maxRetries = 10;
  for (let i = 0; i < maxRetries; i++) {
    const fpEntry = await kv.get<number>(fpKey);
    const ipEntry = await kv.get<number>(ipKey);
    const totalEntry = await kv.get<number>(totalKey);

    const fpCount = fpEntry.value || 0;
    const ipCount = ipEntry.value || 0;
    const totalCount = totalEntry.value || 0;

    // Double check: if either count already at max, reject
    if (fpCount >= config.maxPerPeriod || ipCount >= config.maxPerPeriod) {
      return { success: false, totalCount };
    }

    const result = await kv.atomic()
      .check(fpEntry)
      .check(ipEntry)
      .check(totalEntry)
      .set(fpKey, fpCount + 1, { expireIn })
      .set(ipKey, ipCount + 1, { expireIn })
      .set(totalKey, totalCount + 1)
      .commit();

    if (result.ok) return { success: true, totalCount: totalCount + 1 };

    // Exponential backoff with jitter
    const delay = Math.min(50 * Math.pow(2, i), 1000) + Math.random() * 50;
    await new Promise(resolve => setTimeout(resolve, delay));
  }
  return { success: false, totalCount: -1 };
}

// ============== BURST RATE LIMITING (Anti-Spam) ==============

async function checkBurstLimit(ip: string): Promise<boolean> {
  const minute = Math.floor(Date.now() / (1000 * 60));
  const burstKey = ["burst_limit", ip, String(minute)];

  const maxRetries = 3;
  for (let i = 0; i < maxRetries; i++) {
    const entry = await kv.get<number>(burstKey);
    const count = entry.value || 0;

    if (count >= 10) return false; // max 10 requests per minute per IP

    const result = await kv.atomic()
      .check(entry)
      .set(burstKey, count + 1, { expireIn: 120000 })
      .commit();

    if (result.ok) return true;
    await new Promise(resolve => setTimeout(resolve, 20 * (i + 1)));
  }
  // If retries exhausted, allow (fail-open for burst limit to not block legitimate users)
  return true;
}

// ============== TOTAL GENERATE COUNTER (read-only) ==============

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

  // Block common bot user agents
  const botPatterns = [
    /curl/i, /wget/i, /python/i, /httpie/i, /postman/i,
    /scrapy/i, /httpclient/i, /java\//i, /okhttp/i,
    /node-fetch/i, /axios/i, /go-http/i, /ruby/i, /perl/i,
    /libwww/i, /mechanize/i, /phantom/i, /selenium/i,
    /headless/i, /puppeteer/i, /playwright/i
  ];

  for (const pattern of botPatterns) {
    if (pattern.test(ua)) {
      return { valid: false, error: "Blocked" };
    }
  }

  // Must have standard browser headers
  const accept = req.headers.get("accept") || "";
  if (!accept.includes("json") && !accept.includes("*/*") && !accept.includes("text")) {
    return { valid: false, error: "Invalid request headers" };
  }

  return { valid: true };
}

// ============== API HANDLERS ==============

async function handleGenerate(req: Request): Promise<Response> {
  if (req.method !== "POST") {
    return jsonResponse({ error: "Method not allowed" }, 405);
  }

  // Check Origin/Referer to prevent direct API calls
  const origin = req.headers.get("origin") || "";
  const referer = req.headers.get("referer") || "";
  const host = req.headers.get("host") || "";

  if (origin && !origin.includes(host)) {
    return jsonResponse({ success: false, error: "forbidden", message: "ခွင့်မပြုပါ။" }, 403);
  }

  if (referer && !referer.includes(host)) {
    return jsonResponse({ success: false, error: "forbidden", message: "ခွင့်မပြုပါ။" }, 403);
  }

  const validation = validateRequest(req);
  if (!validation.valid) {
    return jsonResponse({ success: false, error: "invalid_request", message: "ခွင့်မပြုပါ။" }, 403);
  }

  const ip = getClientIP(req);
  const userAgent = req.headers.get("user-agent") || "unknown";

  // Burst rate limit check
  const burstAllowed = await checkBurstLimit(ip);
  if (!burstAllowed) {
    return jsonResponse({
      success: false,
      error: "rate_limited",
      message: "တောင်းဆိုမှု များလွန်းနေပါသည်။ ခဏစောင့်ပါ။"
    }, 429);
  }

  let body: Record<string, unknown>;
  try {
    body = await req.json();

    // Honeypot check
    if (body.website && (body.website as string).length > 0) {
      return jsonResponse({
        success: true,
        payload: btoa("bot-detected-fake-payload-" + Math.random()),
        remaining: 0
      });
    }

    // Second honeypot
    if (body.email && (body.email as string).length > 0) {
      return jsonResponse({
        success: true,
        payload: btoa("bot-detected-fake-payload-" + Math.random()),
        remaining: 0
      });
    }

    // CSRF validation
    if (!body.csrf_token || !(await validateCSRFToken(body.csrf_token as string, ip))) {
      return jsonResponse({
        success: false,
        error: "invalid_token",
        message: "Session သက်တမ်းကုန်ပါပြီ။ Page ကို Refresh လုပ်ပါ။"
      }, 403);
    }

    // Proof-of-Work validation
    if (!body.pow_challenge || !body.pow_nonce) {
      return jsonResponse({
        success: false,
        error: "pow_required",
        message: "Security verification မအောင်မြင်ပါ။ Page ကို Refresh လုပ်ပါ။"
      }, 403);
    }

    const powValid = await verifyPoW(ip, body.pow_challenge as string, body.pow_nonce as string);
    if (!powValid) {
      return jsonResponse({
        success: false,
        error: "pow_invalid",
        message: "Security verification မအောင်မြင်ပါ။ Page ကို Refresh လုပ်ပါ။"
      }, 403);
    }

    // Timestamp validation - reject if request is too old or from the future
    if (body.t) {
      const requestTime = body.t as number;
      const timeDiff = Math.abs(Date.now() - requestTime);
      if (timeDiff > 300000) { // 5 minutes tolerance
        return jsonResponse({
          success: false,
          error: "stale_request",
          message: "Session သက်တမ်းကုန်ပါပြီ။ Page ကို Refresh လုပ်ပါ။"
        }, 403);
      }
    }

  } catch {
    return jsonResponse({ success: false, error: "invalid_body", message: "ခွင့်မပြုပါ။" }, 400);
  }

  const config = getConfig();

  if (!isWithinValidPeriod(config)) {
    return jsonResponse({
      success: false,
      error: "expired",
      message: "လက်ရှိ Key သက်တမ်း ကုန်ဆုံးနေပါသည်။ Key အသစ်ထွက်လာရင် ပြန်လာပါ။"
    }, 403);
  }

  const fingerprint = await generateServerFingerprint(ip, userAgent);
  const ipFingerprint = await hashSHA256(`ip-only-${ip}-patgaduu-salt`);

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

  // Single atomic transaction: increment rate limits + global total count
  const incrementResult = await incrementAllAtomic(fingerprint, ipFingerprint, config);
  if (!incrementResult.success) {
    return jsonResponse({
      success: false,
      error: "server_busy",
      message: "Server အလုပ်များနေပါသည်။ ခဏစောင့်၍ ထပ်ကြိုးစားပါ။"
    }, 503);
  }

  const totalCount = incrementResult.totalCount;
  const remaining = Math.min(fpCheck.remaining, ipCheck.remaining) - 1;

  const encryptedPayload = await encryptPayload(JSON.stringify({
    key: result.key,
    validityText: config.validityText,
    remaining,
    totalGenerated: totalCount,
    ts: Date.now(),
    nonce: crypto.randomUUID()
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
  const ipFingerprint = await hashSHA256(`ip-only-${ip}-patgaduu-salt`);

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
  const { challenge, difficulty } = await generateChallenge(ip);

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
    csrf_token: csrfToken,
    pow_challenge: challenge,
    pow_difficulty: difficulty,
    adminTgLink: config.adminTgLink,
    adminTgHandle: config.adminTgHandle,
    adminNotice: config.adminNotice
  });
}

// ============== DEBUG ENDPOINT ==============

async function handleDebug(req: Request): Promise<Response> {
  const authKey = Deno.env.get("DEBUG_AUTH_KEY") || "";
  const url = new URL(req.url);
  const providedKey = url.searchParams.get("key") || "";

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

  const totalGenerated = await getTotalCount();

  return jsonResponse({
    currentTimeUTC: nowUTC,
    currentTimeMM: myanmarTime,
    totalGenerated,
    config: {
      validFrom: config.validFrom,
      validUntil: config.validUntil,
      keyVersion: config.keyVersion,
      maxPerPeriod: config.maxPerPeriod,
      tzOffset: config.tzOffset,
      keysCount: config.keys.length,
      validityText: config.validityText,
      adminTgLink: config.adminTgLink,
      adminNotice: config.adminNotice ? "(set)" : "(empty)"
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
  const config = getConfig();
  const adminTgLink = config.adminTgLink;
  const adminTgHandle = config.adminTgHandle;
  const adminNotice = config.adminNotice;

  // Build notice slider HTML if adminNotice is set
  const noticeHTML = adminNotice ? `
    <div class="admin-notice-slider" id="adminNoticeSlider">
      <div class="notice-icon">
        <svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/></svg>
      </div>
      <div class="notice-marquee">
        <span class="notice-text">${adminNotice.replace(/</g, '&lt;').replace(/>/g, '&gt;')}</span>
      </div>
      <button class="notice-close" onclick="closeNotice()" aria-label="Close">&times;</button>
    </div>` : '';

  return `<!DOCTYPE html>
<html lang="my">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0, maximum-scale=1.0, user-scalable=no">
  <title>Patgaduu - VLESS Key Generator</title>

  <link rel="preconnect" href="https://fonts.googleapis.com">
  <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
  <link href="https://fonts.googleapis.com/css2?family=Padauk:wght@400;700&family=Inter:wght@300;400;500;600;700&family=JetBrains+Mono:wght@400;500&display=swap" rel="stylesheet">

  <style>
    :root {
      --primary: #6366f1;
      --primary-dark: #4f46e5;
      --primary-light: #818cf8;
      --primary-glow: rgba(99,102,241,0.15);
      --accent: #f59e0b;
      --accent-light: #d97706;
      --bg-main: #f8fafc;
      --bg-card: #ffffff;
      --bg-card-alt: #f1f5f9;
      --glass: rgba(255,255,255,0.85);
      --glass-hover: rgba(255,255,255,0.95);
      --glass-border: rgba(0,0,0,0.08);
      --glass-border-hover: rgba(0,0,0,0.15);
      --text: #1e293b;
      --text-dim: #475569;
      --text-muted: #94a3b8;
      --success: #10b981;
      --success-light: #059669;
      --danger: #ef4444;
      --warning: #f59e0b;
      --cyan: #0891b2;
      --purple: #7c3aed;
      --pink: #ec4899;
      --shadow-sm: 0 1px 3px rgba(0,0,0,0.06), 0 1px 2px rgba(0,0,0,0.04);
      --shadow-md: 0 4px 6px rgba(0,0,0,0.05), 0 2px 4px rgba(0,0,0,0.04);
      --shadow-lg: 0 10px 25px rgba(0,0,0,0.08), 0 4px 10px rgba(0,0,0,0.04);
      --shadow-xl: 0 20px 50px rgba(0,0,0,0.1);
      --radius-sm: 10px;
      --radius-md: 14px;
      --radius-lg: 20px;
      --radius-xl: 24px;
    }

    * { margin: 0; padding: 0; box-sizing: border-box; }

    body {
      font-family: 'Padauk', 'Inter', sans-serif;
      background: var(--bg-main);
      color: var(--text);
      min-height: 100vh;
      overflow-x: hidden;
    }

    [data-aos] {
      opacity: 1 !important;
      transform: none !important;
      transition: opacity 0.6s ease, transform 0.6s ease;
    }

    .bg-decoration {
      position: fixed;
      top: 0; left: 0;
      width: 100%; height: 100%;
      z-index: 0;
      overflow: hidden;
      pointer-events: none;
    }

    .bg-decoration .shape {
      position: absolute;
      border-radius: 50%;
      opacity: 0.4;
      filter: blur(80px);
    }

    .bg-decoration .shape:nth-child(1) {
      width: 500px; height: 500px;
      background: linear-gradient(135deg, rgba(99,102,241,0.15), rgba(139,92,246,0.1));
      top: -200px; left: -100px;
    }

    .bg-decoration .shape:nth-child(2) {
      width: 400px; height: 400px;
      background: linear-gradient(135deg, rgba(6,182,212,0.1), rgba(59,130,246,0.08));
      bottom: -150px; right: -100px;
    }

    .bg-decoration .shape:nth-child(3) {
      width: 300px; height: 300px;
      background: linear-gradient(135deg, rgba(168,85,247,0.08), rgba(236,72,153,0.06));
      top: 50%; left: 60%;
    }

    .container {
      position: relative;
      z-index: 1;
      max-width: 520px;
      margin: 0 auto;
      padding: 16px 14px;
      min-height: 100vh;
      display: flex;
      flex-direction: column;
    }

    /* Admin Notice Slider */
    .admin-notice-slider {
      display: flex;
      align-items: center;
      gap: 10px;
      padding: 10px 14px;
      background: linear-gradient(135deg, #fef3c7, #fde68a);
      border: 1px solid #fbbf24;
      border-radius: var(--radius-md);
      margin-bottom: 14px;
      overflow: hidden;
      position: relative;
      box-shadow: var(--shadow-sm);
    }

    .notice-icon {
      flex-shrink: 0;
      color: #b45309;
      display: flex;
      align-items: center;
    }

    .notice-marquee {
      flex: 1;
      overflow: hidden;
      white-space: nowrap;
      mask-image: linear-gradient(90deg, transparent, black 10%, black 90%, transparent);
      -webkit-mask-image: linear-gradient(90deg, transparent, black 10%, black 90%, transparent);
    }

    .notice-text {
      display: inline-block;
      animation: marquee 15s linear infinite;
      font-size: 13px;
      font-weight: 600;
      color: #92400e;
      padding-left: 100%;
    }

    @keyframes marquee {
      0% { transform: translateX(0); }
      100% { transform: translateX(-100%); }
    }

    .notice-close {
      flex-shrink: 0;
      background: none;
      border: none;
      font-size: 20px;
      color: #b45309;
      cursor: pointer;
      padding: 0 4px;
      line-height: 1;
      opacity: 0.7;
      transition: opacity 0.2s;
    }

    .notice-close:hover { opacity: 1; }

    /* Header */
    .header {
      display: flex;
      align-items: center;
      justify-content: space-between;
      padding: 14px 18px;
      background: var(--glass);
      backdrop-filter: blur(20px);
      -webkit-backdrop-filter: blur(20px);
      border: 1px solid var(--glass-border);
      border-radius: var(--radius-lg);
      margin-bottom: 16px;
      box-shadow: var(--shadow-md);
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
      box-shadow: 0 4px 15px rgba(99,102,241,0.3);
    }

    .logo-icon svg { color: white; width: 20px; height: 20px; }

    .header-brand h1 {
      font-size: 17px;
      font-weight: 700;
      color: var(--primary-dark);
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
      background: rgba(6, 182, 212, 0.08);
      border: 1px solid rgba(6, 182, 212, 0.25);
      border-radius: var(--radius-sm);
      color: var(--cyan);
      font-size: 11px;
      font-weight: 600;
      text-decoration: none;
      transition: all 0.3s;
      font-family: 'Inter', sans-serif;
    }

    .tg-btn:hover {
      background: rgba(6, 182, 212, 0.15);
      border-color: rgba(6, 182, 212, 0.4);
      transform: translateY(-1px);
      box-shadow: var(--shadow-sm);
    }

    .tg-btn svg { width: 13px; height: 13px; }

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
      background: linear-gradient(135deg, rgba(6,182,212,0.04), rgba(99,102,241,0.04));
      border: 1px solid rgba(6,182,212,0.2);
      border-radius: var(--radius-md);
      display: flex;
      align-items: center;
      gap: 12px;
      box-shadow: var(--shadow-sm);
    }

    .validity-notice .vn-icon {
      width: 40px; height: 40px;
      background: rgba(6,182,212,0.1);
      border-radius: var(--radius-sm);
      display: flex;
      align-items: center;
      justify-content: center;
      flex-shrink: 0;
    }

    .validity-notice .vn-icon svg { width: 20px; height: 20px; color: var(--cyan); }

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
      border-color: rgba(239,68,68,0.25) !important;
      background: linear-gradient(135deg, rgba(239,68,68,0.04), rgba(239,68,68,0.02)) !important;
    }

    .validity-expired .vn-icon {
      background: rgba(239,68,68,0.1) !important;
    }

    .validity-expired .vn-icon svg { color: var(--danger) !important; }
    .validity-expired .vn-text strong { color: var(--danger) !important; }

    /* Stats Bar - Single Row Horizontal */
    .stats-bar {
      display: flex;
      gap: 10px;
      margin-bottom: 16px;
      overflow-x: auto;
      scrollbar-width: none;
      -ms-overflow-style: none;
      padding-bottom: 2px;
    }

    .stats-bar::-webkit-scrollbar { display: none; }

    .stat-card {
      flex: 1;
      min-width: 0;
      background: var(--bg-card);
      border: 1px solid var(--glass-border);
      border-radius: var(--radius-md);
      padding: 14px 12px;
      text-align: center;
      transition: all 0.3s;
      position: relative;
      overflow: hidden;
      box-shadow: var(--shadow-sm);
    }

    .stat-card::before {
      content: '';
      position: absolute;
      top: 0; left: 0;
      width: 100%; height: 3px;
      border-radius: 3px 3px 0 0;
    }

    .stat-card:nth-child(1)::before { background: linear-gradient(90deg, var(--primary), var(--purple)); }
    .stat-card:nth-child(2)::before { background: linear-gradient(90deg, var(--cyan), #3b82f6); }
    .stat-card:nth-child(3)::before { background: linear-gradient(90deg, var(--accent), #f97316); }
    .stat-card:nth-child(4)::before { background: linear-gradient(90deg, var(--success), var(--cyan)); }

    .stat-card:hover {
      border-color: var(--glass-border-hover);
      transform: translateY(-2px);
      box-shadow: var(--shadow-md);
    }

    .stat-card .stat-icon {
      width: 32px; height: 32px;
      margin: 0 auto 6px;
      border-radius: 8px;
      display: flex;
      align-items: center;
      justify-content: center;
    }

    .stat-card .stat-icon svg { width: 16px; height: 16px; }

    .stat-card:nth-child(1) .stat-icon { background: rgba(99,102,241,0.1); color: var(--primary); }
    .stat-card:nth-child(2) .stat-icon { background: rgba(6,182,212,0.1); color: var(--cyan); }
    .stat-card:nth-child(3) .stat-icon { background: rgba(245,158,11,0.1); color: var(--accent-light); }
    .stat-card:nth-child(4) .stat-icon { background: rgba(16,185,129,0.1); color: var(--success); }

    .stat-card .stat-value {
      font-size: 16px;
      font-weight: 700;
      color: var(--text);
      font-family: 'Inter', sans-serif;
    }

    .stat-card .stat-label {
      font-size: 10px;
      color: var(--text-muted);
      margin-top: 2px;
      letter-spacing: 0.3px;
      white-space: nowrap;
    }

    /* Main Card */
    .main-card {
      background: var(--bg-card);
      border: 1px solid var(--glass-border);
      border-radius: var(--radius-xl);
      padding: 28px 20px;
      flex: 1;
      position: relative;
      overflow: hidden;
      box-shadow: var(--shadow-lg);
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
      box-shadow: 0 8px 30px rgba(99,102,241,0.3);
      animation: iconPulse 3s ease-in-out infinite;
    }

    @keyframes iconPulse {
      0%, 100% { transform: translateY(0) scale(1); }
      50% { transform: translateY(-4px) scale(1.02); }
    }

    .card-header .icon-wrapper svg { color: white; width: 30px; height: 30px; }

    .card-header h2 {
      font-size: 20px;
      font-weight: 700;
      color: var(--text);
      margin-bottom: 4px;
    }

    .card-header p { font-size: 13px; color: var(--text-dim); }

    .compat-notice {
      margin-bottom: 18px;
      padding: 14px 16px;
      background: rgba(99, 102, 241, 0.03);
      border: 1px solid rgba(99, 102, 241, 0.12);
      border-radius: var(--radius-md);
    }

    .compat-notice .compat-title {
      font-size: 12px;
      font-weight: 700;
      color: var(--primary);
      margin-bottom: 8px;
      display: flex;
      align-items: center;
      gap: 6px;
    }

    .compat-notice .compat-title svg { width: 14px; height: 14px; }

    .compat-apps { display: flex; flex-wrap: wrap; gap: 5px; margin-bottom: 10px; }

    .compat-app {
      padding: 3px 10px;
      background: rgba(16, 185, 129, 0.06);
      border: 1px solid rgba(16, 185, 129, 0.2);
      border-radius: 6px;
      font-size: 11px;
      color: var(--success);
      font-weight: 600;
      font-family: 'Inter', sans-serif;
    }

    .compat-warning {
      display: flex;
      align-items: center;
      gap: 6px;
      padding: 8px 12px;
      background: rgba(239, 68, 68, 0.04);
      border: 1px solid rgba(239, 68, 68, 0.15);
      border-radius: 8px;
      font-size: 11px;
      color: var(--danger);
      margin-top: 8px;
    }

    .compat-warning svg { width: 14px; height: 14px; flex-shrink: 0; color: var(--danger); }

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
      box-shadow: 0 4px 15px rgba(99,102,241,0.3);
    }

    .generate-btn::before {
      content: '';
      position: absolute;
      top: 0; left: -100%;
      width: 100%; height: 100%;
      background: linear-gradient(90deg, transparent, rgba(255,255,255,0.2), transparent);
      transition: left 0.6s;
    }

    .generate-btn:hover::before { left: 100%; }

    .generate-btn:hover {
      transform: translateY(-2px);
      box-shadow: 0 8px 25px rgba(99,102,241,0.4);
    }

    .generate-btn:active { transform: translateY(0); }

    .generate-btn:disabled {
      opacity: 0.5;
      cursor: not-allowed;
      transform: none !important;
      box-shadow: none !important;
    }

    .generate-btn:disabled::before { display: none; }
    .generate-btn svg { width: 20px; height: 20px; }

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
      background: var(--bg-card-alt);
      border: 1px solid rgba(16,185,129,0.2);
      border-radius: var(--radius-md);
      padding: 18px;
      position: relative;
      animation: slideUp 0.5s ease;
      box-shadow: var(--shadow-sm);
    }

    .result-box::before {
      content: '';
      position: absolute;
      top: 0; left: 0;
      width: 100%; height: 3px;
      background: linear-gradient(90deg, var(--success), var(--cyan));
      border-radius: 3px 3px 0 0;
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

    .result-label svg { width: 16px; height: 16px; }

    .result-key {
      background: white;
      border: 1px solid var(--glass-border);
      border-radius: var(--radius-sm);
      padding: 14px;
      font-family: 'JetBrains Mono', monospace;
      font-size: 10.5px;
      color: var(--primary-dark);
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

    .expire-info svg { width: 14px; height: 14px; }

    .action-buttons { display: flex; gap: 8px; }

    .copy-btn, .qr-btn {
      display: flex;
      align-items: center;
      gap: 5px;
      padding: 7px 14px;
      border: 1px solid rgba(99,102,241,0.25);
      border-radius: var(--radius-sm);
      background: rgba(99,102,241,0.06);
      color: var(--primary);
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
      box-shadow: var(--shadow-sm);
    }

    .copy-btn svg, .qr-btn svg { width: 14px; height: 14px; }

    .qr-modal {
      position: fixed;
      top: 0; left: 0;
      width: 100%; height: 100%;
      z-index: 150;
      display: none;
      align-items: center;
      justify-content: center;
      background: rgba(0,0,0,0.4);
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
      box-shadow: var(--shadow-xl);
    }

    .qr-modal-content h3 { color: var(--text); margin-bottom: 4px; font-size: 16px; }
    .qr-modal-content p { color: var(--text-dim); font-size: 12px; margin-bottom: 16px; }

    .qr-code-container {
      background: white;
      border-radius: var(--radius-md);
      padding: 16px;
      display: inline-block;
      margin-bottom: 16px;
      border: 1px solid var(--glass-border);
    }

    .qr-code-container canvas, .qr-code-container img { display: block; }

    .qr-close-btn {
      padding: 10px 28px;
      background: var(--bg-card-alt);
      border: 1px solid var(--glass-border);
      border-radius: var(--radius-sm);
      color: var(--text);
      font-family: 'Padauk', sans-serif;
      font-size: 14px;
      cursor: pointer;
      transition: all 0.3s;
    }

    .qr-close-btn:hover { background: var(--glass-border); }

    .howto-section {
      margin-top: 18px;
      padding: 14px 16px;
      background: var(--bg-card-alt);
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

    .howto-toggle .label svg { width: 15px; height: 15px; }

    .howto-toggle .arrow { color: var(--text-muted); transition: transform 0.3s; }
    .howto-toggle .arrow svg { width: 15px; height: 15px; }
    .howto-toggle.open .arrow { transform: rotate(180deg); }

    .howto-content { max-height: 0; overflow: hidden; transition: max-height 0.4s ease; }
    .howto-content.open { max-height: 600px; }

    .howto-steps { padding-top: 14px; font-size: 12.5px; color: var(--text-dim); line-height: 1.8; }

    .howto-steps .step { display: flex; gap: 10px; margin-bottom: 10px; }

    .howto-steps .step-num {
      width: 22px; height: 22px;
      background: rgba(99,102,241,0.1);
      border-radius: 6px;
      display: flex;
      align-items: center;
      justify-content: center;
      font-size: 11px;
      font-weight: 700;
      color: var(--primary);
      flex-shrink: 0;
      margin-top: 2px;
      font-family: 'Inter', sans-serif;
    }

    .howto-steps .app-name { color: var(--primary); font-weight: 600; }

    /* Info bars - horizontal single line */
    .info-bars {
      display: flex;
      flex-direction: column;
      gap: 8px;
      margin-top: 18px;
    }

    .info-bar {
      padding: 13px 16px;
      background: var(--bg-card-alt);
      border: 1px solid var(--glass-border);
      border-radius: var(--radius-md);
      display: flex;
      align-items: center;
      justify-content: space-between;
    }

    .info-bar .label {
      font-size: 12.5px;
      color: var(--text-dim);
      display: flex;
      align-items: center;
      gap: 6px;
    }

    .info-bar .label svg { width: 15px; height: 15px; }

    .info-bar .count {
      font-size: 17px;
      font-weight: 700;
      font-family: 'Inter', sans-serif;
    }

    .info-bar .count.remaining-val { color: var(--accent-light); }
    .info-bar .count.total-val { color: var(--primary); }
    .info-bar .count.version-val { color: var(--purple); font-size: 13px; text-transform: uppercase; }

    .tg-contact-bar {
      margin-top: 12px;
      padding: 13px 16px;
      background: rgba(6, 182, 212, 0.03);
      border: 1px solid rgba(6, 182, 212, 0.15);
      border-radius: var(--radius-md);
      display: flex;
      align-items: center;
      justify-content: space-between;
    }

    .tg-contact-bar .tg-info { display: flex; align-items: center; gap: 10px; }

    .tg-contact-bar .tg-icon {
      width: 34px; height: 34px;
      background: rgba(6, 182, 212, 0.08);
      border-radius: var(--radius-sm);
      display: flex;
      align-items: center;
      justify-content: center;
      color: var(--cyan);
    }

    .tg-contact-bar .tg-icon svg { width: 17px; height: 17px; }

    .tg-contact-bar .tg-text { font-size: 11px; color: var(--text-muted); }
    .tg-contact-bar .tg-text strong { display: block; color: var(--cyan); font-size: 12px; }

    .tg-contact-bar .tg-link {
      padding: 7px 14px;
      background: rgba(6, 182, 212, 0.06);
      border: 1px solid rgba(6, 182, 212, 0.2);
      border-radius: var(--radius-sm);
      color: var(--cyan);
      font-family: 'Inter', sans-serif;
      font-size: 12px;
      font-weight: 600;
      text-decoration: none;
      transition: all 0.3s;
    }

    .tg-contact-bar .tg-link:hover { background: rgba(6, 182, 212, 0.12); }

    .footer {
      text-align: center;
      padding: 20px 0 10px;
      font-size: 11px;
      color: var(--text-muted);
    }

    .footer a { color: var(--primary); text-decoration: none; }

    .error-msg {
      margin-top: 14px;
      padding: 13px 16px;
      background: rgba(239,68,68,0.04);
      border: 1px solid rgba(239,68,68,0.2);
      border-radius: var(--radius-md);
      color: var(--danger);
      font-size: 13px;
      display: none;
      align-items: center;
      gap: 8px;
      animation: shake 0.5s ease;
    }

    .error-msg.show { display: flex; }
    .error-msg svg { width: 18px; height: 18px; flex-shrink: 0; }

    @keyframes shake {
      0%, 100% { transform: translateX(0); }
      25% { transform: translateX(-5px); }
      75% { transform: translateX(5px); }
    }

    .success-overlay {
      position: fixed;
      top: 0; left: 0;
      width: 100%; height: 100%;
      z-index: 100;
      display: none;
      align-items: center;
      justify-content: center;
      background: rgba(0,0,0,0.3);
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
      box-shadow: var(--shadow-xl);
    }

    @keyframes popIn {
      from { transform: scale(0.5); opacity: 0; }
      to { transform: scale(1); opacity: 1; }
    }

    .success-popup .check-circle {
      width: 56px; height: 56px;
      background: rgba(16,185,129,0.1);
      border-radius: 50%;
      display: flex;
      align-items: center;
      justify-content: center;
      margin: 0 auto 14px;
    }

    .success-popup .check-circle svg { color: var(--success); width: 26px; height: 26px; }
    .success-popup h3 { color: var(--text); margin-bottom: 4px; font-size: 16px; }
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
      box-shadow: 0 4px 20px rgba(16,185,129,0.3);
    }

    .toast.show { transform: translateX(-50%) translateY(0); }
    .toast svg { width: 15px; height: 15px; }

    ::-webkit-scrollbar { width: 3px; }
    ::-webkit-scrollbar-track { background: transparent; }
    ::-webkit-scrollbar-thumb { background: var(--primary); border-radius: 3px; }

    .hp-field {
      position: absolute;
      left: -9999px; top: -9999px;
      opacity: 0; height: 0; width: 0;
      overflow: hidden; pointer-events: none;
    }

    @media (max-width: 420px) {
      .container { padding: 10px; }
      .main-card { padding: 22px 16px; }
      .header { padding: 12px 14px; }
      .header-brand h1 { font-size: 15px; }
      .stats-bar { gap: 8px; }
      .stat-card { min-width: 80px; padding: 12px 8px; }
      .stat-card .stat-value { font-size: 14px; }
      .action-buttons { flex-direction: column; width: 100%; }
      .action-buttons .copy-btn, .action-buttons .qr-btn { width: 100%; justify-content: center; }
      .result-meta { flex-direction: column; align-items: flex-start; }
    }
  </style>
</head>
<body>

  <div class="bg-decoration">
    <div class="shape"></div>
    <div class="shape"></div>
    <div class="shape"></div>
  </div>

  <div class="container">

    ${noticeHTML}

    <div class="header" data-aos="fade-down">
      <div class="header-brand">
        <div class="logo-icon">
          <svg xmlns="http://www.w3.org/2000/svg" width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polygon points="13 2 3 14 12 14 11 22 21 10 12 10 13 2"/></svg>
        </div>
        <div>
          <h1>Patgaduu VPN</h1>
          <span>VLESS Key Generator</span>
        </div>
      </div>
      <div class="header-right">
        <a href="${adminTgLink}" target="_blank" rel="noopener" class="tg-btn" id="headerTgBtn">
          <svg xmlns="http://www.w3.org/2000/svg" width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><line x1="22" y1="2" x2="11" y2="13"/><polygon points="22 2 15 22 11 13 2 9 22 2"/></svg>
          TG
        </a>
        <div class="header-badge">PRO</div>
      </div>
    </div>

    <div class="validity-notice" id="validityNotice" data-aos="fade-up" data-aos-delay="50">
      <div class="vn-icon">
        <svg xmlns="http://www.w3.org/2000/svg" width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="3" y="4" width="18" height="18" rx="2" ry="2"/><line x1="16" y1="2" x2="16" y2="6"/><line x1="8" y1="2" x2="8" y2="6"/><line x1="3" y1="10" x2="21" y2="10"/><path d="m9 16 2 2 4-4"/></svg>
      </div>
      <div class="vn-text">
        <strong id="validityText">Loading...</strong>
        <span id="validityStatus">Key သက်တမ်း စစ်ဆေးနေပါသည်...</span>
      </div>
    </div>

    <div class="stats-bar" data-aos="fade-up" data-aos-delay="100">
      <div class="stat-card">
        <div class="stat-icon">
          <svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/><path d="m9 12 2 2 4-4"/></svg>
        </div>
        <div class="stat-value" id="statRemaining">-</div>
        <div class="stat-label">ကျန်ရှိ</div>
      </div>
      <div class="stat-card">
        <div class="stat-icon">
          <svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polyline points="17 1 21 5 17 9"/><path d="M3 11V9a4 4 0 0 1 4-4h14"/><polyline points="7 23 3 19 7 15"/><path d="M21 13v2a4 4 0 0 1-4 4H3"/></svg>
        </div>
        <div class="stat-value" id="statMaxPeriod">-</div>
        <div class="stat-label">ခွင့်ပြု</div>
      </div>
      <div class="stat-card">
        <div class="stat-icon">
          <svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M16 21v-2a4 4 0 0 0-4-4H6a4 4 0 0 0-4 4v2"/><circle cx="9" cy="7" r="4"/><path d="M22 21v-2a4 4 0 0 0-3-3.87"/><path d="M16 3.13a4 4 0 0 1 0 7.75"/></svg>
        </div>
        <div class="stat-value" id="statTotal">-</div>
        <div class="stat-label">စုစုပေါင်း</div>
      </div>
      <div class="stat-card">
        <div class="stat-icon">
          <svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polyline points="22 12 18 12 15 21 9 3 6 12 2 12"/></svg>
        </div>
        <div class="stat-value" id="statStatus">-</div>
        <div class="stat-label">Status</div>
      </div>
    </div>

    <div class="main-card" data-aos="fade-up" data-aos-delay="200">
      <div class="card-header">
        <div class="icon-wrapper">
          <svg xmlns="http://www.w3.org/2000/svg" width="30" height="30" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="m15.5 7.5 2.3 2.3a1 1 0 0 0 1.4 0l2.1-2.1a1 1 0 0 0 0-1.4L19 4"/><path d="m21 2-9.6 9.6"/><circle cx="7.5" cy="15.5" r="5.5"/></svg>
        </div>
        <h2>VLESS Key ရယူမည်</h2>
        <p>Generate ကိုနှိပ်၍ Key အသစ် ရယူပါ</p>
      </div>

      <div class="compat-notice">
        <div class="compat-title">
          <svg xmlns="http://www.w3.org/2000/svg" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="5" y="2" width="14" height="20" rx="2" ry="2"/><line x1="12" y1="18" x2="12.01" y2="18"/></svg>
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
          <svg xmlns="http://www.w3.org/2000/svg" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="m21.73 18-8-14a2 2 0 0 0-3.48 0l-8 14A2 2 0 0 0 4 21h16a2 2 0 0 0 1.73-3Z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/></svg>
          <span><strong>Hiddify App တွင် သုံး၍ မရနိုင်ပါ။</strong> V2rayNG (သို့) V2Box ကို အသုံးပြုပါ။</span>
        </div>
      </div>

      <div class="hp-field" aria-hidden="true">
        <input type="text" id="hpWebsite" name="website" tabindex="-1" autocomplete="off">
        <input type="text" id="hpEmail" name="email" tabindex="-1" autocomplete="off">
      </div>

      <button class="generate-btn" id="generateBtn" onclick="handleGenerate()">
        <svg xmlns="http://www.w3.org/2000/svg" width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="m12 3-1.912 5.813a2 2 0 0 1-1.275 1.275L3 12l5.813 1.912a2 2 0 0 1 1.275 1.275L12 21l1.912-5.813a2 2 0 0 1 1.275-1.275L21 12l-5.813-1.912a2 2 0 0 1-1.275-1.275L12 3Z"/><path d="M5 3v4"/><path d="M19 17v4"/><path d="M3 5h4"/><path d="M17 19h4"/></svg>
        <span id="btnText">Generate Key</span>
        <div class="spinner" id="spinner"></div>
      </button>

      <div class="error-msg" id="errorMsg">
        <svg xmlns="http://www.w3.org/2000/svg" width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"/><line x1="12" y1="8" x2="12" y2="12"/><line x1="12" y1="16" x2="12.01" y2="16"/></svg>
        <span id="errorText"></span>
      </div>

      <div class="result-area" id="resultArea">
        <div class="result-box">
          <div class="result-label">
            <svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M22 11.08V12a10 10 0 1 1-5.93-9.14"/><polyline points="22 4 12 14.01 9 11.01"/></svg>
            VLESS Key Generated Successfully
          </div>
          <div class="result-key" id="resultKey"></div>
          <div class="result-meta">
            <div class="expire-info">
              <svg xmlns="http://www.w3.org/2000/svg" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="3" y="4" width="18" height="18" rx="2" ry="2"/><line x1="16" y1="2" x2="16" y2="6"/><line x1="8" y1="2" x2="8" y2="6"/><line x1="3" y1="10" x2="21" y2="10"/></svg>
              <span id="expireText"></span>
            </div>
            <div class="action-buttons">
              <button class="copy-btn" onclick="copyKey()">
                <svg xmlns="http://www.w3.org/2000/svg" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="9" y="9" width="13" height="13" rx="2" ry="2"/><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"/></svg>
                Copy
              </button>
              <button class="qr-btn" onclick="showQR()">
                <svg xmlns="http://www.w3.org/2000/svg" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="2" y="2" width="8" height="8" rx="1"/><rect x="14" y="2" width="8" height="8" rx="1"/><rect x="2" y="14" width="8" height="8" rx="1"/><rect x="14" y="14" width="4" height="4" rx="1"/><rect x="20" y="14" width="2" height="2"/><rect x="14" y="20" width="2" height="2"/><rect x="20" y="20" width="2" height="2"/></svg>
                QR
              </button>
            </div>
          </div>
        </div>
      </div>

      <div class="howto-section">
        <div class="howto-toggle" id="howtoToggle" onclick="toggleHowto()">
          <div class="label">
            <svg xmlns="http://www.w3.org/2000/svg" width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"/><path d="M9.09 9a3 3 0 0 1 5.83 1c0 2-3 3-3 3"/><line x1="12" y1="17" x2="12.01" y2="17"/></svg>
            Key အသုံးပြုနည်း
          </div>
          <div class="arrow">
            <svg xmlns="http://www.w3.org/2000/svg" width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polyline points="6 9 12 15 18 9"/></svg>
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
              <div>ချိတ်ဆက်ပြီး ပြထားသော <strong>သက်တမ်းကုန်ဆုံးရက်</strong>ထိ အသုံးပြုနိုင်ပါသည်။</div>
            </div>
            <div class="step" style="margin-top: 6px;">
              <div class="step-num" style="background: rgba(239,68,68,0.08); color: var(--danger);">!</div>
              <div style="color: var(--danger);"><strong>Hiddify App</strong> တွင် ဤ Key ကို သုံး၍ <strong>မရနိုင်ပါ</strong>။ V2rayNG (သို့) V2Box ကို အသုံးပြုပါ။</div>
            </div>
          </div>
        </div>
      </div>

      <div class="info-bars">
        <div class="info-bar">
          <div class="label">
            <svg xmlns="http://www.w3.org/2000/svg" width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="m12 14 4-4"/><path d="M3.34 19a10 10 0 1 1 17.32 0"/></svg>
            ဤသက်တမ်းအတွင်း ကျန်ရှိအကြိမ်
          </div>
          <div class="count remaining-val" id="remainingCount">-</div>
        </div>

        <div class="info-bar">
          <div class="label">
            <svg xmlns="http://www.w3.org/2000/svg" width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><line x1="12" y1="20" x2="12" y2="10"/><line x1="18" y1="20" x2="18" y2="4"/><line x1="6" y1="20" x2="6" y2="16"/></svg>
            စုစုပေါင်း Generate ပြုလုပ်ပြီး (All Users)
          </div>
          <div class="count total-val" id="totalCount">-</div>
        </div>

        <div class="info-bar">
          <div class="label">
            <svg xmlns="http://www.w3.org/2000/svg" width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 2H2v10l9.29 9.29c.94.94 2.48.94 3.42 0l6.58-6.58c.94-.94.94-2.48 0-3.42L12 2Z"/><path d="M7 7h.01"/></svg>
            Key Version
          </div>
          <div class="count version-val" id="keyVersionText">-</div>
        </div>
      </div>

      <div class="tg-contact-bar">
        <div class="tg-info">
          <div class="tg-icon">
            <svg xmlns="http://www.w3.org/2000/svg" width="17" height="17" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><line x1="22" y1="2" x2="11" y2="13"/><polygon points="22 2 15 22 11 13 2 9 22 2"/></svg>
          </div>
          <div class="tg-text">
            အကူအညီ / ဆက်သွယ်ရန်
            <strong id="tgHandleText">${adminTgHandle}</strong>
          </div>
        </div>
        <a href="${adminTgLink}" target="_blank" rel="noopener" class="tg-link" id="tgContactLink">Message</a>
      </div>
    </div>

    <div class="footer">
      Powered by <a href="${adminTgLink}" target="_blank" rel="noopener">Patgaduu</a> &copy; 2026
    </div>
  </div>

  <div class="success-overlay" id="successOverlay">
    <div class="success-popup">
      <div class="check-circle">
        <svg xmlns="http://www.w3.org/2000/svg" width="26" height="26" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"/></svg>
      </div>
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
    <svg xmlns="http://www.w3.org/2000/svg" width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M22 11.08V12a10 10 0 1 1-5.93-9.14"/><polyline points="22 4 12 14.01 9 11.01"/></svg>
    <span>Copy ကူးယူပြီးပါပြီ!</span>
  </div>

<script>
  // ============== ANTI-DEVTOOLS / ANTI-INSPECTION ==============
  (function() {
    // Disable right-click context menu
    document.addEventListener('contextmenu', function(e) { e.preventDefault(); });

    // Disable common devtools shortcuts
    document.addEventListener('keydown', function(e) {
      // F12
      if (e.key === 'F12' || e.keyCode === 123) { e.preventDefault(); return false; }
      // Ctrl+Shift+I / Cmd+Opt+I (Inspector)
      if ((e.ctrlKey || e.metaKey) && e.shiftKey && (e.key === 'I' || e.key === 'i' || e.keyCode === 73)) { e.preventDefault(); return false; }
      // Ctrl+Shift+J / Cmd+Opt+J (Console)
      if ((e.ctrlKey || e.metaKey) && e.shiftKey && (e.key === 'J' || e.key === 'j' || e.keyCode === 74)) { e.preventDefault(); return false; }
      // Ctrl+Shift+C (Element picker)
      if ((e.ctrlKey || e.metaKey) && e.shiftKey && (e.key === 'C' || e.key === 'c' || e.keyCode === 67)) { e.preventDefault(); return false; }
      // Ctrl+U (View source)
      if ((e.ctrlKey || e.metaKey) && (e.key === 'U' || e.key === 'u' || e.keyCode === 85)) { e.preventDefault(); return false; }
      // Ctrl+S (Save page)
      if ((e.ctrlKey || e.metaKey) && (e.key === 'S' || e.key === 's' || e.keyCode === 83)) { e.preventDefault(); return false; }
    });

    // Detect devtools open via debugger timing
    var _dc = 0;
    setInterval(function() {
      var start = performance.now();
      (function(){}).constructor('debugger')();
      var end = performance.now();
      if (end - start > 100) {
        _dc++;
        if (_dc > 2) {
          // DevTools detected - clear sensitive data
          csrfToken = '';
          currentKey = '';
          powChallenge = '';
          powNonce = '';
          document.body.innerHTML = '<div style="display:flex;align-items:center;justify-content:center;height:100vh;font-family:sans-serif;color:#666;"><p>Developer tools detected. Please close them and refresh.</p></div>';
        }
      } else {
        _dc = Math.max(0, _dc - 1);
      }
    }, 2000);

    // Override console methods to prevent data leaking
    var noop = function() {};
    try {
      Object.defineProperty(window, 'console', {
        get: function() {
          return { log: noop, warn: noop, error: noop, info: noop, debug: noop, dir: noop, table: noop, trace: noop, group: noop, groupEnd: noop, clear: noop };
        },
        set: noop
      });
    } catch(e) {}
  })();

  // Load QR code library dynamically
  (function() {
    var s = document.createElement('script');
    s.src = 'https://unpkg.com/qrcode-generator@1.4.4/qrcode.js';
    s.onerror = function() {};
    document.head.appendChild(s);
  })();

  var csrfToken = '';
  var currentKey = '';
  var isGenerating = false;
  var powChallenge = '';
  var powDifficulty = 4;
  var powNonce = '';
  var powReady = false;

  document.addEventListener('DOMContentLoaded', function() {
    checkRemaining();
  });

  // ============== PROOF-OF-WORK SOLVER ==============
  function solvePoW(challenge, difficulty) {
    return new Promise(function(resolve) {
      var prefix = '';
      for (var d = 0; d < difficulty; d++) prefix += '0';

      var nonce = 0;
      var batchSize = 1000;

      function batch() {
        var end = nonce + batchSize;
        for (; nonce < end; nonce++) {
          var testStr = challenge + '||' + nonce;
          // Use sync approach with batching
        }
        // We need async SHA-256 so do it differently
        tryNonces(nonce - batchSize, batchSize, challenge, prefix, resolve);
      }

      function tryNonces(start, count, chal, pfx, cb) {
        var promises = [];
        for (var i = start; i < start + count; i++) {
          promises.push(testNonce(chal, i, pfx));
        }
        Promise.all(promises).then(function(results) {
          for (var j = 0; j < results.length; j++) {
            if (results[j] !== false) {
              cb(results[j]);
              return;
            }
          }
          nonce = start + count;
          if (nonce > 10000000) {
            cb(null); // give up after 10M attempts
            return;
          }
          setTimeout(function() { tryNonces(nonce, Math.min(batchSize, 5000), chal, pfx, cb); }, 0);
        });
      }

      function testNonce(chal, n, pfx) {
        var data = chal + '||' + n;
        var encoder = new TextEncoder();
        var buffer = encoder.encode(data);
        return crypto.subtle.digest('SHA-256', buffer).then(function(hash) {
          var arr = Array.from(new Uint8Array(hash));
          var hex = arr.map(function(b) { return b.toString(16).padStart(2, '0'); }).join('');
          if (hex.startsWith(pfx)) return String(n);
          return false;
        });
      }

      batch();
    });
  }

  function closeNotice() {
    var slider = document.getElementById('adminNoticeSlider');
    if (slider) {
      slider.style.transition = 'all 0.3s ease';
      slider.style.opacity = '0';
      slider.style.maxHeight = '0';
      slider.style.overflow = 'hidden';
      slider.style.marginBottom = '0';
      slider.style.padding = '0';
      setTimeout(function() { slider.style.display = 'none'; }, 300);
    }
  }

  function checkRemaining() {
    fetch('/api/check', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({})
    })
    .then(function(res) { return res.json(); })
    .then(function(data) {
      csrfToken = data.csrf_token || '';
      powChallenge = data.pow_challenge || '';
      powDifficulty = data.pow_difficulty || 4;

      // Start solving PoW in background
      if (powChallenge) {
        powReady = false;
        solvePoW(powChallenge, powDifficulty).then(function(nonce) {
          if (nonce !== null) {
            powNonce = nonce;
            powReady = true;
          }
        });
      }

      // Update TG links dynamically
      if (data.adminTgLink) {
        var headerTg = document.getElementById('headerTgBtn');
        var contactLink = document.getElementById('tgContactLink');
        if (headerTg) headerTg.href = data.adminTgLink;
        if (contactLink) contactLink.href = data.adminTgLink;
      }
      if (data.adminTgHandle) {
        var handleEl = document.getElementById('tgHandleText');
        if (handleEl) handleEl.textContent = data.adminTgHandle;
      }

      var validityNotice = document.getElementById('validityNotice');
      var validityTextEl = document.getElementById('validityText');
      var validityStatus = document.getElementById('validityStatus');

      validityTextEl.textContent = data.validityText || 'N/A';

      if (data.withinPeriod) {
        validityStatus.textContent = '\\u1021\\u101e\\u102f\\u1036\\u1038\\u1015\\u103c\\u102f\\u1014\\u102d\\u102f\\u1004\\u103a\\u1015\\u102b\\u101e\\u100a\\u103a';
        validityNotice.classList.remove('validity-expired');
      } else {
        validityStatus.textContent = 'Key \\u101e\\u1000\\u103a\\u1010\\u1019\\u103a\\u1038 \\u1000\\u102f\\u1014\\u103a\\u1006\\u102f\\u1036\\u1038\\u1014\\u1031\\u1015\\u102b\\u101e\\u100a\\u103a';
        validityNotice.classList.add('validity-expired');
      }

      document.getElementById('statRemaining').textContent = data.remaining + '/' + data.maxPerPeriod;
      document.getElementById('statMaxPeriod').textContent = data.maxPerPeriod + ' \\u1000\\u103c\\u102d\\u1019\\u103a';
      document.getElementById('statTotal').textContent = data.totalGenerated || 0;

      var statusEl = document.getElementById('statStatus');
      if (data.withinPeriod) {
        statusEl.textContent = 'Active';
        statusEl.style.color = 'var(--success)';
      } else {
        statusEl.textContent = 'Expired';
        statusEl.style.color = 'var(--danger)';
      }

      document.getElementById('remainingCount').textContent = data.remaining + ' \\u1000\\u103c\\u102d\\u1019\\u103a';
      document.getElementById('totalCount').textContent = (data.totalGenerated || 0) + ' \\u1000\\u103c\\u102d\\u1019\\u103a';
      document.getElementById('keyVersionText').textContent = data.keyVersion || '-';

      var btn = document.getElementById('generateBtn');
      var btnText = document.getElementById('btnText');

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
    })
    .catch(function(e) {
      // silently fail
    });
  }

  function decryptPayload(base64Data) {
    var binaryStr = atob(base64Data);
    var bytes = new Uint8Array(binaryStr.length);
    for (var i = 0; i < binaryStr.length; i++) {
      bytes[i] = binaryStr.charCodeAt(i);
    }
    var keyData = bytes.slice(0, 32);
    var iv = bytes.slice(32, 44);
    var ciphertext = bytes.slice(44);
    return crypto.subtle.importKey('raw', keyData, { name: 'AES-GCM' }, false, ['decrypt'])
      .then(function(key) {
        return crypto.subtle.decrypt({ name: 'AES-GCM', iv: iv }, key, ciphertext);
      })
      .then(function(decrypted) {
        return JSON.parse(new TextDecoder().decode(decrypted));
      });
  }

  function handleGenerate() {
    if (isGenerating) return;

    if (!powReady) {
      // PoW not ready yet, show brief message
      var errorMsg = document.getElementById('errorMsg');
      document.getElementById('errorText').textContent = 'Security verification \\u1015\\u103c\\u102f\\u101c\\u102f\\u1015\\u103a\\u1014\\u1031\\u1015\\u102b\\u101e\\u100a\\u103a\\u104b \\u1001\\u100f\\u1005\\u1031\\u102c\\u1004\\u103a\\u1037\\u1015\\u102b\\u104b';
      errorMsg.classList.add('show');
      setTimeout(function() { errorMsg.classList.remove('show'); }, 3000);
      return;
    }

    isGenerating = true;

    var btn = document.getElementById('generateBtn');
    var spinner = document.getElementById('spinner');
    var btnText = document.getElementById('btnText');
    var errorMsg = document.getElementById('errorMsg');
    var resultArea = document.getElementById('resultArea');

    errorMsg.classList.remove('show');
    resultArea.classList.remove('show');

    btn.disabled = true;
    spinner.style.display = 'block';
    btnText.textContent = 'Generating...';

    var hpValue = '';
    var hpEl = document.getElementById('hpWebsite');
    if (hpEl) hpValue = hpEl.value || '';

    var hpEmail = '';
    var hpEmailEl = document.getElementById('hpEmail');
    if (hpEmailEl) hpEmail = hpEmailEl.value || '';

    fetch('/api/generate', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-Requested-With': 'XMLHttpRequest'
      },
      body: JSON.stringify({
        csrf_token: csrfToken,
        website: hpValue,
        email: hpEmail,
        pow_challenge: powChallenge,
        pow_nonce: powNonce,
        t: Date.now()
      })
    })
    .then(function(res) { return res.json(); })
    .then(function(data) {
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

        if (data.error === 'invalid_token' || data.error === 'pow_required' || data.error === 'pow_invalid') {
          checkRemaining();
        }

        spinner.style.display = 'none';
        btnText.textContent = 'Generate Key';
        btn.disabled = false;
        isGenerating = false;
        return;
      }

      // Decrypt payload
      decryptPayload(data.payload).then(function(decrypted) {
        currentKey = decrypted.key;

        document.getElementById('resultKey').textContent = currentKey;
        document.getElementById('expireText').textContent = '\\u101e\\u1000\\u103a\\u1010\\u1019\\u103a\\u1038: ' + decrypted.validityText;
        resultArea.classList.add('show');

        var remaining = decrypted.remaining;
        document.getElementById('remainingCount').textContent = remaining + ' \\u1000\\u103c\\u102d\\u1019\\u103a';
        var statRemEl = document.getElementById('statRemaining');
        statRemEl.textContent = remaining + '/' + statRemEl.textContent.split('/')[1];

        if (decrypted.totalGenerated) {
          document.getElementById('statTotal').textContent = decrypted.totalGenerated;
          document.getElementById('totalCount').textContent = decrypted.totalGenerated + ' \\u1000\\u103c\\u102d\\u1019\\u103a';
        }

        showSuccess();

        // Refresh CSRF and PoW for next use
        checkRemaining();

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
        isGenerating = false;
      }).catch(function(e) {
        document.getElementById('errorText').textContent = '\\u1001\\u103b\\u102d\\u1010\\u103a\\u1006\\u1000\\u103a\\u1019\\u103e\\u102f \\u1019\\u1021\\u1031\\u102c\\u1004\\u103a\\u1019\\u103c\\u1004\\u103a\\u1015\\u102b\\u104b \\u1011\\u1015\\u103a\\u1000\\u103c\\u102d\\u102f\\u1038\\u1005\\u102c\\u1038\\u1015\\u102b\\u104b';
        errorMsg.classList.add('show');
        spinner.style.display = 'none';
        btnText.textContent = 'Generate Key';
        btn.disabled = false;
        isGenerating = false;
      });
    })
    .catch(function(e) {
      document.getElementById('errorText').textContent = '\\u1001\\u103b\\u102d\\u1010\\u103a\\u1006\\u1000\\u103a\\u1019\\u103e\\u102f \\u1019\\u1021\\u1031\\u102c\\u1004\\u103a\\u1019\\u103c\\u1004\\u103a\\u1015\\u102b\\u104b \\u1011\\u1015\\u103a\\u1000\\u103c\\u102d\\u102f\\u1038\\u1005\\u102c\\u1038\\u1015\\u102b\\u104b';
      errorMsg.classList.add('show');
      spinner.style.display = 'none';
      btnText.textContent = 'Generate Key';
      btn.disabled = false;
      isGenerating = false;
    });
  }

  function showSuccess() {
    var overlay = document.getElementById('successOverlay');
    overlay.classList.add('show');
    setTimeout(function() { overlay.classList.remove('show'); }, 2000);
  }

  function copyKey() {
    if (!currentKey) return;
    if (navigator.clipboard && navigator.clipboard.writeText) {
      navigator.clipboard.writeText(currentKey).then(function() {
        showToast();
      }).catch(function() {
        fallbackCopy();
      });
    } else {
      fallbackCopy();
    }
  }

  function fallbackCopy() {
    var textarea = document.createElement('textarea');
    textarea.value = currentKey;
    textarea.style.position = 'fixed';
    textarea.style.opacity = '0';
    document.body.appendChild(textarea);
    textarea.select();
    try { document.execCommand('copy'); } catch(e) {}
    document.body.removeChild(textarea);
    showToast();
  }

  function showToast() {
    var toast = document.getElementById('toast');
    toast.classList.add('show');
    setTimeout(function() { toast.classList.remove('show'); }, 2500);
  }

  function showQR() {
    if (!currentKey) return;
    var modal = document.getElementById('qrModal');
    var container = document.getElementById('qrCodeContainer');
    container.innerHTML = '';

    if (typeof qrcode === 'undefined') {
      container.innerHTML = '<p style="color:#666;font-size:12px;padding:20px;">QR Library load \\u1019\\u101b\\u1015\\u102b\\u104b Copy \\u101a\\u1030\\u1020 \\u1021\\u101e\\u102f\\u1036\\u1038\\u1015\\u103c\\u102f\\u1015\\u102b\\u104b</p>';
      modal.classList.add('show');
      return;
    }

    try {
      var qr = qrcode(0, 'L');
      qr.addData(currentKey);
      qr.make();
      var size = 200;
      var cellSize = Math.floor(size / qr.getModuleCount());
      container.innerHTML = qr.createImgTag(cellSize, 0);
    } catch (e) {
      container.innerHTML = '<p style="color:#666;font-size:12px;padding:20px;">Key \\u101b\\u103e\\u100a\\u103a\\u101c\\u103d\\u1014\\u103a\\u1038\\u101e\\u1016\\u1004\\u103a\\u1037 QR \\u1016\\u1014\\u103a\\u1010\\u102e\\u1038 \\u1019\\u101b\\u1015\\u102b\\u104b Copy \\u101a\\u1030\\u1020 \\u1021\\u101e\\u102f\\u1036\\u1038\\u1015\\u103c\\u102f\\u1015\\u102b\\u104b</p>';
    }
    modal.classList.add('show');
  }

  function closeQR() { document.getElementById('qrModal').classList.remove('show'); }

  document.addEventListener('click', function(e) {
    if (e.target === document.getElementById('qrModal')) closeQR();
  });

  function toggleHowto() {
    document.getElementById('howtoToggle').classList.toggle('open');
    document.getElementById('howtoContent').classList.toggle('open');
  }
</script>

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

  // API routes
  if (url.pathname === "/api/generate") {
    return await handleGenerate(req);
  }

  if (url.pathname === "/api/check") {
    return await handleCheckRemaining(req);
  }

  if (url.pathname === "/api/debug") {
    return await handleDebug(req);
  }

  // Block suspicious paths
  const blockedPaths = ["/wp-admin", "/wp-login", "/.env", "/config", "/admin", "/.git", "/xmlrpc", "/phpinfo", "/phpmyadmin", "/.well-known/", "/robots.txt", "/sitemap"];
  if (blockedPaths.some(p => url.pathname.toLowerCase().startsWith(p))) {
    return new Response("Not found", { status: 404 });
  }

  // Block non-GET methods for HTML page
  if (req.method !== "GET" && req.method !== "HEAD") {
    return new Response("Method not allowed", { status: 405 });
  }

  // Only serve on root path
  if (url.pathname !== "/" && url.pathname !== "/index.html") {
    return new Response("Not found", { status: 404 });
  }

  return new Response(getHTML(), {
    headers: {
      "Content-Type": "text/html; charset=utf-8",
      "Cache-Control": "no-store, no-cache, must-revalidate",
      "Content-Security-Policy": "default-src 'self'; script-src 'self' 'unsafe-inline' https://unpkg.com; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; font-src https://fonts.gstatic.com; img-src 'self' data: blob:; connect-src 'self'; frame-ancestors 'none'; base-uri 'self'; form-action 'self';",
      ...securityHeaders,
    }
  });
});
