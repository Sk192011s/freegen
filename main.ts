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
  const userProfile = Deno.env.get("USER_PROFILE") || "Patgaduu Admin";

  return {
    keys, validFrom, validUntil, validityText, maxPerPeriod,
    keyVersion, tzOffset, adminTgLink, adminTgHandle, adminNotice, userProfile
  };
}

// ============== HTML ESCAPING (XSS Prevention) ==============

function escapeHTML(str: string): string {
  return str
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#x27;");
}

function escapeURLAttribute(url: string): string {
  const trimmed = url.trim();
  if (/^https?:\/\//i.test(trimmed)) {
    return escapeHTML(trimmed);
  }
  return "#";
}

// ============== CRYPTO HELPERS ==============

async function hashSHA256(data: string): Promise<string> {
  const encoder = new TextEncoder();
  const dataBuffer = encoder.encode(data);
  const hashBuffer = await crypto.subtle.digest("SHA-256", dataBuffer);
  const hashArray = Array.from(new Uint8Array(hashBuffer));
  return hashArray.map(b => b.toString(16).padStart(2, "0")).join("");
}

function getCSRFSecret(): string {
  const secret = Deno.env.get("CSRF_SECRET");
  if (!secret || secret.length < 32) {
    throw new Error("CSRF_SECRET env variable is missing or too short.");
  }
  return secret;
}

// ============== CSRF TOKEN ==============

async function generateCSRFToken(ip: string): Promise<string> {
  const secret = getCSRFSecret();
  const hour = Math.floor(Date.now() / (1000 * 60 * 60));
  const raw = `${ip}||${hour}||csrf||${secret}`;
  return await hashSHA256(raw);
}

async function validateCSRFToken(token: string, ip: string): Promise<boolean> {
  if (!token || typeof token !== "string" || token.length !== 64) return false;
  const secret = getCSRFSecret();
  const hour = Math.floor(Date.now() / (1000 * 60 * 60));
  const current = await hashSHA256(`${ip}||${hour}||csrf||${secret}`);
  const previous = await hashSHA256(`${ip}||${hour - 1}||csrf||${secret}`);
  return timingSafeEqual(token, current) || timingSafeEqual(token, previous);
}

function timingSafeEqual(a: string, b: string): boolean {
  if (a.length !== b.length) return false;
  let result = 0;
  for (let i = 0; i < a.length; i++) {
    result |= a.charCodeAt(i) ^ b.charCodeAt(i);
  }
  return result === 0;
}

// ============== PROOF OF WORK ==============

async function generateChallenge(ip: string): Promise<{ challenge: string; difficulty: number }> {
  const secret = getCSRFSecret();
  const timestamp = Math.floor(Date.now() / (1000 * 60 * 5));
  const challenge = await hashSHA256(`${ip}||${timestamp}||pow||${secret}`);
  return { challenge, difficulty: 4 };
}

async function verifyPoW(ip: string, challenge: string, nonce: string): Promise<boolean> {
  if (!challenge || typeof challenge !== "string" || challenge.length !== 64) return false;
  if (!nonce || typeof nonce !== "string" || nonce.length > 20) return false;

  const secret = getCSRFSecret();
  const timestamp = Math.floor(Date.now() / (1000 * 60 * 5));
  const expectedChallenge = await hashSHA256(`${ip}||${timestamp}||pow||${secret}`);
  const prevTimestamp = timestamp - 1;
  const prevChallenge = await hashSHA256(`${ip}||${prevTimestamp}||pow||${secret}`);

  if (!timingSafeEqual(challenge, expectedChallenge) && !timingSafeEqual(challenge, prevChallenge)) return false;

  const hash = await hashSHA256(`${challenge}||${nonce}`);
  return hash.startsWith("0000");
}

// ============== FINGERPRINTING ==============

async function generateServerFingerprint(ip: string, userAgent: string): Promise<string> {
  const salt = Deno.env.get("FINGERPRINT_SALT") || "";
  const raw = `${ip}||${userAgent}||${salt}`;
  return await hashSHA256(raw);
}

// ============== VALIDITY PERIOD ==============

function parseUTCFromLocal(dateStr: string, time: string, tzOffset: number): number {
  const dt = new Date(`${dateStr}T${time}+00:00`);
  return dt.getTime() - (tzOffset * 60 * 1000);
}

function isWithinValidPeriod(config: ReturnType<typeof getConfig>): boolean {
  const now = Date.now();
  const fromUTC = parseUTCFromLocal(config.validFrom, "00:00:00", config.tzOffset);
  const untilUTC = parseUTCFromLocal(config.validUntil, "23:59:59", config.tzOffset);
  return now >= fromUTC && now <= untilUTC;
}

function getValidUntilUTC(config: ReturnType<typeof getConfig>): number {
  return parseUTCFromLocal(config.validUntil, "23:59:59", config.tzOffset);
}

// ============== RATE LIMITING ==============

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
      message: `ဤ Key သက်တမ်းအတွင်း Generate လုပ်ခွင့် (${config.maxPerPeriod} ကြိမ်) ကုန်သွားပါပြီ။`
    };
  }

  return { allowed: true, remaining: config.maxPerPeriod - count, message: "" };
}

async function incrementAllAtomic(
  fingerprint: string,
  ipFingerprint: string,
  config: ReturnType<typeof getConfig>
): Promise<{ success: boolean; totalCount: number }> {
  const periodKey = `${config.keyVersion}_${config.validFrom}_${config.validUntil}`;
  const fpKey = ["rate_limit_period", fingerprint, periodKey];
  const ipKey = ["rate_limit_period", ipFingerprint, periodKey];

  const untilUTC = getValidUntilUTC(config);
  const expireIn = Math.max(untilUTC - Date.now() + 86400000, 86400000);

  let allowed = false;
  const maxRetries = 5;

  for (let i = 0; i < maxRetries; i++) {
    const fpEntry = await kv.get<number>(fpKey);
    const ipEntry = await kv.get<number>(ipKey);

    const fpCount = fpEntry.value || 0;
    const ipCount = ipEntry.value || 0;

    if (fpCount >= config.maxPerPeriod || ipCount >= config.maxPerPeriod) {
      return { success: false, totalCount: -1 };
    }

    const result = await kv.atomic()
      .check(fpEntry)
      .check(ipEntry)
      .set(fpKey, fpCount + 1, { expireIn })
      .set(ipKey, ipCount + 1, { expireIn })
      .commit();

    if (result.ok) {
      allowed = true;
      break;
    }

    const delay = Math.min(50 * Math.pow(2, i), 500) + Math.random() * 50;
    await new Promise(resolve => setTimeout(resolve, delay));
  }

  if (!allowed) return { success: false, totalCount: -1 };

  await kv.atomic()
    .mutate({
      type: "sum",
      key: ["stats", "total_generates_u64"],
      value: new Deno.KvU64(1n)
    })
    .commit();

  const totalCount = await getTotalCount();
  return { success: true, totalCount };
}

// ============== TOTAL GENERATE COUNTER ==============

async function getTotalCount(): Promise<number> {
  const legacyEntry = await kv.get<number>(["stats", "total_generates"]);
  const u64Entry = await kv.get<Deno.KvU64>(["stats", "total_generates_u64"]);

  const legacyCount = legacyEntry.value || 0;
  const u64Count = u64Entry.value ? Number(u64Entry.value.value) : 0;

  return legacyCount + u64Count;
}

// ============== BURST RATE LIMITING (Anti-Spam) ==============

async function checkBurstLimit(ip: string): Promise<boolean> {
  const minute = Math.floor(Date.now() / (1000 * 60));
  const burstKey = ["burst_limit", ip, String(minute)];

  const maxRetries = 3;
  for (let i = 0; i < maxRetries; i++) {
    const entry = await kv.get<number>(burstKey);
    const count = entry.value || 0;

    if (count >= 10) return false;

    const result = await kv.atomic()
      .check(entry)
      .set(burstKey, count + 1, { expireIn: 120000 })
      .commit();

    if (result.ok) return true;
    await new Promise(resolve => setTimeout(resolve, 20 * (i + 1)));
  }
  return true;
}

// ============== KEY MANAGEMENT & ENCRYPTION ==============

function getRandomKey(config: ReturnType<typeof getConfig>): { key: string } | null {
  if (config.keys.length === 0) return null;
  const randomBytes = new Uint32Array(1);
  crypto.getRandomValues(randomBytes);
  const randomIndex = randomBytes[0] % config.keys.length;
  return { key: config.keys[randomIndex] };
}

async function deriveEncryptionKey(): Promise<CryptoKey> {
  const secret = Deno.env.get("PAYLOAD_SECRET") || getCSRFSecret();
  const keyMaterial = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(secret),
    { name: "PBKDF2" },
    false,
    ["deriveKey"]
  );
  return await crypto.subtle.deriveKey(
    {
      name: "PBKDF2",
      salt: new TextEncoder().encode("patgaduu-payload-salt-v1"),
      iterations: 100000,
      hash: "SHA-256"
    },
    keyMaterial,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt", "decrypt"]
  );
}

async function encryptPayload(plaintext: string): Promise<string> {
  const key = await deriveEncryptionKey();
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const encoded = new TextEncoder().encode(plaintext);
  const ciphertext = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, key, encoded);

  const combined = new Uint8Array(12 + new Uint8Array(ciphertext).length);
  combined.set(iv, 0);
  combined.set(new Uint8Array(ciphertext), 12);

  return btoa(String.fromCharCode(...combined));
}

async function decryptPayload(base64: string): Promise<string> {
  const key = await deriveEncryptionKey();
  const raw = atob(base64);
  const bytes = new Uint8Array(raw.length);
  for (let i = 0; i < raw.length; i++) bytes[i] = raw.charCodeAt(i);

  const iv = bytes.slice(0, 12);
  const ciphertext = bytes.slice(12);
  const decrypted = await crypto.subtle.decrypt({ name: "AES-GCM", iv }, key, ciphertext);
  return new TextDecoder().decode(decrypted);
}

// ============== HELPERS & VALIDATION ==============

function jsonResponse(data: unknown, status = 200, extraHeaders: Record<string, string> = {}): Response {
  return new Response(JSON.stringify(data), {
    status,
    headers: {
      "Content-Type": "application/json",
      "Cache-Control": "no-store, no-cache, must-revalidate, private",
      "X-Content-Type-Options": "nosniff",
      "X-Frame-Options": "DENY",
      "Referrer-Policy": "strict-origin-when-cross-origin",
      "Permissions-Policy": "camera=(), microphone=(), geolocation=()",
      ...extraHeaders,
    }
  });
}

function getClientIP(req: Request): string {
  return req.headers.get("cf-connecting-ip")
    || req.headers.get("x-real-ip")
    || req.headers.get("x-forwarded-for")?.split(",")[0]?.trim()
    || "unknown";
}

function validateRequest(req: Request): { valid: boolean; error?: string } {
  const ua = req.headers.get("user-agent") || "";
  if (!ua || ua.length < 10) return { valid: false, error: "Invalid request" };

  const botPatterns = [
    /curl/i, /wget/i, /python/i, /httpie/i, /postman/i,
    /scrapy/i, /httpclient/i, /java\//i, /okhttp/i,
    /node-fetch/i, /axios/i, /go-http/i, /ruby/i, /perl/i,
    /headless/i, /puppeteer/i, /playwright/i
  ];

  if (botPatterns.some(pattern => pattern.test(ua))) return { valid: false, error: "Blocked" };
  return { valid: true };
}

// ============== API HANDLERS ==============

async function handleGenerate(req: Request): Promise<Response> {
  if (req.method !== "POST") return jsonResponse({ error: "Method not allowed" }, 405);

  const origin = req.headers.get("origin") || "";
  const host = req.headers.get("host") || "";
  if (origin && !origin.includes(host)) {
    return jsonResponse({ success: false, message: "ခွင့်မပြုပါ။" }, 403);
  }

  if (!validateRequest(req).valid) {
    return jsonResponse({ success: false, message: "ခွင့်မပြုပါ။" }, 403);
  }

  const ip = getClientIP(req);
  const userAgent = req.headers.get("user-agent") || "unknown";

  if (!(await checkBurstLimit(ip))) {
    return jsonResponse({
      success: false, error: "rate_limited",
      message: "တောင်းဆိုမှု များလွန်းနေပါသည်။ ခဏစောင့်ပါ။"
    }, 429);
  }

  let body: Record<string, unknown>;
  try {
    const text = await req.text();
    if (text.length > 4096) {
      return jsonResponse({ success: false, message: "ခွင့်မပြုပါ။" }, 400);
    }
    body = JSON.parse(text);

    if ((body.website as string)?.length > 0 || (body.email as string)?.length > 0) {
      return jsonResponse({
        success: true,
        payload: btoa("fake-payload-" + crypto.randomUUID()),
        remaining: 0
      });
    }

    if (!body.csrf_token || !(await validateCSRFToken(body.csrf_token as string, ip))) {
      return jsonResponse({
        success: false, error: "invalid_token",
        message: "Session သက်တမ်းကုန်ပါပြီ။ Page ကို Refresh လုပ်ပါ။"
      }, 403);
    }

    if (!body.pow_challenge || !body.pow_nonce ||
      !(await verifyPoW(ip, body.pow_challenge as string, body.pow_nonce as string))) {
      return jsonResponse({
        success: false, error: "pow_invalid",
        message: "Security verification မအောင်မြင်ပါ။ Refresh လုပ်ပါ။"
      }, 403);
    }
  } catch {
    return jsonResponse({ success: false, message: "ခွင့်မပြုပါ။" }, 400);
  }

  const config = getConfig();
  if (!isWithinValidPeriod(config)) {
    return jsonResponse({
      success: false, error: "expired",
      message: "လက်ရှိ Key သက်တမ်း ကုန်ဆုံးနေပါသည်။"
    }, 403);
  }

  const fingerprint = await generateServerFingerprint(ip, userAgent);
  const ipFingerprint = await hashSHA256(`ip-only-${ip}-patgaduu-salt`);

  const incrementResult = await incrementAllAtomic(fingerprint, ipFingerprint, config);
  if (!incrementResult.success) {
    return jsonResponse({
      success: false, error: "limit_reached",
      message: `ဤ Key သက်တမ်းအတွင်း Generate လုပ်ခွင့် (${config.maxPerPeriod} ကြိမ်) ကုန်သွားပါပြီ။`,
      remaining: 0
    }, 429);
  }

  const result = getRandomKey(config);
  if (!result) {
    return jsonResponse({
      success: false,
      message: "လက်ရှိ Key မရှိပါ။ နောက်မှ ပြန်လာပါ။"
    }, 503);
  }

  const fpCheck = await checkRateLimit(fingerprint, config);
  const ipCheck = await checkRateLimit(ipFingerprint, config);
  const remaining = Math.min(fpCheck.remaining, ipCheck.remaining);

  const encryptedPayload = await encryptPayload(JSON.stringify({
    key: result.key,
    validityText: config.validityText,
    remaining,
    totalGenerated: incrementResult.totalCount,
    ts: Date.now(),
    nonce: crypto.randomUUID()
  }));

  return jsonResponse({ success: true, payload: encryptedPayload, remaining });
}

async function handleCheckRemaining(req: Request): Promise<Response> {
  if (req.method !== "POST") return jsonResponse({ error: "Method not allowed" }, 405);

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
    remaining, allowed,
    maxPerPeriod: config.maxPerPeriod,
    validityText: config.validityText,
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
  if (!authKey) return new Response("Not found", { status: 404 });

  const authHeader = req.headers.get("authorization") || "";
  const url = new URL(req.url);
  const queryKey = url.searchParams.get("key") || "";

  if (authHeader !== `Bearer ${authKey}` && queryKey !== authKey) {
    return new Response("Not found", { status: 404 });
  }

  const totalGenerated = await getTotalCount();
  return jsonResponse({
    totalGenerated,
    status: "OK",
    timestamp: new Date().toISOString()
  });
}

// ============== HTML PAGE (UI) ==============

function getHTML(): string {
  const config = getConfig();

  const safeAdminTgLink = escapeURLAttribute(config.adminTgLink);
  const safeAdminTgHandle = escapeHTML(config.adminTgHandle);
  const safeUserProfile = escapeHTML(config.userProfile);
  const safeAdminNotice = escapeHTML(config.adminNotice);

  const noticeHTML = config.adminNotice ? `
    <div class="admin-notice-slider" id="adminNoticeSlider">
      <div class="notice-icon"><svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/></svg></div>
      <div class="notice-marquee"><span class="notice-text">${safeAdminNotice}</span></div>
      <button class="notice-close" onclick="closeNotice()">&times;</button>
    </div>` : '';

  const cspNonce = crypto.randomUUID().replace(/-/g, '');

  return `<!DOCTYPE html>
<html lang="my">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0, maximum-scale=1.0, user-scalable=no">
  
  <title>Patgaduu - VLESS Key Generator</title>

  <link rel="preconnect" href="https://fonts.googleapis.com">
  <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
  <link href="https://fonts.googleapis.com/css2?family=Padauk:wght@400;700&family=Inter:wght@400;500;600;700&family=JetBrains+Mono:wght@400&display=swap" rel="stylesheet">

  <style nonce="${cspNonce}">
    :root {
      /* ===== Deep Dark Premium Palette ===== */
      --bg-body: #0b0f1a;
      --bg-body-end: #111827;
      --bg-card: rgba(17, 24, 42, 0.85);
      --bg-card-solid: #131b2e;
      --bg-card-alt: rgba(30, 41, 70, 0.6);
      --glass-border: rgba(99, 130, 255, 0.12);
      --glass-highlight: rgba(255, 255, 255, 0.04);

      /* Accent Colors */
      --primary: #818cf8;
      --primary-bright: #a5b4fc;
      --primary-dark: #6366f1;
      --purple: #a78bfa;
      --purple-bright: #c4b5fd;
      --cyan: #22d3ee;
      --cyan-dim: #0891b2;
      --emerald: #34d399;
      --emerald-dim: #059669;
      --amber: #fbbf24;
      --amber-dim: #d97706;
      --rose: #fb7185;
      --rose-dim: #e11d48;

      /* Text */
      --text: #e2e8f0;
      --text-bright: #f8fafc;
      --text-dim: #94a3b8;
      --text-muted: #64748b;

      /* Shadows & Effects */
      --shadow-sm: 0 2px 8px rgba(0, 0, 0, 0.3);
      --shadow-md: 0 4px 16px rgba(0, 0, 0, 0.35);
      --shadow-lg: 0 12px 40px rgba(0, 0, 0, 0.45);
      --shadow-glow-primary: 0 0 30px rgba(99, 102, 241, 0.25);
      --shadow-glow-emerald: 0 0 30px rgba(52, 211, 153, 0.2);
      --shadow-glow-cyan: 0 0 20px rgba(34, 211, 238, 0.15);

      --radius-sm: 10px;
      --radius-md: 14px;
      --radius-lg: 20px;
      --radius-xl: 24px;
    }

    * { margin: 0; padding: 0; box-sizing: border-box; }

    body {
      font-family: 'Padauk', 'Inter', sans-serif;
      background: linear-gradient(160deg, var(--bg-body) 0%, var(--bg-body-end) 50%, #0f172a 100%);
      color: var(--text);
      min-height: 100vh;
      overflow-x: hidden;
    }

    /* ===== Animated Background Orbs ===== */
    .bg-decoration { position: fixed; top: 0; left: 0; width: 100%; height: 100%; z-index: 0; pointer-events: none; overflow: hidden; }
    .bg-decoration .shape { position: absolute; border-radius: 50%; filter: blur(100px); animation: floatOrb 20s ease-in-out infinite; }
    .bg-decoration .shape:nth-child(1) { width: 600px; height: 600px; background: radial-gradient(circle, rgba(99,102,241,0.18), rgba(139,92,246,0.08)); top: -250px; left: -200px; animation-duration: 25s; }
    .bg-decoration .shape:nth-child(2) { width: 500px; height: 500px; background: radial-gradient(circle, rgba(34,211,238,0.12), rgba(59,130,246,0.06)); bottom: -200px; right: -150px; animation-duration: 22s; animation-delay: -5s; }
    .bg-decoration .shape:nth-child(3) { width: 350px; height: 350px; background: radial-gradient(circle, rgba(251,113,133,0.1), rgba(167,139,250,0.06)); top: 40%; left: 60%; animation-duration: 28s; animation-delay: -10s; }
    @keyframes floatOrb {
      0%, 100% { transform: translate(0, 0) scale(1); }
      25% { transform: translate(30px, -40px) scale(1.05); }
      50% { transform: translate(-20px, 20px) scale(0.95); }
      75% { transform: translate(15px, 35px) scale(1.02); }
    }

    .container { position: relative; z-index: 1; max-width: 520px; margin: 0 auto; padding: 16px 14px; display: flex; flex-direction: column; min-height: 100vh; }

    /* ===== Admin Notice ===== */
    .admin-notice-slider {
      display: flex; align-items: center; gap: 10px; padding: 10px 14px;
      background: rgba(251, 191, 36, 0.1);
      border: 1px solid rgba(251, 191, 36, 0.25);
      border-radius: var(--radius-md);
      margin-bottom: 14px; overflow: hidden;
      box-shadow: 0 0 20px rgba(251, 191, 36, 0.08);
    }
    .notice-icon { color: var(--amber); flex-shrink: 0; }
    .notice-marquee { flex: 1; overflow: hidden; white-space: nowrap; mask-image: linear-gradient(90deg, transparent, black 10%, black 90%, transparent); -webkit-mask-image: linear-gradient(90deg, transparent, black 10%, black 90%, transparent); }
    .notice-text { display: inline-block; animation: marquee 15s linear infinite; font-size: 13px; font-weight: 600; color: var(--amber); padding-left: 100%; }
    @keyframes marquee { 0% { transform: translateX(0); } 100% { transform: translateX(-100%); } }
    .notice-close { background: none; border: none; font-size: 20px; color: var(--amber); cursor: pointer; opacity: 0.7; flex-shrink: 0; }

    /* ===== Header ===== */
    .header {
      display: flex; align-items: center; justify-content: space-between;
      padding: 14px 18px;
      background: rgba(17, 24, 42, 0.75);
      backdrop-filter: blur(20px); -webkit-backdrop-filter: blur(20px);
      border: 1px solid var(--glass-border);
      border-radius: 28px;
      margin-bottom: 16px;
      box-shadow: var(--shadow-md), var(--shadow-glow-primary);
    }
    .header-brand { display: flex; align-items: center; gap: 10px; }
    .logo-icon {
      width: 38px; height: 38px;
      background: linear-gradient(135deg, var(--primary-dark), var(--purple));
      border-radius: var(--radius-sm);
      display: flex; align-items: center; justify-content: center;
      box-shadow: 0 4px 15px rgba(99,102,241,0.4);
      color: white; flex-shrink: 0;
    }
    .logo-icon svg { width: 20px; height: 20px; }
    .header-brand h1 { font-size: 17px; font-weight: 700; color: var(--primary-bright); }
    .header-brand span { font-size: 10px; color: var(--text-muted); letter-spacing: 1px; text-transform: uppercase; }

    .user-profile {
      display: flex; align-items: center; gap: 8px;
      padding: 5px 12px 5px 6px;
      background: rgba(99,102,241,0.1);
      border: 1px solid rgba(99,102,241,0.25);
      border-radius: var(--radius-md);
      transition: all 0.3s ease;
      cursor: default;
    }
    .user-profile:hover { background: rgba(99,102,241,0.18); border-color: rgba(99,102,241,0.4); }
    .up-avatar {
      width: 24px; height: 24px;
      background: linear-gradient(135deg, var(--primary-dark), var(--purple));
      border-radius: 8px;
      display: flex; align-items: center; justify-content: center;
      color: white; box-shadow: 0 2px 5px rgba(99,102,241,0.4);
      flex-shrink: 0;
    }
    .up-avatar svg { width: 13px; height: 13px; }
    .up-name { font-size: 11px; font-weight: 700; color: var(--primary-bright); font-family: 'Inter', sans-serif; white-space: nowrap; }

    /* ===== Validity Notice ===== */
    .validity-notice {
      padding: 14px 16px;
      background: rgba(34, 211, 238, 0.08);
      border: 1px solid rgba(34, 211, 238, 0.2);
      border-radius: var(--radius-md);
      display: flex; align-items: center; gap: 12px;
      margin-bottom: 16px;
      box-shadow: 0 0 20px rgba(34, 211, 238, 0.06);
    }
    .vn-icon {
      width: 40px; height: 40px;
      background: rgba(34, 211, 238, 0.15);
      border-radius: var(--radius-sm);
      display: flex; align-items: center; justify-content: center;
      color: var(--cyan); flex-shrink: 0;
    }
    .vn-icon svg { width: 20px; height: 20px; }
    .vn-text { font-size: 12.5px; color: var(--text-dim); }
    .vn-text strong { color: var(--cyan); font-weight: 700; font-size: 13px; display: block; }

    .validity-expired { border-color: rgba(251, 113, 133, 0.3) !important; background: rgba(251, 113, 133, 0.08) !important; box-shadow: 0 0 20px rgba(251, 113, 133, 0.06) !important; }
    .validity-expired .vn-icon { background: rgba(251, 113, 133, 0.15) !important; color: var(--rose) !important; }
    .validity-expired .vn-text strong { color: var(--rose) !important; }

    /* ===== Stats Bar ===== */
    .stats-bar { display: flex; gap: 10px; margin-bottom: 16px; overflow-x: auto; scrollbar-width: none; }
    .stats-bar::-webkit-scrollbar { display: none; }
    .stat-card {
      flex: 1; min-width: 0;
      background: var(--bg-card);
      backdrop-filter: blur(12px); -webkit-backdrop-filter: blur(12px);
      border: 1px solid var(--glass-border);
      border-radius: var(--radius-md);
      padding: 14px 12px; text-align: center;
      position: relative;
      box-shadow: var(--shadow-sm);
      transition: transform 0.2s ease, box-shadow 0.2s ease;
    }
    .stat-card:hover { transform: translateY(-2px); box-shadow: var(--shadow-md); }
    .stat-card::before { content: ''; position: absolute; top: 0; left: 0; width: 100%; height: 3px; border-radius: 3px 3px 0 0; }
    .stat-card:nth-child(1)::before { background: linear-gradient(90deg, var(--primary-dark), var(--purple)); }
    .stat-card:nth-child(2)::before { background: linear-gradient(90deg, var(--cyan-dim), #3b82f6); }
    .stat-card:nth-child(3)::before { background: linear-gradient(90deg, var(--amber-dim), #f97316); }
    .stat-card:nth-child(4)::before { background: linear-gradient(90deg, var(--emerald-dim), var(--cyan-dim)); }
    .stat-icon { width: 32px; height: 32px; margin: 0 auto 6px; border-radius: 8px; display: flex; align-items: center; justify-content: center; }
    .stat-icon svg { width: 16px; height: 16px; }
    .stat-card:nth-child(1) .stat-icon { background: rgba(129, 140, 248, 0.15); color: var(--primary); }
    .stat-card:nth-child(2) .stat-icon { background: rgba(34, 211, 238, 0.15); color: var(--cyan); }
    .stat-card:nth-child(3) .stat-icon { background: rgba(251, 191, 36, 0.15); color: var(--amber); }
    .stat-card:nth-child(4) .stat-icon { background: rgba(52, 211, 153, 0.15); color: var(--emerald); }
    .stat-value { font-size: 16px; font-weight: 700; font-family: 'Inter', sans-serif; color: var(--text-bright); }
    .stat-label { font-size: 10px; color: var(--text-muted); margin-top: 2px; }

    /* ===== Main Card ===== */
    .main-card {
      background: var(--bg-card);
      backdrop-filter: blur(20px); -webkit-backdrop-filter: blur(20px);
      border: 1px solid var(--glass-border);
      border-radius: 28px;
      padding: 26px 18px;
      flex: 1;
      box-shadow: var(--shadow-lg), inset 0 1px 0 var(--glass-highlight);
    }
    .card-header { text-align: center; margin-bottom: 24px; }
    .icon-wrapper {
      width: 68px; height: 68px; margin: 0 auto 14px; border-radius: 18px;
      background: linear-gradient(135deg, var(--primary-dark), #7c3aed);
      display: flex; align-items: center; justify-content: center;
      box-shadow: 0 8px 30px rgba(99,102,241,0.35), 0 0 60px rgba(99,102,241,0.15);
      color: white;
      animation: iconPulse 3s ease-in-out infinite;
    }
    @keyframes iconPulse { 0%, 100% { transform: translateY(0) scale(1); } 50% { transform: translateY(-4px) scale(1.02); } }
    .icon-wrapper svg { width: 30px; height: 30px; }
    .card-header h2 { font-size: 20px; font-weight: 700; margin-bottom: 4px; color: var(--text-bright); }
    .card-header p { font-size: 13px; color: var(--text-dim); }

    /* ===== Compat Notice ===== */
    .compat-notice {
      padding: 14px 16px;
      background: rgba(129, 140, 248, 0.06);
      border: 1px solid rgba(129, 140, 248, 0.15);
      border-radius: var(--radius-md);
      margin-bottom: 18px;
    }
    .compat-title { font-size: 12px; font-weight: 700; color: var(--primary-bright); margin-bottom: 8px; display: flex; align-items: center; gap: 6px; }
    .compat-apps { display: flex; flex-wrap: wrap; gap: 5px; }
    .compat-app {
      padding: 3px 10px;
      background: rgba(52, 211, 153, 0.1);
      border: 1px solid rgba(52, 211, 153, 0.25);
      border-radius: 6px;
      font-size: 11px; color: var(--emerald); font-weight: 600; font-family: 'Inter', sans-serif;
    }

    /* ===== Generate Button ===== */
    .generate-btn {
      width: 100%; padding: 15px; border: none; border-radius: 18px;
      background: linear-gradient(135deg, #6366f1, #7c3aed 55%, #8b5cf6);
      color: white;
      font-family: 'Padauk', sans-serif; font-size: 16px; font-weight: 700;
      cursor: pointer;
      display: flex; align-items: center; justify-content: center; gap: 10px;
      box-shadow: 0 10px 30px rgba(99,102,241,0.35), 0 0 50px rgba(99,102,241,0.1);
      transition: transform 0.22s ease, box-shadow 0.22s ease, opacity 0.22s ease;
      position: relative;
      overflow: hidden;
    }
    .generate-btn::before {
      content: '';
      position: absolute; top: 0; left: -100%; width: 100%; height: 100%;
      background: linear-gradient(90deg, transparent, rgba(255,255,255,0.15), transparent);
      transition: left 0.5s ease;
    }
    .generate-btn:hover:not(:disabled)::before { left: 100%; }
    .generate-btn:hover:not(:disabled) { transform: translateY(-2px); box-shadow: 0 14px 35px rgba(99,102,241,0.45), 0 0 60px rgba(99,102,241,0.15); }
    .generate-btn:active:not(:disabled) { transform: translateY(0); }
    .generate-btn:disabled { opacity: 0.5; cursor: not-allowed; box-shadow: none; }
    .generate-btn svg { width: 20px; height: 20px; }
    .spinner { width: 20px; height: 20px; border: 2px solid rgba(255,255,255,0.3); border-top: 2px solid white; border-radius: 50%; animation: spin 0.8s linear infinite; display: none; }
    @keyframes spin { to { transform: rotate(360deg); } }

    /* ===== Error Message ===== */
    .error-msg {
      margin-top: 14px; padding: 13px 16px;
      background: rgba(251, 113, 133, 0.1);
      border: 1px solid rgba(251, 113, 133, 0.25);
      border-radius: var(--radius-md);
      color: var(--rose);
      font-size: 13px; display: none; align-items: center; gap: 8px;
    }
    .error-msg.show { display: flex; animation: shake 0.4s ease; }
    @keyframes shake { 0%, 100% { transform: translateX(0); } 25% { transform: translateX(-5px); } 75% { transform: translateX(5px); } }

    /* ===== Result Area ===== */
    .result-area { margin-top: 16px; display: none; }
    .result-area.show { display: block; }

    .result-box {
      background: rgba(52, 211, 153, 0.06);
      border: 1px solid rgba(52, 211, 153, 0.2);
      border-radius: 20px;
      padding: 14px;
      position: relative;
      animation: slideUp 0.45s ease;
      box-shadow: var(--shadow-md), var(--shadow-glow-emerald);
    }
    .result-box::before {
      content: ''; position: absolute; top: 0; left: 0; width: 100%; height: 4px;
      background: linear-gradient(90deg, var(--emerald), var(--cyan));
      border-radius: 4px 4px 0 0;
    }
    @keyframes slideUp { from { opacity: 0; transform: translateY(20px); } to { opacity: 1; transform: translateY(0); } }

    .result-label { display: flex; align-items: center; gap: 8px; margin-bottom: 10px; font-size: 11px; color: var(--emerald); font-weight: 600; }
    .result-label svg { width: 18px; height: 18px; flex-shrink: 0; }

    .result-key {
      background: rgba(0, 0, 0, 0.3);
      border: 1px solid rgba(52, 211, 153, 0.15);
      border-radius: var(--radius-sm);
      padding: 12px;
      font-family: 'JetBrains Mono', monospace;
      font-size: 10px; line-height: 1.5;
      color: var(--emerald);
      word-break: break-all; max-height: 100px; overflow-y: auto;
      user-select: all;
    }

    .result-meta {
      display: flex; align-items: center; justify-content: space-between;
      margin-top: 12px; padding-top: 12px;
      border-top: 1px solid rgba(52, 211, 153, 0.12);
      flex-wrap: wrap; gap: 10px;
    }

    .action-buttons { display: flex; gap: 8px; }
    .copy-btn, .qr-btn {
      display: flex; align-items: center; justify-content: center; gap: 5px;
      min-width: 86px; padding: 9px 14px;
      border: 1px solid rgba(129, 140, 248, 0.25);
      border-radius: 14px;
      background: rgba(129, 140, 248, 0.1);
      color: var(--primary-bright);
      font-family: 'Inter', sans-serif; font-size: 12px; font-weight: 700;
      cursor: pointer;
      transition: all 0.2s ease;
      box-shadow: 0 2px 8px rgba(99,102,241,0.1);
    }
    .copy-btn:hover, .qr-btn:hover {
      background: var(--primary-dark); color: #fff;
      border-color: var(--primary-dark);
      transform: translateY(-1px);
      box-shadow: 0 4px 15px rgba(99,102,241,0.3);
    }

    /* ===== Info Bars & Footer ===== */
    .info-bars { display: flex; flex-direction: column; gap: 8px; margin-top: 18px; }
    .info-bar {
      padding: 13px 16px;
      background: var(--bg-card-alt);
      border: 1px solid var(--glass-border);
      border-radius: var(--radius-md);
      display: flex; align-items: center; justify-content: space-between;
    }
    .info-bar .label { font-size: 12.5px; color: var(--text-dim); display: flex; align-items: center; gap: 6px; }
    .info-bar .count { font-size: 17px; font-weight: 700; font-family: 'Inter', sans-serif; }

    .tg-contact-bar {
      margin-top: 12px; padding: 13px 16px;
      background: rgba(34, 211, 238, 0.06);
      border: 1px solid rgba(34, 211, 238, 0.18);
      border-radius: var(--radius-md);
      display: flex; align-items: center; justify-content: space-between;
    }
    .tg-icon {
      width: 34px; height: 34px;
      background: rgba(34, 211, 238, 0.12);
      border-radius: var(--radius-sm);
      display: flex; align-items: center; justify-content: center;
      color: var(--cyan); flex-shrink: 0;
    }
    .tg-link {
      padding: 7px 14px;
      background: rgba(34, 211, 238, 0.1);
      border: 1px solid rgba(34, 211, 238, 0.25);
      border-radius: var(--radius-sm);
      color: var(--cyan); font-size: 12px; font-weight: 600;
      text-decoration: none;
      transition: all 0.2s ease;
    }
    .tg-link:hover { background: rgba(34, 211, 238, 0.2); box-shadow: var(--shadow-glow-cyan); }

    .footer { text-align: center; padding: 20px 0 10px; font-size: 11px; color: var(--text-muted); }
    .footer a { color: var(--primary); text-decoration: none; }

    /* ===== Modals & Overlays ===== */
    .qr-modal, .success-overlay {
      position: fixed; top: 0; left: 0; width: 100%; height: 100%; z-index: 150;
      display: none; align-items: center; justify-content: center;
      background: rgba(0, 0, 0, 0.6);
      backdrop-filter: blur(10px);
    }
    .qr-modal.show, .success-overlay.show { display: flex; animation: fadeIn 0.3s ease; }
    @keyframes fadeIn { from { opacity: 0; } to { opacity: 1; } }

    .qr-modal-content, .success-popup {
      background: var(--bg-card-solid);
      border: 1px solid var(--glass-border);
      border-radius: var(--radius-xl);
      padding: 28px; text-align: center;
      max-width: 300px; width: 90%;
      box-shadow: var(--shadow-lg), var(--shadow-glow-primary);
      animation: popIn 0.4s cubic-bezier(0.68, -0.55, 0.265, 1.55);
      color: var(--text-bright);
    }
    @keyframes popIn { from { transform: scale(0.5); opacity: 0; } to { transform: scale(1); opacity: 1; } }

    .qr-code-container {
      background: white; padding: 16px; display: inline-block;
      border-radius: var(--radius-md); margin-bottom: 16px;
      border: 1px solid var(--glass-border);
    }
    .qr-close-btn {
      padding: 10px 28px;
      background: var(--bg-card-alt);
      border: 1px solid var(--glass-border);
      border-radius: var(--radius-sm);
      cursor: pointer;
      font-family: 'Padauk', sans-serif;
      color: var(--text);
      transition: all 0.2s ease;
    }
    .qr-close-btn:hover { background: rgba(99,102,241,0.15); border-color: rgba(99,102,241,0.3); }

    .hp-field { position: absolute; left: -9999px; opacity: 0; pointer-events: none; }

    .toast {
      position: fixed; bottom: 30px; left: 50%;
      transform: translateX(-50%) translateY(100px);
      background: linear-gradient(135deg, var(--emerald-dim), var(--emerald));
      color: white; padding: 11px 22px;
      border-radius: var(--radius-sm);
      font-size: 13px; font-weight: 600; z-index: 200;
      transition: transform 0.3s cubic-bezier(0.68, -0.55, 0.265, 1.55);
      display: flex; align-items: center; gap: 8px;
      pointer-events: none;
      box-shadow: 0 8px 25px rgba(52, 211, 153, 0.35);
    }
    .toast.show { transform: translateX(-50%) translateY(0); }
  </style>
</head>
<body>

  <div class="bg-decoration"><div class="shape"></div><div class="shape"></div><div class="shape"></div></div>

  <div class="container">
    ${noticeHTML}

    <div class="header">
      <div class="header-brand">
        <div class="logo-icon">
          <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polygon points="13 2 3 14 12 14 11 22 21 10 12 10 13 2"/></svg>
        </div>
        <div>
          <h1>Patgaduu VPN</h1>
          <span>VLESS Generator</span>
        </div>
      </div>
      <div class="user-profile">
        <div class="up-avatar">
          <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M19 21v-2a4 4 0 0 0-4-4H9a4 4 0 0 0-4 4v2"/><circle cx="12" cy="7" r="4"/></svg>
        </div>
        <span class="up-name">${safeUserProfile}</span>
      </div>
    </div>

    <div class="validity-notice" id="validityNotice">
      <div class="vn-icon"><svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="3" y="4" width="18" height="18" rx="2" ry="2"/><line x1="16" y1="2" x2="16" y2="6"/><line x1="8" y1="2" x2="8" y2="6"/><line x1="3" y1="10" x2="21" y2="10"/><path d="m9 16 2 2 4-4"/></svg></div>
      <div class="vn-text"><strong id="validityText">Loading...</strong><span id="validityStatus">Key သက်တမ်း စစ်ဆေးနေပါသည်...</span></div>
    </div>

    <div class="stats-bar">
      <div class="stat-card"><div class="stat-icon"><svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/><path d="m9 12 2 2 4-4"/></svg></div><div class="stat-value" id="statRemaining">-</div><div class="stat-label">ကျန်ရှိ</div></div>
      <div class="stat-card"><div class="stat-icon"><svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="17 1 21 5 17 9"/><path d="M3 11V9a4 4 0 0 1 4-4h14"/><polyline points="7 23 3 19 7 15"/><path d="M21 13v2a4 4 0 0 1-4 4H3"/></svg></div><div class="stat-value" id="statMaxPeriod">-</div><div class="stat-label">ခွင့်ပြု</div></div>
      <div class="stat-card"><div class="stat-icon"><svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M16 21v-2a4 4 0 0 0-4-4H6a4 4 0 0 0-4 4v2"/><circle cx="9" cy="7" r="4"/><path d="M22 21v-2a4 4 0 0 0-3-3.87"/><path d="M16 3.13a4 4 0 0 1 0 7.75"/></svg></div><div class="stat-value" id="statTotal">-</div><div class="stat-label">စုစုပေါင်း</div></div>
      <div class="stat-card"><div class="stat-icon"><svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="22 12 18 12 15 21 9 3 6 12 2 12"/></svg></div><div class="stat-value" id="statStatus">-</div><div class="stat-label">Status</div></div>
    </div>

    <div class="main-card">
      <div class="card-header">
        <div class="icon-wrapper"><svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="m15.5 7.5 2.3 2.3a1 1 0 0 0 1.4 0l2.1-2.1a1 1 0 0 0 0-1.4L19 4"/><path d="m21 2-9.6 9.6"/><circle cx="7.5" cy="15.5" r="5.5"/></svg></div>
        <h2>VLESS Key ရယူမည်</h2>
        <p>Generate ကိုနှိပ်၍ Key အသစ် ရယူပါ</p>
      </div>

      <div class="compat-notice">
        <div class="compat-title"><svg xmlns="http://www.w3.org/2000/svg" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="5" y="2" width="14" height="20" rx="2" ry="2"/><line x1="12" y1="18" x2="12.01" y2="18"/></svg>Key ထည့်သွင်းအသုံးပြုနိုင်သော VPN Apps များ</div>
        <div class="compat-apps">
          <span class="compat-app">V2rayNG</span><span class="compat-app">V2Box</span><span class="compat-app">Nekoray</span>
        </div>
      </div>

      <div class="hp-field" aria-hidden="true" tabindex="-1">
        <label for="hpWebsite">Website</label><input type="text" id="hpWebsite" name="website" autocomplete="off" tabindex="-1">
        <label for="hpEmail">Email</label><input type="text" id="hpEmail" name="email" autocomplete="off" tabindex="-1">
      </div>

      <button class="generate-btn" id="generateBtn" type="button">
        <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="m12 3-1.912 5.813a2 2 0 0 1-1.275 1.275L3 12l5.813 1.912a2 2 0 0 1 1.275 1.275L12 21l1.912-5.813a2 2 0 0 1 1.275-1.275L21 12l-5.813-1.912a2 2 0 0 1-1.275-1.275L12 3Z"/><path d="M5 3v4"/><path d="M19 17v4"/><path d="M3 5h4"/><path d="M17 19h4"/></svg>
        <span id="btnText">Generate Key</span>
        <div class="spinner" id="spinner"></div>
      </button>

      <div class="error-msg" id="errorMsg" role="alert">
        <svg xmlns="http://www.w3.org/2000/svg" width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/><line x1="12" y1="8" x2="12" y2="12"/><line x1="12" y1="16" x2="12.01" y2="16"/></svg>
        <span id="errorText"></span>
      </div>

      <div class="result-area" id="resultArea">
        <div class="result-box">
          <div class="result-label"><svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M22 11.08V12a10 10 0 1 1-5.93-9.14"/><polyline points="22 4 12 14.01 9 11.01"/></svg> Generated Successfully</div>
          <div class="result-key" id="resultKey"></div>
          <div class="result-meta">
            <div style="font-size: 11px; color: var(--cyan);" id="expireText"></div>
            <div class="action-buttons">
              <button class="copy-btn" id="copyBtn" type="button">Copy</button>
              <button class="qr-btn" id="qrBtn" type="button">QR</button>
            </div>
          </div>
        </div>
      </div>

      <div class="info-bars">
        <div class="info-bar"><div class="label">မိမိGenerateယူခွင့် ကျန်ရှိအကြိမ်</div><div class="count" id="remainingCount" style="color: var(--amber);">-</div></div>
        <div class="info-bar"><div class="label">Userများ စုစုပေါင်း Generateထားသော အကြိမ်</div><div class="count" id="totalCount" style="color: var(--primary);">-</div></div>
      </div>

      <div class="tg-contact-bar">
        <div style="display:flex;align-items:center;gap:10px;">
          <div class="tg-icon"><svg xmlns="http://www.w3.org/2000/svg" width="17" height="17" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><line x1="22" y1="2" x2="11" y2="13"/><polygon points="22 2 15 22 11 13 2 9 22 2"/></svg></div>
          <div style="font-size:11px;color:var(--text-muted);">အကူအညီ / ဆက်သွယ်ရန်<strong style="display:block;color:var(--cyan);font-size:12px;" id="tgHandleText">${safeAdminTgHandle}</strong></div>
        </div>
        <a href="${safeAdminTgLink}" class="tg-link" id="tgContactLink" rel="noopener noreferrer" target="_blank">Message</a>
      </div>
    </div>
    <div class="footer">Powered by <a href="${safeAdminTgLink}" rel="noopener noreferrer" target="_blank">Patgaduu</a> &copy; 2026</div>
  </div>

  <div class="success-overlay" id="successOverlay"><div class="success-popup"><h3>အောင်မြင်ပါသည်!</h3><p style="color:var(--text-dim);margin-top:8px;">Key ကို Copy ယူ၍ V2rayNG တွင် အသုံးပြုပါ</p></div></div>
  <div class="qr-modal" id="qrModal"><div class="qr-modal-content"><h3>QR Code Scan</h3><div class="qr-code-container" id="qrCodeContainer"></div><br><button class="qr-close-btn" id="qrCloseBtn" type="button">ပိတ်မည်</button></div></div>
  <div class="toast" id="toast" role="status">Copy ကူးယူပြီးပါပြီ!</div>

<script nonce="${cspNonce}">
(function() {
  'use strict';

  var qrScript = document.createElement('script');
  qrScript.src = 'https://unpkg.com/qrcode-generator@1.4.4/qrcode.js';
  qrScript.crossOrigin = 'anonymous';
  document.head.appendChild(qrScript);

  var csrfToken = '', currentKey = '', isGenerating = false;
  var powChallenge = '', powDifficulty = 4, powNonce = '', powReady = false;
  var PAYLOAD_SECRET = '';

  var generateBtn = document.getElementById('generateBtn');
  var spinner = document.getElementById('spinner');
  var btnText = document.getElementById('btnText');
  var errorMsg = document.getElementById('errorMsg');
  var errorText = document.getElementById('errorText');
  var resultArea = document.getElementById('resultArea');
  var resultKey = document.getElementById('resultKey');
  var expireText = document.getElementById('expireText');
  var successOverlay = document.getElementById('successOverlay');
  var qrModal = document.getElementById('qrModal');
  var toast = document.getElementById('toast');

  generateBtn.addEventListener('click', handleGenerate);
  document.getElementById('copyBtn').addEventListener('click', copyKey);
  document.getElementById('qrBtn').addEventListener('click', showQR);
  document.getElementById('qrCloseBtn').addEventListener('click', closeQR);

  qrModal.addEventListener('click', function(e) {
    if (e.target === qrModal) closeQR();
  });
  successOverlay.addEventListener('click', function(e) {
    if (e.target === successOverlay) successOverlay.classList.remove('show');
  });

  document.addEventListener('DOMContentLoaded', checkRemaining);

  function solvePoW(challenge, difficulty) {
    return new Promise(function(resolve) {
      var prefix = '';
      for (var d = 0; d < difficulty; d++) prefix += '0';
      var nonce = 0;
      var batchSize = 500;
      var maxNonce = 10000000;

      function processBatch() {
        var promises = [];
        var end = Math.min(nonce + batchSize, maxNonce);
        for (var i = nonce; i < end; i++) {
          promises.push(testNonce(challenge, i, prefix));
        }
        Promise.all(promises).then(function(results) {
          for (var k = 0; k < results.length; k++) {
            if (results[k] !== false) {
              return resolve(results[k]);
            }
          }
          nonce = end;
          if (nonce >= maxNonce) return resolve(null);
          setTimeout(processBatch, 0);
        });
      }

      function testNonce(c, n, p) {
        return crypto.subtle.digest('SHA-256', new TextEncoder().encode(c + '||' + n))
          .then(function(h) {
            var hex = Array.from(new Uint8Array(h)).map(function(b) {
              return b.toString(16).padStart(2, '0');
            }).join('');
            return hex.startsWith(p) ? String(n) : false;
          });
      }

      processBatch();
    });
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

      if (powChallenge) {
        powReady = false;
        solvePoW(powChallenge, data.pow_difficulty || 4).then(function(n) {
          if (n) {
            powNonce = n;
            powReady = true;
          }
        });
      }

      document.getElementById('validityText').textContent = data.validityText || '';
      var vStatus = document.getElementById('validityStatus');
      var vNotice = document.getElementById('validityNotice');
      if (data.withinPeriod) {
        vStatus.textContent = 'အသုံးပြုနိုင်ပါသည်';
        vNotice.classList.remove('validity-expired');
      } else {
        vStatus.textContent = 'Key သက်တမ်း ကုန်ဆုံးနေပါသည်';
        vNotice.classList.add('validity-expired');
      }

      document.getElementById('statRemaining').textContent = data.remaining + '/' + data.maxPerPeriod;
      document.getElementById('statMaxPeriod').textContent = data.maxPerPeriod;
      document.getElementById('statTotal').textContent = data.totalGenerated;
      document.getElementById('statStatus').textContent = data.withinPeriod ? 'Active' : 'Expired';
      document.getElementById('remainingCount').textContent = data.remaining;
      document.getElementById('totalCount').textContent = data.totalGenerated;

      if (data.adminTgHandle) {
        document.getElementById('tgHandleText').textContent = data.adminTgHandle;
      }
      if (data.adminTgLink) {
        var linkEl = document.getElementById('tgContactLink');
        if (/^https?:\\/\\//.test(data.adminTgLink)) {
          linkEl.href = data.adminTgLink;
        }
      }

      generateBtn.disabled = !data.allowed;
      btnText.textContent = !data.allowed
        ? (data.withinPeriod ? 'Keyယူခွင့် ကုန်သွားပါပြီ' : 'သက်တမ်းကုန်နေသည်')
        : 'Generate Key';
    })
    .catch(function() {});
  }

  function handleGenerate() {
    if (isGenerating) return;

    if (!powReady) {
      showError('Security check လုပ်နေပါသည်။ ခဏစောင့်ပါ။');
      return;
    }

    isGenerating = true;
    generateBtn.disabled = true;
    spinner.style.display = 'block';
    btnText.textContent = 'Generating...';
    errorMsg.classList.remove('show');

    fetch('/api/generate', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        csrf_token: csrfToken,
        pow_challenge: powChallenge,
        pow_nonce: powNonce,
        website: document.getElementById('hpWebsite').value,
        email: document.getElementById('hpEmail').value,
        t: Date.now()
      })
    })
    .then(function(r) { return r.json(); })
    .then(function(data) {
      if (!data.success) {
        showError(data.message || 'မအောင်မြင်ပါ။');
        resetButton();
        checkRemaining();
        return;
      }

      var raw = atob(data.payload);
      var bytes = new Uint8Array(raw.length);
      for (var i = 0; i < raw.length; i++) bytes[i] = raw.charCodeAt(i);

      var iv = bytes.slice(0, 12);
      var ciphertext = bytes.slice(12);

      deriveDecryptionKey().then(function(key) {
        return crypto.subtle.decrypt({ name: 'AES-GCM', iv: iv }, key, ciphertext);
      }).then(function(dec) {
        var res = JSON.parse(new TextDecoder().decode(dec));
        currentKey = res.key;
        resultKey.textContent = currentKey;
        expireText.textContent = 'သက်တမ်း: ' + res.validityText;
        resultArea.classList.add('show');

        successOverlay.classList.add('show');
        setTimeout(function() { successOverlay.classList.remove('show'); }, 2000);

        checkRemaining();
        resetButton();
      }).catch(function() {
        showError('Decryption မအောင်မြင်ပါ။ Page Refresh လုပ်ပါ။');
        resetButton();
      });
    })
    .catch(function() {
      showError('ချိတ်ဆက်မှု မအောင်မြင်ပါ။');
      resetButton();
    });
  }

  function deriveDecryptionKey() {
    var secret = PATGADUU_SHARED_SECRET;
    var keyMaterial;
    return crypto.subtle.importKey(
      'raw',
      new TextEncoder().encode(secret),
      { name: 'PBKDF2' },
      false,
      ['deriveKey']
    ).then(function(km) {
      keyMaterial = km;
      return crypto.subtle.deriveKey(
        {
          name: 'PBKDF2',
          salt: new TextEncoder().encode('patgaduu-payload-salt-v1'),
          iterations: 100000,
          hash: 'SHA-256'
        },
        keyMaterial,
        { name: 'AES-GCM', length: 256 },
        false,
        ['decrypt']
      );
    });
  }

  function showError(msg) {
    errorText.textContent = msg;
    errorMsg.classList.add('show');
    setTimeout(function() { errorMsg.classList.remove('show'); }, 5000);
  }

  function resetButton() {
    spinner.style.display = 'none';
    isGenerating = false;
    setTimeout(function() {
      if (!isGenerating) {
        generateBtn.disabled = false;
        btnText.textContent = 'Generate Key';
      }
    }, 3000);
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
    var t = document.createElement('textarea');
    t.value = currentKey;
    t.style.position = 'fixed';
    t.style.left = '-9999px';
    document.body.appendChild(t);
    t.select();
    try { document.execCommand('copy'); } catch(e) {}
    document.body.removeChild(t);
    showToast();
  }

  function showToast() {
    toast.classList.add('show');
    setTimeout(function() { toast.classList.remove('show'); }, 2000);
  }

  function showQR() {
    if (!currentKey || typeof qrcode === 'undefined') return;
    var qr = qrcode(0, 'L');
    qr.addData(currentKey);
    qr.make();
    var container = document.getElementById('qrCodeContainer');
    container.innerHTML = '';
    var img = document.createElement('img');
    img.src = qr.createDataURL(Math.floor(200 / qr.getModuleCount()), 0);
    img.alt = 'QR Code';
    img.width = 200;
    img.height = 200;
    container.appendChild(img);
    qrModal.classList.add('show');
  }

  function closeQR() {
    qrModal.classList.remove('show');
  }

  window.closeNotice = function() {
    var el = document.getElementById('adminNoticeSlider');
    if (el) el.style.display = 'none';
  };

  var PATGADUU_SHARED_SECRET = '${escapeHTML(Deno.env.get("PAYLOAD_CLIENT_SECRET") || "")}';

})();
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
    "X-XSS-Protection": "0",
    "Referrer-Policy": "strict-origin-when-cross-origin",
    "Permissions-Policy": "camera=(), microphone=(), geolocation=(), payment=()",
    "Strict-Transport-Security": "max-age=63072000; includeSubDomains; preload",
    "Content-Security-Policy": [
      "default-src 'none'",
      "script-src 'self' https://unpkg.com 'unsafe-inline'",
      "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com",
      "font-src https://fonts.gstatic.com",
      "img-src 'self' data:",
      "connect-src 'self'",
      "frame-ancestors 'none'",
      "base-uri 'self'",
      "form-action 'self'"
    ].join("; ")
  };

  const lowerPath = url.pathname.toLowerCase();
  const blockedPaths = ["/wp-admin", "/.env", "/.git", "/phpmyadmin", "/admin", "/.htaccess", "/wp-login", "/xmlrpc"];
  if (blockedPaths.some(p => lowerPath.startsWith(p))) {
    return new Response("Not found", { status: 404, headers: securityHeaders });
  }
  
  if (url.pathname === "/robots.txt") {
    return new Response(
      `User-agent: *
Allow: /

Sitemap: https://freegenvless.shop/sitemap.xml
`,
      {
        headers: {
          "Content-Type": "text/plain; charset=utf-8",
          ...securityHeaders,
        },
      },
    );
  }

  if (url.pathname === "/sitemap.xml") {
    return new Response(
      `<?xml version="1.0" encoding="UTF-8"?>
<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
  <url>
    <loc>https://freegenvless.shop/</loc>
    <changefreq>daily</changefreq>
    <priority>1.0</priority>
  </url>
</urlset>`,
      {
        headers: {
          "Content-Type": "application/xml; charset=utf-8",
          ...securityHeaders,
        },
      },
    );
  }

  if (url.pathname === "/api/generate") {
    const response = await handleGenerate(req);
    for (const [key, value] of Object.entries(securityHeaders)) {
      if (!response.headers.has(key)) response.headers.set(key, value);
    }
    return response;
  }

  if (url.pathname === "/api/check") {
    const response = await handleCheckRemaining(req);
    for (const [key, value] of Object.entries(securityHeaders)) {
      if (!response.headers.has(key)) response.headers.set(key, value);
    }
    return response;
  }

  if (url.pathname === "/api/debug") {
    return await handleDebug(req);
  }

  if (req.method !== "GET" && req.method !== "HEAD") {
    return new Response("Method not allowed", { status: 405, headers: securityHeaders });
  }

  if (url.pathname !== "/" && url.pathname !== "/index.html") {
    return new Response("Not found", { status: 404, headers: securityHeaders });
  }

  return new Response(getHTML(), {
    headers: {
      "Content-Type": "text/html; charset=utf-8",
      "Cache-Control": "no-store, no-cache, must-revalidate, private",
      ...securityHeaders
    }
  });
});
