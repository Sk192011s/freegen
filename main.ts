// main.ts - Deno Deploy Entry Point (Patgaduu Secure V4.1 - Ultimate Performance)
// Added: Web Worker PoW, Profile Icon Env, Config Caching, Native Animations

const kv = await Deno.openKv();

// ============== CONFIGURATION CACHE ==============
// Read config ONCE at startup to save CPU on every request
const SYSTEM_CONFIG = (() => {
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
  
  // Profile Image URL from Env (Default to generated avatar if empty)
  const profileImg = Deno.env.get("USER_PROFILE_IMG") || "https://ui-avatars.com/api/?name=Admin&background=6366f1&color=fff&rounded=true";

  return { keys, validFrom, validUntil, validityText, maxPerPeriod, keyVersion, tzOffset, adminTgLink, adminTgHandle, adminNotice, profileImg };
})();

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
  return { challenge, difficulty: 4 }; // 4 zeros difficulty
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

function isWithinValidPeriod(): boolean {
  const now = Date.now();
  const fromLocal = new Date(SYSTEM_CONFIG.validFrom + "T00:00:00");
  const untilLocal = new Date(SYSTEM_CONFIG.validUntil + "T23:59:59");
  const fromUTC = fromLocal.getTime() - (SYSTEM_CONFIG.tzOffset * 60 * 1000);
  const untilUTC = untilLocal.getTime() - (SYSTEM_CONFIG.tzOffset * 60 * 1000);
  return now >= fromUTC && now <= untilUTC;
}

function getValidUntilUTC(): number {
  const untilLocal = new Date(SYSTEM_CONFIG.validUntil + "T23:59:59");
  return untilLocal.getTime() - (SYSTEM_CONFIG.tzOffset * 60 * 1000);
}

async function checkRateLimit(fingerprint: string): Promise<{ allowed: boolean; remaining: number; message: string }> {
  if (!isWithinValidPeriod()) {
    return { allowed: false, remaining: 0, message: "လက်ရှိ Key သက်တမ်း ကုန်ဆုံးနေပါသည်။ Key အသစ်ထွက်လာရင် ပြန်လာပါ။" };
  }

  const periodKey = `${SYSTEM_CONFIG.keyVersion}_${SYSTEM_CONFIG.validFrom}_${SYSTEM_CONFIG.validUntil}`;
  const kvKey = ["rate_limit_period", fingerprint, periodKey];

  const entry = await kv.get<number>(kvKey);
  const count = entry.value || 0;

  if (count >= SYSTEM_CONFIG.maxPerPeriod) {
    return {
      allowed: false,
      remaining: 0,
      message: `ဤ Key သက်တမ်းအတွင်း Generate လုပ်ခွင့် (${SYSTEM_CONFIG.maxPerPeriod} ကြိမ်) ကုန်သွားပါပြီ။`
    };
  }

  return { allowed: true, remaining: SYSTEM_CONFIG.maxPerPeriod - count, message: "" };
}

// ============== ATOMIC INCREMENT (Concurrency handling) ==============

async function incrementAllAtomic(fingerprint: string, ipFingerprint: string): Promise<{ success: boolean; totalCount: number }> {
  const periodKey = `${SYSTEM_CONFIG.keyVersion}_${SYSTEM_CONFIG.validFrom}_${SYSTEM_CONFIG.validUntil}`;
  const fpKey =["rate_limit_period", fingerprint, periodKey];
  const ipKey =["rate_limit_period", ipFingerprint, periodKey];
  const totalKey = ["stats", "total_generates"];

  const untilUTC = getValidUntilUTC();
  const expireIn = Math.max(untilUTC - Date.now() + 86400000, 86400000);

  const maxRetries = 12; // increased retries for high concurrency
  for (let i = 0; i < maxRetries; i++) {
    const fpEntry = await kv.get<number>(fpKey);
    const ipEntry = await kv.get<number>(ipKey);
    const totalEntry = await kv.get<number>(totalKey);

    const fpCount = fpEntry.value || 0;
    const ipCount = ipEntry.value || 0;
    const totalCount = totalEntry.value || 0;

    if (fpCount >= SYSTEM_CONFIG.maxPerPeriod || ipCount >= SYSTEM_CONFIG.maxPerPeriod) {
      return { success: false, totalCount };
    }

    const result = await kv.atomic()
      .check(fpEntry).check(ipEntry).check(totalEntry)
      .set(fpKey, fpCount + 1, { expireIn })
      .set(ipKey, ipCount + 1, { expireIn })
      .set(totalKey, totalCount + 1)
      .commit();

    if (result.ok) return { success: true, totalCount: totalCount + 1 };

    // Optimized Jitter for High Traffic
    const delay = Math.min(30 * Math.pow(1.5, i), 800) + Math.random() * 30;
    await new Promise(resolve => setTimeout(resolve, delay));
  }
  return { success: false, totalCount: -1 };
}

// ============== BURST RATE LIMITING (Anti-Spam) ==============

async function checkBurstLimit(ip: string): Promise<boolean> {
  const minute = Math.floor(Date.now() / (1000 * 60));
  const burstKey =["burst_limit", ip, String(minute)];

  for (let i = 0; i < 3; i++) {
    const entry = await kv.get<number>(burstKey);
    const count = entry.value || 0;
    if (count >= 15) return false; // Max 15 req/min
    const result = await kv.atomic().check(entry).set(burstKey, count + 1, { expireIn: 120000 }).commit();
    if (result.ok) return true;
    await new Promise(resolve => setTimeout(resolve, 10 * i));
  }
  return true;
}

// ============== TOTAL GENERATE COUNTER ==============

async function getTotalCount(): Promise<number> {
  const entry = await kv.get<number>(["stats", "total_generates"]);
  return entry.value || 0;
}

// ============== KEY MANAGEMENT ==============

function getRandomKey(): { key: string } | null {
  if (SYSTEM_CONFIG.keys.length === 0) return null;
  const randomBytes = new Uint32Array(1);
  crypto.getRandomValues(randomBytes);
  const randomIndex = randomBytes[0] % SYSTEM_CONFIG.keys.length;
  return { key: SYSTEM_CONFIG.keys[randomIndex] };
}

// ============== ENCRYPTION ==============

async function encryptPayload(plaintext: string): Promise<string> {
  const key = await crypto.subtle.generateKey({ name: "AES-GCM", length: 256 }, true, ["encrypt", "decrypt"]);
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const encoded = new TextEncoder().encode(plaintext);
  const ciphertext = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, key, encoded);
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
      "Cache-Control": "no-store, no-cache, must-revalidate",
      "Pragma": "no-cache",
      "Expires": "0",
      ...extraHeaders,
    }
  });
}

function getClientIP(req: Request): string {
  const fwIP = req.headers.get("x-forwarded-for")?.split(",")[0]?.trim();
  if (fwIP && fwIP.length > 5 && !fwIP.includes("127.0.0.1")) return fwIP;
  return req.headers.get("cf-connecting-ip") || req.headers.get("x-real-ip") || "unknown";
}

// ============== REQUEST VALIDATION ==============

function validateRequest(req: Request): { valid: boolean; error?: string } {
  const ua = req.headers.get("user-agent") || "";
  if (!ua || ua.length < 10) return { valid: false, error: "Invalid request" };

  const botPatterns =[/curl/i, /wget/i, /python/i, /httpie/i, /postman/i, /axios/i, /go-http/i, /headless/i, /puppeteer/i];
  for (const pattern of botPatterns) {
    if (pattern.test(ua)) return { valid: false, error: "Blocked" };
  }
  return { valid: true };
}

// ============== API HANDLERS ==============

async function handleGenerate(req: Request): Promise<Response> {
  if (req.method !== "POST") return jsonResponse({ error: "Method not allowed" }, 405);

  const origin = req.headers.get("origin") || "";
  const host = req.headers.get("host") || "";
  if (origin && !origin.includes(host)) {
    return jsonResponse({ success: false, error: "forbidden", message: "ခွင့်မပြုပါ။" }, 403);
  }

  if (!validateRequest(req).valid) return jsonResponse({ success: false, error: "invalid_request", message: "ခွင့်မပြုပါ။" }, 403);

  const ip = getClientIP(req);
  const userAgent = req.headers.get("user-agent") || "unknown";

  if (!(await checkBurstLimit(ip))) {
    return jsonResponse({ success: false, error: "rate_limited", message: "တောင်းဆိုမှု များလွန်းနေပါသည်။ ခဏစောင့်ပါ။" }, 429);
  }

  let body: Record<string, unknown>;
  try {
    body = await req.json();
    if (body.website || body.email) { // Honeypot
      return jsonResponse({ success: true, payload: btoa("bot-" + Math.random()), remaining: 0 });
    }
    if (!body.csrf_token || !(await validateCSRFToken(body.csrf_token as string, ip))) {
      return jsonResponse({ success: false, error: "invalid_token", message: "Session ကုန်သွားပါပြီ။ Refresh လုပ်ပါ။" }, 403);
    }
    if (!body.pow_challenge || !body.pow_nonce || !(await verifyPoW(ip, body.pow_challenge as string, body.pow_nonce as string))) {
      return jsonResponse({ success: false, error: "pow_invalid", message: "Security Check မအောင်မြင်ပါ။ Refresh လုပ်ပါ။" }, 403);
    }
    if (body.t && Math.abs(Date.now() - (body.t as number)) > 300000) {
      return jsonResponse({ success: false, error: "stale_request", message: "Session ကုန်သွားပါပြီ။ Refresh လုပ်ပါ။" }, 403);
    }
  } catch {
    return jsonResponse({ success: false, error: "invalid_body", message: "ခွင့်မပြုပါ။" }, 400);
  }

  if (!isWithinValidPeriod()) {
    return jsonResponse({ success: false, error: "expired", message: "Key သက်တမ်း ကုန်ဆုံးနေပါသည်။" }, 403);
  }

  const fingerprint = await generateServerFingerprint(ip, userAgent);
  const ipFingerprint = await hashSHA256(`ip-only-${ip}-patgaduu-salt`);

  const fpCheck = await checkRateLimit(fingerprint);
  const ipCheck = await checkRateLimit(ipFingerprint);

  if (!fpCheck.allowed || !ipCheck.allowed) {
    return jsonResponse({ success: false, error: "limit_reached", message: !fpCheck.allowed ? fpCheck.message : ipCheck.message, remaining: 0 }, 429);
  }

  const result = getRandomKey();
  if (!result) return jsonResponse({ success: false, error: "no_keys", message: "Key မရှိပါ။" }, 503);

  const incrementResult = await incrementAllAtomic(fingerprint, ipFingerprint);
  if (!incrementResult.success) {
    return jsonResponse({ success: false, error: "server_busy", message: "Server အလုပ်များနေပါသည်။ ခဏစောင့်၍ ထပ်ကြိုးစားပါ။" }, 503);
  }

  const remaining = Math.min(fpCheck.remaining, ipCheck.remaining) - 1;
  const encryptedPayload = await encryptPayload(JSON.stringify({
    key: result.key,
    validityText: SYSTEM_CONFIG.validityText,
    remaining,
    totalGenerated: incrementResult.totalCount,
    ts: Date.now(),
    nonce: crypto.randomUUID()
  }));

  return jsonResponse({ success: true, payload: encryptedPayload, remaining });
}

async function handleCheckRemaining(req: Request): Promise<Response> {
  if (req.method !== "POST") return jsonResponse({ error: "Method not allowed" }, 405);

  const ip = getClientIP(req);
  const fingerprint = await generateServerFingerprint(ip, req.headers.get("user-agent") || "unknown");
  const ipFingerprint = await hashSHA256(`ip-only-${ip}-patgaduu-salt`);
  const withinPeriod = isWithinValidPeriod();

  let remaining = 0; let allowed = false;
  if (withinPeriod) {
    const fpCheck = await checkRateLimit(fingerprint);
    const ipCheck = await checkRateLimit(ipFingerprint);
    remaining = Math.min(fpCheck.remaining, ipCheck.remaining);
    allowed = fpCheck.allowed && ipCheck.allowed;
  }

  const csrfToken = await generateCSRFToken(ip);
  const totalGenerated = await getTotalCount();
  const { challenge, difficulty } = await generateChallenge(ip);

  return jsonResponse({
    remaining, allowed, maxPerPeriod: SYSTEM_CONFIG.maxPerPeriod,
    validityText: SYSTEM_CONFIG.validityText, withinPeriod,
    keyVersion: SYSTEM_CONFIG.keyVersion, totalGenerated,
    csrf_token: csrfToken, pow_challenge: challenge, pow_difficulty: difficulty,
    adminTgLink: SYSTEM_CONFIG.adminTgLink, adminTgHandle: SYSTEM_CONFIG.adminTgHandle,
    adminNotice: SYSTEM_CONFIG.adminNotice
  });
}

// ============== HTML PAGE ==============

function getHTML(): string {
  const noticeHTML = SYSTEM_CONFIG.adminNotice ? `
    <div class="admin-notice-slider animate-fade-down" id="adminNoticeSlider">
      <div class="notice-icon">
        <svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/></svg>
      </div>
      <div class="notice-marquee">
        <span class="notice-text">${SYSTEM_CONFIG.adminNotice.replace(/</g, '&lt;').replace(/>/g, '&gt;')}</span>
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
  <link href="https://fonts.googleapis.com/css2?family=Padauk:wght@400;700&family=Inter:wght@400;600;700&family=JetBrains+Mono:wght@400&display=swap" rel="stylesheet">

  <style>
    :root {
      --primary: #6366f1; --primary-dark: #4f46e5;
      --accent: #f59e0b; --accent-light: #d97706;
      --bg-main: #f8fafc; --bg-card: #ffffff; --bg-card-alt: #f1f5f9;
      --glass: rgba(255,255,255,0.85); --glass-border: rgba(0,0,0,0.08);
      --text: #1e293b; --text-dim: #475569; --text-muted: #94a3b8;
      --success: #10b981; --danger: #ef4444; --cyan: #0891b2; --purple: #7c3aed;
      --shadow-sm: 0 1px 3px rgba(0,0,0,0.06);
      --shadow-md: 0 4px 6px rgba(0,0,0,0.05);
      --shadow-lg: 0 10px 25px rgba(0,0,0,0.08);
      --shadow-xl: 0 20px 50px rgba(0,0,0,0.1);
      --radius-sm: 8px; --radius-md: 14px; --radius-lg: 20px; --radius-xl: 24px;
    }

    * { margin: 0; padding: 0; box-sizing: border-box; }
    body { font-family: 'Padauk', 'Inter', sans-serif; background: var(--bg-main); color: var(--text); min-height: 100vh; overflow-x: hidden; }

    /* Custom Native Animations (Replaces heavy AOS library) */
    .animate-fade-down { animation: fadeDown 0.6s ease-out forwards; }
    .animate-fade-up { animation: fadeUp 0.6s ease-out forwards; opacity: 0; }
    .delay-1 { animation-delay: 0.1s; }
    .delay-2 { animation-delay: 0.2s; }
    .delay-3 { animation-delay: 0.3s; }

    @keyframes fadeDown { from { opacity: 0; transform: translateY(-15px); } to { opacity: 1; transform: translateY(0); } }
    @keyframes fadeUp { from { opacity: 0; transform: translateY(20px); } to { opacity: 1; transform: translateY(0); } }

    .bg-decoration { position: fixed; top: 0; left: 0; width: 100%; height: 100%; z-index: 0; overflow: hidden; pointer-events: none; }
    .bg-decoration .shape { position: absolute; border-radius: 50%; opacity: 0.4; filter: blur(80px); }
    .bg-decoration .shape:nth-child(1) { width: 500px; height: 500px; background: linear-gradient(135deg, rgba(99,102,241,0.15), rgba(139,92,246,0.1)); top: -200px; left: -100px; }
    .bg-decoration .shape:nth-child(2) { width: 400px; height: 400px; background: linear-gradient(135deg, rgba(6,182,212,0.1), rgba(59,130,246,0.08)); bottom: -150px; right: -100px; }

    .container { position: relative; z-index: 1; max-width: 520px; margin: 0 auto; padding: 16px 14px; display: flex; flex-direction: column; }

    /* Admin Notice */
    .admin-notice-slider { display: flex; align-items: center; gap: 10px; padding: 10px 14px; background: linear-gradient(135deg, #fef3c7, #fde68a); border: 1px solid #fbbf24; border-radius: var(--radius-md); margin-bottom: 14px; overflow: hidden; position: relative; box-shadow: var(--shadow-sm); }
    .notice-icon { flex-shrink: 0; color: #b45309; }
    .notice-marquee { flex: 1; overflow: hidden; white-space: nowrap; mask-image: linear-gradient(90deg, transparent, black 10%, black 90%, transparent); -webkit-mask-image: linear-gradient(90deg, transparent, black 10%, black 90%, transparent); }
    .notice-text { display: inline-block; animation: marquee 15s linear infinite; font-size: 13px; font-weight: 600; color: #92400e; padding-left: 100%; }
    @keyframes marquee { 0% { transform: translateX(0); } 100% { transform: translateX(-100%); } }
    .notice-close { background: none; border: none; font-size: 20px; color: #b45309; cursor: pointer; opacity: 0.7; }

    /* Header & Profile Icon */
    .header { display: flex; align-items: center; justify-content: space-between; padding: 14px 18px; background: var(--glass); backdrop-filter: blur(20px); border: 1px solid var(--glass-border); border-radius: var(--radius-lg); margin-bottom: 16px; box-shadow: var(--shadow-md); }
    .header-brand { display: flex; align-items: center; gap: 10px; }
    .logo-icon { width: 38px; height: 38px; background: linear-gradient(135deg, var(--primary), var(--purple)); border-radius: var(--radius-sm); display: flex; align-items: center; justify-content: center; box-shadow: 0 4px 15px rgba(99,102,241,0.3); }
    .logo-icon svg { color: white; width: 20px; height: 20px; }
    .header-brand h1 { font-size: 17px; font-weight: 700; color: var(--primary-dark); }
    .header-brand span { font-size: 10px; color: var(--text-muted); display: block; margin-top: -1px; text-transform: uppercase; }
    
    .header-right { display: flex; align-items: center; gap: 8px; }
    .tg-btn { display: flex; align-items: center; gap: 5px; padding: 6px 12px; background: rgba(6, 182, 212, 0.08); border: 1px solid rgba(6, 182, 212, 0.25); border-radius: var(--radius-sm); color: var(--cyan); font-size: 11px; font-weight: 600; text-decoration: none; }
    .header-badge { padding: 5px 10px; background: linear-gradient(135deg, var(--primary), var(--purple)); border-radius: 20px; font-size: 10px; font-weight: 700; color: white; }
    
    /* User Profile Icon Styling */
    .profile-icon {
      width: 32px; 
      height: 32px; 
      border-radius: var(--radius-sm); /* လေးဒေါင့်ဝိုက် (Rounded Square) */
      object-fit: cover;
      border: 2px solid rgba(99,102,241,0.2);
      box-shadow: var(--shadow-sm);
      background: var(--bg-card-alt);
    }

    .validity-notice { margin-bottom: 16px; padding: 14px 16px; background: linear-gradient(135deg, rgba(6,182,212,0.04), rgba(99,102,241,0.04)); border: 1px solid rgba(6,182,212,0.2); border-radius: var(--radius-md); display: flex; align-items: center; gap: 12px; }
    .validity-notice .vn-icon { width: 40px; height: 40px; background: rgba(6,182,212,0.1); border-radius: var(--radius-sm); display: flex; align-items: center; justify-content: center; flex-shrink: 0; }
    .validity-notice .vn-icon svg { width: 20px; height: 20px; color: var(--cyan); }
    .validity-notice .vn-text { font-size: 12.5px; color: var(--text-dim); }
    .validity-notice .vn-text strong { color: var(--cyan); font-weight: 700; display: block; font-size: 13px; }
    .validity-expired { border-color: rgba(239,68,68,0.25) !important; background: linear-gradient(135deg, rgba(239,68,68,0.04), rgba(239,68,68,0.02)) !important; }
    .validity-expired .vn-icon { background: rgba(239,68,68,0.1) !important; }
    .validity-expired .vn-icon svg { color: var(--danger) !important; }
    .validity-expired .vn-text strong { color: var(--danger) !important; }

    /* Stats Bar */
    .stats-bar { display: flex; gap: 10px; margin-bottom: 16px; overflow-x: auto; scrollbar-width: none; }
    .stat-card { flex: 1; min-width: 0; background: var(--bg-card); border: 1px solid var(--glass-border); border-radius: var(--radius-md); padding: 14px 12px; text-align: center; position: relative; box-shadow: var(--shadow-sm); }
    .stat-card::before { content: ''; position: absolute; top: 0; left: 0; width: 100%; height: 3px; border-radius: 3px 3px 0 0; }
    .stat-card:nth-child(1)::before { background: linear-gradient(90deg, var(--primary), var(--purple)); }
    .stat-card:nth-child(2)::before { background: linear-gradient(90deg, var(--cyan), #3b82f6); }
    .stat-card:nth-child(3)::before { background: linear-gradient(90deg, var(--accent), #f97316); }
    .stat-card:nth-child(4)::before { background: linear-gradient(90deg, var(--success), var(--cyan)); }
    .stat-card .stat-icon { width: 32px; height: 32px; margin: 0 auto 6px; border-radius: 8px; display: flex; align-items: center; justify-content: center; }
    .stat-card .stat-icon svg { width: 16px; height: 16px; }
    .stat-card:nth-child(1) .stat-icon { background: rgba(99,102,241,0.1); color: var(--primary); }
    .stat-card:nth-child(2) .stat-icon { background: rgba(6,182,212,0.1); color: var(--cyan); }
    .stat-card:nth-child(3) .stat-icon { background: rgba(245,158,11,0.1); color: var(--accent-light); }
    .stat-card:nth-child(4) .stat-icon { background: rgba(16,185,129,0.1); color: var(--success); }
    .stat-card .stat-value { font-size: 16px; font-weight: 700; color: var(--text); }
    .stat-card .stat-label { font-size: 10px; color: var(--text-muted); margin-top: 2px; }

    /* Main Card */
    .main-card { background: var(--bg-card); border: 1px solid var(--glass-border); border-radius: var(--radius-xl); padding: 28px 20px; box-shadow: var(--shadow-lg); }
    .card-header { text-align: center; margin-bottom: 24px; }
    .card-header .icon-wrapper { width: 68px; height: 68px; margin: 0 auto 14px; border-radius: 18px; background: linear-gradient(135deg, var(--primary), var(--purple)); display: flex; align-items: center; justify-content: center; box-shadow: 0 8px 30px rgba(99,102,241,0.3); animation: iconPulse 3s ease-in-out infinite; }
    @keyframes iconPulse { 0%, 100% { transform: translateY(0) scale(1); } 50% { transform: translateY(-4px) scale(1.02); } }
    .card-header .icon-wrapper svg { color: white; width: 30px; height: 30px; }
    .card-header h2 { font-size: 20px; font-weight: 700; color: var(--text); margin-bottom: 4px; }
    .card-header p { font-size: 13px; color: var(--text-dim); }

    .compat-notice { margin-bottom: 18px; padding: 14px 16px; background: rgba(99, 102, 241, 0.03); border: 1px solid rgba(99, 102, 241, 0.12); border-radius: var(--radius-md); }
    .compat-notice .compat-title { font-size: 12px; font-weight: 700; color: var(--primary); margin-bottom: 8px; display: flex; align-items: center; gap: 6px; }
    .compat-apps { display: flex; flex-wrap: wrap; gap: 5px; margin-bottom: 10px; }
    .compat-app { padding: 3px 10px; background: rgba(16, 185, 129, 0.06); border: 1px solid rgba(16, 185, 129, 0.2); border-radius: 6px; font-size: 11px; color: var(--success); font-weight: 600; }
    .compat-warning { display: flex; align-items: center; gap: 6px; padding: 8px 12px; background: rgba(239, 68, 68, 0.04); border: 1px solid rgba(239, 68, 68, 0.15); border-radius: 8px; font-size: 11px; color: var(--danger); margin-top: 8px; }

    .generate-btn { width: 100%; padding: 15px; border: none; border-radius: var(--radius-md); background: linear-gradient(135deg, var(--primary), var(--purple)); color: white; font-size: 16px; font-weight: 700; cursor: pointer; display: flex; align-items: center; justify-content: center; gap: 10px; box-shadow: 0 4px 15px rgba(99,102,241,0.3); transition: transform 0.2s; }
    .generate-btn:active { transform: translateY(2px); }
    .generate-btn:disabled { opacity: 0.6; cursor: not-allowed; transform: none; box-shadow: none; }
    .spinner { width: 20px; height: 20px; border: 2px solid rgba(255,255,255,0.3); border-top: 2px solid white; border-radius: 50%; animation: spin 0.8s linear infinite; display: none; }
    @keyframes spin { to { transform: rotate(360deg); } }

    .error-msg { margin-top: 14px; padding: 13px 16px; background: rgba(239,68,68,0.04); border: 1px solid rgba(239,68,68,0.2); border-radius: var(--radius-md); color: var(--danger); font-size: 13px; display: none; align-items: center; gap: 8px; }
    .error-msg.show { display: flex; animation: fadeUp 0.3s ease; }

    .result-area { margin-top: 20px; display: none; }
    .result-area.show { display: block; animation: fadeUp 0.5s ease; }
    .result-box { background: var(--bg-card-alt); border: 1px solid rgba(16,185,129,0.2); border-radius: var(--radius-md); padding: 18px; position: relative; }
    .result-box::before { content: ''; position: absolute; top: 0; left: 0; width: 100%; height: 3px; background: linear-gradient(90deg, var(--success), var(--cyan)); border-radius: 3px 3px 0 0; }
    .result-label { display: flex; align-items: center; gap: 8px; margin-bottom: 12px; font-size: 12px; color: var(--success); font-weight: 600; }
    .result-key { background: white; border: 1px solid var(--glass-border); border-radius: var(--radius-sm); padding: 14px; font-family: 'JetBrains Mono', monospace; font-size: 10.5px; color: var(--primary-dark); word-break: break-all; max-height: 110px; overflow-y: auto; user-select: all; }
    .result-meta { display: flex; align-items: center; justify-content: space-between; margin-top: 14px; padding-top: 14px; border-top: 1px solid var(--glass-border); flex-wrap: wrap; gap: 10px; }
    .expire-info { display: flex; align-items: center; gap: 6px; font-size: 11.5px; color: var(--cyan); }
    .action-buttons { display: flex; gap: 8px; }
    .copy-btn, .qr-btn { display: flex; align-items: center; gap: 5px; padding: 7px 14px; border: 1px solid rgba(99,102,241,0.25); border-radius: var(--radius-sm); background: rgba(99,102,241,0.06); color: var(--primary); font-size: 12px; font-weight: 600; cursor: pointer; }

    /* Modals & Overlays */
    .qr-modal, .success-overlay { position: fixed; top: 0; left: 0; width: 100%; height: 100%; z-index: 150; display: none; align-items: center; justify-content: center; background: rgba(0,0,0,0.4); backdrop-filter: blur(8px); }
    .qr-modal.show, .success-overlay.show { display: flex; animation: fadeIn 0.3s ease; }
    @keyframes fadeIn { from { opacity: 0; } to { opacity: 1; } }
    .qr-modal-content, .success-popup { background: var(--bg-card); border-radius: var(--radius-xl); padding: 28px; text-align: center; max-width: 300px; width: 90%; box-shadow: var(--shadow-xl); animation: fadeUp 0.3s ease; }
    .qr-code-container { background: white; border-radius: var(--radius-md); padding: 16px; display: inline-block; margin-bottom: 16px; border: 1px solid var(--glass-border); }
    .qr-close-btn { padding: 10px 28px; background: var(--bg-card-alt); border: 1px solid var(--glass-border); border-radius: var(--radius-sm); cursor: pointer; }
    .success-popup .check-circle { width: 56px; height: 56px; background: rgba(16,185,129,0.1); border-radius: 50%; display: flex; align-items: center; justify-content: center; margin: 0 auto 14px; color: var(--success); }

    .toast { position: fixed; bottom: 30px; left: 50%; transform: translateX(-50%) translateY(100px); background: linear-gradient(135deg, var(--success), #059669); color: white; padding: 11px 22px; border-radius: var(--radius-sm); font-size: 13px; font-weight: 600; z-index: 200; transition: transform 0.3s cubic-bezier(0.68, -0.55, 0.265, 1.55); display: flex; align-items: center; gap: 8px; }
    .toast.show { transform: translateX(-50%) translateY(0); }

    /* Extras */
    .howto-section { margin-top: 18px; padding: 14px 16px; background: var(--bg-card-alt); border-radius: var(--radius-md); }
    .info-bars { display: flex; flex-direction: column; gap: 8px; margin-top: 18px; }
    .info-bar { padding: 13px 16px; background: var(--bg-card-alt); border: 1px solid var(--glass-border); border-radius: var(--radius-md); display: flex; justify-content: space-between; align-items: center; font-size: 12.5px; }
    .info-bar .count { font-size: 16px; font-weight: 700; color: var(--primary); }
    
    .hp-field { position: absolute; left: -9999px; opacity: 0; pointer-events: none; }
  </style>
</head>
<body>

  <div class="bg-decoration">
    <div class="shape"></div><div class="shape"></div>
  </div>

  <div class="container">
    ${noticeHTML}

    <div class="header animate-fade-down delay-1">
      <div class="header-brand">
        <div class="logo-icon"><svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polygon points="13 2 3 14 12 14 11 22 21 10 12 10 13 2"/></svg></div>
        <div><h1>Patgaduu VPN</h1><span>VLESS Key Generator</span></div>
      </div>
      <div class="header-right">
        <a href="${SYSTEM_CONFIG.adminTgLink}" target="_blank" class="tg-btn"><svg xmlns="http://www.w3.org/2000/svg" width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><line x1="22" y1="2" x2="11" y2="13"/><polygon points="22 2 15 22 11 13 2 9 22 2"/></svg> TG</a>
        <div class="header-badge">PRO</div>
        <!-- USER PROFILE ICON ADDED HERE -->
        <img src="${SYSTEM_CONFIG.profileImg}" alt="Profile" class="profile-icon" id="userProfileIcon" onerror="this.src='https://ui-avatars.com/api/?name=User&background=6366f1&color=fff&rounded=true'">
      </div>
    </div>

    <div class="validity-notice animate-fade-up delay-1" id="validityNotice">
      <div class="vn-icon"><svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="3" y="4" width="18" height="18" rx="2" ry="2"/><line x1="16" y1="2" x2="16" y2="6"/><line x1="8" y1="2" x2="8" y2="6"/><line x1="3" y1="10" x2="21" y2="10"/><path d="m9 16 2 2 4-4"/></svg></div>
      <div class="vn-text"><strong id="validityText">Loading...</strong><span id="validityStatus">Key သက်တမ်း စစ်ဆေးနေပါသည်...</span></div>
    </div>

    <div class="stats-bar animate-fade-up delay-2">
      <div class="stat-card"><div class="stat-value" id="statRemaining">-</div><div class="stat-label">ကျန်ရှိ</div></div>
      <div class="stat-card"><div class="stat-value" id="statMaxPeriod">-</div><div class="stat-label">ခွင့်ပြု</div></div>
      <div class="stat-card"><div class="stat-value" id="statTotal">-</div><div class="stat-label">စုစုပေါင်း</div></div>
      <div class="stat-card"><div class="stat-value" id="statStatus">-</div><div class="stat-label">Status</div></div>
    </div>

    <div class="main-card animate-fade-up delay-3">
      <div class="card-header">
        <div class="icon-wrapper"><svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="m15.5 7.5 2.3 2.3a1 1 0 0 0 1.4 0l2.1-2.1a1 1 0 0 0 0-1.4L19 4"/><path d="m21 2-9.6 9.6"/><circle cx="7.5" cy="15.5" r="5.5"/></svg></div>
        <h2>VLESS Key ရယူမည်</h2>
        <p>Generate ကိုနှိပ်၍ Key အသစ် ရယူပါ</p>
      </div>

      <div class="compat-notice">
        <div class="compat-title">အသုံးပြုနိုင်သော Apps များ</div>
        <div class="compat-apps"><span class="compat-app">V2rayNG</span><span class="compat-app">V2Box</span><span class="compat-app">Nekoray</span></div>
        <div class="compat-warning"><strong>Hiddify App တွင် သုံး၍ မရနိုင်ပါ။</strong> V2rayNG (သို့) V2Box ကို အသုံးပြုပါ။</div>
      </div>

      <div class="hp-field"><input type="text" id="hpWebsite"><input type="text" id="hpEmail"></div>

      <button class="generate-btn" id="generateBtn" onclick="handleGenerate()">
        <span id="btnText">Generate Key</span>
        <div class="spinner" id="spinner"></div>
      </button>

      <div class="error-msg" id="errorMsg"><span id="errorText"></span></div>

      <div class="result-area" id="resultArea">
        <div class="result-box">
          <div class="result-label">VLESS Key Generated Successfully</div>
          <div class="result-key" id="resultKey"></div>
          <div class="result-meta">
            <div class="expire-info"><span id="expireText"></span></div>
            <div class="action-buttons">
              <button class="copy-btn" onclick="copyKey()">Copy</button>
              <button class="qr-btn" onclick="showQR()">QR</button>
            </div>
          </div>
        </div>
      </div>

      <div class="info-bars">
        <div class="info-bar"><span>ဤသက်တမ်းအတွင်း ကျန်ရှိအကြိမ်</span><span class="count" id="remainingCount">-</span></div>
        <div class="info-bar"><span>စုစုပေါင်း Generate (All Users)</span><span class="count" id="totalCount">-</span></div>
      </div>
    </div>
  </div>

  <div class="success-overlay" id="successOverlay">
    <div class="success-popup"><div class="check-circle"><svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="3" width="28" height="28"><polyline points="20 6 9 17 4 12"/></svg></div><h3>အောင်မြင်ပါသည်!</h3><p>Key ကို Copy ယူ၍ အသုံးပြုပါ</p></div>
  </div>

  <div class="qr-modal" id="qrModal">
    <div class="qr-modal-content"><h3>QR Code Scan ဖတ်ပါ</h3><div class="qr-code-container" id="qrCodeContainer"></div><button class="qr-close-btn" onclick="closeQR()">ပိတ်မည်</button></div>
  </div>
  <div class="toast" id="toast"><span>Copy ကူးယူပြီးပါပြီ!</span></div>

<script src="https://unpkg.com/qrcode-generator@1.4.4/qrcode.js"></script>
<script>
  let csrfToken = '', currentKey = '', powChallenge = '', powDifficulty = 4, powNonce = '', powReady = false, isGenerating = false;

  // ============== WEB WORKER PROOF-OF-WORK (NO UI FREEZE) ==============
  const workerCode = \`
    self.onmessage = async function(e) {
      const { challenge, difficulty } = e.data;
      const prefix = "0".repeat(difficulty);
      let nonce = 0;
      const batchSize = 5000;
      const encoder = new TextEncoder();

      async function solve() {
        while (true) {
          for (let i = 0; i < batchSize; i++) {
            const currentNonce = nonce + i;
            const data = challenge + "||" + currentNonce;
            const buffer = encoder.encode(data);
            const hashBuffer = await crypto.subtle.digest("SHA-256", buffer);
            const hashArray = Array.from(new Uint8Array(hashBuffer));
            const hex = hashArray.map(b => b.toString(16).padStart(2, "0")).join("");
            if (hex.startsWith(prefix)) {
              self.postMessage(currentNonce);
              return;
            }
          }
          nonce += batchSize;
          if (nonce > 5000000) { self.postMessage(null); return; } // Timeout safety
        }
      }
      solve();
    };
  \`;
  const blob = new Blob([workerCode], { type: "application/javascript" });
  const powWorker = new Worker(URL.createObjectURL(blob));

  powWorker.onmessage = function(e) {
    if (e.data !== null) {
      powNonce = e.data;
      powReady = true;
    }
  };

  document.addEventListener('DOMContentLoaded', checkRemaining);

  function checkRemaining() {
    fetch('/api/check', { method: 'POST', body: '{}' })
    .then(res => res.json())
    .then(data => {
      csrfToken = data.csrf_token || '';
      powChallenge = data.pow_challenge || '';
      powDifficulty = data.pow_difficulty || 4;

      if (powChallenge) {
        powReady = false;
        powWorker.postMessage({ challenge: powChallenge, difficulty: powDifficulty }); // Start Background Calculation
      }

      document.getElementById('validityText').textContent = data.validityText || 'N/A';
      document.getElementById('statRemaining').textContent = data.remaining + '/' + data.maxPerPeriod;
      document.getElementById('statMaxPeriod').textContent = data.maxPerPeriod;
      document.getElementById('statTotal').textContent = data.totalGenerated || 0;
      document.getElementById('remainingCount').textContent = data.remaining + ' ကြိမ်';
      document.getElementById('totalCount').textContent = (data.totalGenerated || 0) + ' ကြိမ်';

      const btn = document.getElementById('generateBtn');
      const btnText = document.getElementById('btnText');
      if (!data.allowed) {
        btn.disabled = true;
        btnText.textContent = data.withinPeriod ? 'Generate ခွင့် ကုန်သွားပါပြီ' : 'Key သက်တမ်း ကုန်နေပါသည်';
      } else {
        btn.disabled = false;
        btnText.textContent = 'Generate Key';
      }
    });
  }

  function handleGenerate() {
    if (isGenerating) return;
    if (!powReady) {
      document.getElementById('errorText').textContent = 'Security Check လုပ်နေဆဲပါ။ ခဏစောင့်ပါ။';
      document.getElementById('errorMsg').classList.add('show');
      setTimeout(() => document.getElementById('errorMsg').classList.remove('show'), 3000);
      return;
    }

    isGenerating = true;
    const btn = document.getElementById('generateBtn');
    const spinner = document.getElementById('spinner');
    
    document.getElementById('errorMsg').classList.remove('show');
    document.getElementById('resultArea').classList.remove('show');
    btn.disabled = true; spinner.style.display = 'block'; document.getElementById('btnText').textContent = '';

    fetch('/api/generate', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        csrf_token: csrfToken, pow_challenge: powChallenge, pow_nonce: powNonce,
        website: document.getElementById('hpWebsite').value, email: document.getElementById('hpEmail').value, t: Date.now()
      })
    }).then(res => res.json()).then(data => {
      if (!data.success) {
        document.getElementById('errorText').textContent = data.message;
        document.getElementById('errorMsg').classList.add('show');
        checkRemaining();
      } else {
        // Decrypt Payload
        const binaryStr = atob(data.payload);
        const bytes = new Uint8Array(binaryStr.length);
        for (let i = 0; i < binaryStr.length; i++) bytes[i] = binaryStr.charCodeAt(i);
        const keyData = bytes.slice(0, 32); const iv = bytes.slice(32, 44); const ciphertext = bytes.slice(44);
        
        crypto.subtle.importKey('raw', keyData, { name: 'AES-GCM' }, false, ['decrypt'])
          .then(key => crypto.subtle.decrypt({ name: 'AES-GCM', iv }, key, ciphertext))
          .then(dec => {
            const parsed = JSON.parse(new TextDecoder().decode(dec));
            currentKey = parsed.key;
            document.getElementById('resultKey').textContent = currentKey;
            document.getElementById('expireText').textContent = 'သက်တမ်း: ' + parsed.validityText;
            document.getElementById('resultArea').classList.add('show');
            document.getElementById('successOverlay').classList.add('show');
            setTimeout(() => document.getElementById('successOverlay').classList.remove('show'), 2000);
            checkRemaining();
          });
      }
    }).finally(() => {
      spinner.style.display = 'none'; document.getElementById('btnText').textContent = 'Generate Key';
      btn.disabled = false; isGenerating = false;
    });
  }

  function copyKey() {
    navigator.clipboard.writeText(currentKey).then(() => {
      document.getElementById('toast').classList.add('show');
      setTimeout(() => document.getElementById('toast').classList.remove('show'), 2500);
    });
  }

  function showQR() {
    const container = document.getElementById('qrCodeContainer');
    container.innerHTML = '';
    const qr = qrcode(0, 'L'); qr.addData(currentKey); qr.make();
    container.innerHTML = qr.createImgTag(Math.floor(200 / qr.getModuleCount()), 0);
    document.getElementById('qrModal').classList.add('show');
  }
  function closeQR() { document.getElementById('qrModal').classList.remove('show'); }
  function closeNotice() { document.getElementById('adminNoticeSlider').style.display = 'none'; }
</script>
</body>
</html>`;
}

// ============== ROUTER ==============

Deno.serve(async (req) => {
  const url = new URL(req.url);

  // Updated CSP to allow blob: for Web Workers securely
  const securityHeaders: Record<string, string> = {
    "X-Frame-Options": "DENY",
    "X-Content-Type-Options": "nosniff",
    "X-XSS-Protection": "1; mode=block",
    "Referrer-Policy": "no-referrer",
    "Permissions-Policy": "camera=(), microphone=(), geolocation=()",
    "Content-Security-Policy": "default-src 'self'; worker-src 'self' blob:; script-src 'self' 'unsafe-inline' https://unpkg.com blob:; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; font-src https://fonts.gstatic.com; img-src 'self' data: blob: https://ui-avatars.com https://*; connect-src 'self'; frame-ancestors 'none';",
  };

  if (url.pathname === "/api/generate") return await handleGenerate(req);
  if (url.pathname === "/api/check") return await handleCheckRemaining(req);
  
  if (req.method !== "GET" && req.method !== "HEAD") return new Response("Method not allowed", { status: 405 });
  if (url.pathname !== "/" && url.pathname !== "/index.html") return new Response("Not found", { status: 404 });

  return new Response(getHTML(), { headers: { "Content-Type": "text/html; charset=utf-8", "Cache-Control": "no-store", ...securityHeaders } });
});
