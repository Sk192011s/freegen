// main.ts - Deno Deploy Entry Point (Patgaduu Secure V4 - Light Theme)
// Fixed: Added User Profile, High Concurrency KV Sum, and UI/UX Enhancements

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
  
  // User Profile Name Config (Env Variable)
  const userProfile = Deno.env.get("USER_PROFILE") || "Patgaduu Admin";

  return { keys, validFrom, validUntil, validityText, maxPerPeriod, keyVersion, tzOffset, adminTgLink, adminTgHandle, adminNotice, userProfile };
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
  return hash.startsWith("0000");
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
      message: `ဤ Key သက်တမ်းအတွင်း Generate လုပ်ခွင့် (${config.maxPerPeriod} ကြိမ်) ကုန်သွားပါပြီ။`
    };
  }

  return { allowed: true, remaining: config.maxPerPeriod - count, message: "" };
}

// ============== ATOMIC INCREMENT (High Concurrency Ready) ==============

async function incrementAllAtomic(
  fingerprint: string,
  ipFingerprint: string,
  config: ReturnType<typeof getConfig>
): Promise<{ success: boolean; totalCount: number }> {
  const periodKey = `${config.keyVersion}_${config.validFrom}_${config.validUntil}`;
  const fpKey =["rate_limit_period", fingerprint, periodKey];
  const ipKey = ["rate_limit_period", ipFingerprint, periodKey];

  const untilUTC = getValidUntilUTC(config);
  const expireIn = Math.max(untilUTC - Date.now() + 86400000, 86400000);

  let allowed = false;
  const maxRetries = 5;

  // 1. Update ONLY User-Specific Limits Atomically (Reduces Lock Contention)
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

    // Exponential backoff
    const delay = Math.min(50 * Math.pow(2, i), 500) + Math.random() * 50;
    await new Promise(resolve => setTimeout(resolve, delay));
  }

  if (!allowed) return { success: false, totalCount: -1 };

  // 2. Increment Global Total using KV U64 Mutate Sum (Zero Contention / Thread Safe)
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
  // Support both legacy number and new U64 counter seamlessly
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

// ============== HELPERS & VALIDATION ==============

function jsonResponse(data: unknown, status = 200, extraHeaders: Record<string, string> = {}): Response {
  return new Response(JSON.stringify(data), {
    status,
    headers: {
      "Content-Type": "application/json",
      "Cache-Control": "no-store, no-cache, must-revalidate",
      "X-Content-Type-Options": "nosniff",
      "X-Frame-Options": "DENY",
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

function validateRequest(req: Request): { valid: boolean; error?: string } {
  const ua = req.headers.get("user-agent") || "";
  if (!ua || ua.length < 10) return { valid: false, error: "Invalid request" };

  const botPatterns =[
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
  if (origin && !origin.includes(host)) return jsonResponse({ success: false, message: "ခွင့်မပြုပါ။" }, 403);

  if (!validateRequest(req).valid) return jsonResponse({ success: false, message: "ခွင့်မပြုပါ။" }, 403);

  const ip = getClientIP(req);
  const userAgent = req.headers.get("user-agent") || "unknown";

  if (!(await checkBurstLimit(ip))) {
    return jsonResponse({ success: false, error: "rate_limited", message: "တောင်းဆိုမှု များလွန်းနေပါသည်။ ခဏစောင့်ပါ။" }, 429);
  }

  let body: Record<string, unknown>;
  try {
    body = await req.json();
    if ((body.website as string)?.length > 0 || (body.email as string)?.length > 0) {
      return jsonResponse({ success: true, payload: btoa("fake-payload-" + Math.random()), remaining: 0 }); // Honeypot
    }

    if (!body.csrf_token || !(await validateCSRFToken(body.csrf_token as string, ip))) {
      return jsonResponse({ success: false, error: "invalid_token", message: "Session သက်တမ်းကုန်ပါပြီ။ Page ကို Refresh လုပ်ပါ။" }, 403);
    }

    if (!body.pow_challenge || !body.pow_nonce || !(await verifyPoW(ip, body.pow_challenge as string, body.pow_nonce as string))) {
      return jsonResponse({ success: false, error: "pow_invalid", message: "Security verification မအောင်မြင်ပါ။ Refresh လုပ်ပါ။" }, 403);
    }
  } catch {
    return jsonResponse({ success: false, message: "ခွင့်မပြုပါ။" }, 400);
  }

  const config = getConfig();
  if (!isWithinValidPeriod(config)) {
    return jsonResponse({ success: false, error: "expired", message: "လက်ရှိ Key သက်တမ်း ကုန်ဆုံးနေပါသည်။" }, 403);
  }

  const fingerprint = await generateServerFingerprint(ip, userAgent);
  const ipFingerprint = await hashSHA256(`ip-only-${ip}-patgaduu-salt`);

  const fpCheck = await checkRateLimit(fingerprint, config);
  const ipCheck = await checkRateLimit(ipFingerprint, config);

  if (!fpCheck.allowed || !ipCheck.allowed) {
    return jsonResponse({ success: false, error: "limit_reached", message: !fpCheck.allowed ? fpCheck.message : ipCheck.message, remaining: 0 }, 429);
  }

  const result = getRandomKey(config);
  if (!result) return jsonResponse({ success: false, message: "လက်ရှိ Key မရှိပါ။ နောက်မှ ပြန်လာပါ။" }, 503);

  const incrementResult = await incrementAllAtomic(fingerprint, ipFingerprint, config);
  if (!incrementResult.success) {
    return jsonResponse({ success: false, message: "Server အလုပ်များနေပါသည်။ ခဏစောင့်၍ ထပ်ကြိုးစားပါ။" }, 503);
  }

  const remaining = Math.min(fpCheck.remaining, ipCheck.remaining) - 1;
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

  let remaining = 0; let allowed = false;
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
  const url = new URL(req.url);
  if (!authKey || url.searchParams.get("key") !== authKey) return new Response("Not found", { status: 404 });

  const totalGenerated = await getTotalCount();
  return jsonResponse({ totalGenerated, status: "OK", timestamp: new Date().toISOString() });
}

// ============== HTML PAGE (UI) ==============

function getHTML(): string {
  const config = getConfig();
  
  const noticeHTML = config.adminNotice ? `
    <div class="admin-notice-slider" id="adminNoticeSlider">
      <div class="notice-icon"><svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/></svg></div>
      <div class="notice-marquee"><span class="notice-text">${config.adminNotice.replace(/</g, '&lt;').replace(/>/g, '&gt;')}</span></div>
      <button class="notice-close" onclick="closeNotice()">&times;</button>
    </div>` : '';

  return `<!DOCTYPE html>
<html lang="my">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0, maximum-scale=1.0, user-scalable=no">
  <title>Patgaduu - VLESS Key Generator</title>

  <link rel="preconnect" href="https://fonts.googleapis.com">
  <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
  <link href="https://fonts.googleapis.com/css2?family=Padauk:wght@400;700&family=Inter:wght@400;500;600;700&family=JetBrains+Mono:wght@400&display=swap" rel="stylesheet">

  <style>
    :root {
      --primary: #6366f1; --primary-dark: #4f46e5; --accent: #f59e0b; --accent-light: #d97706;
      --bg-main: #f8fafc; --bg-card: #ffffff; --bg-card-alt: #f1f5f9;
      --glass: rgba(255,255,255,0.85); --glass-border: rgba(0,0,0,0.08);
      --text: #1e293b; --text-dim: #475569; --text-muted: #94a3b8;
      --success: #10b981; --danger: #ef4444; --cyan: #0891b2; --purple: #7c3aed;
      --shadow-sm: 0 1px 3px rgba(0,0,0,0.06); --shadow-md: 0 4px 6px rgba(0,0,0,0.05);
      --shadow-lg: 0 10px 25px rgba(0,0,0,0.08); --radius-sm: 10px; --radius-md: 14px; --radius-xl: 24px;
    }
    * { margin: 0; padding: 0; box-sizing: border-box; }
    body { font-family: 'Padauk', 'Inter', sans-serif; background: var(--bg-main); color: var(--text); min-height: 100vh; overflow-x: hidden; }
    
    .bg-decoration { position: fixed; top: 0; left: 0; width: 100%; height: 100%; z-index: 0; pointer-events: none; }
    .bg-decoration .shape { position: absolute; border-radius: 50%; opacity: 0.4; filter: blur(80px); }
    .bg-decoration .shape:nth-child(1) { width: 500px; height: 500px; background: linear-gradient(135deg, rgba(99,102,241,0.15), rgba(139,92,246,0.1)); top: -200px; left: -100px; }
    .bg-decoration .shape:nth-child(2) { width: 400px; height: 400px; background: linear-gradient(135deg, rgba(6,182,212,0.1), rgba(59,130,246,0.08)); bottom: -150px; right: -100px; }
    
    .container { position: relative; z-index: 1; max-width: 520px; margin: 0 auto; padding: 16px 14px; display: flex; flex-direction: column; min-height: 100vh;}
    
    /* Admin Notice */
    .admin-notice-slider { display: flex; align-items: center; gap: 10px; padding: 10px 14px; background: #fef3c7; border: 1px solid #fbbf24; border-radius: var(--radius-md); margin-bottom: 14px; overflow: hidden; box-shadow: var(--shadow-sm); }
    .notice-icon { color: #b45309; }
    .notice-marquee { flex: 1; overflow: hidden; white-space: nowrap; mask-image: linear-gradient(90deg, transparent, black 10%, black 90%, transparent); -webkit-mask-image: linear-gradient(90deg, transparent, black 10%, black 90%, transparent); }
    .notice-text { display: inline-block; animation: marquee 15s linear infinite; font-size: 13px; font-weight: 600; color: #92400e; padding-left: 100%; }
    @keyframes marquee { 0% { transform: translateX(0); } 100% { transform: translateX(-100%); } }
    .notice-close { background: none; border: none; font-size: 20px; color: #b45309; cursor: pointer; opacity: 0.7; }
    
    /* Header & User Profile */
    .header { display: flex; align-items: center; justify-content: space-between; padding: 14px 18px; background: var(--glass); backdrop-filter: blur(20px); -webkit-backdrop-filter: blur(20px); border: 1px solid var(--glass-border); border-radius: var(--radius-xl); margin-bottom: 16px; box-shadow: var(--shadow-md); }
    .header-brand { display: flex; align-items: center; gap: 10px; }
    .logo-icon { width: 38px; height: 38px; background: linear-gradient(135deg, var(--primary), var(--purple)); border-radius: var(--radius-sm); display: flex; align-items: center; justify-content: center; box-shadow: 0 4px 15px rgba(99,102,241,0.3); color: white; }
    .logo-icon svg { width: 20px; height: 20px; }
    .header-brand h1 { font-size: 17px; font-weight: 700; color: var(--primary-dark); }
    .header-brand span { font-size: 10px; color: var(--text-muted); letter-spacing: 1px; text-transform: uppercase; }
    
    /* NEW: User Profile Badge */
    .user-profile {
      display: flex; align-items: center; gap: 8px;
      padding: 5px 12px 5px 6px;
      background: linear-gradient(135deg, rgba(99,102,241,0.08), rgba(124,58,237,0.05));
      border: 1px solid rgba(99,102,241,0.2);
      border-radius: var(--radius-md);
      transition: all 0.3s ease;
      cursor: default;
    }
    .user-profile:hover { background: rgba(99,102,241,0.12); border-color: rgba(99,102,241,0.3); }
    .up-avatar {
      width: 24px; height: 24px;
      background: linear-gradient(135deg, var(--primary), var(--purple));
      border-radius: 8px; /* လေးဒေါင့်ဝိုက်လေးပုံစံ */
      display: flex; align-items: center; justify-content: center;
      color: white; box-shadow: 0 2px 5px rgba(99,102,241,0.3);
    }
    .up-avatar svg { width: 13px; height: 13px; }
    .up-name { font-size: 11px; font-weight: 700; color: var(--primary-dark); font-family: 'Inter', sans-serif; white-space: nowrap; }

    /* Validity Notice */
    .validity-notice { padding: 14px 16px; background: linear-gradient(135deg, rgba(6,182,212,0.04), rgba(99,102,241,0.04)); border: 1px solid rgba(6,182,212,0.2); border-radius: var(--radius-md); display: flex; align-items: center; gap: 12px; margin-bottom: 16px; }
    .vn-icon { width: 40px; height: 40px; background: rgba(6,182,212,0.1); border-radius: var(--radius-sm); display: flex; align-items: center; justify-content: center; color: var(--cyan); }
    .vn-icon svg { width: 20px; height: 20px; }
    .vn-text { font-size: 12.5px; color: var(--text-dim); }
    .vn-text strong { color: var(--cyan); font-weight: 700; font-size: 13px; display: block; }
    .validity-expired { border-color: rgba(239,68,68,0.25) !important; background: rgba(239,68,68,0.04) !important; }
    .validity-expired .vn-icon { background: rgba(239,68,68,0.1) !important; color: var(--danger); }
    .validity-expired .vn-text strong { color: var(--danger) !important; }

    /* Stats Bar */
    .stats-bar { display: flex; gap: 10px; margin-bottom: 16px; overflow-x: auto; scrollbar-width: none; }
    .stat-card { flex: 1; min-width: 0; background: var(--bg-card); border: 1px solid var(--glass-border); border-radius: var(--radius-md); padding: 14px 12px; text-align: center; position: relative; box-shadow: var(--shadow-sm); }
    .stat-card::before { content: ''; position: absolute; top: 0; left: 0; width: 100%; height: 3px; border-radius: 3px 3px 0 0; }
    .stat-card:nth-child(1)::before { background: linear-gradient(90deg, var(--primary), var(--purple)); }
    .stat-card:nth-child(2)::before { background: linear-gradient(90deg, var(--cyan), #3b82f6); }
    .stat-card:nth-child(3)::before { background: linear-gradient(90deg, var(--accent), #f97316); }
    .stat-card:nth-child(4)::before { background: linear-gradient(90deg, var(--success), var(--cyan)); }
    .stat-icon { width: 32px; height: 32px; margin: 0 auto 6px; border-radius: 8px; display: flex; align-items: center; justify-content: center; }
    .stat-icon svg { width: 16px; height: 16px; }
    .stat-card:nth-child(1) .stat-icon { background: rgba(99,102,241,0.1); color: var(--primary); }
    .stat-card:nth-child(2) .stat-icon { background: rgba(6,182,212,0.1); color: var(--cyan); }
    .stat-card:nth-child(3) .stat-icon { background: rgba(245,158,11,0.1); color: var(--accent-light); }
    .stat-card:nth-child(4) .stat-icon { background: rgba(16,185,129,0.1); color: var(--success); }
    .stat-value { font-size: 16px; font-weight: 700; font-family: 'Inter', sans-serif; }
    .stat-label { font-size: 10px; color: var(--text-muted); margin-top: 2px; }

    /* Main Card */
    .main-card { background: var(--bg-card); border: 1px solid var(--glass-border); border-radius: var(--radius-xl); padding: 28px 20px; flex: 1; box-shadow: var(--shadow-lg); }
    .card-header { text-align: center; margin-bottom: 24px; }
    .icon-wrapper { width: 68px; height: 68px; margin: 0 auto 14px; border-radius: 18px; background: linear-gradient(135deg, var(--primary), var(--purple)); display: flex; align-items: center; justify-content: center; box-shadow: 0 8px 30px rgba(99,102,241,0.3); color: white; animation: iconPulse 3s ease-in-out infinite; }
    @keyframes iconPulse { 0%, 100% { transform: translateY(0) scale(1); } 50% { transform: translateY(-4px) scale(1.02); } }
    .icon-wrapper svg { width: 30px; height: 30px; }
    .card-header h2 { font-size: 20px; font-weight: 700; margin-bottom: 4px; }
    .card-header p { font-size: 13px; color: var(--text-dim); }

    .compat-notice { padding: 14px 16px; background: rgba(99, 102, 241, 0.03); border: 1px solid rgba(99, 102, 241, 0.12); border-radius: var(--radius-md); margin-bottom: 18px; }
    .compat-title { font-size: 12px; font-weight: 700; color: var(--primary); margin-bottom: 8px; display: flex; align-items: center; gap: 6px; }
    .compat-apps { display: flex; flex-wrap: wrap; gap: 5px; }
    .compat-app { padding: 3px 10px; background: rgba(16, 185, 129, 0.06); border: 1px solid rgba(16, 185, 129, 0.2); border-radius: 6px; font-size: 11px; color: var(--success); font-weight: 600; font-family: 'Inter', sans-serif; }
    
    .generate-btn { width: 100%; padding: 15px; border: none; border-radius: var(--radius-md); background: linear-gradient(135deg, var(--primary), var(--purple)); color: white; font-family: 'Padauk', sans-serif; font-size: 16px; font-weight: 700; cursor: pointer; display: flex; align-items: center; justify-content: center; gap: 10px; box-shadow: 0 4px 15px rgba(99,102,241,0.3); transition: transform 0.2s, box-shadow 0.2s; }
    .generate-btn:hover { transform: translateY(-2px); box-shadow: 0 8px 25px rgba(99,102,241,0.4); }
    .generate-btn:disabled { opacity: 0.6; cursor: not-allowed; transform: none; box-shadow: none; }
    .generate-btn svg { width: 20px; height: 20px; }
    .spinner { width: 20px; height: 20px; border: 2px solid rgba(255,255,255,0.3); border-top: 2px solid white; border-radius: 50%; animation: spin 0.8s linear infinite; display: none; }
    @keyframes spin { to { transform: rotate(360deg); } }

    .error-msg { margin-top: 14px; padding: 13px 16px; background: rgba(239,68,68,0.04); border: 1px solid rgba(239,68,68,0.2); border-radius: var(--radius-md); color: var(--danger); font-size: 13px; display: none; align-items: center; gap: 8px; }
    .error-msg.show { display: flex; animation: shake 0.4s ease; }
    @keyframes shake { 0%, 100% { transform: translateX(0); } 25% { transform: translateX(-5px); } 75% { transform: translateX(5px); } }

    /* Result Area */
    .result-area { margin-top: 20px; display: none; }
    .result-area.show { display: block; }
    .result-box { background: var(--bg-card-alt); border: 1px solid rgba(16,185,129,0.2); border-radius: var(--radius-md); padding: 18px; position: relative; animation: slideUp 0.5s ease; box-shadow: var(--shadow-sm); }
    .result-box::before { content: ''; position: absolute; top: 0; left: 0; width: 100%; height: 3px; background: linear-gradient(90deg, var(--success), var(--cyan)); border-radius: 3px 3px 0 0; }
    @keyframes slideUp { from { opacity: 0; transform: translateY(20px); } to { opacity: 1; transform: translateY(0); } }
    .result-label { display: flex; align-items: center; gap: 8px; margin-bottom: 12px; font-size: 12px; color: var(--success); font-weight: 600; }
    .result-key { background: white; border: 1px solid var(--glass-border); border-radius: var(--radius-sm); padding: 14px; font-family: 'JetBrains Mono', monospace; font-size: 10.5px; color: var(--primary-dark); word-break: break-all; max-height: 110px; overflow-y: auto; user-select: all; }
    .result-meta { display: flex; align-items: center; justify-content: space-between; margin-top: 14px; padding-top: 14px; border-top: 1px solid var(--glass-border); flex-wrap: wrap; gap: 10px; }
    .action-buttons { display: flex; gap: 8px; }
    .copy-btn, .qr-btn { display: flex; align-items: center; gap: 5px; padding: 7px 14px; border: 1px solid rgba(99,102,241,0.25); border-radius: var(--radius-sm); background: rgba(99,102,241,0.06); color: var(--primary); font-family: 'Inter', sans-serif; font-size: 12px; font-weight: 600; cursor: pointer; transition: all 0.2s; }
    .copy-btn:hover, .qr-btn:hover { background: var(--primary); color: white; }

    /* Info Bars & Footer */
    .info-bars { display: flex; flex-direction: column; gap: 8px; margin-top: 18px; }
    .info-bar { padding: 13px 16px; background: var(--bg-card-alt); border: 1px solid var(--glass-border); border-radius: var(--radius-md); display: flex; align-items: center; justify-content: space-between; }
    .info-bar .label { font-size: 12.5px; color: var(--text-dim); display: flex; align-items: center; gap: 6px; }
    .info-bar .count { font-size: 17px; font-weight: 700; font-family: 'Inter', sans-serif; color: var(--primary); }
    .tg-contact-bar { margin-top: 12px; padding: 13px 16px; background: rgba(6, 182, 212, 0.03); border: 1px solid rgba(6, 182, 212, 0.15); border-radius: var(--radius-md); display: flex; align-items: center; justify-content: space-between; }
    .tg-icon { width: 34px; height: 34px; background: rgba(6, 182, 212, 0.08); border-radius: var(--radius-sm); display: flex; align-items: center; justify-content: center; color: var(--cyan); }
    .tg-link { padding: 7px 14px; background: rgba(6, 182, 212, 0.06); border: 1px solid rgba(6, 182, 212, 0.2); border-radius: var(--radius-sm); color: var(--cyan); font-size: 12px; font-weight: 600; text-decoration: none; }
    .footer { text-align: center; padding: 20px 0 10px; font-size: 11px; color: var(--text-muted); }
    .footer a { color: var(--primary); text-decoration: none; }

    /* Modals & Overlays */
    .qr-modal, .success-overlay { position: fixed; top: 0; left: 0; width: 100%; height: 100%; z-index: 150; display: none; align-items: center; justify-content: center; background: rgba(0,0,0,0.4); backdrop-filter: blur(8px); }
    .qr-modal.show, .success-overlay.show { display: flex; animation: fadeIn 0.3s ease; }
    @keyframes fadeIn { from { opacity: 0; } to { opacity: 1; } }
    .qr-modal-content, .success-popup { background: var(--bg-card); border-radius: var(--radius-xl); padding: 28px; text-align: center; max-width: 300px; width: 90%; box-shadow: var(--shadow-xl); animation: popIn 0.4s cubic-bezier(0.68, -0.55, 0.265, 1.55); }
    @keyframes popIn { from { transform: scale(0.5); opacity: 0; } to { transform: scale(1); opacity: 1; } }
    .qr-code-container { background: white; padding: 16px; display: inline-block; border-radius: var(--radius-md); margin-bottom: 16px; border: 1px solid var(--glass-border); }
    .qr-close-btn { padding: 10px 28px; background: var(--bg-card-alt); border: 1px solid var(--glass-border); border-radius: var(--radius-sm); cursor: pointer; }
    .hp-field { position: absolute; left: -9999px; opacity: 0; pointer-events: none; }
    
    .toast { position: fixed; bottom: 30px; left: 50%; transform: translateX(-50%) translateY(100px); background: var(--success); color: white; padding: 11px 22px; border-radius: var(--radius-sm); font-size: 13px; font-weight: 600; z-index: 200; transition: transform 0.3s cubic-bezier(0.68, -0.55, 0.265, 1.55); display: flex; align-items: center; gap: 8px; }
    .toast.show { transform: translateX(-50%) translateY(0); }
  </style>
</head>
<body>

  <div class="bg-decoration"><div class="shape"></div><div class="shape"></div></div>

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
      <!-- User Profile Box -->
      <div class="user-profile">
        <div class="up-avatar">
          <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M19 21v-2a4 4 0 0 0-4-4H9a4 4 0 0 0-4 4v2"/><circle cx="12" cy="7" r="4"/></svg>
        </div>
        <span class="up-name">${config.userProfile}</span>
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
        <div class="compat-title"><svg xmlns="http://www.w3.org/2000/svg" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="5" y="2" width="14" height="20" rx="2" ry="2"/><line x1="12" y1="18" x2="12.01" y2="18"/></svg>အသုံးပြုနိုင်သော Apps များ</div>
        <div class="compat-apps">
          <span class="compat-app">V2rayNG</span><span class="compat-app">V2Box</span><span class="compat-app">Nekoray</span>
        </div>
      </div>

      <div class="hp-field"><input type="text" id="hpWebsite"><input type="text" id="hpEmail"></div>

      <button class="generate-btn" id="generateBtn" onclick="handleGenerate()">
        <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="m12 3-1.912 5.813a2 2 0 0 1-1.275 1.275L3 12l5.813 1.912a2 2 0 0 1 1.275 1.275L12 21l1.912-5.813a2 2 0 0 1 1.275-1.275L21 12l-5.813-1.912a2 2 0 0 1-1.275-1.275L12 3Z"/><path d="M5 3v4"/><path d="M19 17v4"/><path d="M3 5h4"/><path d="M17 19h4"/></svg>
        <span id="btnText">Generate Key</span>
        <div class="spinner" id="spinner"></div>
      </button>

      <div class="error-msg" id="errorMsg">
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
              <button class="copy-btn" onclick="copyKey()">Copy</button>
              <button class="qr-btn" onclick="showQR()">QR</button>
            </div>
          </div>
        </div>
      </div>

      <div class="info-bars">
        <div class="info-bar"><div class="label">ကျန်ရှိအကြိမ်</div><div class="count" id="remainingCount" style="color:var(--accent-light);">-</div></div>
        <div class="info-bar"><div class="label">စုစုပေါင်း Generate ပြုလုပ်ပြီး</div><div class="count" id="totalCount">-</div></div>
      </div>

      <div class="tg-contact-bar">
        <div style="display:flex;align-items:center;gap:10px;">
          <div class="tg-icon"><svg xmlns="http://www.w3.org/2000/svg" width="17" height="17" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><line x1="22" y1="2" x2="11" y2="13"/><polygon points="22 2 15 22 11 13 2 9 22 2"/></svg></div>
          <div style="font-size:11px;color:var(--text-muted);">အကူအညီ / ဆက်သွယ်ရန်<strong style="display:block;color:var(--cyan);font-size:12px;" id="tgHandleText">${config.adminTgHandle}</strong></div>
        </div>
        <a href="${config.adminTgLink}" class="tg-link" id="tgContactLink">Message</a>
      </div>
    </div>
    <div class="footer">Powered by <a href="${config.adminTgLink}">Patgaduu</a> &copy; 2026</div>
  </div>

  <div class="success-overlay" id="successOverlay"><div class="success-popup"><h3>အောင်မြင်ပါသည်!</h3><p>Key ကို Copy ယူ၍ V2rayNG တွင် အသုံးပြုပါ</p></div></div>
  <div class="qr-modal" id="qrModal"><div class="qr-modal-content"><h3>QR Code Scan</h3><div class="qr-code-container" id="qrCodeContainer"></div><br><button class="qr-close-btn" onclick="closeQR()">ပိတ်မည်</button></div></div>
  <div class="toast" id="toast">Copy ကူးယူပြီးပါပြီ!</div>

<script>
  (function() {
    var s = document.createElement('script');
    s.src = 'https://unpkg.com/qrcode-generator@1.4.4/qrcode.js';
    document.head.appendChild(s);
  })();

  var csrfToken='', currentKey='', isGenerating=false, powChallenge='', powDifficulty=4, powNonce='', powReady=false;

  document.addEventListener('DOMContentLoaded', checkRemaining);

  function solvePoW(challenge, difficulty) {
    return new Promise(function(resolve) {
      var pfx = ''; for (var d=0; d<difficulty; d++) pfx += '0';
      var nonce = 0, batchSize = 1000;
      function batch() { tryNonces(nonce, batchSize, challenge, pfx, resolve); }
      function tryNonces(start, count, chal, pfx, cb) {
        var promises =[];
        for (var i=start; i<start+count; i++) {
          promises.push(crypto.subtle.digest('SHA-256', new TextEncoder().encode(chal+'||'+i)).then(function(hash) {
            var hex = Array.from(new Uint8Array(hash)).map(function(b){return b.toString(16).padStart(2,'0')}).join('');
            return hex.startsWith(pfx) ? String(start + promises.indexOf(arguments[0]) /* approximate */) : false; 
            // Better matching logic inside testNonce
          }));
        }
        // Fixed correct Promise mapping
        var realPromises =[];
        for (var j=start; j<start+count; j++) realPromises.push(testNonce(chal, j, pfx));
        Promise.all(realPromises).then(function(res) {
          for (var k=0; k<res.length; k++) if(res[k]!==false) return cb(res[k]);
          nonce = start + count;
          if (nonce > 5000000) return cb(null);
          setTimeout(batch, 0); // Background non-blocking
        });
      }
      function testNonce(c,n,p) {
        return crypto.subtle.digest('SHA-256', new TextEncoder().encode(c+'||'+n)).then(function(h) {
          var hex = Array.from(new Uint8Array(h)).map(function(b){return b.toString(16).padStart(2,'0')}).join('');
          return hex.startsWith(p) ? String(n) : false;
        });
      }
      batch();
    });
  }

  function checkRemaining() {
    fetch('/api/check', { method: 'POST', body: JSON.stringify({}) }).then(res => res.json()).then(data => {
      csrfToken = data.csrf_token || ''; powChallenge = data.pow_challenge || '';
      if(powChallenge) { powReady=false; solvePoW(powChallenge, data.pow_difficulty).then(n => { if(n) { powNonce=n; powReady=true; } }); }
      
      document.getElementById('validityText').textContent = data.validityText;
      var vStatus = document.getElementById('validityStatus'), vNotice = document.getElementById('validityNotice');
      if (data.withinPeriod) { vStatus.textContent = 'အသုံးပြုနိုင်ပါသည်'; vNotice.classList.remove('validity-expired'); } 
      else { vStatus.textContent = 'Key သက်တမ်း ကုန်ဆုံးနေပါသည်'; vNotice.classList.add('validity-expired'); }

      document.getElementById('statRemaining').textContent = data.remaining + '/' + data.maxPerPeriod;
      document.getElementById('statMaxPeriod').textContent = data.maxPerPeriod;
      document.getElementById('statTotal').textContent = data.totalGenerated;
      document.getElementById('remainingCount').textContent = data.remaining;
      document.getElementById('totalCount').textContent = data.totalGenerated;

      var btn = document.getElementById('generateBtn');
      btn.disabled = !data.allowed;
      document.getElementById('btnText').textContent = !data.allowed ? (data.withinPeriod ? 'အခွင့်ကုန်သွားပါပြီ' : 'သက်တမ်းကုန်နေသည်') : 'Generate Key';
    }).catch(e=>{});
  }

  function handleGenerate() {
    if(isGenerating) return;
    if(!powReady) { 
      document.getElementById('errorText').textContent = 'Security check လုပ်နေပါသည်။ ခဏစောင့်ပါ။';
      document.getElementById('errorMsg').classList.add('show'); setTimeout(()=>document.getElementById('errorMsg').classList.remove('show'), 2000); return; 
    }
    isGenerating = true;
    var btn = document.getElementById('generateBtn'), spin = document.getElementById('spinner'), txt = document.getElementById('btnText');
    btn.disabled=true; spin.style.display='block'; txt.textContent='Generating...';
    document.getElementById('errorMsg').classList.remove('show');

    fetch('/api/generate', {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ csrf_token: csrfToken, pow_challenge: powChallenge, pow_nonce: powNonce, website: document.getElementById('hpWebsite').value, t: Date.now() })
    }).then(r=>r.json()).then(data => {
      if(!data.success) {
        document.getElementById('errorText').textContent = data.message; document.getElementById('errorMsg').classList.add('show');
        spin.style.display='none'; btn.disabled=false; txt.textContent='Generate Key'; isGenerating=false; checkRemaining(); return;
      }
      // Decrypt
      var b = atob(data.payload), bytes = new Uint8Array(b.length);
      for(var i=0; i<b.length; i++) bytes[i] = b.charCodeAt(i);
      crypto.subtle.importKey('raw', bytes.slice(0,32), {name:'AES-GCM'}, false, ['decrypt']).then(k => {
        return crypto.subtle.decrypt({name:'AES-GCM', iv: bytes.slice(32,44)}, k, bytes.slice(44));
      }).then(dec => {
        var res = JSON.parse(new TextDecoder().decode(dec));
        currentKey = res.key;
        document.getElementById('resultKey').textContent = currentKey;
        document.getElementById('expireText').textContent = 'သက်တမ်း: ' + res.validityText;
        document.getElementById('resultArea').classList.add('show');
        document.getElementById('successOverlay').classList.add('show'); setTimeout(()=>document.getElementById('successOverlay').classList.remove('show'), 2000);
        checkRemaining(); spin.style.display='none'; txt.textContent='Generate Key'; isGenerating=false;
      });
    }).catch(e => {
      document.getElementById('errorText').textContent = 'ချိတ်ဆက်မှု မအောင်မြင်ပါ။'; document.getElementById('errorMsg').classList.add('show');
      spin.style.display='none'; btn.disabled=false; txt.textContent='Generate Key'; isGenerating=false;
    });
  }

  function copyKey() {
    if(!currentKey) return;
    var t = document.createElement('textarea'); t.value = currentKey; document.body.appendChild(t); t.select(); document.execCommand('copy'); document.body.removeChild(t);
    document.getElementById('toast').classList.add('show'); setTimeout(()=>document.getElementById('toast').classList.remove('show'), 2000);
  }

  function showQR() {
    if(!currentKey || typeof qrcode==='undefined') return;
    var qr = qrcode(0, 'L'); qr.addData(currentKey); qr.make();
    document.getElementById('qrCodeContainer').innerHTML = qr.createImgTag(Math.floor(200/qr.getModuleCount()), 0);
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
  const securityHeaders: Record<string, string> = {
    "X-Frame-Options": "DENY", "X-Content-Type-Options": "nosniff", "X-XSS-Protection": "1; mode=block"
  };

  if (url.pathname === "/api/generate") return await handleGenerate(req);
  if (url.pathname === "/api/check") return await handleCheckRemaining(req);
  if (url.pathname === "/api/debug") return await handleDebug(req);

  if (["/wp-admin", "/.env", "/.git"].some(p => url.pathname.toLowerCase().startsWith(p))) return new Response("Not found", { status: 404 });
  if (req.method !== "GET" && req.method !== "HEAD") return new Response("Method not allowed", { status: 405 });
  if (url.pathname !== "/" && url.pathname !== "/index.html") return new Response("Not found", { status: 404 });

  return new Response(getHTML(), { headers: { "Content-Type": "text/html; charset=utf-8", "Cache-Control": "no-store", ...securityHeaders } });
});
