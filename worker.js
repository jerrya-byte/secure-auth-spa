// ================================================================
// SecureAuth — Cloudflare Worker (v2)
//
// Routes (all POST, differentiated by "action" field in JSON body):
//   action: "check-email"      → verify email exists in Entra ID
//   action: "writeback-email"  → write personalEmail to Entra otherMails
//   action: "generate-token"   → sign and return a JWT with user claims
//
// ENVIRONMENT VARIABLES (Workers → Settings → Variables):
//   ENTRA_TENANT_ID      → your Directory (tenant) ID
//   ENTRA_CLIENT_ID      → your Application (client) ID
//   ENTRA_CLIENT_SECRET  → your client secret VALUE          [mark Encrypted]
//   ALLOWED_ORIGIN       → https://jerrya-byte.github.io
//   JWT_SECRET           → any long random string            [mark Encrypted]
//                          e.g. "s3cur3Auth!jwt$2025#secret"
//
// NEW ENTRA PERMISSION NEEDED (for writeback-email):
//   portal.azure.com → Entra ID → App registrations → your app
//   → API permissions → + Add → Microsoft Graph
//   → Application permissions → User.ReadWrite.All
//   → Grant admin consent ✓
// ================================================================

export default {
  async fetch(request, env) {

    // ── CORS ──────────────────────────────────────────────────
    const allowedOrigin = env.ALLOWED_ORIGIN || '*';
    const cors = {
      'Access-Control-Allow-Origin':  allowedOrigin,
      'Access-Control-Allow-Methods': 'POST, OPTIONS',
      'Access-Control-Allow-Headers': 'Content-Type',
    };

    if (request.method === 'OPTIONS') {
      return new Response(null, { status: 204, headers: cors });
    }
    if (request.method !== 'POST') {
      return respond({ error: 'Method not allowed' }, 405, cors);
    }

    let body;
    try { body = await request.json(); }
    catch { return respond({ error: 'Invalid JSON body' }, 400, cors); }

    try {
      switch (body.action) {
        case 'check-email':
          return respond(await checkEmail(body, env), 200, cors);
        case 'writeback-email':
          return respond(await writebackEmail(body, env), 200, cors);
        case 'generate-token':
          return respond(await generateToken(body, env), 200, cors);
        default:
          return respond({ error: `Unknown action: "${body.action}"` }, 400, cors);
      }
    } catch (err) {
      return respond({ error: err.message || 'Internal Worker error' }, 500, cors);
    }
  }
};

// ── Helpers ───────────────────────────────────────────────────
function respond(data, status, cors) {
  return new Response(JSON.stringify(data), {
    status, headers: { ...cors, 'Content-Type': 'application/json' }
  });
}

async function getEntraToken(env) {
  const res = await fetch(
    `https://login.microsoftonline.com/${env.ENTRA_TENANT_ID}/oauth2/v2.0/token`,
    {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        grant_type:    'client_credentials',
        client_id:     env.ENTRA_CLIENT_ID,
        client_secret: env.ENTRA_CLIENT_SECRET,
        scope:         'https://graph.microsoft.com/.default',
      }),
    }
  );
  const d = await res.json();
  if (!res.ok) throw new Error(d.error_description || d.error || 'Failed to get Entra access token');
  return d.access_token;
}

// ── ACTION: check-email ───────────────────────────────────────
async function checkEmail({ email }, env) {
  if (!email?.includes('@')) throw new Error('Invalid email address');
  const token = await getEntraToken(env);
  const res = await fetch(
    `https://graph.microsoft.com/v1.0/users/${encodeURIComponent(email)}?$select=id,displayName,userPrincipalName`,
    { headers: { Authorization: `Bearer ${token}` } }
  );
  if (res.status === 404) return { found: false };
  if (res.status === 403) throw new Error('Graph API: Forbidden. Ensure User.ReadBasic.All is granted with admin consent.');
  if (!res.ok) { const e = await res.json().catch(()=>({})); throw new Error(e?.error?.message || `Graph API error (HTTP ${res.status})`); }
  const u = await res.json();
  return { found: true, displayName: u.displayName || null };
}

// ── ACTION: writeback-email ───────────────────────────────────
// Requires User.ReadWrite.All application permission in Entra
async function writebackEmail({ entraEmail, personalEmail }, env) {
  if (!entraEmail || !personalEmail) throw new Error('entraEmail and personalEmail are required');
  const token = await getEntraToken(env);
  const res = await fetch(
    `https://graph.microsoft.com/v1.0/users/${encodeURIComponent(entraEmail)}`,
    {
      method:  'PATCH',
      headers: { Authorization: `Bearer ${token}`, 'Content-Type': 'application/json' },
      body:    JSON.stringify({ otherMails: [personalEmail] }),
    }
  );
  if (res.status === 204 || res.status === 200) return { success: true };
  if (res.status === 403) throw new Error('Writeback forbidden. Ensure User.ReadWrite.All application permission is granted with admin consent.');
  const e = await res.json().catch(()=>({}));
  throw new Error(e?.error?.message || `Writeback error (HTTP ${res.status})`);
}

// ── ACTION: generate-token ────────────────────────────────────
async function generateToken({ user }, env) {
  if (!user)           throw new Error('user payload is required');
  if (!env.JWT_SECRET) throw new Error('JWT_SECRET environment variable is not set in Worker');

  const now = Math.floor(Date.now() / 1000);
  const payload = {
    iss:               'secureauth-worker',
    aud:               'secureauth-spa',
    sub:               user.username,
    iat:               now,
    exp:               now + 3600,
    auth_result:       'SUCCESS',
    first_name:        user.firstName,
    last_name:         user.lastName,
    identity_strength: user.identityStrength,
    personal_email:    user.personalEmail,
    entra_email:       user.entraEmail,
  };

  return { token: await signHS256(payload, env.JWT_SECRET) };
}

// ── JWT HS256 signing ─────────────────────────────────────────
async function signHS256(payload, secret) {
  const b64u = v =>
    btoa(typeof v === 'string' ? v : JSON.stringify(v))
      .replace(/=/g,'').replace(/\+/g,'-').replace(/\//g,'_');

  const header  = b64u({ alg: 'HS256', typ: 'JWT' });
  const body    = b64u(payload);
  const signing = `${header}.${body}`;

  const key = await crypto.subtle.importKey(
    'raw', new TextEncoder().encode(secret),
    { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']
  );
  const sig = await crypto.subtle.sign('HMAC', key, new TextEncoder().encode(signing));
  const sigB64 = btoa(String.fromCharCode(...new Uint8Array(sig)))
    .replace(/=/g,'').replace(/\+/g,'-').replace(/\//g,'_');

  return `${signing}.${sigB64}`;
}
