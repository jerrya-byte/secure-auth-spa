// ================================================================
// SecureAuth — Cloudflare Worker (v5)
//
// Routes (all POST, differentiated by body.action):
//   check-reference   → look up reference# in Supabase identity_records
//                       and resolve the matching Entra user (replaces
//                       check-email in the New User flow)
//   check-email       → verify UPN exists in Entra ID (legacy / unused)
//   generate-token    → sign HS256 JWT with user claims
//   generate-tap      → generate Temporary Access Pass via Graph
//   fido2-begin       → start FIDO2 registration ceremony
//   fido2-complete    → complete FIDO2 registration
//   myid-auth-start   → build & return myID OIDC authorization URL (PKCE)
//   myid-callback     → exchange code→tokens, validate IP level, store in Supabase
//
// ENVIRONMENT VARIABLES  (Workers → Settings → Variables & Secrets)
// ─────────────────────────────────────────────────────────────────
//   ENTRA_TENANT_ID       Directory (tenant) ID
//   ENTRA_CLIENT_ID       Application (client) ID
//   ENTRA_CLIENT_SECRET   Client secret [Encrypted]
//   ALLOWED_ORIGIN        https://jerrya-byte.github.io
//   JWT_SECRET            Any long random string [Encrypted]
//   SUPABASE_URL          https://itgpqimnshhllehrvjyt.supabase.co
//   SUPABASE_KEY          Supabase anon key [Encrypted]
//
//   ── myID (update these once DTA provides credentials) ─────────
//   MYID_ENVIRONMENT      'staging' or 'production'
//   MYID_CLIENT_ID        DTA-issued client ID          [PLACEHOLDER]
//   MYID_CLIENT_SECRET    DTA-issued client secret      [PLACEHOLDER][Encrypted]
//   MYID_REDIRECT_URI     https://jerrya-byte.github.io/secure-auth-spa/
// ================================================================

// ── myID OIDC endpoint configuration ─────────────────────────
// NOTE: Confirm exact endpoint URLs with DTA during onboarding.
// These follow the documented auth.identity.gov.au URL pattern.
// DTA provides a /.well-known/openid-configuration discovery doc
// at the issuer URL once your app is onboarded.
const MYID_ENDPOINTS = {
  staging: {
    issuer:                'https://auth.stest.identity.gov.au',                   // ← confirm with DTA
    authorizationEndpoint: 'https://auth.stest.identity.gov.au/oauth2/authorize',  // ← confirm with DTA
    tokenEndpoint:         'https://auth.stest.identity.gov.au/oauth2/token',      // ← confirm with DTA
  },
  production: {
    issuer:                'https://auth.identity.gov.au',
    authorizationEndpoint: 'https://auth.identity.gov.au/oauth2/authorize',        // ← confirm with DTA
    tokenEndpoint:         'https://auth.identity.gov.au/oauth2/token',            // ← confirm with DTA
  },
};

// TDIF Identity Proofing minimum requirement
// IP2 = Standard: requires photo ID (passport/licence) + Medicare or equivalent
// TDIF ACR value: 'urn:id.gov.au:tdif:acr:ip2:cl2'
// IP3 = Strong: same docs as IP2 + biometric selfie matched against passport photo
const REQUIRED_IP_LEVEL = 2;

// ── Helpers ───────────────────────────────────────────────────

function corsHeaders(origin, env) {
  const allowed = env.ALLOWED_ORIGIN || 'https://jerrya-byte.github.io';
  const o = (origin && origin.startsWith(allowed)) ? origin : allowed;
  return {
    'Access-Control-Allow-Origin': o,
    'Access-Control-Allow-Methods': 'POST, OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type',
  };
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
  const data = await res.json();
  if (!res.ok) throw new Error(data.error_description || 'Failed to acquire Entra token');
  return data.access_token;
}

async function callGraph(token, path, method = 'GET', body = null, beta = false) {
  const base = beta
    ? 'https://graph.microsoft.com/beta'
    : 'https://graph.microsoft.com/v1.0';
  const opts = {
    method,
    headers: {
      Authorization: `Bearer ${token}`,
      'Content-Type': 'application/json',
    },
  };
  if (body) opts.body = JSON.stringify(body);
  return fetch(`${base}${path}`, opts);
}

// HS256 JWT signing via Web Crypto (no imports needed in Workers)
async function signJwt(payload, secret) {
  const b64url = (obj) =>
    btoa(JSON.stringify(obj))
      .replace(/=/g, '').replace(/\+/g, '-').replace(/\//g, '_');
  const msg = `${b64url({ alg: 'HS256', typ: 'JWT' })}.${b64url(payload)}`;
  const key = await crypto.subtle.importKey(
    'raw', new TextEncoder().encode(secret),
    { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']
  );
  const sig = await crypto.subtle.sign('HMAC', key, new TextEncoder().encode(msg));
  const sigB64 = btoa(String.fromCharCode(...new Uint8Array(sig)))
    .replace(/=/g, '').replace(/\+/g, '-').replace(/\//g, '_');
  return `${msg}.${sigB64}`;
}

// Parse JWT payload without signature verification.
// SAFE here because we only call this on tokens fetched DIRECTLY
// from myID's token endpoint — never on user-supplied tokens.
function parseJwt(token) {
  const parts = token.split('.');
  if (parts.length !== 3) throw new Error('Invalid JWT: expected 3 parts');
  let payload = parts[1].replace(/-/g, '+').replace(/_/g, '/');
  while (payload.length % 4) payload += '=';
  return JSON.parse(atob(payload));
}

// Extract numeric IP level from TDIF ACR claim string
// 'urn:id.gov.au:tdif:acr:ip2:cl2' → 2
// 'urn:id.gov.au:tdif:acr:ip3:cl2' → 3
function extractIpLevel(acr) {
  if (!acr) return 0;
  const m = acr.match(/ip(\d+)/i);
  return m ? parseInt(m[1], 10) : 0;
}

// ── Main fetch handler ────────────────────────────────────────

export default {
  async fetch(request, env) {
    const origin = request.headers.get('Origin') || '';
    const cors = corsHeaders(origin, env);

    // Preflight
    if (request.method === 'OPTIONS') {
      return new Response(null, { status: 204, headers: cors });
    }

    let body;
    try {
      body = await request.json();
    } catch {
      return new Response(
        JSON.stringify({ error: 'Invalid JSON body' }),
        { status: 400, headers: { ...cors, 'Content-Type': 'application/json' } }
      );
    }

    const respond = (data, status = 200) =>
      new Response(JSON.stringify(data), {
        status,
        headers: { ...cors, 'Content-Type': 'application/json' },
      });

    try {

      // ════════════════════════════════════════════════════════
      // check-email — verify Entra UPN exists
      // ════════════════════════════════════════════════════════
      if (body.action === 'check-email') {
        const token = await getEntraToken(env);
        const email = (body.email || '').toLowerCase().trim();
        const res = await callGraph(
          token,
          `/users?$filter=userPrincipalName eq '${email}'` +
          `&$select=id,displayName,userPrincipalName`
        );
        const data = await res.json();
        if (!res.ok) return respond({ error: data.error?.message || 'Graph API error' }, 400);
        const user = data.value?.[0];
        if (!user) return respond({ exists: false });
        return respond({ exists: true, userId: user.id, displayName: user.displayName });
      }

      // ════════════════════════════════════════════════════════
      // check-reference
      // Looks up an onboarding reference# in the Supabase
      // identity_records table. If found, also resolves the
      // matching Entra user (so subsequent steps — myID + TAP —
      // have a userId to work with).
      //
      // Request body:
      //   reference   string   onboarding reference (e.g. OB-2026-12345)
      //
      // Response (found):
      //   exists      true
      //   reference   string
      //   email       string   email from identity_records
      //   userId      string   Entra user object ID (may be empty)
      //   givenName   string
      //   familyName  string
      //   displayName string   Entra displayName when available
      //
      // Response (not found):
      //   exists      false
      // ════════════════════════════════════════════════════════
      if (body.action === 'check-reference') {
        const reference = (body.reference || '').trim();
        if (!reference) {
          return respond({ error: 'Reference number is required.' }, 400);
        }

        // ── Step 1: Query Supabase identity_records by reference ──
        const supaUrl =
          `${env.SUPABASE_URL}/rest/v1/identity_records` +
          `?reference=eq.${encodeURIComponent(reference)}` +
          `&select=reference,given_name,family_name,email` +
          `&limit=1`;

        const supaRes = await fetch(supaUrl, {
          headers: {
            apikey:        env.SUPABASE_KEY,
            Authorization: `Bearer ${env.SUPABASE_KEY}`,
          },
        });

        if (!supaRes.ok) {
          const errText = await supaRes.text().catch(() => '');
          return respond({
            error: `Supabase lookup failed: ${errText || supaRes.status}`,
          }, 502);
        }

        const rows = await supaRes.json().catch(() => []);
        const record = Array.isArray(rows) && rows.length > 0 ? rows[0] : null;

        if (!record) {
          return respond({ exists: false });
        }

        // ── Step 2: Resolve matching Entra user (best-effort) ─────
        // We look up the Entra user by mail/UPN so the later TAP
        // generation step has the userId. If the user can't be
        // resolved we still return exists:true so the SPA can
        // proceed; downstream errors (e.g. TAP) will be surfaced
        // to the user at that point.
        let entraUserId   = '';
        let entraDisplay  = '';
        const recordEmail = (record.email || '').toLowerCase().trim();

        if (recordEmail) {
          try {
            const token = await getEntraToken(env);
            const filter = `userPrincipalName eq '${recordEmail}' or mail eq '${recordEmail}'`;
            const lookup = await callGraph(
              token,
              `/users?$filter=${encodeURIComponent(filter)}` +
              `&$select=id,displayName,userPrincipalName,mail`
            );
            const data = await lookup.json().catch(() => ({}));
            const user = data.value?.[0];
            if (user) {
              entraUserId  = user.id || '';
              entraDisplay = user.displayName || '';
            }
          } catch (e) {
            console.error('Entra lookup for reference failed (non-fatal):', e.message);
          }
        }

        return respond({
          exists:      true,
          reference:   record.reference,
          email:       record.email || '',
          userId:      entraUserId,
          givenName:   record.given_name  || '',
          familyName:  record.family_name || '',
          displayName: entraDisplay,
        });
      }

      // ════════════════════════════════════════════════════════
      // generate-token — sign HS256 JWT
      // ════════════════════════════════════════════════════════
      if (body.action === 'generate-token') {
        const now = Math.floor(Date.now() / 1000);
        const payload = {
          sub:   body.userId,
          email: body.email,
          name:  body.displayName,
          iat:   now,
          exp:   now + 3600,
          iss:   'secureauth-portal',
        };
        const token = await signJwt(payload, env.JWT_SECRET);
        return respond({ token });
      }

      // ════════════════════════════════════════════════════════
      // generate-tap — Temporary Access Pass via Graph
      // ════════════════════════════════════════════════════════
      if (body.action === 'generate-tap') {
        const token = await getEntraToken(env);
        const res = await callGraph(
          token,
          `/users/${body.userId}/authentication/temporaryAccessPassMethods`,
          'POST',
          { isUsableOnce: true, lifetimeInMinutes: 60 }
        );
        const data = await res.json();
        if (!res.ok) return respond({ error: data.error?.message || 'TAP generation failed' }, 400);
        return respond({
          tap:       data.temporaryAccessPass,
          expiresAt: data.startDateTime,
        });
      }

      // ════════════════════════════════════════════════════════
      // fido2-begin — start FIDO2 registration (Graph beta)
      // ════════════════════════════════════════════════════════
      if (body.action === 'fido2-begin') {
        const token = await getEntraToken(env);
        const res = await callGraph(
          token,
          `/users/${body.userId}/authentication/fido2Methods/creationOptions`,
          'GET', null, true
        );
        const data = await res.json();
        if (!res.ok) return respond({ error: data.error?.message || 'FIDO2 begin failed' }, 400);
        // Graph beta returns options under 'publicKey' (not 'publicKeyCredentialCreationOptions')
        const options = data.publicKey || data.publicKeyCredentialCreationOptions || data;
        return respond({ options });
      }

      // ════════════════════════════════════════════════════════
      // fido2-complete — finish FIDO2 registration (Graph beta)
      // ════════════════════════════════════════════════════════
      if (body.action === 'fido2-complete') {
        const token = await getEntraToken(env);
        const displayName = (body.displayName || 'Security Key').substring(0, 30);
        const res = await callGraph(
          token,
          `/users/${body.userId}/authentication/fido2Methods`,
          'POST',
          {
            displayName,
            publicKeyCredential: {
              id: body.credentialId,
              response: {
                clientDataJSON:    body.clientDataJSON,
                attestationObject: body.attestationObject,
              },
            },
          },
          true
        );
        const data = await res.json();
        if (!res.ok) return respond({ error: data.error?.message || 'FIDO2 complete failed' }, 400);
        return respond({ success: true, methodId: data.id });
      }

      // ════════════════════════════════════════════════════════
      // myid-auth-start
      // Builds and returns the myID OIDC authorization URL.
      // The SPA redirects the user's browser to this URL.
      //
      // Request body:
      //   code_challenge  string   PKCE S256 code challenge (generated by SPA)
      //   state           string   Random state value (generated by SPA)
      //   nonce           string   Random nonce value (generated by SPA)
      //
      // Response:
      //   authorizationUrl  string   Full myID authorization URL
      //   environment       string   'staging' or 'production'
      // ════════════════════════════════════════════════════════
      if (body.action === 'myid-auth-start') {
        const environment = (env.MYID_ENVIRONMENT || 'staging').toLowerCase();
        const config = MYID_ENDPOINTS[environment] || MYID_ENDPOINTS.staging;

        // Guard: fail clearly if DTA credentials haven't been configured yet
        if (!env.MYID_CLIENT_ID || env.MYID_CLIENT_ID.startsWith('PLACEHOLDER')) {
          return respond({
            error: 'myID is not yet configured. ' +
              'Update MYID_CLIENT_ID, MYID_CLIENT_SECRET, and MYID_REDIRECT_URI ' +
              'in Cloudflare Worker secrets after completing DTA onboarding.',
            configRequired: true,
          }, 503);
        }

        const params = new URLSearchParams({
          response_type:         'code',
          client_id:             env.MYID_CLIENT_ID,
          redirect_uri:          env.MYID_REDIRECT_URI || 'https://jerrya-byte.github.io/secure-auth-spa/',
          scope:                 'openid profile email',
          state:                 body.state,
          nonce:                 body.nonce,
          code_challenge:        body.code_challenge,
          code_challenge_method: 'S256',
          // Request minimum IP2 (Standard) identity strength
          // TDIF ACR: urn:id.gov.au:tdif:acr:ip2:cl2  ← confirm exact value with DTA
          acr_values: 'urn:id.gov.au:tdif:acr:ip2:cl2',
        });

        return respond({
          authorizationUrl: `${config.authorizationEndpoint}?${params.toString()}`,
          environment,
        });
      }

      // ════════════════════════════════════════════════════════
      // myid-callback
      // Exchanges the OIDC authorization code for tokens,
      // validates identity proofing level, and stores claims
      // in the Supabase myid_identity_claims table.
      //
      // Request body:
      //   code          string   Authorization code from myID redirect
      //   state         string   State value to validate
      //   nonce         string   Nonce from auth-start (for replay prevention)
      //   code_verifier string   PKCE verifier (generated by SPA before redirect)
      //   entra_email   string   Entra UPN verified in the previous step
      //
      // Response (success):
      //   success       true
      //   ipLevel       number   e.g. 2 for IP2
      //   acr           string   Full ACR claim value
      //   givenName     string
      //   familyName    string
      //   email         string   myID-verified email (may differ from Entra email)
      //
      // Response (insufficient strength):
      //   success       false
      //   reason        'insufficient_strength'
      //   ipLevel       number
      //   acr           string
      //   requiredLevel number   (2)
      //   message       string   Human-readable explanation
      // ════════════════════════════════════════════════════════
      if (body.action === 'myid-callback') {
        const environment = (env.MYID_ENVIRONMENT || 'staging').toLowerCase();
        const config = MYID_ENDPOINTS[environment] || MYID_ENDPOINTS.staging;

        // ── Step 1: Exchange authorization code for tokens ────
        const tokenRes = await fetch(config.tokenEndpoint, {
          method: 'POST',
          headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
          body: new URLSearchParams({
            grant_type:    'authorization_code',
            code:          body.code,
            redirect_uri:  env.MYID_REDIRECT_URI || 'https://jerrya-byte.github.io/secure-auth-spa/',
            client_id:     env.MYID_CLIENT_ID,
            client_secret: env.MYID_CLIENT_SECRET,
            code_verifier: body.code_verifier,
          }),
        });

        if (!tokenRes.ok) {
          const err = await tokenRes.json().catch(() => ({}));
          console.error('myID token exchange error:', JSON.stringify(err));
          return respond({
            error: err.error_description || err.error || 'Token exchange with myID failed',
          }, 400);
        }

        const tokens = await tokenRes.json();

        if (!tokens.id_token) {
          return respond({ error: 'myID did not return an ID token' }, 400);
        }

        // ── Step 2: Parse ID token claims ─────────────────────
        let claims;
        try {
          claims = parseJwt(tokens.id_token);
        } catch (e) {
          return respond({ error: 'Failed to parse myID ID token: ' + e.message }, 400);
        }

        console.log('myID token claims:', JSON.stringify(claims));

        // ── Step 3: Validate nonce (replay attack prevention) ─
        if (claims.nonce !== body.nonce) {
          console.error('Nonce mismatch. Expected:', body.nonce, 'Got:', claims.nonce);
          return respond({ error: 'Nonce mismatch — possible replay attack. Please try again.' }, 400);
        }

        // ── Step 4: Check identity proofing level ─────────────
        // TDIF ACR values:
        //   urn:id.gov.au:tdif:acr:ip1:cl1  →  IP1 (Basic)
        //   urn:id.gov.au:tdif:acr:ip2:cl2  →  IP2 (Standard) ← minimum required
        //   urn:id.gov.au:tdif:acr:ip3:cl2  →  IP3 (Strong)
        const acr = claims.acr || '';
        const ipLevel = extractIpLevel(acr);

        if (ipLevel < REQUIRED_IP_LEVEL) {
          const levelName = ipLevel === 0 ? 'Unknown' : ipLevel === 1 ? 'Basic (IP1)' : `IP${ipLevel}`;
          return respond({
            success:       false,
            reason:        'insufficient_strength',
            ipLevel,
            acr,
            requiredLevel: REQUIRED_IP_LEVEL,
            message: ipLevel === 0
              ? 'Your myID identity strength could not be determined. ' +
                'Please ensure your myID is set to Standard or Strong and try again.'
              : `Your myID identity strength is ${levelName}, but Standard (IP2) or Strong (IP3) is required. ` +
                'Please upgrade your myID identity strength and try again.',
          });
        }

        // ── Step 5: Store all claims in Supabase ──────────────
        const claimsRecord = {
          entra_email:  body.entra_email || null,
          sub:          claims.sub,
          acr:          acr || null,
          ip_level:     `IP${ipLevel}`,
          given_name:   claims.given_name  || null,
          family_name:  claims.family_name || null,
          email:        claims.email       || null,
          raw_claims:   claims,            // full JSONB blob
          verified_at:  new Date().toISOString(),
        };

        const supaRes = await fetch(
          `${env.SUPABASE_URL}/rest/v1/myid_identity_claims`,
          {
            method: 'POST',
            headers: {
              apikey:         env.SUPABASE_KEY,
              Authorization:  `Bearer ${env.SUPABASE_KEY}`,
              'Content-Type': 'application/json',
              Prefer:         'return=minimal',
            },
            body: JSON.stringify(claimsRecord),
          }
        );

        if (!supaRes.ok) {
          // Non-fatal — log but don't block the user
          const supaErr = await supaRes.text();
          console.error('Supabase insert failed (non-fatal):', supaErr);
        }

        // ── Step 6: Return success with verified identity info ─
        return respond({
          success:    true,
          ipLevel,
          acr,
          givenName:  claims.given_name  || '',
          familyName: claims.family_name || '',
          email:      claims.email       || '',
        });
      }

      // Unknown action
      return respond({ error: `Unknown action: ${body.action}` }, 400);

    } catch (err) {
      console.error('Worker unhandled error:', err.message, err.stack);
      return respond({ error: err.message || 'Internal server error' }, 500);
    }
  },
};
