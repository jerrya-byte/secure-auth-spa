// ================================================================
// SecureAuth — Cloudflare Worker
// Proxies the Entra ID email existence check server-side,
// keeping the client secret out of the browser entirely.
//
// DEPLOY STEPS:
// 1. Go to https://workers.cloudflare.com → sign up free
// 2. Click "Create a Worker"
// 3. Replace all the default code with this entire file
// 4. Click "Save and Deploy"
// 5. Copy your Worker URL (e.g. https://secureauth-proxy.your-name.workers.dev)
// 6. Paste that URL into the SPA config panel field labelled "Worker Proxy URL"
//
// ENVIRONMENT VARIABLES (set these in Workers → Settings → Variables):
//   ENTRA_TENANT_ID     → your Entra tenant ID
//   ENTRA_CLIENT_ID     → your Entra app client ID
//   ENTRA_CLIENT_SECRET → your Entra client secret VALUE
//   ALLOWED_ORIGIN      → https://jerrya-byte.github.io
// ================================================================

export default {
  async fetch(request, env) {

    // ── CORS headers ──────────────────────────────────────────
    const allowedOrigin = env.ALLOWED_ORIGIN || '*';
    const corsHeaders = {
      'Access-Control-Allow-Origin':  allowedOrigin,
      'Access-Control-Allow-Methods': 'POST, OPTIONS',
      'Access-Control-Allow-Headers': 'Content-Type',
    };

    // Handle pre-flight
    if (request.method === 'OPTIONS') {
      return new Response(null, { status: 204, headers: corsHeaders });
    }

    // Only accept POST
    if (request.method !== 'POST') {
      return new Response(JSON.stringify({ error: 'Method not allowed' }), {
        status: 405, headers: { ...corsHeaders, 'Content-Type': 'application/json' }
      });
    }

    try {
      // ── Parse request body ─────────────────────────────────
      const { email } = await request.json();

      if (!email || !email.includes('@')) {
        return new Response(JSON.stringify({ error: 'Invalid email address' }), {
          status: 400, headers: { ...corsHeaders, 'Content-Type': 'application/json' }
        });
      }

      // ── Step 1: Get Entra access token (client credentials) ─
      const tokenRes = await fetch(
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

      const tokenData = await tokenRes.json();

      if (!tokenRes.ok) {
        return new Response(JSON.stringify({
          error: 'Failed to obtain Entra access token',
          detail: tokenData.error_description || tokenData.error,
        }), { status: 502, headers: { ...corsHeaders, 'Content-Type': 'application/json' } });
      }

      // ── Step 2: Query Graph API for user by email ──────────
      const graphRes = await fetch(
        `https://graph.microsoft.com/v1.0/users/${encodeURIComponent(email)}?$select=id,displayName,userPrincipalName`,
        { headers: { Authorization: `Bearer ${tokenData.access_token}` } }
      );

      if (graphRes.status === 404) {
        // User not found — expected, not an error
        return new Response(JSON.stringify({ found: false }), {
          status: 200, headers: { ...corsHeaders, 'Content-Type': 'application/json' }
        });
      }

      if (graphRes.status === 401) {
        return new Response(JSON.stringify({ error: 'Graph API: Unauthorized. Check admin consent.' }), {
          status: 502, headers: { ...corsHeaders, 'Content-Type': 'application/json' }
        });
      }

      if (graphRes.status === 403) {
        return new Response(JSON.stringify({ error: 'Graph API: Forbidden. Ensure User.ReadBasic.All permission is granted.' }), {
          status: 502, headers: { ...corsHeaders, 'Content-Type': 'application/json' }
        });
      }

      if (!graphRes.ok) {
        const errData = await graphRes.json().catch(() => ({}));
        return new Response(JSON.stringify({
          error: errData?.error?.message || `Graph API error (HTTP ${graphRes.status})`
        }), { status: 502, headers: { ...corsHeaders, 'Content-Type': 'application/json' } });
      }

      // User found
      const userData = await graphRes.json();
      return new Response(JSON.stringify({
        found: true,
        displayName: userData.displayName || null,
      }), { status: 200, headers: { ...corsHeaders, 'Content-Type': 'application/json' } });

    } catch (err) {
      return new Response(JSON.stringify({ error: err.message || 'Internal Worker error' }), {
        status: 500, headers: { ...corsHeaders, 'Content-Type': 'application/json' }
      });
    }
  }
};
