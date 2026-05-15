import express from 'express';
import bodyParser from 'body-parser';
import cookieParser from 'cookie-parser';
import { randomBytes, createHash, generateKeyPairSync } from 'crypto';
import { SignJWT, exportJWK, importPKCS8 } from 'jose';

const app = express();

app.use(bodyParser.urlencoded({ extended: false }));
app.use(bodyParser.json());
app.use(cookieParser());

// ─── In-memory stores ────────────────────────────────────────────────────────
const clients = new Map();
const authorizationCodes = new Map();
const refreshTokens = new Map();

// ─── Registered clients ──────────────────────────────────────────────────────
clients.set('demo-client', {
  client_id: 'demo-client',
  redirectUris: ['http://localhost:4000/callback'],
});

// ─── Key material (Ed25519) ──────────────────────────────────────────────────
// Generate a fresh key pair on startup so there's no hard-coded placeholder.
const { privateKey: nodePrivateKey, publicKey: nodePublicKey } =
  generateKeyPairSync('ed25519');

const ISSUER  = 'http://localhost:3000';
const KEY_ID  = 'demo-key-1';

// ─── Helpers ─────────────────────────────────────────────────────────────────
function base64url(input) {
  return input
    .toString('base64')
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=+$/, '');
}

function sha256Base64url(str) {
  const hash = createHash('sha256').update(str).digest();
  return base64url(hash);
}

function generateCode() {
  return base64url(randomBytes(32));
}

function demoUser() {
  return {
    sub: 'Vatshal',
    name: 'Venkat Vatshal',
    email: 'venkatvatshal@gmail.com',
  };
}

// ─── GET /authorize ───────────────────────────────────────────────────────────
// Validates the authorization request and shows the consent screen.
app.get('/authorize', (req, res) => {
  const {
    response_type,
    client_id,
    redirect_uri,
    scope = '',
    state,
    code_challenge,
    code_challenge_method,
  } = req.query;

  // --- Validate client ---
  const client = clients.get(client_id);
  if (!client) {
    return res.status(400).json({ error: 'invalid_client', error_description: 'Unknown client_id' });
  }

  // --- Validate redirect_uri ---
  if (!client.redirectUris.includes(redirect_uri)) {
    return res.status(400).json({ error: 'invalid_request', error_description: 'redirect_uri not registered' });
  }

  // --- Validate response_type ---
  if (response_type !== 'code') {
    const url = new URL(redirect_uri);
    url.searchParams.set('error', 'unsupported_response_type');
    if (state) url.searchParams.set('state', state);
    return res.redirect(url.toString());
  }

  // --- PKCE: require code_challenge ---
  if (!code_challenge) {
    const url = new URL(redirect_uri);
    url.searchParams.set('error', 'invalid_request');
    url.searchParams.set('error_description', 'code_challenge required');
    if (state) url.searchParams.set('state', state);
    return res.redirect(url.toString());
  }

  // --- Store request in a temporary cookie and show consent page ---
  const requestId = base64url(randomBytes(16));
  res.cookie(
    `authRequest_${requestId}`,
    JSON.stringify({ client_id, redirect_uri, scope, state, code_challenge, code_challenge_method }),
    { httpOnly: true, maxAge: 5 * 60 * 1000 } // 5 minutes
  );

  // Simple HTML consent page
  res.send(`
    <!DOCTYPE html>
    <html lang="en">
    <head>
      <meta charset="UTF-8" />
      <title>Authorize – Auth Server</title>
      <style>
        *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }
        body { font-family: system-ui, sans-serif; background: #0f0f17; color: #e2e8f0; min-height: 100vh; display: flex; align-items: center; justify-content: center; }
        .card { background: #1a1a2e; border: 1px solid #2d2d4e; border-radius: 12px; padding: 2.5rem; width: 100%; max-width: 420px; box-shadow: 0 20px 60px rgba(0,0,0,.5); }
        h1 { font-size: 1.4rem; font-weight: 700; margin-bottom: 0.25rem; color: #a78bfa; }
        p  { font-size: 0.875rem; color: #94a3b8; margin-bottom: 1.5rem; }
        .info { background: #12122a; border-radius: 8px; padding: 1rem; margin-bottom: 1.5rem; font-size: 0.85rem; }
        .info span { color: #a78bfa; font-weight: 600; }
        .scope-list { list-style: none; margin: 0.5rem 0 0; }
        .scope-list li::before { content: "✓  "; color: #34d399; }
        .actions { display: flex; gap: 0.75rem; }
        button { flex: 1; padding: 0.65rem 1rem; border: none; border-radius: 8px; font-size: 0.9rem; font-weight: 600; cursor: pointer; transition: opacity .15s; }
        button:hover { opacity: 0.85; }
        .btn-approve { background: linear-gradient(135deg, #7c3aed, #a78bfa); color: #fff; }
        .btn-deny   { background: #2d2d4e; color: #94a3b8; }
      </style>
    </head>
    <body>
      <div class="card">
        <h1>Authorization Request</h1>
        <p>An application is requesting access to your account.</p>
        <div class="info">
          <div><span>Client:</span> ${client_id}</div>
          <div style="margin-top:.4rem"><span>Redirect:</span> ${redirect_uri}</div>
          ${scope ? `<div style="margin-top:.4rem"><span>Scopes:</span></div>
          <ul class="scope-list">${scope.split(' ').map(s => `<li>${s}</li>`).join('')}</ul>` : ''}
        </div>
        <form method="POST" action="/authorize/decision">
          <input type="hidden" name="requestId" value="${requestId}" />
          <div class="actions">
            <button class="btn-approve" type="submit" name="decision" value="approve">Allow</button>
            <button class="btn-deny"    type="submit" name="decision" value="deny">Deny</button>
          </div>
        </form>
      </div>
    </body>
    </html>
  `);
});

// ─── POST /authorize/decision ─────────────────────────────────────────────────
// User clicks Allow or Deny on the consent page.
app.post('/authorize/decision', (req, res) => {
  const { requestId, decision } = req.body;
  const cookieKey = `authRequest_${requestId}`;
  const raw = req.cookies[cookieKey];

  if (!raw) {
    return res.status(400).json({ error: 'invalid_request', error_description: 'Session expired or not found' });
  }

  res.clearCookie(cookieKey);
  const { client_id, redirect_uri, scope, state, code_challenge, code_challenge_method } = JSON.parse(raw);
  const redirectUrl = new URL(redirect_uri);

  if (decision !== 'approve') {
    redirectUrl.searchParams.set('error', 'access_denied');
    if (state) redirectUrl.searchParams.set('state', state);
    return res.redirect(redirectUrl.toString());
  }

  // Issue authorization code
  const code = generateCode();
  authorizationCodes.set(code, {
    client_id,
    redirect_uri,
    scope,
    code_challenge,
    code_challenge_method: code_challenge_method || 'S256',
    user: demoUser(),
    expiresAt: Date.now() + 5 * 60 * 1000, // 5 minutes
  });

  redirectUrl.searchParams.set('code', code);
  if (state) redirectUrl.searchParams.set('state', state);
  res.redirect(redirectUrl.toString());
});

// ─── POST /token ──────────────────────────────────────────────────────────────
// Exchanges an authorization code for tokens, or refreshes an access token.
app.post('/token', async (req, res) => {
  const { grant_type } = req.body;

  if (grant_type === 'authorization_code') {
    return handleAuthorizationCode(req, res);
  }

  if (grant_type === 'refresh_token') {
    return handleRefreshToken(req, res);
  }

  return res.status(400).json({ error: 'unsupported_grant_type' });
});

async function handleAuthorizationCode(req, res) {
  const { code, redirect_uri, client_id, code_verifier } = req.body;

  const codeData = authorizationCodes.get(code);

  if (!codeData) {
    return res.status(400).json({ error: 'invalid_grant', error_description: 'Authorization code not found or already used' });
  }

  // Single-use: delete immediately
  authorizationCodes.delete(code);

  // Expiry check
  if (Date.now() > codeData.expiresAt) {
    return res.status(400).json({ error: 'invalid_grant', error_description: 'Authorization code expired' });
  }

  // client_id match
  if (codeData.client_id !== client_id) {
    return res.status(400).json({ error: 'invalid_grant', error_description: 'client_id mismatch' });
  }

  // redirect_uri match
  if (codeData.redirect_uri !== redirect_uri) {
    return res.status(400).json({ error: 'invalid_grant', error_description: 'redirect_uri mismatch' });
  }

  // PKCE verification
  if (!code_verifier) {
    return res.status(400).json({ error: 'invalid_grant', error_description: 'code_verifier required' });
  }

  const expected = sha256Base64url(code_verifier);
  if (expected !== codeData.code_challenge) {
    return res.status(400).json({ error: 'invalid_grant', error_description: 'code_verifier does not match code_challenge' });
  }

  const tokens = await issueTokens(codeData.user, codeData.scope, client_id);
  return res.json(tokens);
}

async function handleRefreshToken(req, res) {
  const { refresh_token, client_id } = req.body;
  const rtData = refreshTokens.get(refresh_token);

  if (!rtData) {
    return res.status(400).json({ error: 'invalid_grant', error_description: 'Refresh token not found or already used' });
  }

  if (Date.now() > rtData.expiresAt) {
    refreshTokens.delete(refresh_token);
    return res.status(400).json({ error: 'invalid_grant', error_description: 'Refresh token expired' });
  }

  if (rtData.client_id !== client_id) {
    return res.status(400).json({ error: 'invalid_grant', error_description: 'client_id mismatch' });
  }

  // Rotate refresh token
  refreshTokens.delete(refresh_token);
  const tokens = await issueTokens(rtData.user, rtData.scope, client_id);
  return res.json(tokens);
}

async function issueTokens(user, scope, client_id) {
  const privateKey = await importPKCS8(
    nodePrivateKey.export({ type: 'pkcs8', format: 'pem' }).toString(),
    'EdDSA'
  );

  const accessToken = await new SignJWT({
    sub: user.sub,
    name: user.name,
    email: user.email,
    scope,
    client_id,
  })
    .setProtectedHeader({ alg: 'EdDSA', kid: KEY_ID })
    .setIssuer(ISSUER)
    .setAudience('http://localhost:5000')
    .setIssuedAt()
    .setExpirationTime('15m')
    .sign(privateKey);

  const refreshToken = base64url(randomBytes(32));
  refreshTokens.set(refreshToken, {
    user,
    scope,
    client_id,
    expiresAt: Date.now() + 7 * 24 * 60 * 60 * 1000, // 7 days
  });

  return {
    access_token: accessToken,
    token_type: 'Bearer',
    expires_in: 900, // 15 minutes in seconds
    refresh_token: refreshToken,
    scope,
  };
}

// ─── GET /.well-known/jwks.json ───────────────────────────────────────────────
// Public key set so resource servers can verify JWTs.
app.get('/.well-known/jwks.json', async (req, res) => {
  const publicJwk = await exportJWK(nodePublicKey);
  publicJwk.kid = KEY_ID;
  publicJwk.use = 'sig';
  res.json({ keys: [publicJwk] });
});

// ─── GET /.well-known/openid-configuration ────────────────────────────────────
// OpenID Connect Discovery document.
app.get('/.well-known/openid-configuration', (req, res) => {
  res.json({
    issuer: ISSUER,
    authorization_endpoint: `${ISSUER}/authorize`,
    token_endpoint: `${ISSUER}/token`,
    jwks_uri: `${ISSUER}/.well-known/jwks.json`,
    response_types_supported: ['code'],
    grant_types_supported: ['authorization_code', 'refresh_token'],
    code_challenge_methods_supported: ['S256'],
    token_endpoint_auth_methods_supported: ['none'],
  });
});

// ─── Start ────────────────────────────────────────────────────────────────────
const PORT = 3000;
app.listen(PORT, () => {
  console.log(`✅  Auth Server running at http://localhost:${PORT}`);
  console.log(`    JWKS: http://localhost:${PORT}/.well-known/jwks.json`);
  console.log(`    Discovery: http://localhost:${PORT}/.well-known/openid-configuration`);
});