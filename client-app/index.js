import express from 'express';
import cookieParser from 'cookie-parser';
import { randomBytes, createHash } from 'crypto';

const app = express();
app.use(cookieParser());
app.use(express.urlencoded({ extended: false }));
app.use(express.json());

// ─── Config ───────────────────────────────────────────────────────────────────
const CLIENT_ID    = 'demo-client';
const REDIRECT_URI = 'http://localhost:4000/callback';
const AUTH_SERVER  = 'http://localhost:3000';
const RESOURCE_SERVER = 'http://localhost:5000';
const SCOPE        = 'read write';

// ─── In-memory token store (per-session) ─────────────────────────────────────
const sessions = new Map(); // sessionId → { access_token, refresh_token }

// ─── Helpers ──────────────────────────────────────────────────────────────────
function base64url(input) {
  return input.toString('base64')
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=+$/, '');
}

function generateCodeVerifier() {
  return base64url(randomBytes(32));
}

function generateCodeChallenge(verifier) {
  const hash = createHash('sha256').update(verifier).digest();
  return base64url(hash);
}

function generateState() {
  return base64url(randomBytes(16));
}

// ─── GET / — Home page ────────────────────────────────────────────────────────
app.get('/', (req, res) => {
  const sessionId = req.cookies.sessionId;
  const session   = sessionId ? sessions.get(sessionId) : null;

  res.send(`
    <!DOCTYPE html>
    <html lang="en">
    <head>
      <meta charset="UTF-8" />
      <meta name="viewport" content="width=device-width, initial-scale=1.0" />
      <title>OAuth Client App</title>
      <style>
        *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }
        body { font-family: system-ui, sans-serif; background: #0f0f17; color: #e2e8f0; min-height: 100vh; display: flex; flex-direction: column; align-items: center; justify-content: center; gap: 1.5rem; padding: 2rem; }
        h1  { font-size: 2rem; font-weight: 700; background: linear-gradient(135deg, #a78bfa, #34d399); -webkit-background-clip: text; -webkit-text-fill-color: transparent; }
        .card { background: #1a1a2e; border: 1px solid #2d2d4e; border-radius: 12px; padding: 2rem; width: 100%; max-width: 480px; box-shadow: 0 20px 60px rgba(0,0,0,.5); }
        p   { font-size: 0.9rem; color: #94a3b8; margin-bottom: 1.25rem; }
        a.btn, button.btn { display: inline-block; padding: 0.65rem 1.4rem; border: none; border-radius: 8px; font-size: 0.9rem; font-weight: 600; cursor: pointer; text-decoration: none; transition: opacity .15s; }
        .btn-primary { background: linear-gradient(135deg, #7c3aed, #a78bfa); color: #fff; }
        .btn-danger  { background: #3d1a1a; color: #f87171; }
        .btn-secondary { background: #1e293b; color: #94a3b8; margin-left: .5rem; }
        .btn:hover { opacity: 0.85; }
        .status { font-size: 0.8rem; color: #34d399; background: #0d2e22; border: 1px solid #34d399; border-radius: 6px; padding: .4rem .8rem; display: inline-block; margin-bottom: 1rem; }
        .token-box { font-size: 0.72rem; font-family: monospace; background: #12122a; border-radius: 6px; padding: .75rem; word-break: break-all; color: #818cf8; margin-top: .75rem; max-height: 120px; overflow-y: auto; }
      </style>
    </head>
    <body>
      <h1>OAuth 2.0 Demo Client</h1>
      <div class="card">
        ${session
          ? `<div class="status">✅ Authenticated</div>
             <p>You have a valid access token. Use the buttons below to call the resource server or log out.</p>
             <a class="btn btn-primary" href="/call-api">Call Resource Server</a>
             <a class="btn btn-secondary" href="/refresh">Refresh Token</a>
             <form method="POST" action="/logout" style="display:inline">
               <button class="btn btn-danger" type="submit" style="margin-left:.5rem">Logout</button>
             </form>`
          : `<p>You are not authenticated. Click below to start the OAuth 2.0 Authorization Code + PKCE flow.</p>
             <a class="btn btn-primary" href="/login">Login with OAuth</a>`
        }
      </div>
    </body>
    </html>
  `);
});

// ─── GET /login — Start the OAuth flow ───────────────────────────────────────
app.get('/login', (req, res) => {
  const codeVerifier  = generateCodeVerifier();
  const codeChallenge = generateCodeChallenge(codeVerifier);
  const state         = generateState();

  // Persist verifier & state in a short-lived cookie
  res.cookie('pkce_verifier', codeVerifier, { httpOnly: true, maxAge: 5 * 60 * 1000 });
  res.cookie('oauth_state',   state,        { httpOnly: true, maxAge: 5 * 60 * 1000 });

  const params = new URLSearchParams({
    response_type:         'code',
    client_id:             CLIENT_ID,
    redirect_uri:          REDIRECT_URI,
    scope:                 SCOPE,
    state,
    code_challenge:        codeChallenge,
    code_challenge_method: 'S256',
  });

  res.redirect(`${AUTH_SERVER}/authorize?${params.toString()}`);
});

// ─── GET /callback — Handle the authorization code redirect ──────────────────
app.get('/callback', async (req, res) => {
  const { code, state, error, error_description } = req.query;

  if (error) {
    return res.send(`
      <p style="color:red;font-family:sans-serif;padding:2rem">
        <b>Error:</b> ${error}<br/>
        ${error_description || ''}
        <br/><br/><a href="/">← Back</a>
      </p>
    `);
  }

  // --- Validate state ---
  const savedState = req.cookies.oauth_state;
  if (!savedState || savedState !== state) {
    return res.status(400).send('<p style="color:red;font-family:sans-serif;padding:2rem">State mismatch — potential CSRF attack.</p>');
  }

  const codeVerifier = req.cookies.pkce_verifier;
  if (!codeVerifier) {
    return res.status(400).send('<p style="color:red;font-family:sans-serif;padding:2rem">Missing code_verifier cookie.</p>');
  }

  // Clear PKCE cookies
  res.clearCookie('pkce_verifier');
  res.clearCookie('oauth_state');

  // --- Exchange code for tokens ---
  try {
    const tokenResponse = await fetch(`${AUTH_SERVER}/token`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        grant_type:    'authorization_code',
        code,
        redirect_uri:  REDIRECT_URI,
        client_id:     CLIENT_ID,
        code_verifier: codeVerifier,
      }),
    });

    const tokens = await tokenResponse.json();

    if (!tokenResponse.ok || tokens.error) {
      return res.status(400).send(`<p style="color:red;font-family:sans-serif;padding:2rem">Token error: ${JSON.stringify(tokens)}</p>`);
    }

    // Store in server-side session
    const sessionId = base64url(randomBytes(16));
    sessions.set(sessionId, tokens);
    res.cookie('sessionId', sessionId, { httpOnly: true, maxAge: 7 * 24 * 60 * 60 * 1000 });
    res.redirect('/');
  } catch (err) {
    res.status(500).send(`<p style="color:red;font-family:sans-serif;padding:2rem">Failed to exchange code: ${err.message}</p>`);
  }
});

// ─── GET /call-api — Call the resource server with the access token ───────────
app.get('/call-api', async (req, res) => {
  const sessionId = req.cookies.sessionId;
  const session   = sessionId ? sessions.get(sessionId) : null;

  if (!session) {
    return res.redirect('/');
  }

  try {
    const apiRes = await fetch(`${RESOURCE_SERVER}/me`, {
      headers: { Authorization: `Bearer ${session.access_token}` },
    });

    const data = await apiRes.json();

    res.send(`
      <!DOCTYPE html>
      <html lang="en">
      <head>
        <meta charset="UTF-8" />
        <title>API Response – OAuth Client</title>
        <style>
          body { font-family: system-ui, sans-serif; background: #0f0f17; color: #e2e8f0; min-height: 100vh; display: flex; flex-direction: column; align-items: center; justify-content: center; gap: 1rem; padding: 2rem; }
          .card { background: #1a1a2e; border: 1px solid #2d2d4e; border-radius: 12px; padding: 2rem; max-width: 560px; width: 100%; }
          h2 { color: #a78bfa; margin-bottom: 1rem; }
          pre { background: #12122a; padding: 1rem; border-radius: 8px; font-size: 0.82rem; color: #34d399; overflow-x: auto; }
          a  { color: #a78bfa; text-decoration: none; font-size: 0.9rem; }
        </style>
      </head>
      <body>
        <div class="card">
          <h2>Resource Server Response</h2>
          <pre>${JSON.stringify(data, null, 2)}</pre>
          <br/><a href="/">← Back Home</a>
        </div>
      </body>
      </html>
    `);
  } catch (err) {
    res.status(500).send(`<p style="color:red;font-family:sans-serif;padding:2rem">API call failed: ${err.message}</p>`);
  }
});

// ─── GET /refresh — Use refresh token to get a new access token ───────────────
app.get('/refresh', async (req, res) => {
  const sessionId = req.cookies.sessionId;
  const session   = sessionId ? sessions.get(sessionId) : null;

  if (!session || !session.refresh_token) {
    return res.redirect('/');
  }

  try {
    const tokenResponse = await fetch(`${AUTH_SERVER}/token`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        grant_type:    'refresh_token',
        refresh_token: session.refresh_token,
        client_id:     CLIENT_ID,
      }),
    });

    const tokens = await tokenResponse.json();

    if (!tokenResponse.ok || tokens.error) {
      return res.status(400).send(`<p style="color:red;font-family:sans-serif;padding:2rem">Refresh error: ${JSON.stringify(tokens)}</p>`);
    }

    sessions.set(sessionId, tokens);
    res.redirect('/');
  } catch (err) {
    res.status(500).send(`<p style="color:red;font-family:sans-serif;padding:2rem">Refresh failed: ${err.message}</p>`);
  }
});

// ─── POST /logout ─────────────────────────────────────────────────────────────
app.post('/logout', (req, res) => {
  const sessionId = req.cookies.sessionId;
  if (sessionId) sessions.delete(sessionId);
  res.clearCookie('sessionId');
  res.redirect('/');
});

// ─── Start ────────────────────────────────────────────────────────────────────
const PORT = 4000;
app.listen(PORT, () => {
  console.log(`✅  Client App running at http://localhost:${PORT}`);
});
