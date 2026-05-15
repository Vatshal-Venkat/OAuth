import express from 'express';
import { createRemoteJWKSet, jwtVerify } from 'jose';

const app = express();
app.use(express.json());

// ─── Config ───────────────────────────────────────────────────────────────────
const ISSUER     = 'http://localhost:3000';
const AUDIENCE   = 'http://localhost:5000';
const JWKS_URI   = `${ISSUER}/.well-known/jwks.json`;

// Fetch JWKS from auth server automatically
const JWKS = createRemoteJWKSet(new URL(JWKS_URI));

// ─── Middleware: verify Bearer token ─────────────────────────────────────────
async function requireAuth(req, res, next) {
  const authHeader = req.headers.authorization;

  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).json({ error: 'unauthorized', error_description: 'Missing Bearer token' });
  }

  const token = authHeader.slice(7);

  try {
    const { payload } = await jwtVerify(token, JWKS, {
      issuer:   ISSUER,
      audience: AUDIENCE,
    });
    req.user = payload;
    next();
  } catch (err) {
    return res.status(401).json({ error: 'invalid_token', error_description: err.message });
  }
}

// ─── GET /me — Return the authenticated user's profile ───────────────────────
app.get('/me', requireAuth, (req, res) => {
  res.json({
    message: 'Access granted to protected resource!',
    user: {
      sub:   req.user.sub,
      name:  req.user.name,
      email: req.user.email,
    },
    scope: req.user.scope,
    token_info: {
      issued_at:  new Date(req.user.iat * 1000).toISOString(),
      expires_at: new Date(req.user.exp * 1000).toISOString(),
      client_id:  req.user.client_id,
      issuer:     req.user.iss,
    },
  });
});

// ─── GET /data — Another protected endpoint ───────────────────────────────────
app.get('/data', requireAuth, (req, res) => {
  // Optionally check specific scopes
  const scopes = (req.user.scope || '').split(' ');
  if (!scopes.includes('read')) {
    return res.status(403).json({ error: 'insufficient_scope', required: 'read' });
  }

  res.json({
    items: [
      { id: 1, name: 'Sample Resource A', owner: req.user.sub },
      { id: 2, name: 'Sample Resource B', owner: req.user.sub },
      { id: 3, name: 'Sample Resource C', owner: req.user.sub },
    ],
  });
});

// ─── Start ────────────────────────────────────────────────────────────────────
const PORT = 5000;
app.listen(PORT, () => {
  console.log(`✅  Resource Server running at http://localhost:${PORT}`);
  console.log(`    Verifying tokens from issuer: ${ISSUER}`);
  console.log(`    JWKS endpoint: ${JWKS_URI}`);
});
