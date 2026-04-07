import "dotenv/config";
import express from "express";
import { createRemoteJWKSet, jwtVerify } from "jose";

// ─── Config ───────────────────────────────────────────────────────────────────
const PORT = Number(process.env.PORT) || 3000;
const AEGIS_BASE_URL = (process.env.AEGIS_BASE_URL || "https://aegis-dev.preprodcxr.co").replace(/\/$/, "");
const AEGIS_COUNTRY = process.env.AEGIS_COUNTRY || "co";
const AEGIS_CLIENT_ID = process.env.AEGIS_CLIENT_ID || "";
const AEGIS_CLIENT_SECRET = process.env.AEGIS_CLIENT_SECRET || "";
// Role required by the /resource/admin route. Override via env.
const AEGIS_REQUIRED_ROLE = process.env.AEGIS_REQUIRED_ROLE || "aegis-admin";
// Optional: restrict accepted issuer (e.g. https://aegis-dev.preprod).
// Leave empty to accept any issuer (useful when the issuer URL is env-specific).
const AEGIS_TOKEN_ISSUER = process.env.AEGIS_TOKEN_ISSUER || undefined;

// ─── Aegis JWKS client ────────────────────────────────────────────────────────
// jose's createRemoteJWKSet fetches the JWKS on first use and caches the keys.
// It automatically handles key rotation (re-fetches when an unknown kid is seen).
let _jwks;
function getJwks() {
  if (!_jwks) {
    _jwks = createRemoteJWKSet(
      new URL(`${AEGIS_BASE_URL}/.well-known/jwks.json`)
    );
  }
  return _jwks;
}

// ─── M2M token cache ──────────────────────────────────────────────────────────
const TOKEN_EXPIRY_BUFFER_MS = 30_000; // refresh 30 s before actual expiry
let _cachedToken = null;
let _tokenExpiresAt = 0;

async function fetchM2MToken() {
  if (_cachedToken && Date.now() < _tokenExpiresAt) {
    return _cachedToken;
  }
  if (!AEGIS_CLIENT_ID || !AEGIS_CLIENT_SECRET) {
    throw new Error("AEGIS_CLIENT_ID and AEGIS_CLIENT_SECRET must be set");
  }
  const basic = Buffer.from(`${AEGIS_CLIENT_ID}:${AEGIS_CLIENT_SECRET}`).toString("base64");
  const res = await fetch(`${AEGIS_BASE_URL}/api/v1/auth/${AEGIS_COUNTRY}/token`, {
    method: "POST",
    headers: { Authorization: `Basic ${basic}` },
  });
  const text = await res.text();
  if (!res.ok) {
    throw new Error(`Aegis M2M login failed [${res.status}]: ${text.slice(0, 300)}`);
  }
  const json = JSON.parse(text);
  const data = json?.data ?? json; // ThStandardResponse: { data: { access_token, expires_in, ... } }
  _cachedToken = data.access_token;
  _tokenExpiresAt = Date.now() + data.expires_in * 1000 - TOKEN_EXPIRY_BUFFER_MS;
  return _cachedToken;
}

// ─── Middleware: validate Aegis JWT ───────────────────────────────────────────
// Fetches Aegis JWKS, verifies the RS256 signature, and checks expiry.
// On success, attaches the decoded payload to req.jwt.
async function validateJwt(req, res, next) {
  const auth = req.headers.authorization ?? "";
  if (!auth.startsWith("Bearer ")) {
    return res.status(401).json({
      error: "Missing or invalid Authorization header",
      hint: "Expected: Authorization: Bearer <aegis_access_token>",
      howToGetToken: `GET /token  →  calls POST ${AEGIS_BASE_URL}/api/v1/auth/${AEGIS_COUNTRY}/token`,
    });
  }
  const token = auth.slice(7);
  try {
    const options = {};
    if (AEGIS_TOKEN_ISSUER) options.issuer = AEGIS_TOKEN_ISSUER;
    const { payload } = await jwtVerify(token, getJwks(), options);
    req.jwt = payload;
    next();
  } catch (err) {
    return res.status(401).json({
      error: "JWT validation failed",
      detail: err.message,
      jwksUrl: `${AEGIS_BASE_URL}/.well-known/jwks.json`,
    });
  }
}

// ─── Middleware: validate JWT + require a specific role ───────────────────────
// Aegis M2M tokens carry roles in the top-level "roles" array.
function requireRole(role) {
  return [
    validateJwt,
    (req, res, next) => {
      const tokenRoles = Array.isArray(req.jwt?.roles) ? req.jwt.roles : [];
      if (tokenRoles.includes(role)) {
        return next();
      }
      return res.status(403).json({
        error: "Forbidden — missing required role",
        required_role: role,
        token_roles: tokenRoles,
      });
    },
  ];
}

// ─── Helpers ──────────────────────────────────────────────────────────────────
function decodeJwtPayload(token) {
  try {
    return JSON.parse(Buffer.from(token.split(".")[1], "base64url").toString());
  } catch {
    return null;
  }
}

function jwtSummary(payload) {
  return {
    sub: payload.sub,
    client_id: payload.client_id ?? payload.azp,
    is_aegis: payload.is_aegis,
    is_m2m: payload.is_m2m,
    roles: payload.roles ?? [],
    scope: payload.scope,
    iss: payload.iss,
    exp: payload.exp ? new Date(payload.exp * 1000).toISOString() : undefined,
  };
}

// ─── Simulated protected resources ───────────────────────────────────────────
const RESOURCES = [
  { id: 1, name: "Quarterly Report Q1-2026", type: "document" },
  { id: 2, name: "Payment Transaction Log", type: "table" },
  { id: 3, name: "User Analytics Dashboard", type: "report" },
];

const ADMIN_RESOURCES = [
  { id: 1, name: "System Configuration", classification: "CONFIDENTIAL" },
  { id: 2, name: "Credentials Vault Index", classification: "SECRET" },
  { id: 3, name: "Audit Log Full Export", classification: "CONFIDENTIAL" },
];

// ─── App ──────────────────────────────────────────────────────────────────────
const app = express();
app.use(express.json());

// ── Public ────────────────────────────────────────────────────────────────────

app.get("/health", (_req, res) => {
  res.json({ ok: true, service: "aegis-backend-test" });
});

// ── Step 1: obtain an Aegis M2M token ─────────────────────────────────────────
// This service acts as the consumer: it calls Aegis with its clientId/clientSecret
// and gets back a signed JWT. That JWT can then be used to call protected endpoints.
app.get("/token", async (_req, res) => {
  try {
    const tokenUrl = `${AEGIS_BASE_URL}/api/v1/auth/${AEGIS_COUNTRY}/token`;
    const basic = Buffer.from(`${AEGIS_CLIENT_ID}:${AEGIS_CLIENT_SECRET}`).toString("base64");

    const upstream = await fetch(tokenUrl, {
      method: "POST",
      headers: { Authorization: `Basic ${basic}` },
    });
    const json = await upstream.json();

    if (!upstream.ok) {
      return res.status(upstream.status).json({ error: "M2M login failed", upstream: json });
    }

    const data = json?.data ?? json;
    // Cache the token
    _cachedToken = data.access_token;
    _tokenExpiresAt = Date.now() + data.expires_in * 1000 - TOKEN_EXPIRY_BUFFER_MS;

    res.json({
      tokenUrl,
      clientId: AEGIS_CLIENT_ID,
      country: AEGIS_COUNTRY,
      upstreamStatus: upstream.status,
      tokenResponse: {
        token_type: data.token_type,
        expires_in: data.expires_in,
        scope: data.scope,
        access_token: data.access_token,
      },
      // Decoded for inspection — in a real service you would NOT return this
      jwtPayload: decodeJwtPayload(data.access_token),
    });
  } catch (err) {
    res.status(500).json({ error: err instanceof Error ? err.message : String(err) });
  }
});

// ── Step 2a: public resource — no auth ────────────────────────────────────────
app.get("/resource/public", (_req, res) => {
  res.json({
    message: "Public resource — no authentication required",
    resources: RESOURCES,
  });
});

// ── Step 2b: protected resource — JWT signature valid, no role check ──────────
// Validates: RS256 signature against Aegis JWKS + token expiry.
// Does NOT check roles — any valid Aegis JWT is accepted.
app.get("/resource/protected", validateJwt, (req, res) => {
  res.json({
    message: "Access granted — JWT signature and expiry valid",
    validation: "RS256 signature (Aegis JWKS) + expiry — no role check",
    jwksUrl: `${AEGIS_BASE_URL}/.well-known/jwks.json`,
    jwt: jwtSummary(req.jwt),
    resources: RESOURCES,
  });
});

// ── Step 2c: admin resource — JWT + role check ────────────────────────────────
// Validates: RS256 signature + token expiry + presence of AEGIS_REQUIRED_ROLE in roles[].
app.get("/resource/admin", ...requireRole(AEGIS_REQUIRED_ROLE), (req, res) => {
  res.json({
    message: `Access granted — JWT valid and role '${AEGIS_REQUIRED_ROLE}' confirmed`,
    validation: `RS256 signature (Aegis JWKS) + expiry + role '${AEGIS_REQUIRED_ROLE}'`,
    jwksUrl: `${AEGIS_BASE_URL}/.well-known/jwks.json`,
    jwt: jwtSummary(req.jwt),
    adminResources: ADMIN_RESOURCES,
  });
});

// ── Step 2d: dynamic role check — test any role from the Aegis token ──────────
// GET /resource/role/aegis-reader  → checks for 'aegis-reader'
// GET /resource/role/ADMIN         → checks for 'ADMIN'
app.get("/resource/role/:roleName", validateJwt, (req, res) => {
  const { roleName } = req.params;
  const tokenRoles = Array.isArray(req.jwt?.roles) ? req.jwt.roles : [];
  if (!tokenRoles.includes(roleName)) {
    return res.status(403).json({
      error: "Forbidden — missing required role",
      required_role: roleName,
      token_roles: tokenRoles,
    });
  }
  res.json({
    message: `Access granted — JWT valid and role '${roleName}' confirmed`,
    validation: `RS256 signature (Aegis JWKS) + expiry + role '${roleName}'`,
    jwksUrl: `${AEGIS_BASE_URL}/.well-known/jwks.json`,
    jwt: jwtSummary(req.jwt),
    resources: RESOURCES,
  });
});

// ─────────────────────────────────────────────────────────────────────────────
app.listen(PORT, () => {
  const base = `http://localhost:${PORT}`;
  console.log(`\nAegis M2M test service → ${base}\n`);
  console.log("  ── Step 1: obtain a token ──────────────────────────────────────────────────");
  console.log(`  GET ${base}/token`);
  console.log(`       Authenticates as '${AEGIS_CLIENT_ID}' via Aegis M2M`);
  console.log(`       (POST ${AEGIS_BASE_URL}/api/v1/auth/${AEGIS_COUNTRY}/token)`);
  console.log("");
  console.log("  ── Step 2: use the token ───────────────────────────────────────────────────");
  console.log(`  GET ${base}/resource/public`);
  console.log(`       No auth required`);
  console.log(`  GET ${base}/resource/protected`);
  console.log(`       Requires: Bearer <token>  →  validates RS256 signature (no roles)`);
  console.log(`  GET ${base}/resource/admin`);
  console.log(`       Requires: Bearer <token>  →  validates signature + role '${AEGIS_REQUIRED_ROLE}'`);
  console.log(`  GET ${base}/resource/role/:roleName`);
  console.log(`       Requires: Bearer <token>  →  validates signature + role :roleName`);
  console.log("");
  console.log("  ── Utils ───────────────────────────────────────────────────────────────────");
  console.log(`  GET ${base}/health`);
  console.log("");
  console.log("Config:");
  console.log(`  AEGIS_BASE_URL:      ${AEGIS_BASE_URL}`);
  console.log(`  AEGIS_COUNTRY:       ${AEGIS_COUNTRY}`);
  console.log(`  AEGIS_CLIENT_ID:     ${AEGIS_CLIENT_ID || "(not set)"}`);
  console.log(`  AEGIS_REQUIRED_ROLE: ${AEGIS_REQUIRED_ROLE}`);
  console.log(`  AEGIS_TOKEN_ISSUER:  ${AEGIS_TOKEN_ISSUER || "(any)"}`);
  console.log(`  JWKS:                ${AEGIS_BASE_URL}/.well-known/jwks.json`);
});
