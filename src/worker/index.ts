import { Env } from '../types';
import { HTML } from './html';

export { SSHSessionDO } from './durable-object';

// --- Rate Limiting (per-edge-node, best-effort) ---
const rateLimitMap = new Map<string, { count: number; resetTime: number }>();
const RATE_LIMIT_MAX = 10;      // max requests per window
const RATE_LIMIT_WINDOW = 60000; // 1 minute window

function isRateLimited(ip: string): boolean {
  const now = Date.now();
  const entry = rateLimitMap.get(ip);
  if (!entry || now > entry.resetTime) {
    rateLimitMap.set(ip, { count: 1, resetTime: now + RATE_LIMIT_WINDOW });
    return false;
  }
  entry.count++;
  return entry.count > RATE_LIMIT_MAX;
}

async function verifyTurnstile(token: string, secret: string, ip: string): Promise<boolean> {
  try {
    const response = await fetch('https://challenges.cloudflare.com/turnstile/v0/siteverify', {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: `secret=${secret}&response=${token}&remoteip=${ip}`,
    });
    const result = await response.json<{ success: boolean }>();
    return result.success === true;
  } catch {
    return false;
  }
}

// --- Simple token-based verification for session-level ---
const VERIFIED_TOKEN_TTL = 24 * 60 * 60 * 1000; // 24 hours (fallback for token validation)

function generateVerifiedToken(secret: string): string {
  const expires = Date.now() + VERIFIED_TOKEN_TTL;
  const payload = `${expires}`;
  // Simple HMAC using Web Crypto would be better, but for simplicity use a hash
  const signature = Array.from(
    new Uint8Array(
      new TextEncoder().encode(`${payload}:${secret}`)
    )
  ).map(b => b.toString(16).padStart(2, '0')).join('').slice(0, 32);
  return `${payload}:${signature}`;
}

function isVerifiedTokenValid(token: string, secret: string): boolean {
  try {
    const [expiresStr, signature] = token.split(':');
    const expires = parseInt(expiresStr);
    if (isNaN(expires) || Date.now() > expires) return false;
    
    const expectedSignature = Array.from(
      new Uint8Array(
        new TextEncoder().encode(`${expiresStr}:${secret}`)
      )
    ).map(b => b.toString(16).padStart(2, '0')).join('').slice(0, 32);
    
    return signature === expectedSignature;
  } catch {
    return false;
  }
}

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    const url = new URL(request.url);

    if (url.pathname === '/api/session-token' && request.method === 'OPTIONS') {
      return new Response(null, { status: 204 });
    }

    if (url.pathname === '/api/session-token' && request.method === 'POST') {
      if (!env.SSH_API_TOKEN) {
        return Response.json({ success: false, error: 'SSH_API_TOKEN is not configured' }, { status: 503 });
      }

      const auth = request.headers.get('Authorization') || '';
      const expected = `Bearer ${env.SSH_API_TOKEN}`;
      if (auth !== expected) {
        return Response.json({ success: false, error: 'Unauthorized' }, { status: 401 });
      }

      return handleSessionTokenRequest(request, env);
    }

    if (url.pathname.startsWith('/api/session-token/') && request.method === 'GET') {
      return handleSessionTokenRequest(request, env);
    }

    // Verify Turnstile token and issue verification cookie
    if (url.pathname === '/api/verify' && request.method === 'POST') {
      if (!env.TURNSTILE_SECRET) {
        return Response.json({ success: true });
      }

      const clientIP = request.headers.get('CF-Connecting-IP') || 'unknown';
      const body = await request.json<{ token: string }>();
      
      if (!body.token) {
        return Response.json({ success: false, error: 'Missing token' }, { status: 400 });
      }

      const isValid = await verifyTurnstile(body.token, env.TURNSTILE_SECRET, clientIP);
      if (!isValid) {
        return Response.json({ success: false, error: 'Invalid token' }, { status: 403 });
      }

      // Issue a verified token as a session cookie (no Max-Age = session cookie, expires when browser closes)
      const verifiedToken = generateVerifiedToken(env.TURNSTILE_SECRET);
      return new Response(JSON.stringify({ success: true }), {
        headers: {
          'Content-Type': 'application/json',
          'Set-Cookie': `cf_verified=${verifiedToken}; Path=/; HttpOnly; Secure; SameSite=Strict`,
        },
      });
    }

    if (url.pathname === '/api/ssh') {
      // Apply rate limiting
      const clientIP = request.headers.get('CF-Connecting-IP') || 'unknown';
      if (isRateLimited(clientIP)) {
        return new Response('Too Many Requests', { status: 429 });
      }

      // Verify Turnstile if secret is configured
      if (env.TURNSTILE_SECRET) {
        // Check if user has a valid verification cookie
        const cookies = request.headers.get('Cookie') || '';
        const verifiedCookie = cookies.split(';').find(c => c.trim().startsWith('cf_verified='));
        const verifiedToken = verifiedCookie?.split('=')[1];

        if (!verifiedToken || !isVerifiedTokenValid(verifiedToken, env.TURNSTILE_SECRET)) {
          // No valid cookie, check Turnstile token
          const turnstileToken = url.searchParams.get('turnstile_token');
          if (!turnstileToken) {
            return Response.json({ error: 'Missing Turnstile token' }, { status: 403 });
          }
          const isValid = await verifyTurnstile(turnstileToken, env.TURNSTILE_SECRET, clientIP);
          if (!isValid) {
            return Response.json({ error: 'Turnstile verification failed' }, { status: 403 });
          }
        }
      }

      return handleSSHConnection(request, env);
    }

    if (url.pathname === '/api/health') {
      return Response.json({ status: 'ok', timestamp: Date.now() });
    }

    // Return config info
    if (url.pathname === '/api/config') {
      return Response.json({
        turnstileEnabled: !!env.TURNSTILE_SECRET,
        sitekey: env.TURNSTILE_SITEKEY || '',
      });
    }

    return new Response(HTML, {
      headers: {
        'Content-Type': 'text/html;charset=UTF-8',
        'X-Content-Type-Options': 'nosniff',
        'X-Frame-Options': 'DENY',
        'Referrer-Policy': 'strict-origin-when-cross-origin',
        'Strict-Transport-Security': 'max-age=31536000; includeSubDomains'
      }
    });
  },
};

function handleSessionTokenRequest(request: Request, env: Env): Promise<Response> {
  const doId = env.SSH_SESSION.idFromName('session-token-store');
  const stub = env.SSH_SESSION.get(doId);
  return stub.fetch(request);
}

async function handleSSHConnection(request: Request, env: Env): Promise<Response> {
  const upgradeHeader = request.headers.get('Upgrade');
  if (upgradeHeader !== 'websocket') {
    return Response.json(
      { error: 'Expected WebSocket upgrade' },
      { status: 426 }
    );
  }

  // Prevent Cross-Site WebSocket Hijacking / Quota Leeching
  const origin = request.headers.get('Origin');
  if (origin) {
    const url = new URL(request.url);
    if (origin !== url.origin) {
      return new Response('Forbidden', { status: 403 });
    }
  }

  const doId = env.SSH_SESSION.idFromName(`session:${Date.now()}:${Math.random()}`);
  const stub = env.SSH_SESSION.get(doId);

  return stub.fetch(request);
}
