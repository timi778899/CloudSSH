import { Env, SSHConnectionConfig, SessionTokenPayload } from '../types';
import { SSHSession } from './ssh-session';

const BLOCKED_PORTS = [80, 443, 25, 465, 587, 3306, 6379, 27017, 11211];
const TOKEN_DEFAULT_TTL = 60;
const TOKEN_MIN_TTL = 10;
const TOKEN_MAX_TTL = 300;

function isBlockedHost(host: string): boolean {
  const h = host.toLowerCase().trim();

  if (h === 'localhost' || h === 'ip6-localhost' || h === 'ip6-loopback') return true;

  if (/^(127\.|10\.|0\.|192\.168\.|169\.254\.)/.test(h)) return true;
  if (/^172\.(1[6-9]|2[0-9]|3[0-1])\./.test(h)) return true;

  const v6 = h.replace(/^\[|\]$/g, '');
  if (v6 === '::1' || v6 === '0:0:0:0:0:0:0:1') return true;
  if (v6 === '::' || v6 === '0:0:0:0:0:0:0:0') return true;
  if (/^fe[89ab]/i.test(v6)) return true;
  if (/^f[cd]/i.test(v6)) return true;

  const v4mapped = v6.match(/^::ffff:(\d+\.\d+\.\d+\.\d+)$/i);
  if (v4mapped) return isBlockedHost(v4mapped[1]);

  return false;
}

function clampTokenTtl(ttl?: number): number {
  if (!ttl || Number.isNaN(ttl)) return TOKEN_DEFAULT_TTL;
  return Math.max(TOKEN_MIN_TTL, Math.min(TOKEN_MAX_TTL, Math.floor(ttl)));
}

function makeToken(): string {
  const bytes = crypto.getRandomValues(new Uint8Array(32));
  let binary = '';
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/g, '');
}

async function tokenStorageKey(token: string): Promise<string> {
  const digest = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(token));
  const bytes = new Uint8Array(digest);
  return `session-token:${Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('')}`;
}

function generateVerifiedToken(secret: string): string {
  const expires = Date.now() + 24 * 60 * 60 * 1000;
  const payload = `${expires}`;
  const signature = Array.from(
    new Uint8Array(new TextEncoder().encode(`${payload}:${secret}`))
  ).map(b => b.toString(16).padStart(2, '0')).join('').slice(0, 32);
  return `${payload}:${signature}`;
}

function jsonResponse(body: unknown, init: ResponseInit = {}): Response {
  return new Response(JSON.stringify(body), {
    ...init,
    headers: {
      'Content-Type': 'application/json',
      ...(init.headers || {}),
    },
  });
}

export class SSHSessionDO {
  private state: DurableObjectState;
  private env: Env;
  private sessions: Map<WebSocket, SSHSession> = new Map();
  private _pendingTimeouts: Map<WebSocket, ReturnType<typeof setTimeout>> = new Map();

  constructor(state: DurableObjectState, env: Env) {
    this.state = state;
    this.env = env;
  }

  async fetch(request: Request): Promise<Response> {
    const url = new URL(request.url);

    if (url.pathname === '/api/session-token' && request.method === 'POST') {
      return this.createSessionToken(request);
    }

    if (url.pathname.startsWith('/api/session-token/') && request.method === 'GET') {
      const token = decodeURIComponent(url.pathname.slice('/api/session-token/'.length));
      return this.consumeSessionToken(token);
    }

    const upgradeHeader = request.headers.get('Upgrade');
    if (upgradeHeader !== 'websocket') {
      return new Response('Expected WebSocket', { status: 400 });
    }

    const pair = new WebSocketPair();
    const [client, server] = [pair[0], pair[1]];

    this.state.acceptWebSocket(server);

    const timeout = setTimeout(() => {
      try {
        server.send(JSON.stringify({ type: 'error', message: 'Connection timeout' }));
        server.close(1011, 'Timeout');
      } catch {}
    }, 10000);

    server.serializeAttachment({ state: 'waiting', timeout: null });
    this._pendingTimeouts.set(server, timeout);

    return new Response(null, {
      status: 101,
      webSocket: client,
    } as any);
  }

  private async createSessionToken(request: Request): Promise<Response> {
    let body: Partial<SSHConnectionConfig> & { ttl?: number; label?: string };
    try {
      body = await request.json();
    } catch {
      return jsonResponse({ success: false, error: 'Invalid JSON body' }, { status: 400 });
    }

    const authMethod = body.authMethod || (body.privateKey ? 'publickey' : 'password');
    const config: SSHConnectionConfig = {
      host: String(body.host || '').replace(/^\[|\]$/g, '').trim(),
      port: Number(body.port || 22),
      username: String(body.username || '').trim(),
      password: body.password,
      authMethod,
      privateKey: body.privateKey,
    };

    const validationError = this.validateConnectionConfig(config);
    if (validationError) {
      return jsonResponse({ success: false, error: validationError }, { status: 400 });
    }

    const ttl = clampTokenTtl(body.ttl);
    const token = makeToken();
    const now = Date.now();
    const payload: SessionTokenPayload = {
      ...config,
      createdAt: now,
      expiresAt: now + ttl * 1000,
      label: typeof body.label === 'string' ? body.label.slice(0, 120) : undefined,
    };

    await this.state.storage.put(await tokenStorageKey(token), payload);

    const url = new URL(request.url);
    return jsonResponse({
      success: true,
      token,
      url: `${url.origin}/connect?token=${encodeURIComponent(token)}`,
      expiresIn: ttl,
    });
  }

  private async consumeSessionToken(token: string): Promise<Response> {
    if (!token) {
      return jsonResponse({ success: false, error: 'Missing token' }, { status: 400 });
    }

    const key = await tokenStorageKey(token);
    const payload = await this.state.storage.get<SessionTokenPayload>(key);
    await this.state.storage.delete(key);

    if (!payload) {
      return jsonResponse({ success: false, error: 'Token not found or already used' }, { status: 404 });
    }

    if (Date.now() > payload.expiresAt) {
      return jsonResponse({ success: false, error: 'Token expired' }, { status: 410 });
    }

    const validationError = this.validateConnectionConfig(payload);
    if (validationError) {
      return jsonResponse({ success: false, error: validationError }, { status: 400 });
    }

    const headers: Record<string, string> = { 'Content-Type': 'application/json' };
    if (this.env.TURNSTILE_SECRET) {
      const verifiedToken = generateVerifiedToken(this.env.TURNSTILE_SECRET);
      headers['Set-Cookie'] = `cf_verified=${verifiedToken}; Path=/; HttpOnly; Secure; SameSite=Strict`;
    }

    return new Response(JSON.stringify({
      success: true,
      config: {
        host: payload.host,
        port: payload.port,
        username: payload.username,
        password: payload.password,
        authMethod: payload.authMethod,
        privateKey: payload.privateKey,
      },
    }), { headers });
  }

  async webSocketMessage(ws: WebSocket, message: string | ArrayBuffer): Promise<void> {
    const session = this.sessions.get(ws);
    if (session) {
      await session.handleWebSocketMessage(message);
      return;
    }

    const timeout = this._pendingTimeouts.get(ws);
    if (timeout) {
      clearTimeout(timeout);
      this._pendingTimeouts.delete(ws);
    }

    try {
      const config = JSON.parse(message as string) as SSHConnectionConfig;
      const validationError = this.validateConnectionConfig(config);

      if (validationError) {
        ws.send(JSON.stringify({ type: 'error', message: validationError }));
        ws.close(1011, 'Invalid credentials');
        return;
      }

      await this.initSSHSession(ws, config);
    } catch {
      ws.send(JSON.stringify({ type: 'error', message: 'Invalid credentials format' }));
      ws.close(1011, 'Invalid format');
    }
  }

  async webSocketClose(ws: WebSocket, code: number, reason: string, wasClean: boolean): Promise<void> {
    const session = this.sessions.get(ws);
    if (session) {
      session.close();
      this.sessions.delete(ws);
    }
    const timeout = this._pendingTimeouts.get(ws);
    if (timeout) {
      clearTimeout(timeout);
      this._pendingTimeouts.delete(ws);
    }
  }

  async webSocketError(ws: WebSocket, error: unknown): Promise<void> {
    await this.webSocketClose(ws, 1011, 'Error', false);
  }

  private validateConnectionConfig(config: SSHConnectionConfig): string | null {
    if (!config.host || !config.username || (!config.password && !config.privateKey)) {
      return 'Missing credentials';
    }

    if (!Number.isInteger(config.port) || config.port < 1 || config.port > 65535) {
      return 'Invalid port';
    }

    if (config.authMethod === 'publickey' && !config.privateKey) {
      return 'Missing privateKey';
    }

    if ((config.authMethod === 'password' || !config.authMethod) && !config.password) {
      return 'Missing password';
    }

    if (isBlockedHost(config.host)) {
      return 'Forbidden target host';
    }

    if (BLOCKED_PORTS.includes(config.port)) {
      return `Forbidden target port: ${config.port}`;
    }

    return null;
  }

  private async initSSHSession(
    ws: WebSocket,
    config: SSHConnectionConfig
  ): Promise<void> {
    try {
      const validationError = this.validateConnectionConfig(config);
      if (validationError) {
        throw new Error(validationError);
      }

      const { connect } = await import('cloudflare:sockets');
      const socket = connect({ hostname: config.host, port: config.port });

      await socket.opened;

      const session = new SSHSession(ws, socket, config);
      this.sessions.set(ws, session);

      await session.startHandshake();
    } catch (error) {
      const errMsg = error instanceof Error ? error.message : String(error);
      console.error('[SSH] Session error:', errMsg);
      try {
        ws.send(JSON.stringify({ type: 'error', message: `连接失败: ${errMsg}` }));
        ws.close(1011, 'SSH connection failed');
      } catch {}
    }
  }
}
