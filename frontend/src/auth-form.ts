import { SSHTerminal } from './terminal';

// --- Credential encryption helpers ---
async function deriveKey(salt: Uint8Array): Promise<CryptoKey> {
  const raw = new TextEncoder().encode(window.location.origin + ':cloudssh');
  const baseKey = await crypto.subtle.importKey('raw', raw, 'PBKDF2', false, ['deriveKey']);
  return crypto.subtle.deriveKey(
    { name: 'PBKDF2', salt: salt as any, iterations: 100000, hash: 'SHA-256' },
    baseKey,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt', 'decrypt']
  );
}

async function encryptCredentials(data: object): Promise<string> {
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const key = await deriveKey(salt);
  const encoded = new TextEncoder().encode(JSON.stringify(data));
  const encrypted = new Uint8Array(await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, encoded));
  // Format: base64(salt + iv + ciphertext)
  const combined = new Uint8Array(salt.length + iv.length + encrypted.length);
  combined.set(salt, 0);
  combined.set(iv, salt.length);
  combined.set(encrypted, salt.length + iv.length);
  return btoa(String.fromCharCode(...combined));
}

async function decryptCredentials(stored: string): Promise<{ host: string; port: string; username: string; password: string } | null> {
  try {
    const raw = Uint8Array.from(atob(stored), c => c.charCodeAt(0));
    const salt = raw.slice(0, 16);
    const iv = raw.slice(16, 28);
    const data = raw.slice(28);
    const key = await deriveKey(salt);
    const decrypted = await crypto.subtle.decrypt({ name: 'AES-GCM', iv }, key, data);
    return JSON.parse(new TextDecoder().decode(decrypted));
  } catch {
    return null;
  }
}

export class ConnectionForm {
  private terminal: SSHTerminal;
  private turnstileEnabled = false;
  private turnstileVerified = false;
  private turnstileWidgetId: string | null = null;
  private turnstileSitekey = '';

  constructor(terminal: SSHTerminal) {
    this.terminal = terminal;
    this.render();
    this.loadSavedCredentials();
    this.checkTurnstileConfig();
  }

  private async checkTurnstileConfig(): Promise<void> {
    try {
      const response = await fetch('/api/config');
      const config = (await response.json()) as { turnstileEnabled: boolean; sitekey: string };
      this.turnstileEnabled = config.turnstileEnabled;
      this.turnstileSitekey = config.sitekey;
      if (this.turnstileEnabled && this.turnstileSitekey) {
        this.renderTurnstile();
      }
    } catch {
      // Config endpoint not available, skip Turnstile
    }
  }

  private renderTurnstile(): void {
    const container = document.getElementById('turnstile-widget');
    if (!container || !window.turnstile) return;

    const wrapper = document.getElementById('turnstile-container');
    if (wrapper) wrapper.style.display = 'block';

    this.turnstileWidgetId = window.turnstile.render(container, {
      sitekey: this.turnstileSitekey,
      theme: 'light',
      callback: async (token: string) => {
        // Verify with backend and get cookie
        try {
          const response = await fetch('/api/verify', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ token }),
          });
          const result = (await response.json()) as { success: boolean };
          if (result.success) {
            this.turnstileVerified = true;
            // Hide Turnstile widget after successful verification
            const wrapper = document.getElementById('turnstile-container');
            if (wrapper) wrapper.style.display = 'none';
          }
        } catch {
          this.turnstileVerified = false;
        }
      },
      'expired-callback': () => {
        this.turnstileVerified = false;
      },
      'error-callback': () => {
        this.turnstileVerified = false;
      },
    });
  }

  private render(): void {
    const container = document.getElementById('connection-form-container')!;

    container.innerHTML = `
      <form class="space-y-5" id="connection-form">
        <div class="connection-grid">
          <div class="form-field host-field">
            <label>主机地址</label>
            <div class="field-with-icon">
              <span class="material-symbols-outlined">dns</span>
              <input id="host" class="terminal-input business-input text-[13px]" placeholder="192.168.1.1 或 2001:db8::1" type="text" required>
            </div>
          </div>
          <div class="form-field port-field">
            <label>端口</label>
            <div class="field-with-icon">
              <span class="material-symbols-outlined">tag</span>
              <input id="port" class="terminal-input business-input text-[13px]" placeholder="22" type="text" value="22">
            </div>
          </div>
        </div>
        <div class="form-field">
          <label>用户名</label>
          <div class="field-with-icon">
            <span class="material-symbols-outlined">person</span>
            <input id="username" class="terminal-input business-input text-[13px]" placeholder="root / admin" type="text" required>
          </div>
        </div>
        <div class="form-field">
          <label>认证方式</label>
          <div class="auth-segment">
            <button type="button" id="auth-tab-password" class="auth-tab is-active">密码登录</button>
            <button type="button" id="auth-tab-key" class="auth-tab">私钥登录</button>
          </div>
          <div id="auth-password-section">
            <div class="field-with-icon">
              <span class="material-symbols-outlined">key</span>
              <input id="password" class="terminal-input business-input text-[13px]" placeholder="请输入登录密码" type="password">
            </div>
          </div>
          <div id="auth-key-section" style="display:none;">
            <textarea id="private-key" class="terminal-input text-[11px] w-full" rows="5" placeholder="-----BEGIN OPENSSH PRIVATE KEY-----&#10;请粘贴 Ed25519 或 RSA 私钥内容&#10;-----END OPENSSH PRIVATE KEY-----" style="resize:vertical;padding:10px 12px;"></textarea>
          </div>
        </div>
        <div id="turnstile-container" style="display:none;">
          <div id="turnstile-widget" class="flex justify-center"></div>
        </div>
        <div class="flex items-center gap-2 mt-2">
          <input type="checkbox" id="remember-me" class="accent-blue-600 w-4 h-4 cursor-pointer">
          <label for="remember-me" class="text-xs text-slate-500 cursor-pointer select-none">记住本次连接信息</label>
        </div>
        <div id="form-error" class="form-error" role="alert" aria-live="polite"></div>
        <div class="pt-4">
          <button id="connect-btn" class="business-button w-full py-3 px-4 text-sm font-semibold tracking-normal flex items-center justify-center gap-2 bg-blue-600 text-white" type="button">
            <span class="material-symbols-outlined" style="font-size: 18px;">power_settings_new</span>
            连接服务器
          </button>
        </div>
        <div class="flex justify-between items-center mt-4">
          <span id="status-text" class="text-[13px] text-slate-500 flex items-center gap-1">
            <span class="w-2 h-2 rounded-full bg-slate-300 inline-block"></span> 状态：离线
          </span>
        </div>
      </form>
    `;

    document.getElementById('connect-btn')!.addEventListener('click', () => {
      this.handleConnect();
    });

    document.getElementById('connection-form')!.addEventListener('keypress', (e) => {
      if (e.key === 'Enter') this.handleConnect();
    });

    // Auth method tab switching
    document.getElementById('auth-tab-password')!.addEventListener('click', () => {
      this.setAuthMode('password');
    });
    document.getElementById('auth-tab-key')!.addEventListener('click', () => {
      this.setAuthMode('key');
    });
  }

  private authMode: 'password' | 'key' = 'password';

  private setAuthMode(mode: 'password' | 'key'): void {
    this.authMode = mode;
    const pwTab = document.getElementById('auth-tab-password')!;
    const keyTab = document.getElementById('auth-tab-key')!;
    const pwSection = document.getElementById('auth-password-section')!;
    const keySection = document.getElementById('auth-key-section')!;

    if (mode === 'password') {
      pwTab.classList.add('is-active');
      keyTab.classList.remove('is-active');
      pwSection.style.display = ''; keySection.style.display = 'none';
    } else {
      keyTab.classList.add('is-active');
      pwTab.classList.remove('is-active');
      keySection.style.display = ''; pwSection.style.display = 'none';
    }
  }

  private showError(message: string): void {
    const errorEl = document.getElementById('form-error');
    if (!errorEl) return;
    errorEl.textContent = message;
    errorEl.classList.add('is-visible');
  }

  private clearError(): void {
    const errorEl = document.getElementById('form-error');
    if (!errorEl) return;
    errorEl.textContent = '';
    errorEl.classList.remove('is-visible');
  }

  private async loadSavedCredentials(): Promise<void> {
    const stored = localStorage.getItem('cloudssh_cred');
    if (!stored) return;
    const cred = await decryptCredentials(stored);
    if (!cred) {
      localStorage.removeItem('cloudssh_cred');
      return;
    }
    (document.getElementById('host') as HTMLInputElement).value = cred.host || '';
    (document.getElementById('port') as HTMLInputElement).value = cred.port || '22';
    (document.getElementById('username') as HTMLInputElement).value = cred.username || '';
    (document.getElementById('password') as HTMLInputElement).value = cred.password || '';
    (document.getElementById('private-key') as HTMLTextAreaElement).value = (cred as any).privateKey || '';
    (document.getElementById('remember-me') as HTMLInputElement).checked = true;
    
    if ((cred as any).authMethod === 'key') {
      this.setAuthMode('key');
    } else {
      this.setAuthMode('password');
    }
  }

  private async handleConnect(): Promise<void> {
    this.clearError();
    const hostInput = (document.getElementById('host') as HTMLInputElement).value;
    const host = hostInput.replace(/^\[|\]$/g, '').trim();
    const port = parseInt(
      (document.getElementById('port') as HTMLInputElement).value || '22'
    );
    const username = (document.getElementById('username') as HTMLInputElement).value;
    const password = (document.getElementById('password') as HTMLInputElement).value;
    const privateKey = (document.getElementById('private-key') as HTMLTextAreaElement).value;
    const remember = (document.getElementById('remember-me') as HTMLInputElement).checked;

    if (!host || !username) {
      this.showError('请填写主机地址和用户名');
      return;
    }

    if (this.authMode === 'password' && !password) {
      this.showError('请输入登录密码');
      return;
    }

    if (this.authMode === 'key' && !privateKey) {
      this.showError('请粘贴私钥内容');
      return;
    }

    // Check Turnstile if enabled
    if (this.turnstileEnabled && !this.turnstileVerified) {
      this.showError('请完成人机验证');
      return;
    }

    // Save or clear credentials
    if (remember) {
      const encrypted = await encryptCredentials({ host, port: port.toString(), username, password, privateKey, authMethod: this.authMode === 'key' ? 'publickey' : 'password' });
      localStorage.setItem('cloudssh_cred', encrypted);
    } else {
      localStorage.removeItem('cloudssh_cred');
    }

    const authSection = document.getElementById('auth-section')!;
    const termSection = document.getElementById('terminal-section')!;

    authSection.classList.add('hidden');
    termSection.classList.remove('hidden');
    termSection.classList.add('flex');

    document.getElementById('term-host')!.textContent = '主机：' + host;
    document.getElementById('term-user')!.textContent = '用户：' + username;
    document.getElementById('term-port')!.textContent = '端口：' + port;

    this.terminal.mount();

    try {
      await this.terminal.connect({
        host,
        port,
        username,
        password,
        authMethod: this.authMode === 'key' ? 'publickey' : 'password',
        privateKey,
      });
    } catch (error) {
      termSection.classList.add('hidden');
      termSection.classList.remove('flex');
      authSection.classList.remove('hidden');
      document.getElementById('status-text')!.innerHTML = '<span class="w-2 h-2 rounded-full bg-slate-300 inline-block"></span> 状态：离线';
    }
  }
}
