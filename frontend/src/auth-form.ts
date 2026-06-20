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
        <div class="grid grid-cols-4 gap-4">
          <div class="col-span-3">
            <label class="block text-xs font-bold tracking-normal text-slate-500 mb-2">Host address</label>
            <div class="flex items-center">
               <input id="host" class="terminal-input text-[13px]" placeholder="192.168.1.1 or 2001:db8::1" type="text" required>
            </div>
          </div>
          <div class="col-span-1">
            <label class="block text-xs font-bold tracking-normal text-slate-500 mb-2">Port</label>
            <div class="flex items-center">
              <input id="port" class="terminal-input text-[13px]" placeholder="22" type="text" value="22">
            </div>
          </div>
        </div>
        <div>
          <label class="block text-xs font-bold tracking-normal text-slate-500 mb-2">User name</label>
          <div class="flex items-center">
            <span class="material-symbols-outlined text-slate-500 mr-2" style="font-size: 16px;">person</span>
            <input id="username" class="terminal-input text-[13px]" placeholder="admin" type="text" required>
          </div>
        </div>
        <div>
          <label class="block text-xs font-bold tracking-normal text-slate-500 mb-2">Authentication</label>
          <div class="flex gap-2 mb-3">
            <button type="button" id="auth-tab-password" class="auth-tab px-3 py-2 text-[12px] font-semibold tracking-normal border border-blue-600 text-white bg-blue-600 rounded-md cursor-pointer transition-all">Password</button>
            <button type="button" id="auth-tab-key" class="auth-tab px-3 py-2 text-[12px] font-semibold tracking-normal border border-slate-200 text-slate-500 bg-white rounded-md cursor-pointer transition-all">Private key</button>
          </div>
          <div id="auth-password-section">
            <div class="flex items-center">
              <span class="material-symbols-outlined text-slate-500 mr-2" style="font-size: 16px;">key</span>
              <input id="password" class="terminal-input text-[13px]" placeholder="••••••••" type="password">
            </div>
          </div>
          <div id="auth-key-section" style="display:none;">
            <textarea id="private-key" class="terminal-input text-[11px] w-full" rows="5" placeholder="-----BEGIN OPENSSH PRIVATE KEY-----&#10;...粘贴 Ed25519 私钥内容...&#10;-----END OPENSSH PRIVATE KEY-----" style="resize:vertical;padding:10px 12px;"></textarea>
          </div>
        </div>
        <div id="turnstile-container" style="display:none;">
          <div id="turnstile-widget" class="flex justify-center"></div>
        </div>
        <div class="flex items-center gap-2 mt-2">
          <input type="checkbox" id="remember-me" class="accent-blue-600 w-4 h-4 cursor-pointer">
          <label for="remember-me" class="text-xs text-slate-500 cursor-pointer select-none">Remember connection</label>
        </div>
        <div class="pt-4">
          <button id="connect-btn" class="business-button w-full py-3 px-4 text-xs font-bold tracking-normal uppercase flex items-center justify-center gap-2 bg-blue-600 text-white" type="button">
            <span class="material-symbols-outlined" style="font-size: 18px;">power_settings_new</span>
            Connect
          </button>
        </div>
        <div class="flex justify-between items-center mt-4">
          <span id="status-text" class="text-[13px] text-slate-500 flex items-center gap-1">
            <span class="w-2 h-2 rounded-full bg-slate-300 inline-block"></span> Status: Offline
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
      pwTab.style.background = '#2563eb'; pwTab.style.color = '#ffffff';
      pwTab.style.borderColor = '#2563eb';
      keyTab.style.background = '#ffffff'; keyTab.style.color = '#64748b';
      keyTab.style.borderColor = '#e2e8f0';
      pwSection.style.display = ''; keySection.style.display = 'none';
    } else {
      keyTab.style.background = '#2563eb'; keyTab.style.color = '#ffffff';
      keyTab.style.borderColor = '#2563eb';
      pwTab.style.background = '#ffffff'; pwTab.style.color = '#64748b';
      pwTab.style.borderColor = '#e2e8f0';
      keySection.style.display = ''; pwSection.style.display = 'none';
    }
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
      alert('请填写主机名和用户名');
      return;
    }

    if (this.authMode === 'password' && !password) {
      alert('请输入密码');
      return;
    }

    if (this.authMode === 'key' && !privateKey) {
      alert('请粘贴私钥内容');
      return;
    }

    // Check Turnstile if enabled
    if (this.turnstileEnabled && !this.turnstileVerified) {
      alert('请完成人机验证');
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

    document.getElementById('term-host')!.textContent = 'Host: ' + host;
    document.getElementById('term-user')!.textContent = 'User: ' + username;
    document.getElementById('term-port')!.textContent = 'Port: ' + port;

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
      document.getElementById('status-text')!.innerHTML = '<span class="w-2 h-2 rounded-full bg-slate-300 inline-block"></span> Status: Offline';
    }
  }
}

