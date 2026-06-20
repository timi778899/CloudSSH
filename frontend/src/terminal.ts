import { Terminal } from '@xterm/xterm';
import { FitAddon } from '@xterm/addon-fit';
import { WebLinksAddon } from '@xterm/addon-web-links';
import { WebglAddon } from '@xterm/addon-webgl';
import { ZmodemHandler } from './zmodem-handler';
import '@xterm/xterm/css/xterm.css';

export interface SSHConnectionConfig {
  host: string;
  port: number;
  username: string;
  password?: string;
  authMethod?: 'password' | 'publickey';
  privateKey?: string;
}

export const THEMES = {
  business: {
    background: '#ffffff',
    foreground: '#172033',
    cursor: '#2563eb',
    cursorAccent: '#ffffff',
    selectionBackground: '#dbeafe',
  },
  glacier: {
    background: '#0a192f',
    foreground: '#64ffda',
    cursor: '#e6f1ff',
    cursorAccent: '#0a192f',
    selectionBackground: '#112240',
  },
  gruvbox: {
    background: '#282828',
    foreground: '#ebdbb2',
    cursor: '#d3869b',
    cursorAccent: '#282828',
    selectionBackground: '#504945',
  }
};

export class SSHTerminal {
  private terminal: Terminal;
  private fitAddon: FitAddon;
  private webglAddon!: WebglAddon;
  private ws: WebSocket | null = null;
  private container: HTMLElement;
  private contextMenu: HTMLDivElement;
  private disposables: { dispose(): void }[] = [];
  private heartbeatInterval: ReturnType<typeof setInterval> | null = null;
  private reconnectAttempts: number = 0;
  private maxReconnectAttempts: number = 5;
  private reconnectTimeout: ReturnType<typeof setTimeout> | null = null;
  private lastConfig: SSHConnectionConfig | null = null;

  constructor(containerId: string) {
    this.container = document.getElementById(containerId)!;
    this.contextMenu = this.createContextMenu();

    this.terminal = new Terminal({
      cursorBlink: true,
      cursorStyle: 'block',
      fontSize: 14,
      fontFamily: '"JetBrains Mono", "Fira Code", "Cascadia Code", monospace',
      theme: THEMES.business,
      allowProposedApi: true,
      scrollback: 10000,
    });

    this.fitAddon = new FitAddon();
    this.terminal.loadAddon(this.fitAddon);
    this.terminal.loadAddon(new WebLinksAddon());

    window.addEventListener('resize', () => this.fit());
    document.addEventListener('click', () => this.hideContextMenu());
    window.addEventListener('blur', () => this.hideContextMenu());

    this.container.addEventListener('contextmenu', (e) => {
      e.preventDefault();
      this.showContextMenu(e);
    });
  }

  setTheme(themeName: keyof typeof THEMES): void {
    this.terminal.options.theme = THEMES[themeName];
  }

  mount(): void {
    this.terminal.open(this.container);
    
    // Load WebGL addon after terminal is opened
    try {
      this.webglAddon = new WebglAddon();
      this.webglAddon.onContextLoss(e => {
        console.warn('WebGL context lost', e);
        this.webglAddon.dispose();
      });
      this.terminal.loadAddon(this.webglAddon);
    } catch (e) {
      console.warn('WebGL addon failed to load, falling back to canvas/dom', e);
    }

    this.fit();

    this.terminal.writeln('\x1b[34mKvmidc-SSH\u7ec8\u7aef\u6b63\u5728\u5efa\u7acb\u5b89\u5168\u7ec8\u7aef\u4f1a\u8bdd...\x1b[0m');
    this.terminal.writeln('');
  }

  async connect(config: SSHConnectionConfig): Promise<void> {
    this.lastConfig = config;
    const wsUrl = new URL(window.location.href);
    wsUrl.protocol = wsUrl.protocol === 'https:' ? 'wss:' : 'ws:';
    wsUrl.pathname = '/api/ssh';

    return new Promise((resolve, reject) => {
      this.ws = new WebSocket(wsUrl.toString());

      this.ws.onopen = () => {
        this.terminal.writeln('\x1b[32m[+] WebSocket \u5df2\u8fde\u63a5\uff0c\u6b63\u5728\u53d1\u9001\u8ba4\u8bc1\u4fe1\u606f...\x1b[0m');
        this.ws?.send(JSON.stringify({
          host: config.host,
          port: config.port,
          username: config.username,
          password: config.password,
          authMethod: config.authMethod,
          privateKey: config.privateKey,
        }));
        
        this.reconnectAttempts = 0;
        this.startHeartbeat();
        resolve();
      };

      this.ws.onerror = () => {
        reject(new Error('WebSocket connection failed'));
      };

      // Zmodem support
      const zmodemHandler = new ZmodemHandler(
        (data) => this.terminal.write(data),
        (data) => {
          if (this.ws?.readyState === WebSocket.OPEN) {
            this.ws.send(data);
          }
        }
      );

      this.ws.onmessage = (event) => {
        if (typeof event.data === 'string') {
          try {
            const msg = JSON.parse(event.data);
            switch (msg.type) {
              case 'status':
                this.terminal.writeln(`\x1b[32m[*] ${msg.message}\x1b[0m`);
                if (msg.message === '\u8ba4\u8bc1\u6210\u529f') {
                  document.getElementById('status-text')!.innerHTML = '<span class="w-2 h-2 rounded-full bg-emerald-500 inline-block animate-pulse"></span> \u72b6\u6001\uff1a\u5728\u7ebf';
                  document.getElementById('term-status')!.innerHTML = '<div class="w-2 h-2 rounded-full bg-emerald-500"></div> \u5df2\u8fde\u63a5';
                }
                break;
              case 'error':
                this.terminal.writeln(`\x1b[31m[!] ${msg.message}\x1b[0m`);
                break;
            }
          } catch {
            this.terminal.write(event.data);
          }
        } else {
          const reader = new FileReader();
          reader.onload = () => {
            zmodemHandler.consume(reader.result as ArrayBuffer);
          };
          reader.readAsArrayBuffer(event.data);
        }
      };

      this.ws.onclose = (event) => {
        this.stopHeartbeat();
        this.terminal.writeln(
          `\x1b[33m[*] \u8fde\u63a5\u5df2\u5173\u95ed\uff08\u4ee3\u7801\uff1a${event.code}\uff09\x1b[0m`
        );
        document.getElementById('term-status')!.innerHTML = '<div class="w-2 h-2 rounded-full bg-red-500"></div> \u5df2\u65ad\u5f00';
        document.getElementById('status-text')!.innerHTML = '<span class="w-2 h-2 rounded-full bg-slate-300 inline-block"></span> \u72b6\u6001\uff1a\u79bb\u7ebf';
        
        if (event.code !== 1000 && this.lastConfig && this.reconnectAttempts < this.maxReconnectAttempts) {
          this.scheduleReconnect();
        }
      };

      this.ws.onerror = () => {
        this.terminal.writeln('\x1b[31m[!] \u8fde\u63a5\u51fa\u9519\x1b[0m');
        reject(new Error('WebSocket connection failed'));
      };

      this.disposables.push(
        this.terminal.onData((data) => {
          if (this.ws?.readyState === WebSocket.OPEN) {
            this.ws.send(data);
          }
        })
      );

      this.disposables.push(
        this.terminal.onResize(({ cols, rows }) => {
          if (this.ws?.readyState === WebSocket.OPEN) {
            this.ws.send(JSON.stringify({
              type: 'resize',
              cols,
              rows,
            }));
          }
        })
      );
    });
  }

  fit(): void {
    this.fitAddon.fit();
  }

  private createContextMenu(): HTMLDivElement {
    const menu = document.createElement('div');
    menu.className = 'terminal-context-menu';
    menu.innerHTML = `
      <button type="button" data-action="copy">\u590d\u5236</button>
      <button type="button" data-action="paste">\u7c98\u8d34</button>
    `;

    menu.addEventListener('click', async (event) => {
      const button = (event.target as HTMLElement).closest<HTMLButtonElement>('button');
      if (!button || button.disabled) return;

      this.hideContextMenu();
      if (button.dataset.action === 'copy') {
        await this.copySelection();
      }
      if (button.dataset.action === 'paste') {
        await this.pasteFromClipboard();
      }
    });

    document.body.appendChild(menu);
    return menu;
  }

  private showContextMenu(event: MouseEvent): void {
    const copyButton = this.contextMenu.querySelector<HTMLButtonElement>('[data-action="copy"]');
    if (copyButton) {
      copyButton.disabled = !this.terminal.hasSelection();
    }

    this.contextMenu.style.left = '0px';
    this.contextMenu.style.top = '0px';
    this.contextMenu.classList.add('is-open');

    const menuRect = this.contextMenu.getBoundingClientRect();
    const left = Math.min(event.clientX, window.innerWidth - menuRect.width - 8);
    const top = Math.min(event.clientY, window.innerHeight - menuRect.height - 8);

    this.contextMenu.style.left = `${Math.max(8, left)}px`;
    this.contextMenu.style.top = `${Math.max(8, top)}px`;
  }

  private hideContextMenu(): void {
    this.contextMenu.classList.remove('is-open');
  }

  private async copySelection(): Promise<void> {
    const text = this.terminal.getSelection();
    if (!text) return;

    try {
      await navigator.clipboard.writeText(text);
      this.terminal.clearSelection();
    } catch (err) {
      console.error('Failed to copy terminal selection', err);
    }
  }

  private async pasteFromClipboard(): Promise<void> {
    try {
      const text = await navigator.clipboard.readText();
      if (text && this.ws?.readyState === WebSocket.OPEN) {
        this.ws.send(text);
      }
    } catch (err) {
      console.error('Failed to read clipboard', err);
    }
  }

  private startHeartbeat(): void {
    this.stopHeartbeat();
    this.heartbeatInterval = setInterval(() => {
      if (this.ws?.readyState === WebSocket.OPEN) {
        this.ws.send(JSON.stringify({ type: 'ping' }));
      }
    }, 30000);
  }

  private stopHeartbeat(): void {
    if (this.heartbeatInterval) {
      clearInterval(this.heartbeatInterval);
      this.heartbeatInterval = null;
    }
  }

  private scheduleReconnect(): void {
    if (this.reconnectTimeout) {
      clearTimeout(this.reconnectTimeout);
    }
    
    this.reconnectAttempts++;
    const delay = Math.min(1000 * Math.pow(2, this.reconnectAttempts), 30000);
    
    this.terminal.writeln(`\x1b[33m[*] ${delay / 1000} \u79d2\u540e\u91cd\u8fde\uff08\u7b2c ${this.reconnectAttempts}/${this.maxReconnectAttempts} \u6b21\uff09...\x1b[0m`);
    
    this.reconnectTimeout = setTimeout(async () => {
      if (this.lastConfig) {
        this.terminal.writeln('\x1b[32m[+] \u6b63\u5728\u91cd\u8fde...\x1b[0m');
        try {
          await this.connect(this.lastConfig);
        } catch (e) {
          this.terminal.writeln('\x1b[31m[!] \u91cd\u8fde\u5931\u8d25\x1b[0m');
        }
      }
    }, delay);
  }

  disconnect(): void {
    this.hideContextMenu();
    this.stopHeartbeat();
    if (this.reconnectTimeout) {
      clearTimeout(this.reconnectTimeout);
      this.reconnectTimeout = null;
    }
    this.reconnectAttempts = this.maxReconnectAttempts;
    this.ws?.close(1000);
    this.ws = null;
    this.disposables.forEach(d => d.dispose());
    this.disposables = [];
  }

  dispose(): void {
    this.disconnect();
    this.contextMenu.remove();
    this.terminal.dispose();
  }
}
