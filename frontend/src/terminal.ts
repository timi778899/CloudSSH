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
  dimBlack: {
    background: '#000000',
    foreground: '#f5f5f5',
    cursor: '#ffffff',
    cursorAccent: '#000000',
    selectionBackground: '#4b5563',
    black: '#000000',
    red: '#ef4444',
    green: '#22c55e',
    yellow: '#facc15',
    blue: '#38bdf8',
    magenta: '#d946ef',
    cyan: '#06b6d4',
    white: '#f8fafc',
    brightBlack: '#64748b',
    brightRed: '#f87171',
    brightGreen: '#4ade80',
    brightYellow: '#fde047',
    brightBlue: '#7dd3fc',
    brightMagenta: '#e879f9',
    brightCyan: '#22d3ee',
    brightWhite: '#ffffff',
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
  private allowReconnect: boolean = false;
  private metricsWs: WebSocket | null = null;
  private metricsBuffer: string = '';
  private isRefreshingMetrics: boolean = false;
  private metricsInterval: number | null = null;
  private metricsTimeout: number | null = null;
  private readonly metricsStartMarker = '__KVMIDC_SYSINFO_START__';
  private readonly metricsEndMarker = '__KVMIDC_SYSINFO_END__';

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

    document.getElementById('server-metrics-refresh')?.addEventListener('click', () => {
      if (this.metricsWs?.readyState === WebSocket.OPEN) {
        this.refreshServerMetrics();
      } else {
        this.startServerMetricsSession();
      }
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
    this.allowReconnect = false;
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
                  this.allowReconnect = true;
                  this.reconnectAttempts = 0;
                  document.getElementById('status-text')!.innerHTML = '<span class="w-2 h-2 rounded-full bg-emerald-500 inline-block animate-pulse"></span> \u72b6\u6001\uff1a\u5728\u7ebf';
                  document.getElementById('term-status')!.innerHTML = '<div class="w-2 h-2 rounded-full bg-emerald-500"></div> \u5df2\u8fde\u63a5';
                }
                if (msg.message === 'Shell \u5df2\u5c31\u7eea') {
                  window.setTimeout(() => this.startServerMetricsSession(), 600);
                }
                break;
              case 'error':
                this.allowReconnect = false;
                this.lastConfig = null;
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
        this.stopServerMetricsPolling();
        this.terminal.writeln(
          `\x1b[33m[*] \u8fde\u63a5\u5df2\u5173\u95ed\uff08\u4ee3\u7801\uff1a${event.code}\uff09\x1b[0m`
        );
        document.getElementById('term-status')!.innerHTML = '<div class="w-2 h-2 rounded-full bg-red-500"></div> \u5df2\u65ad\u5f00';
        document.getElementById('status-text')!.innerHTML = '<span class="w-2 h-2 rounded-full bg-slate-300 inline-block"></span> \u72b6\u6001\uff1a\u79bb\u7ebf';
        this.setMetricsStatus('\u5df2\u65ad\u5f00');
        
        if (event.code !== 1000 && this.allowReconnect && this.lastConfig && this.reconnectAttempts < this.maxReconnectAttempts) {
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

  refreshServerMetrics(): void {
    if (this.metricsWs?.readyState !== WebSocket.OPEN || this.isRefreshingMetrics) return;

    this.isRefreshingMetrics = true;
    this.metricsBuffer = '';
    this.setMetricsStatus('\u6b63\u5728\u5237\u65b0...');
    this.metricsWs.send(this.buildMetricsCommand());

    if (this.metricsTimeout) clearTimeout(this.metricsTimeout);
    this.metricsTimeout = window.setTimeout(() => {
      if (this.isRefreshingMetrics) {
        this.isRefreshingMetrics = false;
        this.metricsBuffer = '';
        this.setMetricsStatus('\u5237\u65b0\u8d85\u65f6');
      }
      this.metricsTimeout = null;
    }, 6000);
  }

  private startServerMetricsSession(): void {
    if (!this.lastConfig || this.metricsWs?.readyState === WebSocket.OPEN || this.metricsWs?.readyState === WebSocket.CONNECTING) {
      return;
    }

    this.stopServerMetricsPolling();
    this.setMetricsStatus('\u6b63\u5728\u8fde\u63a5...');

    const wsUrl = new URL(window.location.href);
    wsUrl.protocol = wsUrl.protocol === 'https:' ? 'wss:' : 'ws:';
    wsUrl.pathname = '/api/ssh';

    this.metricsWs = new WebSocket(wsUrl.toString());
    this.metricsWs.onopen = () => {
      this.metricsWs?.send(JSON.stringify({
        host: this.lastConfig!.host,
        port: this.lastConfig!.port,
        username: this.lastConfig!.username,
        password: this.lastConfig!.password,
        authMethod: this.lastConfig!.authMethod,
        privateKey: this.lastConfig!.privateKey,
      }));
    };

    this.metricsWs.onmessage = (event) => {
      if (typeof event.data === 'string') {
        try {
          const msg = JSON.parse(event.data);
          if (msg.type === 'status' && msg.message === 'Shell \u5df2\u5c31\u7eea') {
            this.startServerMetricsPolling();
          } else if (msg.type === 'error') {
            this.setMetricsStatus('\u72b6\u6001\u83b7\u53d6\u5931\u8d25');
          }
        } catch {}
        return;
      }

      const reader = new FileReader();
      reader.onload = () => this.captureMetricsOutput(reader.result as ArrayBuffer);
      reader.readAsArrayBuffer(event.data);
    };

    this.metricsWs.onclose = () => {
      this.stopServerMetricsPolling(false);
      this.metricsWs = null;
    };

    this.metricsWs.onerror = () => {
      this.setMetricsStatus('\u72b6\u6001\u83b7\u53d6\u5931\u8d25');
    };
  }

  private startServerMetricsPolling(): void {
    if (this.metricsInterval) return;
    this.refreshServerMetrics();
    this.metricsInterval = window.setInterval(() => this.refreshServerMetrics(), 5000);
  }

  private stopServerMetricsPolling(closeSocket = true): void {
    if (this.metricsInterval) {
      clearInterval(this.metricsInterval);
      this.metricsInterval = null;
    }
    if (this.metricsTimeout) {
      clearTimeout(this.metricsTimeout);
      this.metricsTimeout = null;
    }
    this.isRefreshingMetrics = false;
    this.metricsBuffer = '';
    if (closeSocket && this.metricsWs) {
      this.metricsWs.close(1000);
      this.metricsWs = null;
    }
  }

  private buildMetricsCommand(): string {
    return [
      `__KVMIDC_S='__KVMIDC_SYSINFO_'"START__"; __KVMIDC_E='__KVMIDC_SYSINFO_'"END__";`,
      `printf '\\n%s\\n' "$__KVMIDC_S";`,
      `LOAD=$(awk '{print $1" "$2" "$3}' /proc/loadavg 2>/dev/null || printf -- '-');`,
      `read _ u1 n1 s1 i1 io1 irq1 sirq1 st1 _ < /proc/stat 2>/dev/null;`,
      `t1=$((u1+n1+s1+i1+io1+irq1+sirq1+st1)); idle1=$((i1+io1));`,
      `sleep 1;`,
      `read _ u2 n2 s2 i2 io2 irq2 sirq2 st2 _ < /proc/stat 2>/dev/null;`,
      `t2=$((u2+n2+s2+i2+io2+irq2+sirq2+st2)); idle2=$((i2+io2));`,
      `dt=$((t2-t1)); di=$((idle2-idle1));`,
      `if [ "$dt" -gt 0 ] 2>/dev/null; then CPU=$((100*(dt-di)/dt)); else CPU=-; fi;`,
      `MEM=$(awk '/MemTotal/{t=$2}/MemAvailable/{a=$2}END{if(t>0) printf "%.0f %.0f %.0f",(t-a)/1024,t/1024,(t-a)*100/t; else printf "- - -"}' /proc/meminfo 2>/dev/null);`,
      `SWAP=$(awk '/SwapTotal/{t=$2}/SwapFree/{f=$2}END{if(t>0) printf "%.0f %.0f %.0f",(t-f)/1024,t/1024,(t-f)*100/t; else printf "0 0 0"}' /proc/meminfo 2>/dev/null);`,
      `DISK=$(df -Pm / 2>/dev/null | awk 'NR==2{gsub("%","",$5); printf "%s %s %s",$3,$2,$5}');`,
      `printf 'load=%s\\ncpu=%s\\nmem=%s\\nswap=%s\\ndisk=%s\\n' "$LOAD" "$CPU" "$MEM" "$SWAP" "$DISK";`,
      `printf '%s\\n' "$__KVMIDC_E";`,
    ].join(' ') + '\n';
  }

  private captureMetricsOutput(data: ArrayBuffer): boolean {
    const text = new TextDecoder().decode(data);
    let chunk = text;

    if (!this.metricsBuffer) {
      const startIndex = chunk.indexOf(this.metricsStartMarker);
      if (startIndex === -1) return false;
      chunk = chunk.slice(startIndex + this.metricsStartMarker.length);
    }

    const endIndex = chunk.indexOf(this.metricsEndMarker);
    if (endIndex >= 0) {
      this.metricsBuffer += chunk.slice(0, endIndex);
      this.isRefreshingMetrics = false;
      if (this.metricsTimeout) {
        clearTimeout(this.metricsTimeout);
        this.metricsTimeout = null;
      }
      this.renderServerMetrics(this.metricsBuffer);
      this.metricsBuffer = '';
      return true;
    }

    this.metricsBuffer += chunk;
    return true;
  }

  private renderServerMetrics(raw: string): void {
    const clean = raw.replace(/\x1b\[[0-9;?]*[A-Za-z]/g, '').replace(/\r/g, '');
    const values = new Map<string, string>();
    for (const line of clean.split('\n')) {
      const [key, ...rest] = line.trim().split('=');
      if (key && rest.length) values.set(key, rest.join('='));
    }

    const load = values.get('load') || '--';
    this.setText('metric-load', load);

    const cpu = this.toPercent(values.get('cpu'));
    this.setText('metric-cpu', cpu == null ? '--' : `${cpu}%`);
    this.setBar('metric-cpu-bar', cpu);

    this.renderSizedMetric('metric-memory', 'metric-memory-bar', values.get('mem'));
    this.renderSizedMetric('metric-swap', 'metric-swap-bar', values.get('swap'));
    this.renderSizedMetric('metric-disk', 'metric-disk-bar', values.get('disk'));
    this.setMetricsStatus(new Date().toLocaleTimeString('zh-CN', { hour12: false }));
  }

  private renderSizedMetric(textId: string, barId: string, value?: string): void {
    const parts = (value || '').split(/\s+/).map(Number);
    if (parts.length < 3 || parts.some(Number.isNaN)) {
      this.setText(textId, '--');
      this.setBar(barId, null);
      return;
    }

    const [used, total, percent] = parts;
    this.setText(textId, `${this.formatMiB(used)} / ${this.formatMiB(total)} (${Math.round(percent)}%)`);
    this.setBar(barId, percent);
  }

  private toPercent(value?: string): number | null {
    if (!value || value === '-') return null;
    const parsed = Number(value);
    if (Number.isNaN(parsed)) return null;
    return Math.max(0, Math.min(100, Math.round(parsed)));
  }

  private formatMiB(value: number): string {
    if (value >= 1024) return `${(value / 1024).toFixed(value >= 10240 ? 0 : 1)}G`;
    return `${Math.round(value)}M`;
  }

  private setText(id: string, value: string): void {
    const element = document.getElementById(id);
    if (element) element.textContent = value;
  }

  private setBar(id: string, percent: number | null): void {
    const element = document.getElementById(id) as HTMLElement | null;
    if (element) element.style.width = `${percent == null ? 0 : Math.max(0, Math.min(100, percent))}%`;
  }

  private setMetricsStatus(value: string): void {
    this.setText('metrics-updated', value);
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
    this.stopServerMetricsPolling();
    if (this.reconnectTimeout) {
      clearTimeout(this.reconnectTimeout);
      this.reconnectTimeout = null;
    }
    this.reconnectAttempts = this.maxReconnectAttempts;
    this.allowReconnect = false;
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
