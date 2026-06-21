import { SSHTerminal, THEMES } from './terminal';
import { ConnectionForm } from './auth-form';

const THEME_STORAGE_KEY = 'kvmidc_terminal_theme';

type ThemeName = keyof typeof THEMES;

function getSavedTheme(): ThemeName {
  const savedTheme = localStorage.getItem(THEME_STORAGE_KEY);
  return savedTheme && savedTheme in THEMES ? savedTheme as ThemeName : 'business';
}

const terminal = new SSHTerminal('terminal-container');
const savedTheme = getSavedTheme();
terminal.setTheme(savedTheme);
new ConnectionForm(terminal);

const themeSelector = document.getElementById('theme-selector') as HTMLSelectElement | null;
if (themeSelector) {
  themeSelector.value = savedTheme;
}

document.getElementById('disconnect-btn')?.addEventListener('click', () => {
  terminal.disconnect();
  const termSection = document.getElementById('terminal-section')!;
  termSection.classList.add('hidden');
  termSection.classList.remove('flex');
  document.getElementById('auth-section')!.classList.remove('hidden');
  document.getElementById('status-text')!.innerHTML = '<span class="w-2 h-2 rounded-full bg-slate-300 inline-block"></span> 状态：离线';
});

themeSelector?.addEventListener('change', (e) => {
  const theme = (e.target as HTMLSelectElement).value as ThemeName;
  if (!(theme in THEMES)) return;
  terminal.setTheme(theme);
  localStorage.setItem(THEME_STORAGE_KEY, theme);
});

// Set current year for copyright
const copyrightYearSpan = document.getElementById('copyright-year');
if (copyrightYearSpan) {
  copyrightYearSpan.textContent = new Date().getFullYear().toString();
}
