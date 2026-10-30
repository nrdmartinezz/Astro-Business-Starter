/**
 * Runs pa11y-ci with a Chrome/Chromium binary Puppeteer can launch.
 * Uses Puppeteer's cache when present; otherwise common system install paths.
 */
import { spawnSync } from 'node:child_process';
import { existsSync } from 'node:fs';
import { join } from 'node:path';

const env = { ...process.env };

if (!env.PUPPETEER_EXECUTABLE_PATH) {
  try {
    const puppeteer = await import('puppeteer');
    const cached = puppeteer.default.executablePath?.();
    if (cached && existsSync(cached)) {
      env.PUPPETEER_EXECUTABLE_PATH = cached;
    }
  } catch {
    // puppeteer optional until audit:a11y runs
  }
}

if (!env.PUPPETEER_EXECUTABLE_PATH) {
  const candidates = [];
  if (process.platform === 'win32') {
    const programFiles = process.env['ProgramFiles'] ?? 'C:\\Program Files';
    const programFilesX86 = process.env['ProgramFiles(x86)'] ?? 'C:\\Program Files (x86)';
    const localAppData = process.env.LOCALAPPDATA ?? '';
    candidates.push(
      join(programFiles, 'Google', 'Chrome', 'Application', 'chrome.exe'),
      join(programFilesX86, 'Google', 'Chrome', 'Application', 'chrome.exe'),
      join(localAppData, 'Google', 'Chrome', 'Application', 'chrome.exe'),
    );
  } else if (process.platform === 'darwin') {
    candidates.push('/Applications/Google Chrome.app/Contents/MacOS/Google Chrome');
  } else {
    candidates.push(
      '/usr/bin/google-chrome',
      '/usr/bin/google-chrome-stable',
      '/usr/bin/chromium',
      '/usr/bin/chromium-browser',
    );
  }

  for (const candidate of candidates) {
    if (candidate && existsSync(candidate)) {
      env.PUPPETEER_EXECUTABLE_PATH = candidate;
      break;
    }
  }
}

if (!env.PUPPETEER_EXECUTABLE_PATH) {
  console.error(
    'No Chrome/Chromium found for pa11y-ci. Install Google Chrome or run:\n' +
      '  npx puppeteer browsers install chrome',
  );
  process.exit(1);
}

const result = spawnSync('npx', ['pa11y-ci'], {
  stdio: 'inherit',
  env,
  shell: process.platform === 'win32',
});

process.exit(result.status ?? 1);
