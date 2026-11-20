import {existsSync} from 'node:fs';
import path from 'node:path';
import {fileURLToPath} from 'node:url';

export function hostTestShell() {
  if (process.env.VANTA_TEST_SHELL) return process.env.VANTA_TEST_SHELL;
  if (process.platform!=='win32') return '/bin/sh';
  const bundled = fileURLToPath(new URL('../../.tools/w64devkit/root/w64devkit/bin/sh.exe',import.meta.url));
  const git = path.join(process.env.ProgramFiles || 'C:/Program Files','Git/bin/sh.exe');
  return [bundled,git].find(candidate=>existsSync(candidate)) || 'sh.exe';
}
