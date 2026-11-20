import { AsyncLocalStorage } from 'node:async_hooks';
import { existsSync } from 'node:fs';
import { homedir } from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { shQuote } from './adb.js';

const requests = new AsyncLocalStorage();
export const connectionOptions = () => requests.getStore() ?? {};
const legacyUSBConfig = fileURLToPath(new URL('../secrets/vanta-usb/client.json', import.meta.url));

export function usbConfigPath() {
  if (process.env.VANTA_CONFIG) return path.resolve(process.env.VANTA_CONFIG);
  const base = process.platform==='win32'
    ? process.env.APPDATA || path.join(homedir(),'AppData','Roaming')
    : process.env.XDG_CONFIG_HOME || path.join(homedir(),'.config');
  const preferred = path.join(base,'vanta-mcp','usb','client.json');
  return existsSync(preferred) || !existsSync(legacyUSBConfig) ? preferred : legacyUSBConfig;
}

export function configuredTransport() {
  if (process.env.VANTA_TRANSPORT && !['usb','adb'].includes(process.env.VANTA_TRANSPORT)) throw new Error('invalid VANTA_TRANSPORT');
  return process.env.VANTA_TRANSPORT || (existsSync(usbConfigPath()) ? 'usb' : 'adb');
}

export function requestedPrivilege(args = {}) {
  const legacy = args.root === undefined ? undefined : args.root ? 'root' : 'shell';
  if (legacy && args.privilege && legacy !== args.privilege) throw new Error('root and privilege conflict');
  const privilege = args.privilege ?? legacy ?? connectionOptions().privilege ?? 'shell';
  if (!['shell', 'root', 'shizuku'].includes(privilege)) throw new Error('invalid privilege');
  return privilege;
}

export async function withConnection(args, action) {
  if (args.transport && !['adb', 'usb'].includes(args.transport)) throw new Error('invalid transport');
  if (args.serial !== undefined && (typeof args.serial !== 'string' || !/^[A-Za-z0-9][A-Za-z0-9._:[\]%-]{0,254}$/.test(args.serial))) {
    throw new Error('invalid device serial');
  }
  const transport = args.transport ?? configuredTransport();
  if (transport === 'usb' && args.serial !== undefined) throw new Error('serial is only supported with the adb transport');
  const serial = transport === 'adb' ? args.serial ?? process.env.VANTA_SERIAL ?? process.env.TABLET_SERIAL ?? process.env.ANDROID_SERIAL : undefined;
  return requests.run({ transport, serial, privilege: requestedPrivilege(args) }, action);
}

// The package must belong to the actual caller UID. Shizuku verifies this itself.
// This adapter does not install rish, start Shizuku, grant permission, or run su.
export function shizukuCommand(command, env = process.env) {
  const script = env.VANTA_RISH_PATH;
  if (!script) throw new Error('Shizuku requires VANTA_RISH_PATH pointing to the exported rish script');
  if (!script.startsWith('/') || /[\0\r\n]/.test(script)) throw new Error('VANTA_RISH_PATH must be an absolute Android path');
  const application = env.VANTA_RISH_APPLICATION_ID || 'com.android.shell';
  if (!/^[A-Za-z_][\w]*(?:\.[A-Za-z_][\w]*)+$/.test(application)) throw new Error('invalid Shizuku application package');
  return `RISH_APPLICATION_ID=${shQuote(application)} RISH_PRESERVE_ENV=0 /system/bin/sh ${shQuote(script)} -c ${shQuote(command)}`;
}

export function usbShellCommand(command) {
  // 0.4.4 switches on the device. Older daemons only drop UID/capabilities.
  // Inspect the current execution instead of caching a version across reconnects.
  const invoke = '/system/bin/sh -c "$1"';
  return `set -- ${shQuote(command)}; if [ "$(/system/bin/id -Z 2>/dev/null)" = u:r:shell:s0 ]; then exec ${invoke}; fi; exec /system/bin/runcon u:r:shell:s0 ${invoke}`;
}
