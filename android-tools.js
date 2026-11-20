import { z } from 'zod';
import { runAdb, ensureAdb } from './adb.js';
import { runDevice, ensureDevice, shellArgs, shQuote, transportName } from './transport.js';
import { connectionOptions } from './connection.js';

export function statusCommand() {
  return [
    'echo model=$(getprop ro.product.model)',
    'echo android=$(getprop ro.build.version.release)',
    'echo sdk=$(getprop ro.build.version.sdk)',
    'echo abi=$(getprop ro.product.cpu.abilist)',
    'echo kernel=$(uname -r)',
    'echo uid=$(id -u)',
    'echo selinux=$(getenforce 2>/dev/null || echo unknown)',
    'echo root_binary=$(command -v su 2>/dev/null || echo absent)',
    'echo root_access=not_probed',
  ].join('; ');
}

export function logcatCommand(args) {
  const command = ['logcat', '-d', '-v', 'threadtime', '-t', String(args.lines ?? 200)];
  if (args.pid) command.push(`--pid=${args.pid}`);
  if (args.buffer) command.push('-b', args.buffer);
  if (args.tag) command.push(`${args.tag}:${args.priority ?? 'V'}`, '*:S');
  else if (args.priority) command.push(`*:${args.priority}`);
  return command.map(shQuote).join(' ');
}

function packageName(value) {
  if (typeof value !== 'string' || !/^[A-Za-z_][\w]*(?:\.[A-Za-z_][\w]*)+$/.test(value)) {
    throw new Error('a valid Android package is required');
  }
  return value;
}

export function shizukuDiagnostic(message) {
  if (/request timeout/i.test(message)) return `Shizuku Binder request timed out before authorization could be verified: ${message}`;
  if (/server is not running/i.test(message)) return `Shizuku service is not running: ${message}`;
  if (/permission denied/i.test(message)) return `Shizuku or Android denied access: ${message}`;
  return message;
}

export function registerAndroidTools(register, {run = runDevice, adb = runAdb} = {}) {
  async function remote(command, maxChars = 6000) {
    const result = ensureDevice(await run(shellArgs(command), {timeoutMs:20000,maxChars}));
    return result.stdout.trim();
  }

  register('connection', '查看连接配置、枚举 ADB 设备或显式检查所选权限；不自动提权或切换通道。', {
    action: z.enum(['info','devices','check']).default('info'),
  }, async args => {
    if (args.action === 'devices') {
      // This is an explicit host-wide inventory, never a command to the selected device.
      return ensureAdb(await adb(['devices','-l'], {serial:null,maxChars:12000})).stdout;
    }
    const context = connectionOptions();
    const info = {
      transport: transportName(),
      serial: transportName() === 'adb' ? context.serial || process.env.VANTA_SERIAL || process.env.TABLET_SERIAL || process.env.ANDROID_SERIAL || '(adb default)' : '(paired USB device)',
      privilege: context.privilege ?? 'shell',
      shizuku: process.env.VANTA_RISH_PATH ? 'rish_configured_not_verified' : 'rish_not_configured',
      fallback: false,
    };
    if (args.action === 'check') {
      try {
        info.identity = await remote('id; getenforce 2>/dev/null; echo sdk=$(getprop ro.build.version.sdk); echo abi=$(getprop ro.product.cpu.abilist)');
        if (info.privilege === 'shizuku') {
          if (!/^uid=\d+(?:\([^\r\n()]+\))?\s+gid=\d+/m.test(info.identity)) {
            throw new Error('Shizuku returned no Android execution identity');
          }
          info.shizuku = 'rish_verified';
        }
      } catch (error) {
        if (info.privilege === 'shizuku') throw new Error(shizukuDiagnostic(error.message),{cause:error});
        throw error;
      }
    }
    return JSON.stringify(info, null, 2);
  });

  register('app', '按 Android 用户查看应用、APK/split 路径、PID 或显式启动/停止应用。', {
    action: z.enum(['list','info','paths','pids','start','stop']),
    package: z.string().optional(),
    component: z.string().optional(),
    user: z.number().int().min(0).optional(),
    third_party: z.boolean().optional(),
    max_chars: z.number().int().min(500).max(20000).optional(),
  }, async args => {
    const user = args.user ?? 'current';
    let command;
    if (args.action === 'list') {
      command = `pm list packages --user ${user}${args.third_party ? ' -3' : ''}${args.package ? ` ${shQuote(packageName(args.package))}` : ''}`;
    } else {
      const pkg = packageName(args.package);
      if (args.action === 'paths') command = `pm path --user ${user} ${shQuote(pkg)}`;
      if (args.action === 'info') command = `pm path --user ${user} ${shQuote(pkg)} && dumpsys package ${shQuote(pkg)} | head -n 200`;
      if (args.action === 'pids') command = `user=${args.user ?? '$(am get-current-user)'}; ps -A -o PID,UID,NAME | awk -v pkg=${shQuote(pkg)} -v user="$user" 'NR==1 || ($2>=user*100000 && $2<(user+1)*100000 && ($3==pkg || index($3,pkg ":")==1))'`;
      if (args.action === 'stop') command = `am force-stop --user ${user} ${shQuote(pkg)}`;
      if (args.action === 'start') {
        if (!args.component || !/^\.?[A-Za-z_$][\w.$]*$/.test(args.component)) throw new Error('a valid activity component is required');
        command = `am start -W --user ${user} -n ${shQuote(`${pkg}/${args.component}`)}`;
      }
    }
    return remote(command, args.max_chars ?? 12000);
  });

  register('diagnostics', '读取有界系统诊断：内存、帧耗时、电量、活动、崩溃记录；不清日志。', {
    service: z.enum(['meminfo','gfxinfo','battery','activity','package','dropbox']),
    package: z.string().optional(),
    max_chars: z.number().int().min(500).max(20000).optional(),
  }, async args => {
    let command = `dumpsys ${args.service}`;
    if (['meminfo','gfxinfo','package'].includes(args.service)) command += ` ${shQuote(packageName(args.package))}`;
    if (args.service === 'activity') command += ' activities';
    // Dropbox summary omits --print: crash bodies can contain application secrets.
    return remote(`${command} | head -n 200`, args.max_chars ?? 12000);
  });
}
