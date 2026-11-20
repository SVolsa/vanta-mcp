/**
 * [INPUT]: 接收本地程序或 APK 与显式设备连接参数。
 * [OUTPUT]: 返回执行收据或安装结果，清理设备临时文件。
 * [POS]: 通过 transport 实现 MCP 的 run 和 install_apk。
 * [PROTOCOL]: Update this header on change, then check AGENTS.md
 */
import fs from 'node:fs/promises';
import path from 'node:path';
import { randomUUID } from 'node:crypto';
import { runDevice, ensureDevice, shellArgs, shQuote, transportName } from './transport.js';
import { requestedPrivilege } from './connection.js';

async function cleanly(action, cleanup, onCleanupError) {
  let result, failure;
  try { result = await action(); }
  catch (error) { failure = error; throw error; }
  finally {
    try { await cleanup(); }
    catch (error) {
      if (failure || !onCleanupError) throw new Error(`${failure ? `${failure.message}; ` : ''}temporary file cleanup failed: ${error.message}`);
      result = onCleanupError(result,error);
    }
  }
  return result;
}

function forensicCommand(remote, argv, seconds, marker) {
  const child = [
    '"$0" "$@" & pid=$!',
    'stat=$(cat "/proc/$pid/stat" 2>/dev/null)',
    'set -- ${stat##*) }',
    "printf '\\n" + marker + "_START=%s:%s\\n' \"$pid\" \"${20:-}\"",
    'wait "$pid"; rc=$?',
    "printf '\\n" + marker + "_CHILD=%s\\n' \"$rc\"",
  ].join('\n');
  const invocation = [shQuote(remote), ...argv.map(shQuote)].join(' ');
  return `chmod 700 ${shQuote(remote)} && timeout -k 1 ${seconds} /system/bin/sh -c ${shQuote(child)} ${invocation}; rc=$?; printf '\\n${marker}=%s\\n' "$rc"; exit 0`;
}

function forensicSummary(result, marker, duration) {
  const stdout = result.stdout.replaceAll('\r\n','\n');
  const status = new RegExp(`\\n${marker}=(\\d{1,3})\\s*$`).exec(stdout);
  const start = new RegExp(`\\n${marker}_START=([1-9]\\d*):(\\d*)(?=\\n|$)`).exec(stdout);
  const child = new RegExp(`\\n${marker}_CHILD=(\\d{1,3})(?=\\n|$)`).exec(stdout);
  const output = stdout.split('\n').filter(line=>!line.startsWith(marker)).join('\n').trimEnd();
  const wrapperCode = status ? Number(status[1]) : null;
  const childCode = wrapperCode === 0 && child ? Number(child[1]) : null;
  const timedOut = wrapperCode === 124 || (!status && result.timedOut);
  let exit = 'unknown', detail = 'exit_type=lost';
  if (childCode !== null) {
    exit = childCode;
    const ambiguous = childCode >= 129 && childCode <= 192;
    detail = ambiguous ? `exit_type=ambiguous shell_status=${childCode}` : `exit_type=exit code=${childCode}`;
  } else if (timedOut) {
    exit = 'timeout';
    detail = 'exit_type=timeout';
  } else if (wrapperCode && !start) {
    exit = wrapperCode;
    detail = `exit_type=launch_error wrapper_status=${wrapperCode}`;
  }
  const receipt = childCode !== null || (wrapperCode !== null && wrapperCode !== 0);
  return {exit,output,detail:`${detail}\npid=${start?.[1] ?? 'unknown'}\nstart_tick=${start?.[2] || 'unavailable'}\nduration_ms=${duration}\nduration_source=host\nreceipt=${receipt}`};
}

export async function runProgram(args, run = runDevice) {
  if (args.args !== undefined && args.argv !== undefined) throw new Error('use either args or argv, not both');
  if (args.forensics && args.args !== undefined) throw new Error('run forensics requires argv instead of args');
  const local = path.resolve(args.local);
  if (!(await fs.stat(local)).isFile()) throw new Error('run requires a regular file');
  const base = path.basename(local).replace(/[^\w.-]/g, '_');
  const remote = `/data/local/tmp/vanta-run-${randomUUID()}-${base}`;
  const marker = `__VANTA_EXIT_${randomUUID().replaceAll('-','')}__`;
  const budget = args.timeout_ms ?? 10000;
  const privilege = requestedPrivilege(args);
  return cleanly(async () => {
    ensureDevice(await run(['push', local, remote], {timeoutMs:120000,maxChars:2000}));
    const parameters = args.argv ? args.argv.map(shQuote).join(' ') : args.args ?? '';
    const seconds = Math.ceil(budget/1000);
    const command = args.forensics
      ? forensicCommand(remote,args.argv ?? [],seconds,marker)
      : `chmod 700 ${shQuote(remote)} && timeout ${seconds} ${shQuote(remote)}${parameters ? ` ${parameters}` : ''}; rc=$?; printf '\\n${marker}=%s\\n' "$rc"; exit "$rc"`;
    const started = performance.now();
    const result = await run(shellArgs(command, privilege), {timeoutMs:budget+8000,maxChars:args.max_chars ?? 8000})
      .catch(error => {
        if (!args.forensics) throw error;
        return {stdout:'',stderr:error.message,timedOut:false};
      });
    if (result.tooLarge) throw new Error('program output exceeded the size limit');
    const kept = args.keep ? ' (kept)' : '';
    const stderr = result.stderr.trim() ? `\nstderr:\n${result.stderr.trim()}` : '';
    if (args.forensics) {
      const {exit,output,detail} = forensicSummary(result,marker,Math.round(performance.now()-started));
      return `remote=${remote}\nexit=${exit}${kept}\n${detail}\n---\n${output || '(no output)'}${stderr}`;
    }
    const match = result.stdout.match(new RegExp(`\\n${marker}=(\\d+)\\s*$`));
    const code = result.timedOut ? 'timeout' : match ? Number(match[1]) : result.code;
    if (!match && !result.timedOut && result.code === 0) throw new Error('program did not return its execution receipt');
    const output = match ? result.stdout.slice(0,match.index) : result.stdout;
    return `remote=${remote}\nexit=${code}${kept}\n---\n${output || '(no output)'}${stderr}`;
  }, async () => {
    if (!args.keep) ensureDevice(await run(shellArgs(`rm -f -- ${shQuote(remote)}`, privilege), {maxChars:1000}));
  }, args.forensics ? (output,error)=>`cleanup_error=${JSON.stringify(error.message)}\n${output}` : undefined);
}

export async function installApk(args, run = runDevice) {
  const local = path.resolve(args.local);
  if (path.extname(local).toLowerCase() !== '.apk') throw new Error('local must be an APK file');
  const stat = await fs.stat(local);
  if (!stat.isFile() || stat.size === 0) throw new Error('install requires a nonempty APK file');
  const privilege = requestedPrivilege(args);
  const flags = `${args.replace === false ? '' : '-r '}${args.user === undefined ? '' : `--user ${args.user} `}`;
  const check = result => {
    ensureDevice(result);
    if (!/^Success\s*$/m.test(result.stdout)) throw new Error(result.stdout.trim() || 'package manager did not confirm installation');
    return `transport=${transportName()}\nprivilege=${privilege}\n${result.stdout.trim()}`;
  };
  if (transportName() === 'adb' && privilege === 'shell') {
    return check(await run(['install', ...(args.replace === false ? [] : ['-r']), ...(args.user === undefined ? [] : ['--user',String(args.user)]), local], {timeoutMs:120000,maxChars:6000}));
  }
  const remote = `/data/local/tmp/vanta-install-${randomUUID()}.apk`;
  return cleanly(async () => {
    ensureDevice(await run(['push', local, remote], {timeoutMs:120000,maxChars:2000}));
    // Feed the installer through stdin so the staging APK can remain mode 600.
    return check(await run(shellArgs(`chmod 600 ${shQuote(remote)} && pm install ${flags}-S ${stat.size} < ${shQuote(remote)}`, privilege), {timeoutMs:120000,maxChars:6000}));
  }, async () => {
    // The staging file was created by the base shell transport, not by rish/su.
    ensureDevice(await run(shellArgs(`rm -f -- ${shQuote(remote)}`, 'shell'), {maxChars:1000}));
  });
}
