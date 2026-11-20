import fs from 'node:fs/promises';
import https from 'node:https';
import path from 'node:path';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { isIP } from 'node:net';
import { randomUUID } from 'node:crypto';
import { runAdb, runAdbBuffer, shellArgs as adbShellArgs, shQuote, ensureAdb, clip } from './adb.js';
import {uploadFile,downloadFile} from './file-transfer.js';
import { connectionOptions, requestedPrivilege, shizukuCommand, usbShellCommand, configuredTransport, usbConfigPath } from './connection.js';
export { shQuote, validName } from './adb.js';

let usbCache;
export async function discoverUSB() {
  if (usbCache && Date.now()-usbCache.time<10000) return usbCache;
  if (process.platform !== 'win32') throw new Error('USB discovery currently supports Windows hosts');
  const script="Get-NetIPConfiguration | Where-Object { $_.InterfaceDescription -match 'RNDIS|USB.*(Ethernet|NCM)|NCM' -and $_.NetAdapter.Status -eq 'Up' } | ForEach-Object { if ($_.IPv4Address) { [pscustomobject]@{local=$_.IPv4Address[0].IPAddress;remote=$_.IPv4DefaultGateway.NextHop} } } | ConvertTo-Json -Compress";
  const {stdout}=await promisify(execFile)('powershell.exe',['-NoProfile','-NonInteractive','-Command',script],{windowsHide:true,timeout:8000});
  const parsed=JSON.parse(stdout.trim() || '[]');const links=Array.isArray(parsed)?parsed:[parsed];
  if (links.length===0) throw new Error('USB management interface is not enumerated; enable/start Vanta in KernelSU Next and check the USB data connection. No Wi-Fi or Internet connection is required.');
  if (links.length!==1) throw new Error('multiple active USB network adapters; cannot select the paired device safely');
  const local=links[0].local, remote=links[0].remote || '169.254.77.1';
  if (isIP(local)!==4 || isIP(remote)!==4) throw new Error('invalid USB interface addresses');
  usbCache={local,remote,time:Date.now()};return usbCache;
}
export function transportName() {
  return connectionOptions().transport ?? configuredTransport();
}
export function shellArgs(command, root) {
  const privilege = typeof root === 'string' ? requestedPrivilege({privilege:root}) : requestedPrivilege({root});
  return ['vanta-shell', privilege, command];
}

export async function usbRequest(route, payload, { timeoutMs = 20000, maxResponse = 96 * 1024 * 1024 } = {}) {
  const configPath = usbConfigPath();
  const config = JSON.parse(await fs.readFile(configPath,'utf8'));
  if (config?.endpoint!=='usb:auto') throw new Error('USB configuration must use automatic USB interface discovery');
  if (![config.ca,config.cert,config.key,config.servername].every(item=>typeof item==='string' && item.trim())) {
    throw new Error('USB configuration must specify ca, cert, key and servername');
  }
  const link=await discoverUSB();
  const url = new URL(route, `https://${link.remote}:22445`);
  const [ca, cert, key] = await Promise.all([config.ca,config.cert,config.key].map(file=>fs.readFile(path.resolve(path.dirname(configPath),file))));
  const body = payload === undefined ? undefined : Buffer.from(JSON.stringify(payload));
  return new Promise((resolve, reject) => {
    const request = https.request(url, { method:body ? 'POST' : 'GET', ca, cert, key,
      servername:config.servername, minVersion:'TLSv1.3', rejectUnauthorized:true, agent:false,localAddress:link.local,
      headers:body ? {'content-type':'application/json','content-length':body.length} : {} }, response => {
      const chunks=[]; let size=0;
      response.on('data', chunk => { size += chunk.length; if (size > maxResponse) request.destroy(new Error('USB response exceeds limit')); else chunks.push(chunk); });
      response.on('error', reject);
      response.on('end', () => {
        if (response.statusCode !== 200) { reject(new Error(`USB endpoint HTTP ${response.statusCode}`)); return; }
        try { resolve(JSON.parse(Buffer.concat(chunks).toString('utf8'))); } catch { reject(new Error('invalid USB endpoint response')); }
      });
    });
    const timer=setTimeout(() => request.destroy(new Error('USB request timed out')), timeoutMs + 5000);
    request.on('close', () => clearTimeout(timer));
    request.on('error', error => {usbCache=undefined;reject(error)}); request.end(body);
  });
}

async function execute(command, root, options, input) {
  const timeoutMs=options.timeoutMs ?? 20000;
  if (!root) command = usbShellCommand(command);
  const answer=await usbRequest('/v1/exec', {command,root,timeout_ms:Math.min(timeoutMs,120000),
    max_bytes:options.maxBytes ?? Math.min(4 * (options.maxChars ?? 12000),64*1024*1024),
    stdin:input?.toString('base64') ?? ''}, {timeoutMs});
  if (!Number.isInteger(answer.code) || ![null,'string'].includes(answer.stdout === null ? null : typeof answer.stdout) ||
      ![null,'string'].includes(answer.stderr === null ? null : typeof answer.stderr)) throw new Error('invalid USB execution result');
  return {...answer,stdout:Buffer.from(answer.stdout ?? '','base64'),stderr:Buffer.from(answer.stderr ?? '','base64'),signal:null};
}

export async function runDeviceBuffer(args, options = {}) {
  const privilege = args[0] === 'vanta-shell' ? args[1] : requestedPrivilege();
  const command = args[0] === 'vanta-shell' ? args[2] : args[0] === 'exec-out' ? args.slice(1).map(shQuote).join(' ') : args.map(shQuote).join(' ');
  const adbOnly = ['forward','reverse','devices','connect','disconnect','pair','tcpip','install','push','pull'].includes(args[0]);
  const limited = transportName() === 'adb' && !adbOnly
    ? `timeout -k 1 ${Math.ceil((options.timeoutMs ?? 20000)/1000)} /system/bin/sh -c ${shQuote(command)}` : command;
  let elevated = limited;
  if (privilege === 'shizuku' && !adbOnly) {
    // rish may put this command on a PTY even when ADB uses exec-out.
    // Disable output processing on that terminal before sending binary data.
    const payload = options.textMode ? limited : `if [ -t 1 ]; then /system/bin/stty -F /dev/stdout -opost || exit; fi;\n${limited}`;
    elevated = shizukuCommand(payload);
  }
  if (transportName() === 'adb') {
    if (!adbOnly && !options.textMode) {
      // Some ROM/ADB combinations still apply CRLF conversion with `shell -T`.
      // exec-out preserves bytes; an outer shell appends the actual exit status.
      const marker = `\n__VANTA_BINARY_EXIT_${randomUUID().replaceAll('-','')}__=`;
      const execution = adbShellArgs(elevated,privilege==='root').at(-1);
      const framed = `${execution}; rc=$?; printf '${marker.replaceAll('\n','\\n')}%s\\n' "$rc"`;
      const limit = options.maxBytes ?? 64*1024*1024;
      const result = await runAdbBuffer(['exec-out',framed], {...options,maxBytes:limit+128,timeoutMs:(options.timeoutMs ?? 20000)+2000,serial:connectionOptions().serial});
      if (result.timedOut || result.tooLarge || result.code !== 0) return result;
      const boundary = result.stdout.lastIndexOf(Buffer.from(marker));
      const code = boundary < 0 ? '' : result.stdout.subarray(boundary+Buffer.byteLength(marker)).toString('ascii');
      if (!/^\d{1,3}\r?\n$/.test(code)) throw new Error('ADB binary command did not return its execution receipt');
      result.code = Number(code.trim());
      result.stdout = result.stdout.subarray(0,boundary);
      result.tooLarge = result.stdout.length > limit;
      result.timedOut = result.code === 124;
      if (result.tooLarge) result.stdout = result.stdout.subarray(0,limit);
      return result;
    }
    if (!adbOnly) {
      args = args[0] === 'exec-out' ? ['exec-out', adbShellArgs(elevated,privilege==='root').at(-1)] : adbShellArgs(elevated,privilege==='root');
    }
    const settings = {...options,timeoutMs:(options.timeoutMs ?? 20000)+2000,serial:connectionOptions().serial};
    const result = options.textMode ? await runAdb(args,settings) : await runAdbBuffer(args,settings);
    if (options.textMode) {
      result.stdout = Buffer.from(result.stdout);
      result.stderr = Buffer.from(result.stderr);
    }
    if (!adbOnly && result.code === 124) result.timedOut = true;
    return result;
  }
  if (['forward','reverse','devices','connect','disconnect','pair','tcpip','install'].includes(args[0])) throw new Error('ADB-specific operation unavailable on the USB module transport');
  return execute(elevated, privilege==='root', options);
}

export async function runDevice(args, options = {}) {
  if (args[0] === 'pull') {
    const remote = async (command,chunkOptions) => {
      const result = ensureDevice(await runDeviceBuffer(shellArgs(command),chunkOptions));
      return result.stdout;
    };
    const transfer = await downloadFile(args[1],args[2],remote,options);
    return {code:0,timedOut:false,tooLarge:false,signal:null,stdout:`pull verified: ${transfer.bytes} bytes, SHA256 ${transfer.sha256}, ${transfer.chunks} chunks`,stderr:'',transfer};
  }
  if (transportName() === 'adb') {
    if (['forward','reverse','devices','connect','disconnect','pair','tcpip','install','push','pull'].includes(args[0])) {
      return runAdb(args, {...options, serial:connectionOptions().serial});
    }
  }
  let answer;
  if (['push','pull'].includes(args[0])) {
    const remote=async(command,chunkOptions,input)=>{
      const result=await execute(command,false,chunkOptions,input);
      ensureDevice(result);return result.stdout;
    };
    const transfer=args[0]==='push' ? await uploadFile(args[1],args[2],remote) : await downloadFile(args[1],args[2],remote,options);
    answer={code:0,timedOut:false,tooLarge:false,signal:null,stdout:Buffer.from(`${args[0]} verified: ${transfer.bytes} bytes, SHA256 ${transfer.sha256}, ${transfer.chunks} chunks`),stderr:Buffer.alloc(0),transfer};
  } else answer=await runDeviceBuffer(args,{...options,textMode:true});
  return {...answer,stdout:clip(answer.stdout.toString('utf8'),options.maxChars ?? 12000),stderr:answer.stderr.toString('utf8')};
}
export function ensureDevice(result) {
  if (result.timedOut) throw new Error('device command timed out');
  if (result.tooLarge) throw new Error('device output exceeded the size limit');
  return ensureAdb(result);
}
