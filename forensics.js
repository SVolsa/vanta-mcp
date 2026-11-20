/**
 * [INPUT]: 接收显式 Root 请求、设备传输和本地 ELF 工具。
 * [OUTPUT]: 写入内核快照和模块实验收据。
 * [POS]: 注册内核取证入口，将设备读取与模块操作结果分别入档。
 * [PROTOCOL]: Update this header on change, then check AGENTS.md
 */
import fs from 'node:fs/promises';
import path from 'node:path';
import {createHash, randomUUID} from 'node:crypto';
import {z} from 'zod';
import {ensureDevice, runDevice, runDeviceBuffer, shellArgs, shQuote} from './transport.js';
import {connectionOptions} from './connection.js';
import {elfIdentity, host, localFile, outputDirectory, sha256, toolchain, writeJson} from './inspection-io.js';
import {moduleVersions} from './binary-inspection.js';

const defaultIO = {adb:runDevice, buffer:runDeviceBuffer};
const digest = data => createHash('sha256').update(data).digest('hex');

function requireRoot(args, tool) {
  if (args.privilege !== 'root') throw new Error(`${tool} requires privilege=root`);
}

function readError(error) {
  const message = error instanceof Error ? error.message : String(error);
  let status = 'read_failed';
  if (/device offline|device (?:.+ )?not found|no devices|disconnected|connection (?:reset|closed|refused)/i.test(message)) status = 'disconnected';
  else if (/timed out|deadline exceeded/i.test(message)) status = 'timeout';
  else if (/permission denied|operation not permitted/i.test(message)) status = 'permission_denied';
  else if (/no such file or directory/i.test(message)) status = 'source_unavailable';
  return {status,error:message};
}

async function rootText(io, command, options) {
  const result = ensureDevice(await io.adb(shellArgs(command,'root'),options));
  return result.stdout.replaceAll('\r\n','\n').trimEnd();
}

const dmesgCommand = lines => `messages=$(dmesg) || exit $?; printf '%s\\n' "$messages" | tail -n ${lines}`;

async function collectPstore(io, directory, perFile, remaining) {
  const entries = [];
  if (!perFile) return {status:'skipped',entries};
  let listing;
  try {
    listing = await rootText(io,'ls -1 /sys/fs/pstore/',{timeoutMs:remaining(),maxChars:16000});
  } catch (error) {
    return {...readError(error),entries};
  }

  const names = listing.split('\n').filter(name=>/^(?:dmesg|console|ftrace|pmsg)-[\w-]{1,120}(?:\.enc\.z)?$/.test(name));
  if (!names.length) return {status:'empty',entries};
  const pstore = path.join(directory,'pstore');
  await fs.mkdir(pstore,{mode:0o700});
  const limit = Math.min(32,Math.floor(16*1024*1024/perFile));
  for (const name of names.slice(0,limit)) {
    let data;
    try {
      const command = `head -c ${perFile+1} /sys/fs/pstore/${shQuote(name)}`;
      data = ensureDevice(await io.buffer(shellArgs(command,'root'),{maxBytes:perFile+1,timeoutMs:remaining()})).stdout;
    } catch (error) {
      entries.push({name,...readError(error)});
      continue;
    }
    const truncated = data.length > perFile;
    const bytes = data.subarray(0,perFile);
    await fs.writeFile(path.join(pstore,name),bytes,{flag:'wx',mode:0o600});
    entries.push({name,size:truncated ? null : data.length,saved:bytes.length,truncated,sha256:digest(bytes),status:'captured'});
  }
  const captured = entries.filter(entry=>entry.status === 'captured').length;
  let status = captured === names.length ? 'captured' : 'partial';
  if (!captured && entries.every(entry=>entry.status === entries[0].status)) status = entries[0].status;
  return {status,entries,skipped_by_limit:Math.max(0,names.length-limit)};
}

export async function kernelSnapshot(args, io = defaultIO) {
  requireRoot(args,'kernel_snapshot');
  const lines = args.dmesg_lines ?? 500;
  const perFile = args.pstore_max_bytes ?? 256*1024;
  const deadline = performance.now()+(args.timeout_ms ?? 90000);
  const remaining = () => {
    const budget = Math.floor(deadline-performance.now());
    if (budget <= 0) throw new Error('snapshot deadline exceeded');
    return Math.min(budget,45000);
  };

  const identity = await rootText(io,[
    'boot_id=$(cat /proc/sys/kernel/random/boot_id) && release=$(uname -r) && machine=$(uname -m) || exit $?',
    'printf "boot_id=%s\\nrelease=%s\\nmachine=%s\\n" "$boot_id" "$release" "$machine"',
    'printf "selinux=%s\\n" "$(getenforce 2>/dev/null || echo unknown)"',
    'printf "kptr_restrict=%s\\n" "$(cat /proc/sys/kernel/kptr_restrict 2>/dev/null || echo unknown)"',
    'printf "panic=%s\\n" "$(cat /proc/sys/kernel/panic 2>/dev/null || echo unknown)"',
    'printf "panic_on_oops=%s\\n" "$(cat /proc/sys/kernel/panic_on_oops 2>/dev/null || echo unknown)"',
    'printf "epoch=%s\\n" "$(date +%s)"; printf "uptime_s=%s\\n" "$(awk \'{print $1}\' /proc/uptime)"',
  ].join('\n'),{timeoutMs:remaining(),maxChars:4000});
  const facts = Object.fromEntries(identity.split('\n').map(line=>/^([a-z_]+)=(.*)$/.exec(line))
    .filter(Boolean).map(([,key,value])=>[key,value]));
  if (!facts.boot_id || !facts.release || !facts.machine) throw new Error('kernel_snapshot could not read the device boot identity');
  const dir = await outputDirectory(args.output,'kernel-snapshot');

  let dmesg = {status:'skipped',lines:0};
  if (lines) {
    let data;
    try {
      data = await rootText(io,dmesgCommand(lines),{timeoutMs:remaining(),maxChars:Math.max(8000,lines*256)});
      if (/\u2026 \d+ chars omitted \u2026/.test(data)) throw new Error('dmesg output exceeded the text limit');
    } catch (error) {
      dmesg = {...readError(error),lines:0};
    }
    if (data !== undefined && !dmesg.error) {
      const bytes = Buffer.from(data ? data+'\n' : '');
      await fs.writeFile(path.join(dir,'dmesg.txt'),bytes,{flag:'wx',mode:0o600});
      dmesg = {status:data ? 'captured' : 'empty',lines:data ? data.split('\n').length : 0,sha256:digest(bytes)};
    }
  }

  const pstore = await collectPstore(io,dir,perFile,remaining);
  const manifest = {
    tool:'kernel_snapshot',captured_at_epoch:facts.epoch ?? null,
    device:{...facts,serial:connectionOptions().serial ?? null},
    outcome:pstore.status,dmesg_lines_saved:dmesg.lines,dmesg_error:dmesg.error ?? null,
    dmesg,pstore:pstore.entries,pstore_skipped_by_limit:pstore.skipped_by_limit ?? 0,pstore_error:pstore.error ?? null,
  };
  const manifestPath = await writeJson(dir,'snapshot.json',manifest);
  return `outcome=${pstore.status}\n${manifestPath}`;
}

async function readModule(file, symvers) {
  const {readelf} = await toolchain();
  const switches = symvers ? ['-h','-p','.modinfo','-x','__versions'] : ['-h','-p','.modinfo'];
  const {stdout} = await host(readelf,[...switches,file],{maxBuffer:8*1024*1024});
  const identity = elfIdentity(stdout);
  const info = Object.fromEntries([...stdout.matchAll(/^\s*\[[^\]\n]+\]\s*(\w+)=(.*)$/gm)]
    .map(([,key,value])=>[key,value.trim()]));
  if (identity.type !== 'REL' || !info.vermagic) throw new Error('expected a relocatable ELF kernel module with .modinfo vermagic');
  const name = info.name ?? path.basename(file).replace(/\.ko$/i,'');
  if (!/^[A-Za-z0-9_][\w-]{0,127}$/.test(name)) throw new Error('module contains an unsupported name');
  return {name,vermagic:info.vermagic,records:symvers ? moduleVersions(stdout,identity) : null};
}

async function checkCRCs(file, records) {
  const input = await localFile(file,32*1024*1024,'Module.symvers');
  const reference = new Map();
  for (const line of (await fs.readFile(input,'utf8')).split(/\r?\n/)) {
    const match = /^(0x[\da-f]{8})\s+(\w+)\s+/i.exec(line);
    if (!match) continue;
    const [,hex,symbol] = match;
    const crc = hex.slice(2).toLowerCase();
    if (reference.has(symbol) && reference.get(symbol) !== crc) throw new Error('Module.symvers has conflicting CRC records');
    reference.set(symbol,crc);
  }
  if (!reference.size) throw new Error('Module.symvers has no valid CRC records');
  if (!records?.length) return {status:'unknown',reason:'no supported __versions records'};
  const mismatches = records.filter(({symbol,crc})=>reference.has(symbol) && reference.get(symbol) !== crc);
  const missing = records.filter(({symbol})=>!reference.has(symbol)).map(({symbol})=>symbol);
  return {status:mismatches.length ? 'mismatch' : missing.length ? 'unknown' : 'match',
    checked:records.length-missing.length,mismatches,missing};
}

function moduleParameters(args) {
  if (args.params !== undefined && !args.load) throw new Error('params requires load=true');
  const params = typeof args.params === 'string' ? args.params.trim().split(/[ \t]+/).filter(Boolean) : args.params ?? [];
  if (params.length > 64 || params.some(param=>param.length > 512 || !/^[A-Za-z_]\w*=[^\0\r\n]*$/.test(param))) {
    throw new Error('module parameters must be name=value arguments');
  }
  return params;
}

async function moduleState(io, name, lines) {
  const options = {timeoutMs:15000,maxChars:16000};
  const state = {modules:null,dmesg_tail:null,errors:{}};
  try {
    const command = `modules=$(cat /proc/modules) || exit $?; printf '%s\\n' "$modules" | awk -v name=${shQuote(name)} '$1 == name { print; found=1 } END { if (!found) print "@absent" }'; [ ! -d /sys/module/${shQuote(name)} ] && echo sysfs=absent || echo sysfs=present`;
    state.modules = await rootText(io,command,options);
  } catch (error) {
    state.errors.modules = readError(error);
  }
  try {
    state.dmesg_tail = await rootText(io,dmesgCommand(lines),options);
  } catch (error) {
    state.errors.dmesg = readError(error);
  }
  return state;
}

async function moduleAction(io, command) {
  try {
    const result = await io.adb(shellArgs(command,'root'),{timeoutMs:30000,maxChars:4000});
    const exit = result.timedOut ? 'timeout' : result.code ?? 'unknown';
    return {exit,stderr:result.stderr.trim() || null};
  } catch (error) {
    return {exit:'unknown',...readError(error)};
  }
}

async function loadModule(io, file, params) {
  const remote = `/data/local/tmp/vanta-krec-${randomUUID()}.ko`;
  let result, cleanupError;
  try {
    ensureDevice(await io.adb(['push',file,remote],{timeoutMs:120000,maxChars:2000}));
    result = await moduleAction(io,['insmod',shQuote(remote),...params.map(shQuote)].join(' '));
  } catch (error) {
    result = {exit:'unknown',...readError(error)};
  } finally {
    try {
      await rootText(io,`rm -f -- ${shQuote(remote)}`,{timeoutMs:10000,maxChars:1000});
    } catch (error) {
      cleanupError = readError(error);
    }
  }
  return {params,...result,cleanup_error:cleanupError ?? null};
}

export async function kernelRecord(args, io = defaultIO) {
  requireRoot(args,'kernel_record');
  const params = moduleParameters(args);
  const file = await localFile(args.local,512*1024*1024,'kernel module');
  const checksum = await sha256(file);
  const {name,vermagic,records} = await readModule(file,args.module_symvers);
  const crcCheck = args.module_symvers ? await checkCRCs(args.module_symvers,records) : null;
  const size = (await fs.stat(file)).size;
  const dir = await outputDirectory(args.output,'kernel-record');
  const before = await moduleState(io,name,30);
  const stateFailed = !!before.errors.modules;
  let load = null, unload = null;
  if (args.load) {
    if (stateFailed) load = {exit:'skipped',reason:'module state unavailable'};
    else if (await sha256(file) !== checksum) load = {exit:'skipped',reason:'local module changed'};
    else load = await loadModule(io,file,params);
  }
  if (args.unload) {
    unload = stateFailed || (args.load && load?.exit !== 0)
      ? {exit:'skipped',reason:'module state or successful load not confirmed'}
      : await moduleAction(io,`rmmod ${shQuote(name)}`);
  }
  const after = await moduleState(io,name,40);
  const record = {tool:'kernel_record',module:name,file,sha256:checksum,size,vermagic,crc_check:crcCheck,before,load,after,unload};
  const recordPath = await writeJson(dir,'record.json',record);
  return `module=${name}\nvermagic=${vermagic}\ncrc_check=${crcCheck?.status ?? 'skipped'}\nload=${load ? `exit=${load.exit}` : 'not_requested'}\nunload=${unload ? `exit=${unload.exit}` : 'not_requested'}\n${recordPath}`;
}

export function registerForensicsTools(register) {
  const output = z.string().min(1).max(1024).optional();
  register('kernel_snapshot','采集内核日志与 pstore 快照。需要显式 privilege=root。',{
    output,dmesg_lines:z.number().int().min(0).max(5000).optional(),
    pstore_max_bytes:z.number().int().min(0).max(2*1024*1024).optional(),
    timeout_ms:z.number().int().min(5000).max(120000).optional(),
  },args=>kernelSnapshot(args));
  register('kernel_record','记录模块身份与操作前后状态。load 和 unload 由调用方分别指定。需要显式 privilege=root。',{
    local:z.string().min(1).max(1024),
    params:z.union([z.array(z.string().max(512)).max(64),z.string().max(4096)]).optional(),
    load:z.boolean().optional(),unload:z.boolean().optional(),
    module_symvers:z.string().min(1).max(1024).optional(),output,
  },args=>kernelRecord(args));
}
