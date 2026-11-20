import fs from 'node:fs/promises';
import path from 'node:path';
import { connectionOptions } from './connection.js';
import { deviceText, elfIdentity, host, localFile, outputDirectory, sha256, toolchain, writeJson } from './inspection-io.js';

const maxELF = 512*1024*1024;

export async function binaryInspection(args) {
  const file = await localFile(args.local,maxELF,'ELF');
  const tools = await toolchain();
  const {stdout:header} = await host(tools.readelf,['-h','-n',file]);
  const identity = elfIdentity(header);
  if (!identity.machine || !identity.type) throw new Error('unrecognized ELF header');
  const sections = await host(tools.readelf,['-SW','-lW','-dW',file]);
  const symbols = args.symbols === false ? null : await host(tools.readelf,['--symbols','--relocations','--wide',file],{maxBuffer:12*1024*1024});
  const report = {file,sha256:await sha256(file),...identity,
    needed:[...sections.stdout.matchAll(/Shared library: \[([^\]]+)\]/g)].map(match => match[1]),
    header, sections_and_dynamic:sections.stdout, symbols_and_relocations:symbols?.stdout ?? null};
  if (args.start_address !== undefined || args.byte_count !== undefined) {
    if (args.start_address === undefined || args.byte_count === undefined) throw new Error('start_address and byte_count must be given together');
    const start = BigInt(args.start_address), end = start + BigInt(args.byte_count);
    if (end > (1n<<64n)) throw new Error('address range exceeds ELF address space');
    const section = args.section ? [`--section=${args.section}`] : [];
    const {stdout} = await host(tools.objdump,['-d',...section,`--start-address=0x${start.toString(16)}`,`--stop-address=0x${end.toString(16)}`,file]);
    report.disassembly = {section:args.section ?? null,start:args.start_address,byte_count:args.byte_count,text:stdout};
  } else if (args.section) {
    throw new Error('section requires a disassembly address range');
  }
  const dir = await outputDirectory(args.output,'elf');
  return {report:await writeJson(dir,'elf.json',report), type:identity.type,machine:identity.machine,build_id:identity.build_id,needed:report.needed};
}

function parseModinfo(raw) {
  const entries = new Map();
  for (const line of raw.split(/\r?\n/)) {
    const match = /^\s*\[\s*[\da-f]+\]\s+(\w+)=(.*)$/i.exec(line);
    if (match) entries.set(match[1],match[2].trim());
  }
  return entries;
}

const checksum = value => value?.toLowerCase().replace(/^0x/,'').padStart(8,'0');

export function moduleVersions(raw, identity) {
  const hex = [...raw.matchAll(/^\s*0x[0-9a-f]+\s+((?:[0-9a-f]{8}(?: |$)){1,4})/gmi)].map(match => match[1].replace(/\s/g,'')).join('');
  const bytes = Buffer.from(hex,'hex');
  if (!bytes.length || bytes.length % 64 !== 0 || !identity.data?.includes('little endian')) return null;
  const offset = identity.class === 'ELF64' ? 8 : identity.class === 'ELF32' ? 4 : 0;
  if (!offset) return null;
  const versions = [];
  for (let i=0;i<bytes.length;i+=64) {
    const field = bytes.subarray(i+offset,i+64);
    const end = field.indexOf(0);
    const name = end > 0 ? field.subarray(0,end).toString('ascii') : '';
    if (!/^\w+$/.test(name) || (offset === 8 && bytes.readUInt32LE(i+4) !== 0)) return null;
    versions.push({symbol:name,crc:checksum(bytes.readUInt32LE(i).toString(16))});
  }
  return versions;
}

function kmi(release) {
  const parts = /^(\d+\.\d+)\.\d+.*?-(android\d+)-(\d+)(?:[-.+]|$)/.exec(release);
  return parts ? parts.slice(1).join('-') : null;
}

function kernelSeries(release) {
  return /^(\d+\.\d+)\.\d+/.exec(release ?? '')?.[1] ?? null;
}

function machineName(value) {
  if (/aarch64|arm64/i.test(value)) return 'arm64';
  if (/x86[-_ ]?64|x86-64|advanced micro devices x86/i.test(value)) return 'x86_64';
  if (/^(arm|armv[5-9])/i.test(value)) return 'arm';
  if (/i[3-6]86|80386/i.test(value)) return 'x86';
  if (/risc.?v/i.test(value)) return 'riscv';
  return null;
}

export function compatibility({identity, vermagic, symbols, reference, facts}) {
  const checks = [];
  const add = (check,status,detail) => checks.push({check,status,detail});
  const built = machineName(identity.machine), device = machineName(facts.machine);
  const release = vermagic?.split(/\s+/)[0];
  const moduleSeries = kernelSeries(release), deviceSeries = kernelSeries(facts.release);
  const moduleKmi = release && kmi(release), deviceKmi = kmi(facts.release);
  add('architecture', !built || !device ? 'unknown' : built === device ? 'match' : 'mismatch',
    {module:identity.machine,device:facts.machine});
  add('kernel_series', !moduleSeries || !deviceSeries ? 'unknown' : moduleSeries === deviceSeries ? 'match' : 'mismatch',
    {module:moduleSeries,device:deviceSeries});
  add('gki_kmi', !moduleKmi || !deviceKmi ? 'unknown' : moduleKmi === deviceKmi ? 'match' : 'mismatch',
    {module:moduleKmi ?? null,device:deviceKmi});
  const versioned = symbols?.length || /\bmodversions\b/.test(vermagic ?? '');
  add('kernel_release', !release ? 'unknown' : release === facts.release ? 'match' : versioned ? 'review' : 'mismatch',
    {module:release ?? null,device:facts.release, note:'A differing release with modversion records requires checking the actual kernel build and CRCs.'});
  if (reference && symbols?.length) {
    const differences = symbols.filter(({symbol,crc}) => reference.has(symbol) && reference.get(symbol) !== crc);
    const missing = symbols.filter(({symbol}) => !reference.has(symbol)).map(({symbol})=>symbol);
    add('symbol_crcs',differences.length ? 'mismatch' : missing.length ? 'unknown' : 'match',
      {checked:symbols.length-missing.length, mismatches:differences.map(item => ({...item,reference:reference.get(item.symbol)})),missing,
        note:'Module.symvers is caller-supplied. Confirm it came from the device kernel build.'});
  } else {
    add('symbol_crcs','unknown',{records:symbols?.length ?? 0,reason:reference ? 'no supported __versions records' : 'no Module.symvers supplied'});
  }
  return checks;
}

function classifyLogs(text, moduleName) {
  const category = line => {
    if (/avc:.*denied/i.test(line)) return 'selinux_denial';
    if (/unsigned module|signature|key was rejected|required key not available/i.test(line)) return 'signature';
    if (/disagrees about version of symbol|version magic|invalid module format|wrong elf/i.test(line)) return 'module_version';
    if (/unknown symbol|unresolved symbol/i.test(line)) return 'missing_symbol';
    if (/permission denied|operation not permitted/i.test(line)) return 'permission';
    return null;
  };
  const pattern = new RegExp(`(?:^|[^\\w])${moduleName.replace(/[-_]/g,'[-_]')}(?:$|[^\\w])`,'i');
  return text.split(/\r?\n/).filter(line=>pattern.test(line)).flatMap(line => {
    const kind = category(line);
    return kind ? [{kind, line:line.slice(0,1200)}] : [];
  }).slice(-100);
}

export async function modulePreflight(args) {
  if (args.kernel_machine && !args.kernel_release) throw new Error('kernel_machine requires kernel_release for offline preflight');
  if (args.log_path && args.device_logs) throw new Error('select one kernel log source');
  const file = await localFile(args.local,maxELF,'kernel module');
  const tools = await toolchain();
  const {stdout} = await host(tools.readelf,['-h','-n','-SW','-p','.modinfo','-x','__versions',file],{maxBuffer:8*1024*1024});
  const identity = elfIdentity(stdout), info = parseModinfo(stdout);
  if (identity.type !== 'REL' || !info.has('vermagic')) throw new Error('expected a relocatable ELF kernel module with .modinfo vermagic');
  const moduleName = info.get('name') ?? path.basename(file).replace(/\.ko$/i,'');
  if (!/^[\w-]{1,128}$/.test(moduleName)) throw new Error('module contains an unsupported name');
  const symbols = moduleVersions(stdout,identity);
  const dependencies = (info.get('depends') ?? '').split(',').filter(Boolean);
  const facts = args.kernel_release
    ? {release:args.kernel_release,machine:args.kernel_machine ?? '',source:'caller',modules:null}
    : await readKernelFacts();
  let reference;
  if (args.module_symvers) {
    const input = await localFile(args.module_symvers,32*1024*1024,'Module.symvers');
    reference = new Map();
    for (const line of (await fs.readFile(input,'utf8')).split(/\r?\n/)) {
      const match = /^(0x[\da-f]{8})\s+(\w+)\s+/i.exec(line);
      if (!match) continue;
      const value = checksum(match[1]);
      if (reference.has(match[2]) && reference.get(match[2]) !== value) throw new Error('Module.symvers has conflicting CRC records');
      reference.set(match[2],value);
    }
    if (!reference.size) throw new Error('Module.symvers has no valid CRC records');
  }
  const checks = compatibility({identity,vermagic:info.get('vermagic'),symbols,reference,facts});
  if (dependencies.length) {
    const loaded = facts.modules?.map(name=>name.replaceAll('-','_')) ?? null;
    checks.push({check:'dependencies',status:'review',detail:{required:dependencies,
      not_listed_as_loaded:loaded && dependencies.filter(name=>!loaded.includes(name.replaceAll('-','_'))),
      note:'Built-in modules may be absent from /proc/modules.'}});
  }
  let logs, logSource;
  if (args.log_path) {
    logSource = 'local';
    logs = await fs.readFile(await localFile(args.log_path,8*1024*1024,'kernel log'),'utf8');
  } else if (args.device_logs) {
    if (args.kernel_release || connectionOptions().privilege !== 'root') throw new Error('device_logs requires a live target and explicit privilege=root');
    logSource = 'device';
    // Preserve a failed permission lookup. Tail is only used after dmesg succeeds.
    logs = await deviceText('messages=$(dmesg) || exit $?; printf "%s\\n" "$messages" | tail -n 400',{maxBytes:512*1024});
  }
  const mismatches = checks.filter(check=>check.status==='mismatch').map(check=>check.check);
  const report = {module:moduleName,file,sha256:await sha256(file),...identity,vermagic:info.get('vermagic'),dependencies,
    device:{...facts,modules:undefined},checks,verdict:mismatches.length ? 'mismatch_detected' : 'no_confirmed_mismatch',
    signature_trust:'unknown',logs:logs === undefined ? null : {source:logSource,findings:classifyLogs(logs,moduleName)}};
  const dir = await outputDirectory(args.output,'module');
  return {report:await writeJson(dir,'preflight.json',report),module:moduleName,verdict:report.verdict,mismatches};
}

async function readKernelFacts() {
  const output = await deviceText('uname -r && uname -m && { cat /proc/modules 2>/dev/null || echo @unavailable; }',{maxBytes:256*1024});
  const [release,machine,...lines] = output.trim().split('\n');
  if (!release || !machine) throw new Error('device did not report its kernel ABI');
  return {release,machine,source:'device',modules:lines.includes('@unavailable') ? null : lines.map(line=>line.split(/\s+/)[0])};
}
