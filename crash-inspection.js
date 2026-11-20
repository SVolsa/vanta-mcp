import fs from 'node:fs/promises';
import path from 'node:path';
import { connectionOptions } from './connection.js';
import { shQuote } from './transport.js';
import { deviceText, elfIdentity, host, localFile, outputDirectory, toolchain, writeJson } from './inspection-io.js';

const again = (value,label) => {
  if (!/^\d{1,10}$/.test(value)) throw new Error(`invalid device ${label}`);
  return Number(value);
};
const belongs = (name,pkg) => name === pkg || name?.startsWith(pkg+':');
const eventUID = text => /^\s*uid:\s*(\d+)\b/m.exec(text)?.[1];
const nativeName = text => />>>\s*([^\s<>]+)\s*<<</.exec(text)?.[1] ?? /^\s*Cmdline:\s*([^\s]+)\s*$/m.exec(text)?.[1];

function logUID(value) {
  if (/^\d+$/.test(value)) return Number(value);
  const app = /^u(\d+)_a(\d+)$/.exec(value);
  return app ? Number(app[1])*100000+10000+Number(app[2]) : null;
}

export function crashEntries(raw,{pkg,uid,since}) {
  const groups = new Map(), selected = [];
  const commit = group => {
    if (!group) return;
    const body = group.lines.join('\n');
    const process = group.kind === 'native' ? nativeName(body) : /^Process:\s*([^,]+),\s*PID:\s*\d+/m.exec(body)?.[1];
    const owner = group.kind === 'native' && eventUID(body) !== undefined ? Number(eventUID(body)) : group.uid;
    if (belongs(process,pkg) && owner === uid) selected.push({kind:group.kind,epoch:group.epoch,process,text:body});
  };
  for (const line of raw.split('\n')) {
    const match = /^\s*(\d{9,}\.\d+)\s+(?:(\S+)\s+)?(\d+)\s+(\d+)\s+[VDIWEFS]\s+([^:]+):\s?(.*)$/.exec(line);
    if (!match) continue;
    const [,timestamp,owner,pid,,tag,payload] = match;
    const epoch = Number(timestamp);
    if (epoch < since || !['DEBUG','AndroidRuntime'].includes(tag.trim())) continue;
    const key = tag.trim()+':'+pid;
    if (/^\*\*\* \*\*\*/.test(payload) || /^FATAL EXCEPTION:/.test(payload)) {
      commit(groups.get(key));
      groups.set(key,{kind:tag.trim()==='DEBUG' ? 'native' : 'java',uid:logUID(owner ?? ''),epoch,lines:[payload]});
    } else {
      groups.get(key)?.lines.push(payload);
    }
  }
  for (const group of groups.values()) commit(group);
  return selected.sort((a,b)=>a.epoch-b.epoch);
}

function exitRecords(raw,{pkg,uid,cutoff}) {
  return raw.split(/(?=ApplicationExitInfo\s+#\d+:)/).flatMap(block => {
    if (!block.startsWith('ApplicationExitInfo')) return [];
    const process = /\bprocess=([^\s]+)/.exec(block)?.[1];
    const timestamp = /\btimestamp=(\d{4}-\d\d-\d\d \d\d:\d\d:\d\d)/.exec(block)?.[1];
    const packageUID = /\bpackageUid=(\d+)/.exec(block)?.[1];
    const pid = /\bpid=(\d+)/.exec(block)?.[1];
    const reason = /\breason=(\d+) \(([^\r\n]+?)\)(?:\s+subreason=|\s*$)/m.exec(block);
    if (!belongs(process,pkg) || !timestamp || timestamp < cutoff || Number(packageUID) !== uid || !reason || !pid) return [];
    return [{process,timestamp,pid:Number(pid),reason:Number(reason[1]),label:reason[2],text:block.trim()}];
  });
}

async function selectedTextTraces(options) {
  const {pkg,uid,since,exits} = options;
  const tombstones = [], anrs = [];
  const statuses = {};
  // Each root source has fixed directories, bounded listings and per-file read limits.
  for (const [kind,base,glob] of [
    ['tombstone','/data/tombstones','tombstone_[0-9][0-9]'],
    ['anr','/data/anr','anr_*'],
  ]) {
    try {
      const result = await deviceText(`ls -1t ${base} >/dev/null && { for f in ${base}/${glob}; do [ -f "$f" ] && [ ! -L "$f" ] || continue; stat -c '%Y %n' "$f" || exit $?; done; }`);
      const valid = kind === 'tombstone' ? /^\/data\/tombstones\/tombstone_\d\d$/ : /^\/data\/anr\/anr_[\w.-]+$/;
      const files = result.split('\n').flatMap(line => {
        const record = /^(\d+) (.*)$/.exec(line);
        return record && valid.test(record[2]) && Number(record[1]) >= since ? [[Number(record[1]),record[2]]] : [];
      }).sort((a,b)=>b[0]-a[0]).slice(0,16);
      let unreadable = 0;
      for (const [mtime,file] of files) {
        const quoted = shQuote(file);
        const raw = await deviceText(`[ ! -L ${quoted} ] && cat ${quoted}`,{maxBytes:2*1024*1024}).catch(()=>null);
        if (raw === null) {++unreadable; continue;}
        if (kind === 'tombstone') {
          if (belongs(nativeName(raw),pkg) && Number(eventUID(raw)) === uid) tombstones.push({mtime,text:raw});
          continue;
        }
        for (const block of raw.split(/(?=^----- pid \d+ at )/m)) {
          const header = /^----- pid (\d+) at (\d{4}-\d\d-\d\d \d\d:\d\d:\d\d)/.exec(block);
          const name = /^Cmd line:\s*(\S+)\s*$/m.exec(block)?.[1];
          if (!header || !belongs(name,pkg)) continue;
          // ANR text does not always contain UID. Require a corroborating per-user exit record.
          if (exits.some(event => event.reason===6 && event.pid===Number(header[1]) && event.process===name &&
              Math.abs(Date.parse(event.timestamp.replace(' ','T')+'Z')-Date.parse(header[2].replace(' ','T')+'Z')) <= 120000)) {
            anrs.push({mtime,text:block.trim()});
          }
        }
      }
      statuses[kind] = {scanned:files.length,unreadable,matched:(kind === 'tombstone' ? tombstones : anrs).length};
    } catch (error) {
      statuses[kind] = {unavailable:error.message.slice(0,200)};
    }
  }
  return {tombstones,anrs,statuses};
}

export async function crashScope(args) {
  if (!args.package) throw new Error('package is required for crash collection');
  const pkg = args.package;
  const user = args.user ?? again((await deviceText('am get-current-user')).trim(),'user');
  const members = await deviceText(`pm list packages -U --user ${user} ${shQuote(pkg)}`);
  const field = members.split('\n').map(line=>/^package:(\S+) uid:(\d+)$/.exec(line)).find(match=>match?.[1]===pkg);
  if (!field) throw new Error('could not resolve the package UID for this Android user');
  const uid = again(field[2],'uid');
  const now = again((await deviceText('date +%s')).trim(),'clock');
  const since = now-(args.minutes ?? 30)*60;
  return {pkg,user,uid,now,since};
}

export async function crashBuffer() {
  return deviceText('logcat -b crash -d -v threadtime -v epoch -v uid -t 3000',{maxBytes:2*1024*1024});
}

export async function collectCrash(args) {
  const {pkg,user,uid,now,since} = await crashScope(args);
  const cutoff = (await deviceText(`date -d @${since} '+%F %T'`)).trim();
  if (!/^\d{4}-\d\d-\d\d \d\d:\d\d:\d\d$/.test(cutoff)) throw new Error('could not determine device time window');
  const [crash,exit] = await Promise.allSettled([
    crashBuffer(),
    deviceText(`dumpsys activity exit-info ${shQuote(pkg)}`,{maxBytes:512*1024}),
  ]);
  const events = crash.status === 'fulfilled' ? crashEntries(crash.value,{pkg,uid,since}) : [];
  const exits = exit.status === 'fulfilled' ? exitRecords(exit.value,{pkg,uid,cutoff}) : [];
  const root = connectionOptions().privilege === 'root';
  const traces = root ? await selectedTextTraces({pkg,uid,since,exits}) : {
    tombstones:[],anrs:[],statuses:{tombstone:'requires explicit root',anr:'requires explicit root'},
  };
  const dir = await outputDirectory(args.output,'crash');
  const artifacts = [];
  async function write(name,body) {
    await fs.writeFile(path.join(dir,name),body,{flag:'wx',mode:0o600});
    artifacts.push(name);
  }
  for (const [index,event] of events.entries()) await write(`crash-${index}-${event.kind}.txt`,event.text);
  for (const [index,item] of traces.tombstones.entries()) await write(`tombstone-${index}.txt`,item.text);
  for (const [index,item] of traces.anrs.entries()) await write(`anr-${index}.txt`,item.text);
  const report = {package:pkg,user,uid,from_epoch:since,to_epoch:now,artifacts,
    events:events.map(({text,...entry})=>entry),exit_records:exits,
    sources:{crash:crash.status === 'rejected' ? {unavailable:crash.reason.message.slice(0,200)} : {examined_lines:3000,matched:events.length},
      exit:exit.status === 'rejected' ? {unavailable:exit.reason.message.slice(0,200)} : {matched:exits.length},
      ...traces.statuses}};
  return {report:await writeJson(dir,'crash.json',report),directory:dir,artifacts,events:events.length,exit_records:exits.length};
}

const machineABI = [
  [/aarch64/i,'arm64'],[/^arm\b/i,'arm'],[/x86[-_ ]?64/i,'x86_64'],[/i[3-6]86|80386/i,'x86'],[/risc.?v/i,'riscv64'],
];
function normalizeABI(value) {
  return ({'arm64-v8a':'arm64','armeabi-v7a':'arm'})[value] ?? value;
}

export function crashingFrameLines(trace) {
  const lines = trace.split(/\r?\n/);
  const start = lines.findIndex(line=>/^\s*backtrace:\s*$/i.test(line));
  if (start < 0) return lines;
  const frames = [];
  for (const line of lines.slice(start+1)) {
    if (/^\s*#\d+\s+pc\s+/i.test(line)) frames.push(line);
    else if (frames.length || line.trim()) break;
  }
  return frames;
}

export async function symbolizeCrash(args) {
  if (!args.trace || !args.symbols?.length) throw new Error('trace and a list of unstripped ELF symbol files are required');
  const file = await localFile(args.trace,8*1024*1024,'trace');
  const trace = await fs.readFile(file,'utf8');
  const declared = [...new Set([...trace.matchAll(/\bABI:\s*'([\w-]+)'/g)].map(match=>normalizeABI(match[1])))];
  if (declared.length > 1 || (args.abi && declared[0] && normalizeABI(args.abi) !== declared[0])) throw new Error('trace ABI is mixed or conflicts with the requested ABI');
  const abi = normalizeABI(args.abi ?? declared[0]);
  if (!abi) throw new Error('trace has no ABI header; provide abi explicitly');
  const tools = await toolchain(), index = new Map();
  for (const item of args.symbols) {
    const binary = await localFile(item,512*1024*1024,'symbol ELF');
    const {stdout} = await host(tools.readelf,['-h','-n','-SW',binary]);
    const identity = elfIdentity(stdout);
    const arch = machineABI.find(([pattern])=>pattern.test(identity.machine ?? ''))?.[1];
    if (arch !== abi || !identity.build_id || !/^\s*\[\s*\d+\]\s+\.(?:z?debug_line)\s/m.test(stdout)) continue;
    const entries = index.get(identity.build_id) ?? new Set();
    entries.add(binary);
    index.set(identity.build_id,entries);
  }
  const frames = [], pending = new Map();
  for (const line of crashingFrameLines(trace)) {
    const match = /#(\d{1,3})\s+pc\s+([\da-f]{1,16})\s+(\S+)/i.exec(line);
    if (!match) continue;
    if (frames.length >= 256) throw new Error('trace has more than 256 native frames; select one crash trace');
    const id = /\(BuildId:\s*([0-9a-f]+)\)/i.exec(line)?.[1].toLowerCase();
    const candidates = index.get(id);
    const frame = {number:Number(match[1]),pc:'0x'+match[2],object:match[3],build_id:id ?? null,
      status:!id ? 'missing_build_id' : !candidates ? 'no_exact_match' : candidates.size!==1 ? 'ambiguous_symbols' : 'pending'};
    frames.push(frame);
    if (frame.status !== 'pending') continue;
    const [binary] = candidates;
    if (!pending.has(binary)) pending.set(binary,[]);
    pending.get(binary).push(frame);
  }
  if (!frames.length) throw new Error('no Android native backtrace frames found in the trace');
  for (const [binary,requests] of pending) {
    const {stdout} = await host(tools.symbolizer,['--output-style=JSON',`--obj=${binary}`,...requests.map(frame=>frame.pc)]);
    const json = stdout.trim();
    const records = json.startsWith('[') ? JSON.parse(json) : json.split(/\r?\n/).map(line=>JSON.parse(line));
    if (records.length !== requests.length) throw new Error('LLVM symbolizer did not return one result per address');
    for (const [i,frame] of requests.entries()) {
      const record = records[i];
      if (typeof record.Address !== 'string' || BigInt(record.Address) !== BigInt(frame.pc)) throw new Error('LLVM symbolizer returned a different address');
      frame.locations = (record.Symbol ?? []).filter(symbol=>symbol.FileName && symbol.FileName!=='??' && symbol.Line>0).map(symbol=>({
        function:symbol.FunctionName,file:symbol.FileName,line:symbol.Line,column:symbol.Column,
      }));
      frame.status = frame.locations.length ? 'symbolized' : 'matched_without_source_line';
    }
  }
  const dir = await outputDirectory(args.output,'symbols');
  return {report:await writeJson(dir,'symbolized.json',{trace:file,abi,frames}),abi,
    frames:frames.length,symbolized:frames.filter(frame=>frame.status==='symbolized').length};
}
