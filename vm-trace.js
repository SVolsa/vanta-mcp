import fs from 'node:fs/promises';
import { elfIdentity, host, localFile, outputDirectory, toolchain, writeJson } from './inspection-io.js';

const hashOK = value => typeof value === 'string' && /^[a-f0-9]{64}$/i.test(value);
const buildIdOK = value => typeof value === 'string' && /^(?:[a-f0-9]{2}){8,64}$/i.test(value);
const pcOK = value => typeof value === 'string' && /^(?:0x[0-9a-f]{1,16}|[0-9]{1,20})$/i.test(value);

export function parseVMTrace(text) {
  const events = [];
  let meta = {}, present = false;
  for (const [index,line] of text.split(/\r?\n/).entries()) {
    if (!line.trim()) continue;
    if (line.length > 4096) throw new Error(`VM trace line ${index+1} exceeds its size limit`);
    let data;
    try {data = JSON.parse(line);} catch {throw new Error(`invalid VM trace JSON on line ${index+1}`);}
    if (!data || typeof data !== 'object' || Array.isArray(data)) throw new Error(`invalid VM trace record on line ${index+1}`);
    if (data.type === 'meta') {
      if (present || events.length || (data.input_sha256 !== undefined && !hashOK(data.input_sha256)) ||
          (data.elf_build_id !== undefined && !buildIdOK(data.elf_build_id)) ||
          (data.pc_base !== undefined && !pcOK(data.pc_base))) throw new Error('invalid or misplaced VM trace metadata');
      meta = {
        input_sha256:data.input_sha256?.toLowerCase() ?? null,
        elf_build_id:data.elf_build_id?.toLowerCase(),
        base:data.pc_base ? BigInt(data.pc_base) : 0n,
      };
      present = true;
      continue;
    }
    if (events.length >= 100000) throw new Error('VM trace exceeds 100000 events');
    if ((data.type !== undefined && data.type !== 'step') || !pcOK(data.pc) || typeof data.op !== 'string' ||
        !/^[A-Za-z0-9_.:-]{1,64}$/.test(data.op) || (data.next_pc !== undefined && !pcOK(data.next_pc)) ||
        (data.native_vaddr !== undefined && (!pcOK(data.native_vaddr) || BigInt(data.native_vaddr) > 0xffffffffffffffffn)) ||
        (data.state_sha256 !== undefined && !hashOK(data.state_sha256))) throw new Error(`invalid VM step on line ${index+1}`);
    const normalize = value => {
      const address = BigInt(value);
      if (address < (meta.base ?? 0n) || address > 0xffffffffffffffffn) throw new Error(`VM address outside range on line ${index+1}`);
      return '0x'+(address-(meta.base ?? 0n)).toString(16);
    };
    events.push({pc:normalize(data.pc),op:data.op,next_pc:data.next_pc === undefined ? null : normalize(data.next_pc),
      ...(data.native_vaddr === undefined ? {} : {native_vaddr:'0x'+BigInt(data.native_vaddr).toString(16)}),
      state_sha256:data.state_sha256?.toLowerCase() ?? null});
  }
  if (!events.length) throw new Error('VM trace has no step records');
  return {input_sha256:meta.input_sha256 ?? null,elf_build_id:meta.elf_build_id ?? null,events};
}

function summarize(trace) {
  const opcodes = new Map(), edges = new Map();
  for (const [i,step] of trace.events.entries()) {
    opcodes.set(step.op,(opcodes.get(step.op) ?? 0)+1);
    const next = step.next_pc ?? trace.events[i+1]?.pc;
    if (!next) continue;
    const source = step.next_pc ? 'reported' : 'adjacent';
    const key = `${step.pc} ${next} ${source}`;
    const edge = edges.get(key) ?? {from:step.pc,to:next,source,count:0};
    ++edge.count;
    edges.set(key,edge);
  }
  return {input_sha256:trace.input_sha256,elf_build_id:trace.elf_build_id,steps:trace.events.length,unique_edges:edges.size,
    opcodes:[...opcodes].sort((a,b)=>b[1]-a[1]).slice(0,1000).map(([op,count])=>({op,count})),
    edges:[...edges.values()].sort((a,b)=>b.count-a.count).slice(0,5000)};
}

export function compareVMTraces(left,right) {
  if (left.input_sha256 && right.input_sha256 && left.input_sha256 !== right.input_sha256) throw new Error('VM traces describe different inputs');
  const steps = Math.max(left.events.length,right.events.length);
  let first_difference = null, state_checks = 0, edge_checks = 0;
  for (let i=0;i<steps;i++) {
    const a = left.events[i], b = right.events[i];
    const fields = [];
    if (!a || !b) fields.push('length');
    else {
      for (const key of ['pc','op']) {
        if (a[key] !== b[key]) fields.push(key);
      }
      if (a.next_pc && b.next_pc) {
        edge_checks++;
        if (a.next_pc !== b.next_pc) fields.push('next_pc');
      }
      if (a.state_sha256 && b.state_sha256) {
        state_checks++;
        if (a.state_sha256 !== b.state_sha256) fields.push('state_sha256');
      }
    }
    if (fields.length && !first_difference) first_difference = {index:i,fields,left:a ?? null,right:b ?? null};
  }
  return {input_verified:!!left.input_sha256 && !!right.input_sha256, first_difference,state_checks,edge_checks,
    left:summarize(left),right:summarize(right)};
}

async function locateNativeStep(file,trace,step,tools) {
  const binary = await localFile(file,512*1024*1024,'trace ELF');
  const {stdout:headers} = await host(tools.readelf,['-h','-n','-SW',binary]);
  const identity = elfIdentity(headers);
  if (!trace.elf_build_id) throw new Error('trace is missing elf_build_id');
  if (identity.build_id !== trace.elf_build_id) throw new Error('ELF Build ID does not match its VM trace');
  if (!['EXEC','DYN'].includes(identity.type)) throw new Error('trace locations require a linked executable or shared object');
  if (!step?.native_vaddr) return {status:'trace_missing_native_address',build_id:identity.build_id};
  const address = BigInt(step.native_vaddr);
  for (const row of headers.split(/\r?\n/)) {
    const match = /^\s*\[\s*\d+\]\s+(\S+)\s+(\S+)\s+([0-9a-f]+)\s+([0-9a-f]+)\s+([0-9a-f]+)\s+[0-9a-f]+\s+(\S+)/i.exec(row);
    if (!match || !match[6].includes('X') || match[2] === 'NOBITS') continue;
    const start = BigInt('0x'+match[3]), size = BigInt('0x'+match[5]);
    if (address < start || address >= start+size) continue;
    const offset = BigInt('0x'+match[4])+address-start;
    const {stdout} = await host(tools.symbolizer,['--output-style=JSON',`--obj=${binary}`,step.native_vaddr]);
    const output = JSON.parse(stdout.trim());
    const data = Array.isArray(output) ? output[0] : output;
    if (!data?.Address || BigInt(data.Address) !== address) throw new Error('LLVM returned a different address');
    const source = (data.Symbol ?? []).map(item=>({function:item.FunctionName,file:item.FileName,line:item.Line}))
      .filter(item=>item.function && item.function !== '??');
    return {status:'located',build_id:identity.build_id,section:match[1],elf_vaddr:step.native_vaddr,
      file_offset:'0x'+offset.toString(16),source};
  }
  return {status:'outside_executable_section',build_id:identity.build_id,elf_vaddr:step.native_vaddr};
}

export async function inspectVMTrace(args) {
  const read = async file => parseVMTrace(await fs.readFile(await localFile(file,16*1024*1024,'VM trace'),'utf8'));
  const left = await read(args.trace);
  if (args.action === 'compare' && !args.other) throw new Error('other is required for VM trace comparison');
  if (args.action !== 'compare' && (args.left_elf || args.right_elf)) throw new Error('ELF locations require action=compare');
  const right = args.action === 'compare' ? await read(args.other) : null;
  const report = right ? compareVMTraces(left,right) : summarize(left);
  if (report.first_difference && (args.left_elf || args.right_elf)) {
    const tools = await toolchain();
    const hit = report.first_difference;
    hit.native = {};
    if (args.left_elf) hit.native.left = await locateNativeStep(args.left_elf,left,hit.left,tools);
    if (args.right_elf) hit.native.right = await locateNativeStep(args.right_elf,right,hit.right,tools);
  }
  const dir = await outputDirectory(args.output,'vm');
  return {report:await writeJson(dir,'vm-trace.json',report),steps:left.events.length,
    ...(args.action === 'compare' ? {first_difference:report.first_difference,input_verified:report.input_verified} : {})};
}
