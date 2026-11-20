import fs from 'node:fs/promises';
import path from 'node:path';
import {apkInspection,packageSchema,userSchema} from './apk-inspection.js';
import {crashBuffer,crashEntries,crashScope} from './crash-inspection.js';
import {deviceText,writeJson} from './inspection-io.js';
import {shQuote} from './transport.js';

const abiIdentity = {
  'arm64-v8a':['ELF64',/^AArch64$/i], 'armeabi-v7a':['ELF32',/^ARM$/i],
  x86:['ELF32',/^(?:Intel )?80386$/i], x86_64:['ELF64',/(?:X86-64|x86_64)$/i], riscv64:['ELF64',/^RISC-V$/i],
};
export const nativeABIs = Object.keys(abiIdentity);
// The graph checks APK contents. These standard Android libraries are supplied by the platform.
const platformLibraries = new Set(['libc.so','libdl.so','libm.so','liblog.so','libandroid.so','libz.so']);
const nextStep = {
  abi_mismatch:'Rebuild or move this library so its ELF architecture matches the ABI directory.',
  elf_load_alignment:'Rebuild this library for 16 KB ELF LOAD segment alignment.',
  apk_zip_alignment:'Check APK packaging alignment for this uncompressed library.',
  dependency_not_in_apks:'Check the target ABI split and whether the library is supplied outside the APK.',
};

function alignedSegment(segment,page) {
  const alignment = BigInt(segment.align);
  return alignment >= page && (alignment & (alignment-1n))===0n && BigInt(segment.offset)%page===BigInt(segment.vaddr)%page;
}

export function analyzeNative(apks,{abi,pageSize,codePath,events=[]}={}) {
  const findings = [];
  const all = apks.flatMap(apk=>apk.entries.filter(item=>item.kind==='native').map(item=>({
    ...item,apk:apk.file,split:apk.split,name:path.posix.basename(item.path),
  })));
  const selected = abi ? all.filter(item=>item.abi===abi) : all;
  const extract = apks.find(apk=>apk.split===null)?.extract_native_libs ?? null;
  const packaged = new Map();
  for (const item of all) {
    if (!packaged.has(item.name)) packaged.set(item.name,new Set());
    packaged.get(item.name).add(item.abi);
  }
  const add = (item,check,status,evidence) => findings.push({check,status,apk:item.apk,split:item.split,
    entry:item.path,abi:item.abi,build_id:item.build_id,next_step:nextStep[check],...evidence});

  if (!selected.length) findings.push({check:abi && all.length ? 'abi_not_packaged' : 'native_inventory',
    status:abi && all.length ? 'review' : 'unknown',abi:abi ?? null,
    packaged_abis:[...new Set(all.map(item=>item.abi))],reason:'no native libraries for the selected ABI in the supplied APKs'});

  for (const item of selected) {
    const expected = abiIdentity[item.abi];
    if (!item.elf_readable || !expected || !item.machine || !item.elf_class || !item.byte_order) {
      add(item,'elf_identity','unknown',{machine:item.machine,elf_class:item.elf_class});
      continue;
    }
    if (item.elf_class!==expected[0] || !expected[1].test(item.machine) || !/little endian/i.test(item.byte_order) || item.elf_type!=='DYN') {
      add(item,'abi_mismatch','mismatch',{machine:item.machine,elf_class:item.elf_class,byte_order:item.byte_order,elf_type:item.elf_type});
      continue;
    }
    if (pageSize===16384) {
      const bad = item.load_segments.filter(segment=>!alignedSegment(segment,16384n));
      if (!item.load_segments.length) add(item,'elf_load_alignment','unknown',{required:pageSize});
      if (bad.length) add(item,'elf_load_alignment','mismatch',{required:pageSize,segments:bad});
      if (item.zip_stored && item.zip_data_offset%pageSize!==0 && extract!==true) {
        add(item,'apk_zip_alignment',extract===false ? 'mismatch' : 'review',{
          required:pageSize,zip_data_offset:item.zip_data_offset,extract_native_libs:extract,
        });
      }
    }
    for (const library of new Set(item.needed)) {
      const abis = packaged.get(library);
      if (platformLibraries.has(library) || abis?.has(item.abi)) continue;
      add(item,'dependency_not_in_apks','review',{needed:library,other_packaged_abis:[...(abis ?? [])]});
    }
  }

  const seen = new Set();
  for (const {epoch,process,text} of events) {
    for (const line of text.split('\n')) {
      const match = /\bdlopen failed: library "([^"\r\n]+)" not found: needed by ([^\r\n]+?) in namespace /.exec(line);
      if (!match || !codePath || !match[2].startsWith(codePath+'/') || seen.has(line)) continue;
      const parent = selected.find(item=>item.name===path.posix.basename(match[2]) && item.needed.includes(match[1]) &&
        (!match[2].includes('.apk!/') || match[2]===`${codePath}/${item.apk}!/${item.path}`));
      if (!parent) continue;
      seen.add(line);
      const present = packaged.get(match[1])?.has(parent.abi) ?? false;
      add(parent,'linker_missing_dependency','observed',{needed:match[1],epoch,process,log:line.trim().slice(0,800),
        packaged_for_abi:present,next_step:present ? 'Check linker namespace visibility for the packaged library.' :
          'Check how the missing dependency is supplied to this ABI in the installed build.'});
    }
  }
  return {findings,native_entries:selected.length,packaged_abis:[...new Set(all.map(item=>item.abi))],extract_native_libs:extract};
}

async function installedBuild(pkg) {
  const raw = await deviceText(`dumpsys package ${shQuote(pkg)}`,{maxBytes:512*1024});
  const lines = raw.split('\n');
  const index = lines.findIndex(line=>line.trimStart().startsWith(`Package [${pkg}] (`));
  if (index===-1) throw new Error('installed package metadata was not found');
  const facts = lines.slice(index+1).join('\n').split(/^  \S/m)[0];
  const field = key => new RegExp(`^\\s*${key}=(.+)$`,'m').exec(facts)?.[1].trim() ?? null;
  const codePath = field('codePath');
  if (!codePath?.startsWith('/')) throw new Error('installed package code path is unavailable');
  return {codePath,version:field('versionCode'),updated:field('lastUpdateTime'),abi:field('primaryCpuAbi')};
}

async function loaderEvents(scope,build) {
  if (!/^\d{4}-\d\d-\d\d \d\d:\d\d:\d\d$/.test(build.updated ?? '')) return {status:'package_update_time_unavailable',events:[]};
  try {
    const updated = Number((await deviceText(`date -d ${shQuote(build.updated)} +%s`)).trim());
    if (!Number.isSafeInteger(updated) || updated<=0 || updated>scope.now) return {status:'package_update_time_unavailable',events:[]};
    const events = crashEntries(await crashBuffer(),{...scope,since:Math.max(scope.since,updated+1)}).filter(item=>item.kind==='java');
    return {status:'checked',events};
  } catch (error) {
    return {status:'unavailable',events:[],error:error.message.slice(0,200)};
  }
}

export async function diagnoseNative(args) {
  const installed = args.package!==undefined;
  if (installed===Boolean(args.apks?.length)) throw new Error('provide either an installed package or local APKs');
  if ((installed && (args.abi!==undefined || args.page_size!==undefined)) || (!installed && args.user!==undefined)) {
    throw new Error('ABI and page_size describe local APKs only; user selects an installed package');
  }
  const target = {source:installed ? 'installed' : 'local',abi:args.abi ?? null,page_size:args.page_size ?? null};
  let build, user, scope, report;
  let runtime = {status:'local_apks',events:[]};
  if (installed) {
    const pkg = packageSchema.parse(args.package);
    const current = args.user===undefined ? (await deviceText('am get-current-user')).trim() : String(args.user);
    if (!/^\d{1,5}$/.test(current)) throw new Error('could not resolve the Android user');
    user = userSchema.parse(Number(current));
    build = await installedBuild(pkg);
    const page = Number((await deviceText('getconf PAGE_SIZE').catch(()=>'')).trim());
    target.page_size = page===4096 || page===16384 ? page : null;
    target.abi = nativeABIs.includes(build.abi) ? build.abi : null;
    scope = await crashScope({...args,user}).catch(()=>null);
    report = await apkInspection({action:'export',package:pkg,user,output:args.output},{nativeDetails:true});
    runtime = scope ? await loaderEvents(scope,build) : {status:'crash_scope_unavailable',events:[]};
    const after = await installedBuild(pkg);
    if (JSON.stringify(after)!==JSON.stringify(build)) throw new Error('installed package metadata changed during native diagnosis');
  } else {
    report = await apkInspection({action:'inspect',apks:args.apks,output:args.output},{nativeDetails:true});
  }

  const inventory = JSON.parse(await fs.readFile(report.report,'utf8'));
  const result = analyzeNative(inventory.apks,{abi:target.abi,pageSize:target.page_size,codePath:build?.codePath,
    events:target.abi && inventory.splits_consistent ? runtime.events : []});
  const counts = {observed:0,mismatch:0,review:0,unknown:0};
  for (const item of result.findings) ++counts[item.status];
  const summary = {package:report.package,user:user ?? null,target,...counts,native_entries:result.native_entries,
    runtime:runtime.status,splits_consistent:inventory.splits_consistent};
  if (target.page_size===null) summary.page_size_check = 'target_page_size_unknown';
  if (target.abi===null) summary.abi_scope = 'all_packaged_abis';
  const evidence = await writeJson(report.directory,'native-diagnosis.json',{...summary,...result,inventory:report.report,
    runtime_error:runtime.error});
  const priority = {observed:0,mismatch:1,review:2,unknown:3};
  const findings = [...result.findings].sort((a,b)=>priority[a.status]-priority[b.status]).slice(0,20);
  return {...summary,report:evidence,findings};
}
