import test from 'node:test';
import assert from 'node:assert/strict';
import { compareInventory } from './apk-inspection.js';
import { parseManifestFacts } from './apk-manifest.js';
import { compatibility,moduleVersions } from './binary-inspection.js';
import { crashEntries,crashingFrameLines } from './crash-inspection.js';
import { compareVMTraces,parseVMTrace } from './vm-trace.js';
import { analyzeNative,diagnoseNative } from './native-diagnosis.js';

const library = (name,fields={}) => ({path:`lib/arm64-v8a/${name}`,kind:'native',abi:'arm64-v8a',elf_readable:true,
  machine:'AArch64',elf_class:'ELF64',elf_type:'DYN',byte_order:'little endian',zip_stored:true,zip_data_offset:16384,
  load_segments:[{offset:'0x4000',vaddr:'0x8000',align:'0x4000'}],needed:[],...fields});
const nativeApk = (entries,extract_native_libs=false) => ({file:'base.apk',split:null,extract_native_libs,entries});

test('native diagnosis distinguishes APK alignment, ELF alignment and mislabeled ABI', () => {
  const apk = nativeApk([
    library('libzip.so',{zip_data_offset:4096}),
    library('libsegment.so',{load_segments:[{offset:'0x1000',vaddr:'0x5000',align:'0x1000'}]}),
    library('libwrong.so',{machine:'Advanced Micro Devices X86-64'}),
    library('libgood.so',{needed:['libc.so']}),
  ]);
  assert.deepEqual(analyzeNative([apk],{pageSize:16384}).findings.map(item=>[item.check,item.entry.split('/').at(-1)]),
    [['apk_zip_alignment','libzip.so'],['elf_load_alignment','libsegment.so'],['abi_mismatch','libwrong.so']]);
  apk.extract_native_libs=true;
  assert.ok(!analyzeNative([apk],{pageSize:16384}).findings.some(item=>item.check==='apk_zip_alignment'));
  apk.extract_native_libs=null;
  assert.equal(analyzeNative([apk],{pageSize:16384}).findings[0].status,'review');
  assert.deepEqual(analyzeNative([apk],{pageSize:4096}).findings.map(item=>item.check),['abi_mismatch']);
});

test('native diagnosis joins split dependencies only for the same ABI and requires a matching runtime path', () => {
  const needed = library('libparent.so',{needed:['libdep.so','libc.so']});
  const base = nativeApk([needed]);
  const split = {...nativeApk([library('libdep.so')]),file:'split_arm64.apk',split:'config.arm64_v8a'};
  assert.deepEqual(analyzeNative([base,split],{abi:'arm64-v8a'}).findings,[]);
  const codePath = '/data/app/dev.example-token';
  const event = path => ({epoch:123,process:'dev.example',text:`java.lang.UnsatisfiedLinkError: dlopen failed: library "libdep.so" not found: needed by ${path} in namespace classloader-namespace`});
  const result = analyzeNative([base],{abi:'arm64-v8a',codePath,events:[event('/data/app/old/libparent.so'),
    event(`${codePath}/split_wrong.apk!/${needed.path}`), event(`${codePath}/base.apk!/${needed.path}`)]});
  assert.deepEqual(result.findings.map(item=>[item.check,item.status,item.needed]),[
    ['dependency_not_in_apks','review','libdep.so'],['linker_missing_dependency','observed','libdep.so'],
  ]);
  assert.equal(result.findings[1].packaged_for_abi,false);
});

test('native diagnosis rejects ambiguous inputs before accessing any files or device', async () => {
  await assert.rejects(diagnoseNative({package:'dev.example',apks:['base.apk']}),/either/);
  await assert.rejects(diagnoseNative({package:'dev.example',page_size:16384}),/local APKs only/);
  await assert.rejects(diagnoseNative({apks:['base.apk'],user:0}),/user selects/);
});

test('APK comparison reports split removal, certificate rotation and DEX changes separately', () => {
  const entry = (digest) => ({path:'classes.dex',kind:'dex',sha256:digest});
  const base = (digest,cert) => ({split:null,sha256:digest,entries:[entry(digest)],signature:{verified:true,certificates:[cert]}});
  const first = {package:'dev.example',apks:[base('a','old'),{split:'config.en'}]};
  const second = {package:'dev.example',apks:[base('b','new')]};
  const delta = compareInventory(first,second);
  assert.equal(delta.changes[0].entries[0].kind,'dex');
  assert.equal(delta.changes[0].certificates.changed,true);
  assert.deepEqual(delta.changes[1],{split:'config.en',change:'removed'});
  assert.throws(()=>compareInventory(first,{...second,package:'dev.other'}),/different/);
});

test('APK manifest comparison retains declared states, filter boundaries and older inventories', () => {
  const tree = (target, permission, activity, exported, filters) => `N: android=http://schemas.android.com/apk/res/android (line=1)
  E: manifest (line=1)
      E: uses-sdk (line=2)
        A: http://schemas.android.com/apk/res/android:targetSdkVersion(0x01010270)=${target}
      E: ${permission} (line=3)
        A: android:name(0x01010003)="dev.example.ACCESS" (Raw: "dev.example.ACCESS")
      E: application (line=4)
        A: android:permission(0x01010006)="dev.example.INTERNAL" (Raw: "dev.example.INTERNAL")
          E: activity (line=5)
            A: android:name(0x01010003)="${activity}"
${exported ? `            A: android:exported(0x01010010)=${exported}\n` : ''}${filters.map(([action, host]) => `              E: intent-filter (line=6)
                  E: action (line=7)
                    A: android:name(0x01010003)="${action}"
                  E: data (line=8)
                    A: android:scheme(0x01010027)="https"
                    A: android:host(0x01010028)="${host}"
`).join('')}`;
  const view = ['android.intent.action.VIEW','viewer.example'];
  const send = ['android.intent.action.SEND','share.example'];
  const changedView = ['android.intent.action.VIEW','new.example'];
  const first = parseManifestFacts(tree('34','uses-permission','.Viewer','(type 0x12)0x0',[view,send]),'dev.example');
  const reordered = parseManifestFacts(tree('34','uses-permission','dev.example.Viewer','false',[send,view]),'dev.example');
  const second = parseManifestFacts(tree('35','uses-permission-sdk-23','Viewer',null,[send,changedView]),'dev.example');
  assert.deepEqual(first, reordered);
  assert.equal(first.components[0].attributes.exported,false);
  assert.equal(Object.hasOwn(second.components[0].attributes,'exported'),false);
  assert.equal(first.application.permission,'dev.example.INTERNAL');
  const inventory = (sha256,manifest_facts,split=null) => ({package:'dev.example',apks:[{split,sha256,manifest_facts,
    entries:[],signature:{verified:true,certificates:[]}}]});
  const report = compareInventory(inventory('a',first),inventory('b',second)).changes[0].manifest_delta;
  assert.equal(report.status,'changed');
  assert.deepEqual(report.sdk,{before:{targetSdkVersion:34},after:{targetSdkVersion:35}});
  assert.deepEqual(report.permissions.map(item=>[item.kind,item.change]),[
    ['uses-permission','removed'],['uses-permission-sdk-23','added'],
  ]);
  assert.equal(report.components[0].name,'dev.example.Viewer');
  assert.deepEqual(report.components[0].after[0].intent_filters.find(item=>item.actions.includes(view[0])).data,
    [{scheme:'https',host:'new.example'}]);
  assert.equal(compareInventory(inventory('a',first),inventory('b',reordered)).changes[0].manifest_delta.status,'unchanged');
  assert.equal(compareInventory(inventory('a',first),inventory('b',undefined)).changes[0].manifest_delta.status,'insufficient_inventory');
  const split = compareInventory(inventory('a',first),inventory('b',second,'feature')).changes[1];
  assert.equal(split.manifest_delta.components[0].change,'added');
  assert.equal(parseManifestFacts('AAPT2 error','dev.example'),null);
});

test('kernel module CRC decoder and preflight distinguish CRC and KMI mismatch from a release difference', () => {
  const raw = Buffer.alloc(64);
  raw.writeUInt32LE(0x11223344);
  raw.write('example_symbol',8);
  const text = [0,16,32,48].map(offset => '0x'+offset.toString(16)+' '+
    raw.subarray(offset,offset+16).toString('hex').match(/.{8}/g).join(' ')+' ....').join('\n');
  const identity = {machine:'AArch64',class:'ELF64',data:'little endian'};
  const symbols = moduleVersions(text,identity);
  assert.deepEqual(symbols,[{symbol:'example_symbol',crc:'11223344'}]);
  assert.equal(moduleVersions(text.slice(0,80),identity),null);
  const results = compatibility({identity,symbols,vermagic:'6.6.57-android15-8-old SMP modversions',
    facts:{machine:'aarch64',release:'6.6.89-android15-8-new'},reference:new Map([['example_symbol','11223345']])});
  const status = Object.fromEntries(results.map(item=>[item.check,item.status]));
  assert.deepEqual(status,{architecture:'match',kernel_series:'match',gki_kmi:'match',kernel_release:'review',symbol_crcs:'mismatch'});
  const custom = compatibility({identity,symbols,vermagic:'5.10.245-custom SMP modversions',
    facts:{machine:'aarch64',release:'6.6.89-android15-8-device'}});
  assert.equal(custom.find(item=>item.check==='kernel_series').status,'mismatch');
  assert.equal(custom.find(item=>item.check==='gki_kmi').status,'unknown');
});

test('crash export only returns a matching package, UID and time window', () => {
  const log = (ts,pid,uid,tag,message) => `         ${ts} ${uid}  ${pid}  ${pid} F ${tag}   : ${message}`;
  const emu = [
    log('1794970610.001',22,10123,'DEBUG','*** *** ***'),
    log('1794970610.001',22,10123,'DEBUG','uid: 10123'),
    log('1794970610.001',22,10123,'DEBUG','pid: 91  >>> dev.target:app <<<'),
    log('1794970611.001',23,10123,'AndroidRuntime','FATAL EXCEPTION: main'),
    log('1794970611.001',23,10123,'AndroidRuntime','Process: dev.target2, PID: 23'),
    log('1794970612.001',24,1010123,'AndroidRuntime','FATAL EXCEPTION: main'),
    log('1794970612.001',24,1010123,'AndroidRuntime','Process: dev.target, PID: 24'),
    log('1794970600.001',25,10123,'AndroidRuntime','FATAL EXCEPTION: main'),
    log('1794970600.001',25,10123,'AndroidRuntime','Process: dev.target, PID: 25'),
  ].join('\n');
  const results = crashEntries(emu,{pkg:'dev.target',uid:10123,since:1794970605});
  assert.deepEqual(results.map(({kind,process})=>[kind,process]),[['native','dev.target:app']]);
});

test('full text tombstones symbolize the crashing thread without scanning all other frames', () => {
  const first = '      #00 pc 00004640 /app/libprobe.so';
  const later = '      #00 pc 00001000 /system/libart.so';
  const tombstone = ['crash header','backtrace:',first,'','another thread','backtrace:',...Array(300).fill(later)].join('\n');
  assert.deepEqual(crashingFrameLines(tombstone),[first]);
  assert.deepEqual(crashingFrameLines(first),[first]);
});

test('VM compares rebased PCs with independent state and branch checks and rejects a different input', () => {
  const input = '5'.repeat(64);
  const trace = (base,next,state,hash=input) => parseVMTrace([
    {type:'meta',input_sha256:hash,pc_base:base.toString()},
    {pc:base.toString(),op:'load',next_pc:(base+next).toString(),state_sha256:state.repeat(64)},
  ].map(item=>JSON.stringify(item)).join('\n'));
  assert.equal(compareVMTraces(trace(4096,8,'a'),trace(8192,8,'a')).first_difference,null);
  const changed = compareVMTraces(trace(4096,8,'a'),trace(8192,16,'b'));
  assert.deepEqual(changed.first_difference.fields,['next_pc','state_sha256']);
  assert.equal(changed.input_verified,true);
  assert.throws(()=>compareVMTraces(trace(4096,8,'a'),trace(8192,8,'a','6'.repeat(64))),/different inputs/);
  assert.throws(()=>parseVMTrace('{"pc":"18446744073709551616","op":"halt"}'),/outside range/);
});
