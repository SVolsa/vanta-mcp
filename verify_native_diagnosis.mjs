// Run native diagnostics on signed test APKs and reproduce a real linker failure.
import assert from 'node:assert/strict';
import path from 'node:path';
import {setTimeout as sleep} from 'node:timers/promises';
import {Client} from '@modelcontextprotocol/sdk/client/index.js';
import {StdioClientTransport} from '@modelcontextprotocol/sdk/client/stdio.js';
import {ensureAdb,runAdb} from './adb.js';
import {here,outputDirectory,validationAdb,writeJson} from './inspection-io.js';

const [serial,good,missing,wrongAbi,misaligned,...extra] = process.argv.slice(2);
if (!/^emulator-\d+$/.test(serial ?? '') || ![good,missing,wrongAbi,misaligned].every(Boolean) || extra.length) {
  throw new Error('usage: node verify_native_diagnosis.mjs <disposable-emulator-serial> <good-dir> <missing-dependency-dir> <wrong-abi-dir> <misaligned-dir>');
}
process.env.ADB_PATH ||= validationAdb();
const pkg = 'dev.vanta.inspectionprobe';
const directory = await outputDirectory(undefined,'native-diagnosis-verification');
const client = new Client({name:'vanta-native-diagnosis-verification',version:'1'});
const adb = async args => ensureAdb(await runAdb(args,{serial,timeoutMs:30000,maxChars:24000})).stdout.trim();
const shell = command => adb(['shell','-T',command]);
const apkSet = folder => ['base.apk','split_diagnostics.apk'].map(file=>path.resolve(folder,file));
const receipt = {serial,passed:false,cases:{},cleanup:false};
let installed = false;

async function diagnose(args) {
  const result = await client.callTool({name:'apk_inspect',arguments:{action:'diagnose_native',transport:'adb',serial,
    privilege:'shell',output:directory,...args}},undefined,{timeout:120000});
  assert.ok(!result.isError,result.content[0].text);
  return JSON.parse(result.content[0].text);
}

async function install(folder) {
  assert.match(await adb(['install-multiple','--no-incremental',...apkSet(folder)]),/Success/);
  installed=true;
}

async function remove() {
  assert.equal(await adb(['uninstall',pkg]),'Success');
  installed=false;
  assert.equal(await shell('pm path '+pkg+' || true'),'');
}

async function launch() {
  // Use a distinct second after installation so old events cannot match the new build.
  await sleep(1300);
  await shell('am start -W -n '+pkg+'/.InspectionProbe --ez load_only true');
}

try {
  assert.equal(await shell('getprop ro.kernel.qemu'),'1');
  assert.equal(await shell('getprop ro.product.cpu.abi'),'x86_64');
  assert.equal(await shell('pm path '+pkg+' || true'),'','probe already installed');
  receipt.device_page_size=Number(await shell('getconf PAGE_SIZE'));
  await client.connect(new StdioClientTransport({command:process.execPath,args:[path.join(here,'server.js')],env:{...process.env}}));
  receipt.host_version=client.getServerVersion().version;

  for (const [name,folder] of Object.entries({good,missing,wrongAbi,misaligned})) {
    receipt.cases[name]=await diagnose({apks:apkSet(folder),abi:'x86_64',page_size:16384});
  }
  const offline = receipt.cases;
  assert.deepEqual(offline.good.findings,[],JSON.stringify(offline.good));
  assert.equal(offline.good.native_entries,2);
  assert.deepEqual(offline.missing.findings.map(item=>[item.check,item.status,item.needed]),[
    ['dependency_not_in_apks','review','libvanta_probe_dep.so'],
  ]);
  assert.deepEqual(offline.wrongAbi.findings.map(item=>[item.check,item.machine]),[['abi_mismatch','AArch64']]);
  assert.ok(offline.misaligned.findings.some(item=>item.check==='apk_zip_alignment' && item.status==='mismatch'),JSON.stringify(offline.misaligned));
  assert.ok(offline.misaligned.findings.some(item=>item.check==='elf_load_alignment' && item.status==='mismatch'));

  await install(missing);
  await launch();
  for (let attempt=0;attempt<10;attempt++) {
    receipt.cases.installedMissing=await diagnose({package:pkg,minutes:5});
    if (receipt.cases.installedMissing.observed>0) break;
    await sleep(500);
  }
  const live = receipt.cases.installedMissing;
  assert.equal(live.target.page_size,receipt.device_page_size);
  assert.equal(live.target.abi,'x86_64');
  assert.ok(live.findings.some(item=>item.check==='linker_missing_dependency' && item.status==='observed' &&
    item.needed==='libvanta_probe_dep.so' && item.packaged_for_abi===false && /dlopen failed/.test(item.log)),JSON.stringify(live));
  await remove();

  await install(good);
  await launch();
  const log = await shell('logcat -d -t 300 -s VantaInspectionProbe:I');
  assert.match(log,/Native probe loaded/);
  receipt.cases.installedGood=await diagnose({package:pkg,minutes:5});
  assert.deepEqual(receipt.cases.installedGood.findings,[]);
  receipt.passed=true;
} catch (error) {
  receipt.error=error.message;
} finally {
  try {
    if (installed) await remove();
    receipt.cleanup=true;
  } catch (error) {
    receipt.cleanup_error=error.message;
  }
  await client.close();
  receipt.passed &&= receipt.cleanup;
  const report = await writeJson(directory,'acceptance.json',receipt);
  console.log(JSON.stringify({report,passed:receipt.passed,cleanup:receipt.cleanup,page_size:receipt.device_page_size,
    cases:Object.keys(receipt.cases),error:receipt.error,cleanup_error:receipt.cleanup_error},null,2));
  if (!receipt.passed) process.exitCode=1;
}
