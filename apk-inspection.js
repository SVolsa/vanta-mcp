import fs from 'node:fs/promises';
import path from 'node:path';
import { z } from 'zod';
import { compareManifestFacts, manifestFactsSchema, parseManifestFacts } from './apk-manifest.js';
import { runDevice, ensureDevice, shQuote } from './transport.js';
import { here, host, toolchain, deviceText, outputDirectory, localFile, sha256, writeJson } from './inspection-io.js';

const maxAPK = 512 * 1024 * 1024;
const schema = 'vanta-apk-inventory/v1';
const splitName = /^[A-Za-z0-9][A-Za-z0-9._+-]{0,180}\.apk$/;
export const packageSchema = z.string().max(255).regex(/^[A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z_][A-Za-z0-9_]*)*$/);
export const userSchema = z.number().int().min(0).max(21474);
export const directorySchema = z.string().min(1).max(1024).optional();

function field(line, name) {
  return new RegExp(`\\b${name}='([^']*)'`).exec(line)?.[1] ?? null;
}

async function inventory(apk, tools, manifestPath, budget, nativeDetails) {
  await localFile(apk,maxAPK,'APK');
  const digest = await sha256(apk);
  const {stdout:badging} = await host(tools.aapt2,['dump','badging',apk]);
  const declaration = badging.split(/\r?\n/).find(line => line.startsWith('package:'));
  const name = field(declaration ?? '', 'name');
  if (!name) throw new Error('aapt2 did not report an APK package name');
  const {stdout:manifest} = await host(tools.aapt2,['dump','xmltree','--file','AndroidManifest.xml',apk]);
  if (!tools.apksignerJar) throw new Error('set VANTA_APKSIGNER_JAR or configure the Android SDK Build Tools');
  const signed = await host(tools.java, ['-jar',tools.apksignerJar,'verify','--verbose','--print-certs',apk],{allowFailure:true});
  const certificates = [...signed.stdout.matchAll(/^Signer #\d+ certificate SHA-256 digest:\s*([0-9a-f]{64})\b/gmi)].map(match => match[1].toLowerCase());
  const {stdout:files} = await host(tools.python,[path.join(here,'inspect-apk-zip.py'),apk,tools.readelf,
    String(budget.bytes),String(budget.entries),...(nativeDetails ? ['native-details'] : [])],
  {timeout:120000,maxBuffer:nativeDetails ? 16*1024*1024 : undefined});
  const entries = JSON.parse(files);
  budget.bytes -= entries.reduce((total,entry)=>total+entry.bytes,0);
  budget.entries -= entries.length;
  if ((await sha256(apk)) !== digest) throw new Error('APK changed during inspection');
  await fs.writeFile(manifestPath,manifest,{flag:'wx',mode:0o600});
  const extraction = /^\s*A: (?:android|http:\/\/schemas\.android\.com\/apk\/res\/android):extractNativeLibs\([^)]*\)=(true|false|\(type 0x12\)0x[\da-f]+)\s*$/mi.exec(manifest)?.[1];
  return {
    file:path.basename(apk), split:field(declaration,'split'), name,
    version_code:field(declaration,'versionCode'), version_name:field(declaration,'versionName'),
    bytes:(await fs.stat(apk)).size, sha256:digest, manifest:path.basename(manifestPath),
    manifest_facts:parseManifestFacts(manifest,name),
    signature:{verified:signed.code === 0 && certificates.length > 0, certificates, details:(signed.stdout+'\n'+signed.stderr).trim().slice(0,12000)},
    ...(nativeDetails ? {extract_native_libs:extraction === undefined ? null : extraction === 'true' ||
      (extraction.includes(')') && BigInt(extraction.split(')')[1])!==0n)} : {}),
    entries,
  };
}

function packagePaths(output) {
  const files = output.trim().split('\n').map(line => /^package:(\/[^\x00-\x1f]+\.apk)$/.exec(line)?.[1]);
  if (!files.length || files.length > 128 || files.some(file => !file) || new Set(files).size !== files.length) {
    throw new Error('package manager did not return a complete, valid APK path list');
  }
  const names = files.map(file => path.posix.basename(file));
  if (names.some(name => !splitName.test(name)) || new Set(names.map(name => name.toLowerCase())).size !== names.length) {
    throw new Error('unsafe or duplicate APK filenames');
  }
  return files;
}

async function sizeBudget(files) {
  let total = 0;
  for (const file of files) {
    total += (await fs.stat(file)).size;
    if (total > maxAPK) throw new Error('combined APK size exceeds 512 MiB');
  }
}

async function readInventory(file) {
  const input = await localFile(file,16*1024*1024,'inventory');
  const parsed = JSON.parse(await fs.readFile(input,'utf8'));
  const digest = z.string().regex(/^[a-f0-9]{64}$/);
  const inventory = z.object({
    schema:z.literal(schema), package:packageSchema,
    apks:z.array(z.object({
      split:z.string().nullable(), version_code:z.string().nullable(), version_name:z.string().nullable(),
      sha256:digest, signature:z.object({verified:z.boolean(),certificates:z.array(digest)}),
      manifest_facts:manifestFactsSchema.nullable().optional(),
      entries:z.array(z.object({path:z.string(),kind:z.string(),sha256:digest,build_id:z.string().nullable().optional()})).max(5000),
    })).min(1).max(128),
  }).parse(parsed);
  if (new Set(inventory.apks.map(apk=>apk.split ?? '')).size !== inventory.apks.length ||
      inventory.apks.some(apk=>new Set(apk.entries.map(entry=>entry.path)).size !== apk.entries.length)) {
    throw new Error('inventory contains duplicate split or entry names');
  }
  return inventory;
}

export function compareInventory(left,right) {
  if (left.package !== right.package) throw new Error('inventories describe different Android packages');
  const index = source => new Map(source.apks.map(apk => [apk.split ?? '',apk]));
  const before = index(left), after = index(right);
  const changes = [];
  for (const split of new Set([...before.keys(),...after.keys()])) {
    const a = before.get(split), b = after.get(split);
    if (!a || !b) {
      const manifest_delta = (a ?? b).manifest_facts ? compareManifestFacts(a,b) : undefined;
      changes.push({split:split || 'base',change:a ? 'removed' : 'added',...(manifest_delta ? {manifest_delta} : {})});
      continue;
    }
    if (a.sha256 === b.sha256) continue;
    const first = new Map(a.entries.map(entry => [entry.path,entry]));
    const second = new Map(b.entries.map(entry => [entry.path,entry]));
    const entries = [];
    for (const name of new Set([...first.keys(),...second.keys()])) {
      const x = first.get(name), y = second.get(name);
      if (x?.sha256 === y?.sha256) continue;
      entries.push({path:name,kind:(y ?? x).kind,change:!x ? 'added' : !y ? 'removed' : 'changed',
        before:x?.build_id ?? x?.sha256 ?? null,after:y?.build_id ?? y?.sha256 ?? null});
    }
    const cert = apk => [...apk.signature.certificates].sort().join(',');
    changes.push({split:split || 'base', change:'changed', version:[a.version_code,b.version_code],
      certificates:{before:a.signature.certificates,after:b.signature.certificates,changed:cert(a) !== cert(b)},
      signature_verified:[a.signature.verified,b.signature.verified], entries, manifest_delta:compareManifestFacts(a,b)});
  }
  return {package:left.package,changes};
}

export async function apkInspection(args,{nativeDetails=false}={}) {
  if (args.action === 'compare') {
    if (!args.left || !args.right) throw new Error('left and right inventory.json paths are required');
    const comparison = compareInventory(...await Promise.all([readInventory(args.left),readInventory(args.right)]));
    const directory = await outputDirectory(args.output,'apk-compare');
    return {report:await writeJson(directory,'comparison.json',comparison),package:comparison.package,changed_apks:comparison.changes.length,
      changed_manifest_apks:comparison.changes.filter(apk=>apk.manifest_delta?.status === 'changed').length};
  }
  const tools = await toolchain();
  let files, remote, user;
  if (args.action === 'export') {
    const pkg = packageSchema.parse(args.package);
    const userText = args.user === undefined ? (await deviceText('am get-current-user')).trim() : String(args.user);
    if (!/^\d{1,5}$/.test(userText)) throw new Error('could not resolve the Android user');
    user = userSchema.parse(Number(userText));
    const list = () => deviceText(`pm path --user ${user} ${shQuote(pkg)}`).then(packagePaths);
    remote = await list();
    const sizes = await deviceText(remote.map(file => `stat -c %s -- ${shQuote(file)}`).join(' && '));
    const bytes = sizes.trim().split('\n').map(Number);
    if (bytes.length !== remote.length || bytes.some(n => !Number.isSafeInteger(n) || n <= 0) ||
        bytes.reduce((sum,n)=>sum+n,0) > maxAPK) throw new Error('invalid APK sizes or combined APK size exceeds 512 MiB');
    const directory = await outputDirectory(args.output,'apk');
    files = remote.map(file => path.join(directory,path.posix.basename(file)));
    for (let index=0;index<remote.length;++index) {
      ensureDevice(await runDevice(['pull',remote[index],files[index]],{overwrite:false,maxFileBytes:bytes[index]}));
    }
    if (JSON.stringify(await list()) !== JSON.stringify(remote)) throw new Error('APK installation changed during export');
    return buildReport(files,tools,directory,{package:pkg,user,remote},nativeDetails);
  }
  if (!args.apks?.length) throw new Error('apks must contain local APK paths');
  files = await Promise.all(args.apks.map(file => localFile(file,maxAPK,'APK')));
  await sizeBudget(files);
  const directory = await outputDirectory(args.output,'apk');
  return buildReport(files,tools,directory,{},nativeDetails);
}

async function buildReport(files, tools, directory, source,nativeDetails) {
  const apks = [];
  const budget = {bytes:maxAPK,entries:5000};
  for (let index=0;index<files.length;++index) {
    apks.push(await inventory(files[index],tools,path.join(directory,`manifest-${index}.txt`),budget,nativeDetails));
  }
  const name = source.package ?? apks[0].name;
  if (apks.some(apk => apk.name !== name) || new Set(apks.map(apk => apk.split ?? '')).size !== apks.length ||
      (source.remote && !apks.some(apk => apk.split === null))) throw new Error('APK package/split identities do not match');
  const signer = apk => [...apk.signature.certificates].sort().join(',');
  const signaturesVerified = apks.every(apk => apk.signature.verified);
  const splitsConsistent = signaturesVerified && apks.every(apk =>
    apk.version_code === apks[0].version_code && signer(apk) === signer(apks[0]));
  const report = {schema, package:name, user:source.user ?? null, exported:!!source.remote, splits_consistent:splitsConsistent,
    apk_paths:files, abis:[...new Set(apks.flatMap(apk => apk.entries.filter(entry => entry.abi).map(entry => entry.abi)))],
    apks};
  return {report:await writeJson(directory,'inventory.json',report), directory, package:name,
    apk_count:apks.length, abis:report.abis, signatures_verified:signaturesVerified,splits_consistent:splitsConsistent};
}
