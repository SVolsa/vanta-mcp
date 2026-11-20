import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import {existsSync} from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import {execFile} from 'node:child_process';
import {promisify} from 'node:util';
import {kernelSnapshot, kernelRecord} from './forensics.js';
import {runProgram} from './operations.js';
import {toolchain} from './inspection-io.js';

const execute = promisify(execFile);
const ok = stdout=>({code:0,timedOut:false,tooLarge:false,stdout,stderr:''});
const failed = stderr=>({...ok(''),code:1,stderr});
const report = async output=>JSON.parse(await fs.readFile(output.trim().split('\n').at(-1),'utf8'));

async function tmpdir(t) {
  const dir = await fs.mkdtemp(path.join(os.tmpdir(),'vanta-forensics-'));
  t.after(()=>fs.rm(dir,{recursive:true,force:true}));
  return dir;
}

test('run forensics keeps the child status separate from its deadline and transport', async t => {
  const local = path.join(await tmpdir(t),'program.sh');
  await fs.writeFile(local,'fixture');
  const request = {local,forensics:true};
  const runWith = (child,wrapper,{start = '4321:53128',timedOut = false} = {})=>async args => {
    if (args[0] === 'push' || args[2].startsWith('rm -f')) return ok('');
    const marker = args[2].match(/(__VANTA_EXIT_[a-f0-9]+__)/)[1];
    assert.doesNotMatch(args[2],/pgrep/);
    const lines = ['program output'];
    if (start) lines.push(`${marker}_START=${start}`);
    if (child !== null) lines.push(`${marker}_CHILD=${child}`);
    if (wrapper !== null) lines.push(`${marker}=${wrapper}`);
    return {...ok(lines.join('\r\n')+'\r\n'),timedOut};
  };

  const normal = await runProgram(request,runWith(124,0));
  assert.match(normal,/exit=124\nexit_type=exit code=124/);
  assert.match(normal,/pid=4321\nstart_tick=53128\nduration_ms=\d+\nduration_source=host\nreceipt=true/);
  assert.doesNotMatch(normal,/__VANTA_EXIT_/);
  const ambiguous = await runProgram(request,runWith(143,0,{start:'4321:'}));
  assert.match(ambiguous,/exit_type=ambiguous shell_status=143/);
  assert.match(ambiguous,/start_tick=unavailable/);
  const timeout = await runProgram(request,runWith(null,124));
  assert.match(timeout,/exit=timeout\nexit_type=timeout/);
  assert.match(timeout,/receipt=true/);
  const lost = await runProgram(request,runWith(null,null,{start:null}));
  assert.match(lost,/exit=unknown\nexit_type=lost\npid=unknown/);
  assert.match(lost,/receipt=false/);
  const hostTimeout = await runProgram(request,runWith(null,null,{start:null,timedOut:true}));
  assert.match(hostTimeout,/exit=timeout\nexit_type=timeout/);
  assert.match(hostTimeout,/receipt=false/);
  const offline = await runProgram(request,async args => {
    if (args[0] === 'push') return ok('');
    throw new Error('device offline');
  });
  assert.match(offline,/cleanup_error="device offline"/);
  assert.match(offline,/exit_type=lost/);
  await assert.rejects(runProgram({...request,args:'legacy'}),/requires argv/);
});

const identity = 'boot_id=fixture-boot\nrelease=6.6.89-test\nmachine=aarch64\nepoch=1795000000\nuptime_s=1281.24';

function fakeSnapshotIo(listing, {dmesg = ok('line1\nline2'),pstore = Buffer.from('pstore-data')} = {}) {
  const calls = [];
  return {calls,io:{
    adb:async (args,options)=>{
      calls.push({args,options});
      const cmd = args[2];
      if (cmd.includes('boot_id')) return ok(identity);
      if (cmd.startsWith('messages=$(dmesg)')) return dmesg;
      if (cmd.startsWith('ls -1 /sys/fs/pstore/')) {
        if (listing instanceof Error) throw listing;
        return listing;
      }
      throw new Error('unexpected text request');
    },
    buffer:async (args,options)=>{
      calls.push({args,options});
      assert.match(args[2],/^head -c /);
      return {...ok(''),stdout:pstore.subarray(0,options.maxBytes)};
    },
  }};
}

test('kernel_snapshot hashes saved bytes, truncates pstore and honors the request budget', async t => {
  const output = await tmpdir(t);
  const {io,calls} = fakeSnapshotIo(ok('dmesg-ramoops-0.enc.z\nconsole-ramoops-0'));
  const args = {output,privilege:'root',dmesg_lines:10,pstore_max_bytes:6,timeout_ms:5000};
  await assert.rejects(kernelSnapshot({...args,privilege:'shell'},io),/requires privilege=root/);
  assert.equal(calls.length,0);
  const result = await kernelSnapshot(args,io);
  const captured = await report(result);
  assert.match(result,/outcome=captured/);
  assert.equal(captured.device.boot_id,'fixture-boot');
  assert.equal(captured.dmesg.lines,2);
  assert.match(captured.dmesg.sha256,/^[a-f0-9]{64}$/);
  assert.equal(captured.pstore.length,2);
  const {size,saved,truncated,sha256} = captured.pstore[0];
  assert.deepEqual({size,saved,truncated},{size:null,saved:6,truncated:true});
  assert.match(sha256,/^[a-f0-9]{64}$/);
  assert.ok(calls.every(({args:cmd,options})=>cmd[1] === 'root' && options.timeoutMs <= 5000));
  const dir = path.dirname(result.trim().split('\n').at(-1));
  assert.equal(await fs.readFile(path.join(dir,'dmesg.txt'),'utf8'),'line1\nline2\n');
  assert.equal(await fs.readFile(path.join(dir,'pstore','console-ramoops-0'),'utf8'),'pstore');
});

test('kernel_snapshot keeps failures distinct from a successful empty read', async t => {
  const args = {output:await tmpdir(t),privilege:'root'};
  for (const [listing,want] of [
    [ok(''),'empty'],[failed('No such file or directory'),'source_unavailable'],
    [failed('Permission denied'),'permission_denied'],[new Error('device offline'),'disconnected'],
  ]) {
    const {io} = fakeSnapshotIo(listing,{dmesg:failed('dmesg: Operation not permitted')});
    const captured = await report(await kernelSnapshot(args,io));
    assert.equal(captured.outcome,want);
    assert.equal(captured.dmesg.status,'permission_denied');
    assert.equal(captured.dmesg_lines_saved,0);
  }
  const {io} = fakeSnapshotIo(ok(''),{dmesg:ok('')});
  assert.equal((await report(await kernelSnapshot(args,io))).dmesg.status,'empty');
});

async function fixtureKo(t, dir) {
  const {readelf} = await toolchain();
  const clang = path.join(path.dirname(readelf),process.platform === 'win32' ? 'clang.exe' : 'clang');
  if (!existsSync(clang)) {
    t.skip('Android NDK clang unavailable');
    return null;
  }
  const src = path.join(dir,'fixture.c');
  const ko = path.join(dir,'testmod.ko');
  await fs.writeFile(src,String.raw`__attribute__((used,section(".modinfo"))) static const char info[] = "name=testmod\0vermagic=6.6.89-test SMP preempt mod_unload\0license=GPL\0";`);
  await execute(clang,['--target=aarch64-linux-gnu','-c',src,'-o',ko]);
  return ko;
}

function fakeRecordIo({loadError, cleanupError} = {}) {
  let loaded = false;
  const calls = [];
  return {calls,io:{
    adb:async args=>{
      const cmd = args[2];
      calls.push(cmd);
      if (args[0] === 'push') return ok('');
      if (cmd.startsWith('modules=')) return ok(loaded ? 'testmod entry\nsysfs=present' : '@absent\nsysfs=absent');
      if (cmd.startsWith('messages=$(dmesg)')) return ok('log line');
      if (cmd.startsWith('insmod')) {
        if (loadError) throw loadError;
        loaded = true;
        return ok('');
      }
      if (cmd.startsWith('rmmod')) {
        loaded = false;
        return ok('');
      }
      if (cmd.startsWith('rm -f')) return cleanupError ? failed(cleanupError) : ok('');
      throw new Error('unexpected device command');
    },
  }};
}

test('kernel_record validates parameters, then records state after the last requested action', async t => {
  const output = await tmpdir(t);
  const local = await fixtureKo(t,output);
  if (!local) return;
  const args = {local,output,privilege:'root'};
  const {io,calls} = fakeRecordIo();
  const observed = await report(await kernelRecord(args,io));
  assert.equal(observed.module,'testmod');
  assert.equal(observed.load,null);
  assert.equal(observed.unload,null);
  assert.equal(calls.length,4);
  await assert.rejects(kernelRecord({...args,load:true,params:['invalid']},io),/name=value/);
  const actions = {...args,load:true,unload:true,params:["label=two words'"]};
  const record = await report(await kernelRecord(actions,io));
  assert.equal(record.load.exit,0);
  assert.equal(record.unload.exit,0);
  assert.equal(record.after.modules,'@absent\nsysfs=absent');
  assert.ok(calls.findIndex(cmd=>cmd.startsWith('rmmod')) < calls.findLastIndex(cmd=>cmd.startsWith('modules=')));
  assert.ok(calls.some(cmd=>cmd.startsWith('insmod') && cmd.endsWith(`'label=two words'"'"''`)));
});

test('kernel_record attempts cleanup after a transport failure and skips unconfirmed unload', async t => {
  const output = await tmpdir(t);
  const local = await fixtureKo(t,output);
  if (!local) return;
  const {io,calls} = fakeRecordIo({loadError:new Error('device offline'),cleanupError:'Permission denied'});
  const result = await report(await kernelRecord({local,output,privilege:'root',load:true,unload:true},io));
  assert.equal(result.load.status,'disconnected');
  assert.equal(result.load.cleanup_error.status,'permission_denied');
  assert.equal(result.unload.exit,'skipped');
  assert.equal(calls.some(cmd=>cmd.startsWith('rmmod')),false);
});
