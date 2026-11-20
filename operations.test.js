import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import {runProgram,installApk} from './operations.js';
import {withConnection} from './connection.js';

async function source(t, ext = '.sh') {
  const dir = await fs.mkdtemp(path.join(os.tmpdir(),'vanta-operation-'));
  t.after(() => fs.rm(dir,{recursive:true,force:true}));
  const file = path.join(dir,`program${ext}`);
  await fs.writeFile(file,'sample');
  return file;
}
const ok = stdout => ({code:0,timedOut:false,tooLarge:false,stdout,stderr:''});

test('run uses unique paths, preserves nonzero exits and quotes argv', async t => {
  const local = await source(t);
  const paths = [], commands = [];
  const fake = async args => {
    if (args[0] === 'push') { paths.push(args[2]); return ok(''); }
    if (args[2].startsWith('rm -f')) return ok('');
    commands.push(args[2]);
    const marker = args[2].match(/(__VANTA_EXIT_[a-f0-9]+__)/)[1];
    return {...ok(`hello\n${marker}=7\n`),code:7};
  };
  assert.match(await runProgram({local,argv:['a;echo bad',"it's"]},fake), /exit=7/);
  await runProgram({local},fake);
  assert.notEqual(paths[0],paths[1]);
  assert.match(commands[0], /'a;echo bad'/);
});

test('run cleans partial uploads and reports both execution and cleanup errors', async t => {
  const local = await source(t);
  const calls = [];
  await assert.rejects(runProgram({local},async args => {
    calls.push(args);
    throw new Error(args[0] === 'push' ? 'transfer failed' : 'offline');
  }), /transfer failed; temporary file cleanup failed: offline/);
  assert.equal(calls.length,2);
});

test('ordinary ADB installation never requests su or uploads a staging file', async t => {
  const local = await source(t,'.apk');
  await withConnection({transport:'adb'},async () => {
    const calls = [];
    await installApk({local},async args => {calls.push(args);return ok('Success\n');});
    assert.deepEqual(calls,[['install','-r',local]]);
  });
});

test('root installation stages privately and cleans even when the package manager rejects it', async t => {
  const local = await source(t,'.apk');
  await withConnection({transport:'usb',privilege:'root'},async () => {
    const calls = [];
    await assert.rejects(installApk({local},async args => {
      calls.push(args);
      return ok(args[2]?.includes('pm install') ? 'Failure [INSTALL_FAILED_TEST_ONLY]' : '');
    }), /INSTALL_FAILED_TEST_ONLY/);
    assert.match(calls[1][2],/chmod 600/);
    assert.match(calls[1][2],/pm install -r -S 6 </);
    assert.equal(calls.at(-1)[1],'shell');
  });
});
