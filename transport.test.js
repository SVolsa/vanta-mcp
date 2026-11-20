import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import {usbConfigPath} from './connection.js';
import {transportName, shellArgs, runDevice, ensureDevice, usbRequest} from './transport.js';

test('USB selection rejects ADB-specific operations without falling back', async () => {
  const previous=process.env.VANTA_TRANSPORT;
  try {
    process.env.VANTA_TRANSPORT='usb';
    await assert.rejects(runDevice(['forward','--list']),/ADB-specific/);
    process.env.VANTA_TRANSPORT='bad';
    assert.throws(transportName,/invalid/);
  } finally { if(previous===undefined) delete process.env.VANTA_TRANSPORT;else process.env.VANTA_TRANSPORT=previous; }
});
test('privilege request remains explicit, with command text unchanged', () => {
  assert.deepEqual(shellArgs("echo 'a b'"),['vanta-shell','shell',"echo 'a b'"]);
  assert.deepEqual(shellArgs('id',true),['vanta-shell','root','id']);
});
test('device errors, timeout, and size limit are distinct failures', () => {
  assert.throws(()=>ensureDevice({timedOut:true}),/timed out/);
  assert.throws(()=>ensureDevice({tooLarge:true}),/size limit/);
  assert.throws(()=>ensureDevice({code:7,stdout:'',stderr:'failed'}),/failed/);
});

test('an explicit USB config takes precedence and invalid pairing fails before network access', async t => {
  const folder = await fs.mkdtemp(path.join(os.tmpdir(),'vanta-config-'));
  const previous = {config:process.env.VANTA_CONFIG,transport:process.env.VANTA_TRANSPORT};
  t.after(async () => {
    if (previous.config===undefined) delete process.env.VANTA_CONFIG;
    else process.env.VANTA_CONFIG=previous.config;
    if (previous.transport===undefined) delete process.env.VANTA_TRANSPORT;
    else process.env.VANTA_TRANSPORT=previous.transport;
    await fs.rm(folder,{recursive:true,force:true});
  });
  delete process.env.VANTA_TRANSPORT;
  const file = path.join(folder,'client.json');
  process.env.VANTA_CONFIG=path.relative(process.cwd(),file) || file;
  assert.equal(usbConfigPath(),file);
  assert.equal(transportName(),'adb');
  await fs.writeFile(file,JSON.stringify({endpoint:'usb:auto'}),'utf8');
  assert.equal(transportName(),'usb');
  await assert.rejects(usbRequest('/v1/status'),/ca, cert, key and servername/);
});
