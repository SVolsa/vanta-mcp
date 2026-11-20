import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import path from 'node:path';
import os from 'node:os';
import crypto from 'node:crypto';
import {spawn} from 'node:child_process';
import {uploadFile,downloadFile,CHUNK_BYTES} from './file-transfer.js';
import {hostTestShell} from './test-app/host-shell.js';

const shell=hostTestShell();
function remote(command,_options,input) {
  return new Promise((resolve,reject)=>{
    const child=spawn(shell,['-c',command],{windowsHide:true});
    const stdout=[],stderr=[];
    child.stdout.on('data',d=>stdout.push(d));child.stderr.on('data',d=>stderr.push(d));
    child.on('error',reject);child.stdin.on('error',()=>{});
    child.on('close',code=>{if(code)reject(new Error(Buffer.concat(stderr).toString()||`remote exited ${code}`));else resolve(Buffer.concat(stdout))});
    child.stdin.end(input);
  });
}
async function fixture(t) {
  const dir=await fs.mkdtemp(path.join(os.tmpdir(),'vanta-transfer-'));
  t.after(()=>fs.rm(dir,{recursive:true,force:true}));
  return {dir,source:path.join(dir,"source ' data.bin"),device:path.join(dir,"device ' data.bin").replaceAll('\\','/'),destination:path.join(dir,'destination.bin')};
}

test('bidirectional multichunk transfer verifies content, bounds each request, and quotes paths',async t=>{
  const f=await fixture(t),data=crypto.randomBytes(2*CHUNK_BYTES+19);await fs.writeFile(f.source,data);
  let maxInput=0;
  const bounded=async(command,options,input)=>{maxInput=Math.max(maxInput,input?.length??0);return remote(command,options,input)};
  const sent=await uploadFile(f.source,f.device,bounded);
  const received=await downloadFile(f.device,f.destination,bounded);
  assert.equal(sent.bytes,data.length);assert.equal(received.sha256,sent.sha256);
  assert.ok(maxInput<=CHUNK_BYTES);assert.equal(sent.chunks,3);
  assert.deepEqual(await fs.readFile(f.destination),data);
});
test('empty file is valid and verified in both directions',async t=>{
  const f=await fixture(t);await fs.writeFile(f.source,'');
  const sent=await uploadFile(f.source,f.device,remote);await downloadFile(f.device,f.destination,remote);
  assert.equal(sent.bytes,0);assert.equal((await fs.stat(f.destination)).size,0);
});
test('failed upload preserves existing destination and removes its temporary file',async t=>{
  const f=await fixture(t);await fs.writeFile(f.source,Buffer.alloc(CHUNK_BYTES+1,7));await fs.writeFile(f.device,'old');
  let writes=0;
  await assert.rejects(uploadFile(f.source,f.device,async(c,o,input)=>{
    if(input?.length&&++writes===2)throw new Error('connection lost');return remote(c,o,input);
  }),/connection lost/);
  assert.equal(await fs.readFile(f.device,'utf8'),'old');
  assert.ok(!(await fs.readdir(f.dir)).some(n=>n.includes('.vanta-upload-')));
});
test('corrupt download is rejected without overwriting an existing file',async t=>{
  const f=await fixture(t);await fs.writeFile(f.device,crypto.randomBytes(100));await fs.writeFile(f.destination,'old');
  await assert.rejects(downloadFile(f.device,f.destination,async(c,o,input)=>{
    const data=await remote(c,o,input);if(c.startsWith('dd '))data[0]^=1;return data;
  },{overwrite:true}),/SHA256/);
  assert.equal(await fs.readFile(f.destination,'utf8'),'old');
  assert.ok(!(await fs.readdir(f.dir)).some(n=>n.includes('.vanta-pull-')));
});
test('source mutation during upload is rejected before commit',async t=>{
  const f=await fixture(t);await fs.writeFile(f.source,Buffer.alloc(CHUNK_BYTES+1,7));await fs.writeFile(f.device,'old');
  let changed=false;
  await assert.rejects(uploadFile(f.source,f.device,async(c,o,input)=>{
    const data=await remote(c,o,input);if(input?.length&&!changed){changed=true;await fs.appendFile(f.source,'x')}return data;
  }),/source changed/);
  assert.equal(await fs.readFile(f.device,'utf8'),'old');
});
test('default download cannot overwrite an existing file',async t=>{
  const f=await fixture(t);await fs.writeFile(f.device,'new');await fs.writeFile(f.destination,'old');
  await assert.rejects(downloadFile(f.device,f.destination,remote),/EEXIST/);
  assert.equal(await fs.readFile(f.destination,'utf8'),'old');
});
test('interrupted download cleans partial output and preserves previous file',async t=>{
  const f=await fixture(t);await fs.writeFile(f.device,Buffer.alloc(CHUNK_BYTES+1,7));await fs.writeFile(f.destination,'old');
  let reads=0;
  await assert.rejects(downloadFile(f.device,f.destination,async(c,o,input)=>{
    if(c.startsWith('dd ')&&++reads===2)throw new Error('connection lost');return remote(c,o,input);
  },{overwrite:true}),/connection lost/);
  assert.equal(await fs.readFile(f.destination,'utf8'),'old');
  assert.ok(!(await fs.readdir(f.dir)).some(n=>n.includes('.vanta-pull-')));
});

test('upload rejects corrupted remote content before replacing the destination',async t=>{
  const f=await fixture(t);await fs.writeFile(f.source,'new');await fs.writeFile(f.device,'old');
  await assert.rejects(uploadFile(f.source,f.device,async(c,o,input)=>{
    const result=await remote(c,o,input);
    if(input?.length) {
      const name=(await fs.readdir(f.dir)).find(n=>n.includes('.vanta-upload-'));
      await fs.writeFile(path.join(f.dir,name),'bad');
    }
    return result;
  }),/SHA256/);
  assert.equal(await fs.readFile(f.device,'utf8'),'old');
  assert.ok(!(await fs.readdir(f.dir)).some(n=>n.includes('.vanta-upload-')));
});

test('download detects a remote source change after reading the last chunk',async t=>{
  const f=await fixture(t);await fs.writeFile(f.device,'new');await fs.writeFile(f.destination,'old');
  await assert.rejects(downloadFile(f.device,f.destination,async(c,o,input)=>{
    const result=await remote(c,o,input);if(c.startsWith('dd '))await fs.writeFile(f.device,'bad');return result;
  },{overwrite:true}),/SHA256/);
  assert.equal(await fs.readFile(f.destination,'utf8'),'old');
});

test('upload rejects directories and invalid remote paths',async t=>{
  const f=await fixture(t);await fs.writeFile(f.source,'new');await fs.mkdir(f.device);
  await assert.rejects(uploadFile(f.source,f.device,remote));
  assert.deepEqual(await fs.readdir(f.device),[]);
  await assert.rejects(uploadFile(f.dir,f.device,remote),/regular file/);
  await assert.rejects(uploadFile(f.source,'bad\0path',remote),/invalid remote/);
  await assert.rejects(downloadFile('',f.destination,remote),/invalid remote/);
});
