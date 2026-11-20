import test from 'node:test';
import assert from 'node:assert/strict';
import {readFile} from 'node:fs/promises';
import {fileURLToPath} from 'node:url';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {mkdtemp,rm} from 'node:fs/promises';
import {Client} from '@modelcontextprotocol/sdk/client/index.js';
import {StdioClientTransport} from '@modelcontextprotocol/sdk/client/stdio.js';

test('stdio protocol advertises all tools and rejects conflicting requests before connecting to a device', async t => {
  const client = new Client({name:'vanta-host-test',version:'1'});
  const transport = new StdioClientTransport({command:process.execPath,args:[fileURLToPath(new URL('./server.js',import.meta.url))],env:{...process.env,VANTA_TRANSPORT:'adb'}});
  t.after(() => client.close());
  await client.connect(transport);
  const metadata = JSON.parse(await readFile(new URL('./package.json',import.meta.url),'utf8'));
  assert.equal(client.getServerVersion().version,metadata.version);
  const {tools} = await client.listTools();
  assert.equal(tools.length,25);
  for (const name of ['apk_inspect','crash_report','kernel_preflight','elf_inspect','vm_trace','device_use']) {
    assert.ok(tools.some(tool=>tool.name===name),name);
  }
  for (const tool of tools) {
    for (const key of ['transport','serial','privilege']) assert.ok(tool.inputSchema.properties[key],`${tool.name}: ${key}`);
  }
  const info = await client.callTool({name:'connection',arguments:{action:'info',transport:'adb',serial:'test-device'}});
  assert.equal(JSON.parse(info.content[0].text).serial,'test-device');
  const conflict = await client.callTool({name:'shell',arguments:{command:'id',root:true,privilege:'shizuku'}});
  assert.equal(conflict.isError,true);
  assert.match(conflict.content[0].text,/conflict/);
  const rootOnly = await client.callTool({name:'kernel',arguments:{action:'modules',privilege:'shell'}});
  assert.equal(rootOnly.isError,true);
  assert.match(rootOnly.content[0].text,/requires privilege=root/);
  const serial = await client.callTool({name:'connection',arguments:{transport:'usb',serial:'test-device'}});
  assert.equal(serial.isError,true);
});

test('stdio forensic tools require explicit root and dispatch to the device adapter', async t => {
  const output = await mkdtemp(join(tmpdir(),'vanta-stdio-forensics-'));
  const client = new Client({name:'vanta-forensics-test',version:'1'});
  const env = {...process.env,VANTA_TRANSPORT:'adb',ADB_PATH:join(output,'missing-adb')};
  t.after(async () => {
    await client.close();
    await rm(output,{recursive:true,force:true});
  });
  await client.connect(new StdioClientTransport({
    command:process.execPath,args:[fileURLToPath(new URL('./server.js',import.meta.url))],env,
  }));
  for (const [name,args] of [
    ['kernel_snapshot',{dmesg_lines:0}],
    ['kernel_record',{local:join(output,'missing.ko')}],
  ]) {
    for (const privilege of [undefined,'shell','shizuku']) {
      const response = await client.callTool({name,arguments:{...args,output,privilege}});
      assert.equal(response.isError,true);
      assert.match(response.content[0].text,/requires privilege=root/);
    }
  }
  const snapshot = await client.callTool({name:'kernel_snapshot',arguments:{output,dmesg_lines:0,privilege:'root'}});
  assert.equal(snapshot.isError,true);
  assert.match(snapshot.content[0].text,/missing-adb.*ENOENT/);
  const run = await client.callTool({name:'run',arguments:{local:fileURLToPath(new URL('./package.json',import.meta.url)),forensics:true}});
  assert.equal(run.isError,true);
  assert.match(run.content[0].text,/missing-adb.*ENOENT/);
});
