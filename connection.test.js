import test from 'node:test';
import assert from 'node:assert/strict';
import { withConnection, connectionOptions, requestedPrivilege, shizukuCommand, usbShellCommand } from './connection.js';
import { shellArgs, transportName } from './transport.js';

test('concurrent requests keep their device and privilege isolated', async () => {
  const results = await Promise.all(['first', 'second'].map(serial => withConnection({ transport: 'adb', serial, privilege: 'shizuku' }, async () => {
    await new Promise(resolve => setTimeout(resolve, serial === 'first' ? 10 : 1));
    return { ...connectionOptions(), args: shellArgs('id') };
  })));
  assert.deepEqual(results.map(r => r.serial), ['first', 'second']);
  assert.deepEqual(results[0].args, ['vanta-shell', 'shizuku', 'id']);
  assert.deepEqual(connectionOptions(), {});
});

test('privilege conflicts and invalid device selection are rejected before execution', async () => {
  assert.throws(() => requestedPrivilege({ root: true, privilege: 'shizuku' }), /conflict/);
  assert.throws(() => requestedPrivilege({ root: false, privilege: 'root' }), /conflict/);
  for (const args of [{ transport: 'bad' }, { transport: 'usb', serial: 'abc' }, { serial: '-s' }, { serial: 'a\n' }]) {
    await assert.rejects(withConnection(args, async () => {}), /invalid|only/);
  }
});

test('a request pins automatic transport selection for its entire operation', async () => {
  const previous = process.env.VANTA_TRANSPORT;
  try {
    process.env.VANTA_TRANSPORT = 'usb';
    await withConnection({},async () => {
      process.env.VANTA_TRANSPORT = 'adb';
      assert.equal(transportName(),'usb');
    });
  } finally {
    if (previous === undefined) delete process.env.VANTA_TRANSPORT;
    else process.env.VANTA_TRANSPORT = previous;
  }
});

test('Shizuku uses the official rish entry point, quotes arguments, and fails closed without configuration', () => {
  assert.throws(() => shizukuCommand('id', {}), /VANTA_RISH_PATH/);
  assert.throws(() => shizukuCommand('id', { VANTA_RISH_PATH: 'relative' }), /absolute/);
  assert.throws(() => shizukuCommand('id', { VANTA_RISH_PATH: '/tmp/rish', VANTA_RISH_APPLICATION_ID: 'bad;id' }), /package/);
  const command = shizukuCommand("printf '%s' 'a b'", { VANTA_RISH_PATH: '/data/local/tmp/rish' });
  assert.match(command, /RISH_PRESERVE_ENV=0/);
  assert.match(command, /RISH_APPLICATION_ID='com.android.shell'/);
  assert.match(command, /\/system\/bin\/sh '\/data\/local\/tmp\/rish' -c/);
  assert.doesNotMatch(command, /su -c|chmod/);
});

test('USB UID drop also transitions SELinux before executing operator input, without fallback', () => {
  const command = usbShellCommand("id; printf '%s' 'a b'");
  assert.match(command,/^set -- '/);
  assert.match(command,/if \[ .*u:r:shell:s0 \]; then exec \/system\/bin\/sh -c "\$1"/);
  assert.match(command,/fi; exec \/system\/bin\/runcon u:r:shell:s0 \/system\/bin\/sh -c "\$1"/);
  assert.doesNotMatch(command,/\|\|/);
});
