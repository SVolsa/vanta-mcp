import test from 'node:test';
import assert from 'node:assert/strict';
import { statusCommand, logcatCommand, registerAndroidTools, shizukuDiagnostic } from './android-tools.js';
import { withConnection } from './connection.js';

test('default status does not request elevated permission or scan unrelated processes', () => {
  const command = statusCommand();
  assert.doesNotMatch(command, /su -c|rish|ps -A|dumpsys window/);
  assert.match(command, /id -u/);
});

test('a Shizuku binder timeout is distinct from a reported denial or stopped service', () => {
  assert.match(shizukuDiagnostic('Request timeout. The connection may be blocked.'),/timed out before authorization/);
  assert.match(shizukuDiagnostic('Permission denied'),/denied access/);
  assert.match(shizukuDiagnostic('Server is not running'),/service is not running/);
});

test('connection verifies Shizuku only when its check returns an Android identity', async () => {
  let stdout = 'uid=2000(shell) gid=2000(shell)\nEnforcing\nsdk=37\nabi=x86_64';
  const handlers = new Map();
  registerAndroidTools((name, _desc, _schema, handler) => handlers.set(name, handler), {
    run: async args => {
      assert.equal(args[1], 'shizuku');
      return {code:0,stdout,stderr:''};
    },
  });
  const connection = handlers.get('connection');
  await withConnection({transport:'adb',serial:'emulator-5554',privilege:'shizuku'}, async () => {
    assert.notEqual(JSON.parse(await connection({action:'info'})).shizuku, 'rish_verified');
    const checked = JSON.parse(await connection({action:'check'}));
    assert.equal(checked.shizuku, 'rish_verified');
    assert.equal(checked.fallback, false);
    stdout = 'sdk=37\nabi=x86_64';
    await assert.rejects(connection({action:'check'}), /no Android execution identity/);
  });
});

test('logcat quotes filters and supports PID, buffer and priority', () => {
  const command = logcatCommand({ pid: 123, buffer: 'crash', tag: 'A;echo bad', priority: 'E', lines: 5 });
  assert.match(command, /--pid=123/);
  assert.match(command, /'-b' 'crash'/);
  assert.match(command, /'A;echo bad:E' '\*:S'/);
});

test('app tools reject missing and malformed package identifiers before device access', async () => {
  const handlers = new Map();
  registerAndroidTools((name, _desc, _schema, handler) => handlers.set(name, handler), {
    run: async () => { throw new Error('unexpected device call'); },
  });
  for (const args of [{action:'info'}, {action:'start',package:'a;id'}, {action:'stop',package:'--all'}]) {
    await assert.rejects(handlers.get('app')(args), /package/);
  }
});

test('app launch requires an explicit component and does not guess a launcher', async () => {
  const handlers = new Map();
  const commands = [];
  registerAndroidTools((name, _desc, _schema, handler) => handlers.set(name, handler), {
    run: async args => {commands.push(args); return {code:0,stdout:'ok',stderr:''};},
  });
  await assert.rejects(handlers.get('app')({action:'start',package:'dev.example'}), /component/);
  await handlers.get('app')({action:'start',package:'dev.example',component:'.MainActivity',user:10});
  assert.match(commands[0][2], /am start -W --user 10 -n 'dev.example\/\.MainActivity'/);
});
