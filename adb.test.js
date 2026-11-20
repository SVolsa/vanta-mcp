import test from 'node:test';
import assert from 'node:assert/strict';
import { clip, deviceArgs, shellArgs, shQuote, validName } from './adb.js';

test('clip preserves both ends and reports omission', () => {
  const result = clip(`${'a'.repeat(300)}middle${'z'.repeat(300)}`, 100);
  assert.ok(result.startsWith('a'.repeat(50)));
  assert.ok(result.endsWith('z'.repeat(50)));
  assert.match(result, /chars omitted/);
});

test('deviceArgs selects a serial without changing command arguments', () => {
  assert.deepEqual(deviceArgs(['shell', 'id'], 'abc123'), ['-s', 'abc123', 'shell', 'id']);
  assert.deepEqual(deviceArgs(['shell', 'id'], ''), ['shell', 'id']);
});

test('shellArgs keeps the remote command intact', () => {
  const command = "printf '%s %s' one two";
  assert.deepEqual(shellArgs(command), ['shell', '-T', command]);
  assert.deepEqual(shellArgs(command, true), ['shell', '-T', `su -c ${shQuote(command)}`]);
});

test('shQuote handles embedded single quotes', () => {
  assert.equal(shQuote("a'b"), "'a'\"'\"'b'");
});

test('validName accepts job names and rejects paths', () => {
  assert.equal(validName('pcap-test_1'), true);
  assert.equal(validName('../escape'), false);
  assert.equal(validName('two words'), false);
});
