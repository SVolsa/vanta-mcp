import test from 'node:test';
import assert from 'node:assert/strict';
import {spawnSync} from 'node:child_process';
import {jobScript} from './job-scripts.js';
import {hostTestShell} from './test-app/host-shell.js';

test('all job scripts parse as POSIX shell, reject invalid identities and avoid shared writable state', () => {
  const shell = hostTestShell();
  for (const action of ['start','stop','list','log','status']) {
    const script = jobScript(action,{name:'example',command:"sleep 5; echo 'a b'"});
    const result = spawnSync(shell,['-n'],{input:script,encoding:'utf8',windowsHide:true});
    assert.equal(result.status,0,result.stderr);
    assert.doesNotMatch(script,/chmod 1777/);
  }
  for (const name of ['../escape','a;id','',undefined]) assert.throws(() => jobScript('stop',{name}), /invalid job name/);
});
