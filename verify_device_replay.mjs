// Repeat the Device Use replay on one explicitly selected ADB device.
import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import path from 'node:path';
import {setTimeout as sleep} from 'node:timers/promises';
import {Client} from '@modelcontextprotocol/sdk/client/index.js';
import {StdioClientTransport} from '@modelcontextprotocol/sdk/client/stdio.js';
import {ensureAdb,runAdb,shQuote} from './adb.js';
import {selectedVantaInput} from './device-input.js';
import {here,host,outputDirectory,toolchain,validationAdb,writeJson} from './inspection-io.js';

const cli = process.argv.slice(2);
const shizuku = cli.at(-1)==='--shizuku';
if (shizuku) cli.pop();
const [serial,probe,mode,input,...rest] = cli;
const emulator = mode==='--disposable-emulator';
if (!/^[a-zA-Z0-9][a-zA-Z0-9._:[\]%-]{0,254}$/.test(serial ?? '') || !probe || rest.length ||
    (emulator ? !/^emulator-\d+$/.test(serial) || !input : mode!==undefined || /^emulator-\d+$/.test(serial))) {
  throw new Error('usage: node verify_device_replay.mjs <adb-serial> <probe.apk> [--disposable-emulator <input.apk>] [--shizuku]');
}

process.env.ADB_PATH ||= validationAdb();
const pkg = 'dev.vanta.inspectionprobe';
const imePkg = 'dev.vanta.deviceinput';
const ime = imePkg+'/.VantaKeyboard';
const flowFile = path.join(here,'test-app/device-replay-flow.json');
const directory = await outputDirectory(undefined,'replay-acceptance');
const privilege = shizuku ? 'shizuku' : 'shell';
const receipt = {serial,environment:emulator ? 'disposable_emulator' : 'physical',privilege,passed:false,rounds:[],interruptions:{},cleanup:false};
const client = new Client({name:'vanta-device-replay-acceptance',version:'1'});
const adb = async (args,timeoutMs=20000) => ensureAdb(await runAdb(args,{serial,timeoutMs,maxChars:24000})).stdout.trim();
const shell = command => adb(['shell','-T',command]);
let user, installed=false, imeInstalled=false, oldIme, oldHardKeyboard, stoppedEmulator=false;

async function mustBeUnlocked() {
  if (!/^ *mWakefulness=Awake *$/m.test(await shell('dumpsys power | grep mWakefulness='))) {
    throw new Error('screen_not_awake');
  }
  const keyguard = (await shell('dumpsys window policy')).split('KeyguardServiceDelegate')[1] ?? '';
  if (!/^\s*showing=false\s*$/m.test(keyguard) || /^\s*(showing|inputRestricted|mInputRestricted|mIsShowing)=true\s*$/m.test(keyguard)) {
    throw new Error('keyguard_active_or_unavailable');
  }
}

async function request(name,args) {
  return client.callTool({
    name,arguments:{...args,transport:'adb',serial,privilege},
  },undefined,{timeout:95000});
}

async function call(args) {
  const result = await request('device_use',args);
  if (result.isError) throw new Error(result.content[0].text);
  return JSON.parse(result.content[0].text);
}

async function checkShizuku() {
  const result = await request('connection',{action:'check'});
  const value = result.content[0].text;
  if (result.isError) throw new Error(value);
  const checked = JSON.parse(value);
  assert.equal(checked.privilege,'shizuku');
  assert.equal(checked.shizuku,'rish_verified');
  assert.equal(checked.fallback,false);
  assert.match(checked.identity,/^uid=\d+/);
  if (emulator) assert.match(checked.identity,/^uid=2000\(shell\)/);
  return checked;
}

async function openProbe() {
  await mustBeUnlocked();
  assert.equal(await shell('am get-current-user'),String(user),'Android user changed during the test');
  await shell('am force-stop --user '+user+' '+pkg);
  assert.match(await shell('am start -W --user '+user+' -n '+pkg+'/.DeviceUseProbe --ez keep_awake true --ez replay true'),/Status: ok/);
  const opened = await call({action:'open',package:pkg,image:false,tree:false});
  assert.ok(opened.session,JSON.stringify(opened));
  return opened.session;
}

async function runInterrupt(key,expected) {
  if (key==='disconnect') assert.equal(await shell('getprop ro.kernel.qemu'),'1');
  if (key==='disconnect') {
    await shell('input keyevent KEYCODE_WAKEUP; wm dismiss-keyguard');
  }
  const session = await openProbe();
  const pid = await shell('pidof -s '+pkg);
  assert.match(pid,/^[1-9]\d*$/);
  const selector = {resource_id:pkg+':id/probe_input'};
  const pending = call({action:'replay',session,output:directory,flow:{version:1,package:pkg,steps:[
    {kind:'tap',selector},
    {kind:'wait_for',selector:{text:'__vanta_wait_for_interrupt__'},timeout_ms:20000},
    {kind:'type',selector,text:'unexpected follow-up'},
  ]}});
  // Attach a catch immediately so early MCP failures cannot become unhandled.
  pending.catch(()=>{});
  try {
    const deadline = performance.now()+12000;
    let firstInput = false;
    while (performance.now()<deadline) {
      const log = await shell('/system/bin/logcat -d -t 150 --pid='+pid+' -s VantaReplayProbe:I');
      if (log.includes('Replay input focused')) {
        firstInput=true;
        break;
      }
      await sleep(350);
    }
    assert.ok(firstInput,'test editor never received the first replay tap');
    await sleep(650);
    if (key==='cancel') {
      const deadline = performance.now()+5000;
      let active;
      do {
        active = await call({action:'status',session});
        if (active.progress?.step===2) break;
        await sleep(120);
      } while (performance.now()<deadline);
      assert.equal(active.active_action,'replay');
      assert.deepEqual(active.progress,{step:2,kind:'wait_for',total:3});
      assert.equal((await call({action:'cancel',session})).cancel_requested,true);
    } else if (key==='disconnect') {
      await adb(['emu','kill'],5000);
      stoppedEmulator=true;
    } else if (key==='shizuku_stop') {
      assert.equal(await shell('getprop ro.kernel.qemu'),'1');
      const daemon = await shell('pidof -s shizuku_server');
      assert.match(daemon,/^[1-9]\d*$/);
      assert.match(await shell('ps -p '+daemon+' -o UID,NAME'),/^UID\s+NAME\s+2000\s+shizuku_server$/);
      await shell('kill -TERM '+daemon);
    } else {
      await shell('input keyevent '+key);
    }
    const result = await pending;
    assert.equal(result.passed,false,JSON.stringify(result));
    assert.match(result.reason,expected);
    assert.equal(result.failed_step,2,JSON.stringify(result));
    assert.equal(result.steps[0].inputs_sent,1);
    assert.equal(result.steps.length,2);
    assert.ok(!result.evidence.screenshot && !result.evidence.tree && !result.evidence.logs);
    if (key==='cancel') {
      const status = await call({action:'status',session});
      assert.equal(status.active_action,null);
      assert.equal(status.last_replay.reason,'cancelled');
      assert.equal(status.frame,null);
      assert.equal((await call({action:'cancel',session})).cancel_requested,false);
    }
    return {reason:result.reason,failed_step:result.failed_step,report:result.report};
  } finally {
    await pending.catch(()=>{});
    await call({action:'close',session});
  }
}

async function verifyApk(file,expectedName) {
  const sdk = await toolchain();
  const {stdout} = await host(sdk.aapt2,['dump','badging',path.resolve(file)]);
  assert.equal(/^package: name='([^']+)'/m.exec(stdout)?.[1],expectedName,'unexpected APK package');
  return stdout;
}

try {
  assert.equal((await shell('getprop ro.kernel.qemu'))==='1',emulator,'ADB target kind differs from the selected mode');
  receipt.android = await shell('getprop ro.build.version.release');
  if (emulator) await shell('input keyevent KEYCODE_WAKEUP; wm dismiss-keyguard');
  await mustBeUnlocked();
  user=Number(await shell('am get-current-user'));
  assert.ok(Number.isInteger(user) && user>=0 && user<=21474);
  const imeSetting = 'settings --user '+user+' get secure default_input_method';
  oldIme=await shell(imeSetting);
  if (!emulator && !selectedVantaInput(oldIme)) throw new Error('vanta_input_not_selected');
  await client.connect(new StdioClientTransport({command:process.execPath,args:[path.join(here,'server.js')],env:{...process.env}}));
  receipt.host_version=client.getServerVersion().version;
  if (shizuku) receipt.connection=await checkShizuku();
  assert.equal(await shell('dumpsys package '+pkg+' | grep -F '+shQuote('Package ['+pkg+']')+' || true'),'','test package already exists');
  const probeBadging = await verifyApk(probe,pkg);
  const native = /^native-code:\s*(.*)$/m.exec(probeBadging)?.[1] ?? '';
  const abis = (await shell('getprop ro.product.cpu.abilist')).split(',');
  assert.ok(abis.some(abi=>abi && native.includes("'"+abi+"'")),'fixture native ABI is incompatible with this device');
  if (emulator) {
    await verifyApk(input,imePkg);
    assert.equal(await shell('pm path '+imePkg+' || true'),'','test input method already exists');
    oldHardKeyboard=await shell('settings get secure show_ime_with_hard_keyboard');
    assert.match(await adb(['install','--no-incremental',path.resolve(input)]),/Success/);
    imeInstalled=true;
    await shell('settings put secure show_ime_with_hard_keyboard 1 && ime enable '+ime+' && ime set '+ime);
    assert.ok(selectedVantaInput(await shell(imeSetting)));
  }
  assert.match(await adb(['install','--no-incremental','--user',String(user),path.resolve(probe)],45000),/Success/);
  installed=true;
  for (let round=1;round<=3;round++) {
    const session=await openProbe();
    try {
      if (round===1) {
        const observed = await request('device_use',{action:'observe',session});
        const state = JSON.parse(observed.content[0].text);
        assert.ok(!observed.isError && state.frame && !state.image_error && !state.tree_error,JSON.stringify(state));
        assert.ok(state.nodes.some(node=>node.resource_id===pkg+':id/probe_input'));
        const image = observed.content.find(item=>item.type==='image');
        assert.equal(image?.mimeType,'image/png');
        assert.equal(Buffer.from(image.data,'base64').subarray(0,8).toString('hex'),'89504e470d0a1a0a');
        receipt.observation={png:true,nodes:state.nodes.length};
        const selected = await call({action:'perform',session,frame:state.frame,image:false,tree:true,
          step:{kind:'tap_selector',selector:{text:'COUNT TAP'}}});
        assert.equal(selected.action_sent,true);
        const afterTap = await call({action:'observe',session,image:false});
        assert.ok(afterTap.nodes.some(node=>node.text==='Tapped 1'));
        const held = await call({action:'perform',session,frame:afterTap.frame,image:false,tree:true,
          step:{kind:'long_press_selector',selector:{text:'Gesture probe'},duration_ms:640}});
        assert.equal(held.gesture.duration_ms,640);
        const afterHold = await call({action:'observe',session,image:false});
        assert.ok(afterHold.nodes.some(node=>/^Gesture probe \d+ ms$/.test(node.text ?? '')));
        receipt.observation.selector_tap=true;
        receipt.observation.selector_long_press=true;
      }
      const outcome=await call({action:'replay',session,flow_file:flowFile,output:directory,timeout_ms:65000});
      receipt.rounds.push({round,passed:outcome.passed,reason:outcome.reason,report:outcome.report,elapsed_ms:outcome.elapsed_ms});
      assert.equal(outcome.passed,true,JSON.stringify(outcome));
      assert.equal(outcome.steps[2].text_method,'ime');
      assert.ok(outcome.steps[4].scrolls>0,'test submit button must require scrolling');
      assert.equal(outcome.steps.length,8);
    } finally {
      await call({action:'close',session});
    }
  }
  if (emulator) receipt.interruptions.cancel=await runInterrupt('cancel',/^cancelled$/);
  if (emulator && shizuku) {
    receipt.interruptions.shizuku_stop=await runInterrupt('shizuku_stop',/^device_observation_failed$/);
    const stopped = await request('connection',{action:'check'});
    assert.equal(stopped.isError,true);
    assert.match(stopped.content[0].text,/service is not running|Binder request timed out/i);
    assert.equal(await shell('id -u'),'2000','ordinary ADB must still be available');
    receipt.shizuku_after_stop=stopped.content[0].text;
    receipt.adb_after_stop=true;
  } else if (emulator) {
    receipt.interruptions.home=await runInterrupt('KEYCODE_HOME',/^target_not_focused$/);
    receipt.interruptions.lock=await runInterrupt('KEYCODE_SLEEP',/^(screen_not_awake|keyguard_active)$/);
    receipt.interruptions.adb_disconnect=await runInterrupt('disconnect',/^device_observation_failed$/);
  }
  receipt.passed=true;
} catch (error) {
  receipt.error=error.message;
} finally {
  try {
    if (stoppedEmulator) {
      // This case intentionally ends the disposable emulator to break the active ADB link.
      receipt.cleanup='disposable_emulator_stopped';
    } else {
      if (installed) {
        assert.equal(await adb(['uninstall',pkg]),'Success');
        assert.equal(await shell('pm path '+pkg+' || true'),'');
      }
      if (imeInstalled) {
        if (oldIme && oldIme!=='null') await shell('ime set '+shQuote(oldIme));
        assert.equal(await adb(['uninstall',imePkg]),'Success');
        await shell(oldHardKeyboard==='null' ? 'settings delete secure show_ime_with_hard_keyboard' :
          'settings put secure show_ime_with_hard_keyboard '+shQuote(oldHardKeyboard));
      }
      receipt.cleanup=true;
    }
  } catch (error) {
    receipt.cleanup_error=error.message;
  }
  await client.close();
  receipt.passed &&= Boolean(receipt.cleanup);
  const report = await writeJson(directory,'acceptance.json',receipt);
  console.log(JSON.stringify({report,...receipt},null,2));
  if (!receipt.passed) process.exitCode=1;
}
