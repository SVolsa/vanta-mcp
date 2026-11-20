// Foreground UI acceptance on a disposable Android emulator.
import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import path from 'node:path';
import { setTimeout } from 'node:timers/promises';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { StdioClientTransport } from '@modelcontextprotocol/sdk/client/stdio.js';
import { ensureAdb,runAdb,shQuote } from './adb.js';
import { here,outputDirectory,validationAdb,writeJson } from './inspection-io.js';

const [serial,apk,imeApk] = process.argv.slice(2);
if (!/^emulator-\d+$/.test(serial ?? '') || !apk) throw new Error('usage: node verify_device_use.mjs <disposable-emulator-serial> <probe-base.apk> [input.apk]');
process.env.ADB_PATH ||= validationAdb();
const directory = await outputDirectory(undefined,'device-use');
const receipt = {serial,passed:false,checks:{},cleanup:false};
const pkg = 'dev.vanta.inspectionprobe';
const imePkg = 'dev.vanta.deviceinput';
const imeComponent = imePkg+'/.VantaKeyboard';
const client = new Client({name:'vanta-device-use-acceptance',version:'1'});
const adb = async argv => ensureAdb(await runAdb(argv,{serial,timeoutMs:30000,maxChars:6000})).stdout.trim();
const shell = command => adb(['shell','-T',command]);
let installed = false, imeInstalled = false, oldIme, settings;

async function call(args, expectedError) {
  const result = await client.callTool({name:'device_use',arguments:{transport:'adb',serial,...args}},undefined,{timeout:70000});
  const values = result.content.filter(item=>item.type==='text').map(item=>item.text);
  if (expectedError) {
    assert.equal(result.isError,true,values.join('\n'));
    assert.match(values.join('\n'),expectedError);
    return {};
  }
  if (result.isError) throw new Error(values.join('\n'));
  return {...Object.assign({},...values.map(text=>JSON.parse(text))),image:result.content.find(item=>item.type==='image')};
}

async function launch(secure = false,replay = false) {
  if (await shell('getprop sys.boot_completed') !== '1') throw new Error('emulator boot is incomplete');
  await shell('input keyevent KEYCODE_WAKEUP; wm dismiss-keyguard');
  const launch = await shell(`am force-stop ${pkg}; am start -W -n ${pkg}/.DeviceUseProbe --ez keep_awake true --ez secure ${secure} --ez replay ${replay}`);
  assert.match(launch,/Status: ok/);
}

try {
  assert.equal(await shell('getprop ro.kernel.qemu'),'1');
  assert.equal(await shell(`pm path ${pkg} || true`),'','test package already installed');
  await client.connect(new StdioClientTransport({command:process.execPath,args:[path.join(here,'server.js')],env:{...process.env}}));
  const metadata = JSON.parse(await fs.readFile(path.join(here,'package.json'),'utf8'));
  assert.equal(client.getServerVersion().version,metadata.version);
  assert.match(await adb(['install','--no-incremental',path.resolve(apk)]),/Success/);
  installed=true;
  settings=[
    ['global','stay_on_while_plugged_in',await shell('settings get global stay_on_while_plugged_in')],
    ['system','screen_off_timeout',await shell('settings get system screen_off_timeout')],
  ];
  await shell('settings put global stay_on_while_plugged_in 0 && settings put system screen_off_timeout 1500');
  await launch();
  await setTimeout(12000);
  assert.match(await shell('dumpsys power | grep -m1 mWakefulness='),/Awake/);
  assert.match(await shell('dumpsys power | grep -m1 mStayOn='),/false/);
  assert.equal(await shell('settings get system screen_off_timeout'),'1500');
  receipt.checks.foreground_kept_screen_on_past_idle_timeout=true;

  const first = await call({action:'open',package:pkg});
  assert.ok(first.session && first.frame,JSON.stringify(first));
  assert.equal(first.image?.mimeType,'image/png',JSON.stringify({...first,image:null}));
  assert.ok(Buffer.from(first.image.data,'base64').subarray(1,4).equals(Buffer.from('PNG')));
  assert.ok(first.nodes.some(node=>node.password && !node.text && !node.description));
  assert.ok(!JSON.stringify(first.nodes).includes('probe-placeholder'));
  const button = first.nodes.find(node=>node.text?.toLowerCase()==='count tap');
  assert.ok(button,JSON.stringify(first.nodes));
  const next = await call({action:'perform',session:first.session,frame:first.frame,step:{kind:'tap_node',node:button.id},image:false});
  assert.equal(next.action_sent,true,JSON.stringify(next));
  assert.ok(next.nodes?.some(node=>node.text==='Tapped 1'),JSON.stringify(next));
  await call({action:'perform',session:first.session,frame:first.frame,step:{kind:'tap_node',node:button.id}},/stale or missing/);
  receipt.checks.inline_png_redaction_click_and_stale_frame=true;
  const edit = next.nodes.find(node=>node.editable && !node.password);
  assert.ok(edit);
  const selected = await call({action:'perform',session:first.session,frame:next.frame,step:{kind:'tap_node',node:edit.id},image:false});
  assert.equal(selected.action_sent,true,JSON.stringify(selected));
  const typed = await call({action:'perform',session:first.session,frame:selected.frame,step:{kind:'type',text:'vanta probe'},image:false});
  assert.equal(typed.action_sent,true,JSON.stringify(typed));
  assert.ok(typed.nodes?.some(node=>node.text==='vanta probe'),JSON.stringify(typed));
  receipt.checks.focused_text_input_and_readback=true;

  const key = (frame,key,modifiers) => call({action:'perform',session:first.session,frame,step:{kind:'key',key,modifiers},image:false});
  const selectAll = await key(typed.frame,'A',['CTRL']);
  assert.equal(selectAll.action_sent,true,JSON.stringify(selectAll));
  const uppercase = await key(selectAll.frame,'K',['SHIFT']);
  assert.ok(uppercase.action_sent && uppercase.nodes?.some(node=>node.text==='K'),JSON.stringify(uppercase));
  const digit = await key(uppercase.frame,'2');
  assert.ok(digit.action_sent && digit.nodes?.some(node=>node.text==='K2'),JSON.stringify(digit));
  receipt.checks.keyboard_and_modifier_shortcuts=true;

  if (imeApk) {
    assert.equal(await shell(`pm path ${imePkg} || true`),'','test input method already installed');
    const unicode='中文：∑≤∞，😀 👩‍💻 e\u0301 %s';
    const missing = await call({action:'perform',session:first.session,frame:digit.frame,image:false,
      step:{kind:'type',text:unicode}});
    assert.equal(missing.blocked,'vanta_input_not_selected');
    oldIme=await shell('settings get secure default_input_method');
    assert.match(oldIme,/\//);
    settings.push(['secure','show_ime_with_hard_keyboard',await shell('settings get secure show_ime_with_hard_keyboard')]);
    assert.match(await adb(['install','--no-incremental',path.resolve(imeApk)]),/Success/);
    imeInstalled=true;
    // Test on the disposable emulator. Real users choose the input method on Android.
    await shell(`settings put secure show_ime_with_hard_keyboard 1 && ime enable ${imeComponent} && ime set ${imeComponent}`);
    await launch();
    const visible = await call({action:'observe',session:first.session,image:false});
    const text = visible.nodes?.find(node=>node.editable && !node.password);
    assert.ok(text,JSON.stringify(visible));
    const editing = await call({action:'perform',session:first.session,frame:visible.frame,image:false,
      step:{kind:'tap_node',node:text.id}});
    assert.ok(editing.frame && editing.action_sent,JSON.stringify(editing));
    const result = await call({action:'perform',session:first.session,frame:editing.frame,image:false,
      step:{kind:'type',text:unicode}});
    assert.equal(result.text_method,'ime',JSON.stringify(result));
    assert.equal(result.action_sent,true);
    async function waitForText(snapshot,expected) {
      for (let attempt=0;attempt<4;attempt++) {
        if (snapshot.nodes?.some(node=>node.editable && node.text===expected)) return snapshot;
        await setTimeout(300);
        snapshot=await call({action:'observe',session:first.session,image:false});
      }
      throw new Error('focused editor did not return expected text: '+JSON.stringify(snapshot));
    }
    const readback=await waitForText(result,unicode);
    const symbols = ' @#$^&*()[]{}<>?"\'\\/|+=_-';
    const appended = await call({action:'perform',session:first.session,frame:readback.frame,image:false,
      step:{kind:'type',text:symbols,method:'ime'}});
    assert.equal(appended.action_sent,true,JSON.stringify(appended));
    await waitForText(appended,unicode+symbols);
    const reject = await shell(`am broadcast --receiver-foreground -n ${imePkg}/.TextReceiver -a ${imePkg}.COMMIT_TEXT --es target_package dev.example.other --es text_b64 eA`);
    assert.match(reject,/result=0, data="editor_changed"/);
    receipt.checks.unicode_and_symbols_exact_readback=true;
    receipt.checks.ime_requires_selection_and_correct_target=true;

    await launch(false,true);
    const flow = JSON.parse(await fs.readFile(path.join(here,'test-app/device-replay-flow.json'),'utf8'));
    const expectedText = flow.steps.at(-1).selector.text;
    const flowFile = await writeJson(directory,'flow.json',flow);
    const replay = await call({action:'replay',session:first.session,flow_file:flowFile,output:directory,timeout_ms:55000});
    assert.equal(replay.passed,true,JSON.stringify(replay));
    assert.ok(replay.steps[4].scrolls>0,JSON.stringify(replay.steps[4]));
    assert.equal(replay.steps[2].text_method,'ime');
    assert.equal(JSON.parse(await fs.readFile(replay.report,'utf8')).passed,true);
    await call({action:'replay',session:first.session,flow:{...flow,package:'dev.example.other'}},/replay package differs/);
    const failedFlow = {...flow,steps:[{kind:'assert',selector:{text:'Unexpected result'}},...flow.steps]};
    const failed = await call({action:'replay',session:first.session,flow:failedFlow,output:directory});
    assert.equal(failed.passed,false);
    assert.equal(failed.failed_step,1);
    assert.equal(failed.reason,'element_missing');
    assert.equal(failed.steps.length,1);
    assert.ok(failed.evidence.screenshot && failed.evidence.tree && failed.evidence.logs,JSON.stringify(failed));
    assert.ok((await fs.readFile(failed.evidence.screenshot)).subarray(1,4).equals(Buffer.from('PNG')));
    assert.ok(JSON.parse(await fs.readFile(failed.evidence.tree,'utf8')).nodes.some(node=>node.text===expectedText));
    assert.match(await fs.readFile(failed.evidence.logs,'utf8'),/Test form submitted/);
    receipt.checks.replay={passed_report:replay.report,failed_report:failed.report,scrolls:replay.steps[4].scrolls};
    await shell('ime set '+shQuote(oldIme));
  }

  await launch();
  async function swipe(speed,expectedMs) {
    for (let attempt=1;attempt<=3;attempt++) {
      const screen = await call({action:'observe',session:first.session});
      const gesture = screen.nodes?.find(node=>node.text?.startsWith('Gesture probe'));
      assert.ok(gesture && screen.frame && screen.image,JSON.stringify({...screen,image:undefined}));
      const [x1,y1,x2,y2] = gesture.bounds;
      assert.ok(y2-y1>440);
      const x = Math.floor((x1+x2)/2), y = y1+20;
      let moved;
      try {
        moved = await call({action:'perform',session:first.session,frame:screen.frame,image:false,
          step:{kind:'swipe',x1:x,y1:y,x2:x,y2:y+400,speed_px_s:speed}});
      } catch (error) {
        // Only retry the stale screenshot guard, which rejects before input.
        if (attempt===3 || !/screenshot changed; observe again before sending/.test(error.message)) throw error;
        continue;
      }
      assert.equal(moved.action_sent,true,JSON.stringify(moved));
      assert.equal(moved.gesture.duration_ms,expectedMs);
      const measurement = moved.nodes?.map(node=>/^Gesture probe (\d+) ms$/.exec(node.text ?? '')).find(Boolean);
      assert.ok(measurement,JSON.stringify(moved));
      return Number(measurement[1]);
    }
  }
  const fast=await swipe(1600,250);
  const slow=await swipe(400,1000);
  assert.ok(fast>=200 && fast<700 && slow>=850 && slow>fast+500,JSON.stringify({fast,slow}));
  receipt.checks.swipe_measured_ms={fast,slow};

  await launch(true);
  const protectedWindow = await call({action:'observe',session:first.session});
  assert.equal(protectedWindow.blocked,'secure_window',JSON.stringify({blocked:protectedWindow.blocked}));
  assert.ok(!protectedWindow.image && !protectedWindow.frame);
  receipt.checks.secure_window_blocked=true;
  await shell('input keyevent KEYCODE_SLEEP');
  await setTimeout(700);
  const asleep = await call({action:'observe',session:first.session});
  assert.equal(asleep.blocked,'screen_not_awake');
  assert.ok(!asleep.image);
  const sleepingReplay = await call({action:'replay',session:first.session,output:directory,
    flow:{version:1,package:pkg,steps:[{kind:'key',key:'A'}]}});
  assert.equal(sleepingReplay.reason,'screen_not_awake',JSON.stringify(sleepingReplay));
  assert.deepEqual(sleepingReplay.evidence,{});
  receipt.checks.replay_stops_on_sleep=true;
  assert.match(await shell('dumpsys power | grep -m1 mWakefulness='),/Asleep/);
  await call({action:'close',session:first.session});
  await call({action:'observe',session:first.session},/missing or expired/);
  receipt.checks.sleep_preserved_and_session_closed=true;
  receipt.passed=true;
} catch (error) {
  receipt.error=error.stack;
} finally {
  try {
    if (imeInstalled) {
      await shell('ime set '+shQuote(oldIme));
      assert.equal(await adb(['uninstall',imePkg]),'Success');
      assert.equal(await shell('settings get secure default_input_method'),oldIme);
    }
    if (installed) assert.equal(await adb(['uninstall',pkg]),'Success');
    if (settings) {
      for (const [realm,key,value] of settings) {
        await shell(value==='null' ? `settings delete ${realm} ${key}` : `settings put ${realm} ${key} ${shQuote(value)}`);
        assert.equal(await shell(`settings get ${realm} ${key}`),value);
      }
    }
    receipt.cleanup=true;
  } catch (error) {
    receipt.cleanup_error=error.message;
  }
  await client.close();
  receipt.passed &&= receipt.cleanup;
  console.log(JSON.stringify({receipt:await writeJson(directory,'acceptance.json',receipt),...receipt},null,2));
  if (!receipt.passed) process.exitCode=1;
}
