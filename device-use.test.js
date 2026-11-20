import test from 'node:test';
import assert from 'node:assert/strict';
import { gestureTiming,keyboardCommand,screenState,uiNodes } from './device-use.js';
import { imeReceipt,selectedVantaInput,textInputPlan } from './device-input.js';

const pkg = 'dev.example';
function state({wake='Awake',guard=false,focus=pkg+'/.Main',flags='KEEP_SCREEN_ON',mode='fullscreen'}={}) {
  return `@boot
12345678-1234-1234-1234-123456789abc
@power
 mWakefulness=${wake}
@policy
 KeyguardServiceDelegate
  showing=${guard}
  inputRestricted=${guard}
@display
 Display: mDisplayId=0 (organized)
    cur=1080x2400
  mCurrentFocus=Window{a001 u0 ${focus}}
    mCurrentRotation=ROTATION_0
@windows
  Window #0 Window{a001 u0 ${focus}}:
    mDisplayId=0
    mAttrs={fl=${flags}}
    mWindowingMode=${mode}`;
}

test('Device Use blocks sleeping, locked, moved and protected foreground windows', () => {
  const good=screenState(state(),pkg);
  assert.equal(good.component,pkg+'/.Main');
  assert.equal(good.width,1080);
  assert.equal(screenState(state({wake:'Asleep'}),pkg).blocked,'screen_not_awake');
  assert.equal(screenState(state({guard:true}),pkg).blocked,'keyguard_active');
  assert.equal(screenState(state({focus:pkg+'2/.Main'}),pkg).blocked,'target_not_focused');
  assert.equal(screenState(state({flags:'0x2000'}),pkg).blocked,'secure_window');
  assert.equal(screenState(state({flags:'HARDWARE_ACCELERATED SECURE'}),pkg).blocked,'secure_window');
  assert.equal(screenState(state({mode:'freeform'}),pkg).blocked,'unsupported_window_mode');
});

test('UI tree filters other packages, out-of-bounds nodes, password values and invalid XML', () => {
  const xml = `<hierarchy>
    <node package="${pkg}" bounds="[1,10][90,20]" class="android.widget.EditText" password="true" text="test-password" content-desc="test-secret" />
    <node package="com.example.other" bounds="[1,10][90,20]" text="other app text" />
    <node package="${pkg}" bounds="[1,10][999,20]" text="oversized node" />
    <node package="${pkg}" bounds="[2,10][90,20]" text="a &amp; b &#x4e2d;" clickable="true" enabled="true" />
  </hierarchy>`;
  const nodes=uiNodes(xml,pkg,100,100);
  assert.equal(nodes.length,2);
  assert.equal(nodes[0].password,true);
  assert.equal(nodes[0].text,undefined);
  assert.equal(nodes[0].description,undefined);
  assert.equal(nodes[1].text,'a & b 中');
  assert.equal(nodes[1].clickable,true);
  assert.throws(()=>uiNodes('<!DOCTYPE hierarchy><hierarchy></hierarchy>',pkg,100,100),/invalid UI/);
});

test('UI tree reads both XML quote styles and preserves escaped symbols', () => {
  const xml = '<hierarchy><node package="dev.example" bounds="[1,10][90,20]" class="android.widget.EditText" '
    + "text='中文 &#128512; &lt;&gt;?\"&apos; &amp; &#10;&#9; %s' focused=\"true\" /></hierarchy>";
  const [node]=uiNodes(xml,pkg,100,100);
  assert.equal(node.text,'中文 😀 <>?"\' & \n\t %s');
  assert.equal(node.focused,true);
  assert.equal(node.editable,true);
});

test('gesture duration is derived from Euclidean distance and speed with legacy ms preserved', () => {
  const swipe = {kind:'swipe',x1:0,y1:0,x2:300,y2:400};
  assert.deepEqual(gestureTiming({...swipe,speed_px_s:1000}),{duration_ms:500,speed_px_s:1000});
  assert.deepEqual(gestureTiming({...swipe,ms:250}),{duration_ms:250,speed_px_s:2000});
  assert.deepEqual(gestureTiming({...swipe,duration_ms:1000}),{duration_ms:1000,speed_px_s:500});
  assert.deepEqual(gestureTiming({kind:'long_press',duration_ms:800}),{duration_ms:800});
  assert.throws(()=>gestureTiming({...swipe,ms:200,speed_px_s:500}),/choose only one/);
  assert.throws(()=>gestureTiming({...swipe,speed_px_s:90000}),/100–2000/);
  assert.throws(()=>gestureTiming({...swipe,x2:0,y2:0,speed_px_s:200}),/distinct/);
});

test('keyboard command keeps modifiers ordered, handles hold time and rejects unknown keys', () => {
  assert.match(keyboardCommand({key:'8'}),/keyevent KEYCODE_8$/);
  assert.match(keyboardCommand({key:'DEL',hold_ms:350}),/keyevent --duration 350 KEYCODE_DEL$/);
  assert.match(keyboardCommand({key:'A',modifiers:['CTRL','SHIFT'],hold_ms:60}),
    /keycombination -t 60 KEYCODE_CTRL_LEFT KEYCODE_SHIFT_LEFT KEYCODE_A$/);
  assert.throws(()=>keyboardCommand({key:'A',modifiers:['CTRL','CTRL']}),/duplicate/);
  assert.throws(()=>keyboardCommand({key:'POWER'}),/unsupported/);
});

test('text input keeps native ASCII and transports Unicode and literal symbols without shell interpretation', () => {
  const state={user:12};
  assert.deepEqual(textInputPlan({text:'hello world'},state,pkg),{
    command:"/system/bin/cmd input keyboard -d 0 text 'hello%sworld'",textMethod:'keyboard',
  });
  const text='中文：∑≤∞，😀 👩‍💻 e\u0301 %s " \' $ &';
  const plan=textInputPlan({text},state,pkg);
  assert.equal(plan.textMethod,'ime');
  assert.match(plan.checkCommand,/--user 12 get secure default_input_method/);
  const encoded=plan.command.match(/--es text_b64 '([\w-]+)'$/)[1];
  assert.equal(Buffer.from(encoded,'base64url').toString('utf8'),text);
  assert.equal(textInputPlan({text:'%s'},state,pkg).textMethod,'ime');
  assert.throws(()=>textInputPlan({text,method:'keyboard'},state,pkg),/requires Vanta Device Input/);
  assert.throws(()=>textInputPlan({text:'bad\uD800'},state,pkg),/malformed Unicode/);
  assert.throws(()=>textInputPlan({text:'bad\u0000'},state,pkg),/malformed Unicode/);
});

test('IME selection and result require the exact component and an explicit editor receipt', () => {
  assert.equal(selectedVantaInput('dev.vanta.deviceinput/.VantaKeyboard\n'),true);
  assert.equal(selectedVantaInput('dev.vanta.deviceinput/.OtherKeyboard'),false);
  assert.deepEqual(imeReceipt('Broadcast completed: result=1, data="accepted"\n'),{accepted:true});
  assert.deepEqual(imeReceipt('Broadcast completed: result=0, data="editor_changed"'),{accepted:false,blocked:'editor_changed'});
  assert.equal(imeReceipt('Broadcast completed: result=0'),null);
});
