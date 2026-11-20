import { createHash, randomUUID } from 'node:crypto';
import fs from 'node:fs/promises';
import path from 'node:path';
import { setTimeout } from 'node:timers/promises';
import { z } from 'zod';
import { connectionOptions, withConnection } from './connection.js';
import { deviceBytes, deviceText, outputDirectory, writeJson } from './inspection-io.js';
import { logcatCommand } from './android-tools.js';
import { shQuote } from './adb.js';
import { imeReceipt, keyboardStep, ordinaryKeys, selectedVantaInput, textInputPlan, textMethod } from './device-input.js';
import { devicePackage, deviceSelector, matchNode, ReplayFailure, replayFlow, replaySchema } from './device-replay.js';

const sessionTTL = 10*60*1000;
const frameTTL = 120*1000;
const pngSignature = Buffer.from([137,80,78,71,13,10,26,10]);
const bindings = ['transport','serial','privilege'];
const stateCommand = [
  'printf "@boot\\n"; cat /proc/sys/kernel/random/boot_id',
  'printf "@power\\n"; dumpsys power',
  'printf "@policy\\n"; dumpsys window policy',
  'printf "@display\\n"; dumpsys window displays',
  'printf "@windows\\n"; dumpsys window windows',
].join('\n');

function splitState(raw) {
  const chunks = raw.split(/^@(boot|power|policy|display|windows)\s*$/m);
  return Object.fromEntries(['boot','power','policy','display','windows'].map(name=>[name,chunks[chunks.indexOf(name)+1] ?? '']));
}

function secureFlag(attributes) {
  if (/^0x[0-9a-f]+\b/i.test(attributes)) return !!(BigInt(attributes.split(/\s/)[0]) & 0x2000n);
  return /\b(?:FLAG_)?SECURE\b/.test(attributes);
}

export function screenState(raw, expectedPackage) {
  const body = splitState(raw);
  const boot = body.boot.trim();
  if (!/^[a-f0-9-]{36}$/.test(boot)) return {blocked:'device_identity_unavailable'};
  if (!/^\s*mWakefulness=Awake\s*$/m.test(body.power)) return {boot,blocked:'screen_not_awake'};
  const guard = body.policy.split(/KeyguardServiceDelegate/)[1] ?? '';
  const showing = /^\s*showing=(true|false)\s*$/m.exec(guard)?.[1];
  if (showing !== 'false' || /^\s*(?:inputRestricted|mInputRestricted|mIsShowing)=true\s*$/m.test(guard)) {
    return {boot,blocked:showing ? 'keyguard_active' : 'keyguard_state_unavailable'};
  }
  const focus = /^\s*mCurrentFocus=Window\{([a-f0-9]+) u(\d+) ([^}\r\n]+)\}/m.exec(body.display);
  const component = focus?.[3];
  if (!component?.startsWith(expectedPackage+'/')) return {boot,blocked:'target_not_focused'};
  const split = body.windows.split(/(?=^\s*Window #\d+ Window\{)/m);
  const block = split.find(entry=>new RegExp(`^\\s*Window #\\d+ Window\\{${focus[1]} u${focus[2]} `,'m').test(entry));
  if (!block || !/\bmDisplayId=0\b/.test(block)) return {boot,blocked:'focused_display_unavailable'};
  const flags = /(?:^|[\s{])fl=([^\r\n}]*)/m.exec(block)?.[1];
  if (flags === undefined) return {boot,blocked:'window_flags_unavailable'};
  if (secureFlag(flags)) return {boot,blocked:'secure_window'};
  for (const other of split) {
    if (other === block || !other.includes(`package=${expectedPackage} `) || !/\bmHasSurface=true\b/.test(other)) continue;
    const visibleFlags = /(?:^|[\s{])fl=([^\r\n}]*)/m.exec(other)?.[1];
    if (visibleFlags && secureFlag(visibleFlags)) return {boot,blocked:'secure_window'};
  }
  if (/mWindowingMode=(?:multi-window|freeform|pinned)/.test(block)) return {boot,blocked:'unsupported_window_mode'};
  const display = body.display.split(/(?=^\s*Display: mDisplayId=)/m).find(text=>/^\s*Display: mDisplayId=0\b/m.test(text));
  const dims = /\bcur=(\d+)x(\d+)\b/.exec(display ?? '');
  const rotation = /\bmCurrentRotation=ROTATION_(0|90|180|270)\b/.exec(display ?? '')?.[1];
  if (!dims || rotation === undefined) return {boot,blocked:'display_geometry_unavailable'};
  return {boot,window:focus[1],user:Number(focus[2]),component,width:Number(dims[1]),height:Number(dims[2]),rotation:Number(rotation)};
}

const xmlChars = {'amp':'&','lt':'<','gt':'>','quot':'"','apos':"'"};
const decode = value => (value ?? '').replace(/&(#x[0-9a-f]+|#\d+|amp|lt|gt|quot|apos);/gi, (literal, entity) => {
  if (Object.hasOwn(xmlChars,entity)) return xmlChars[entity];
  const point = /^#x/i.test(entity) ? Number.parseInt(entity.slice(2),16) : Number(entity.slice(1));
  return Number.isInteger(point) && (point===9 || point===10 || point===13 || point>=32) && point<=0x10ffff
    ? String.fromCodePoint(point) : literal;
});

export function uiNodes(xml, pkg, width, height) {
  if (!/<hierarchy[\s>]/.test(xml) || !/<\/hierarchy>/.test(xml) || /<!DOCTYPE|<!ENTITY/i.test(xml)) throw new Error('invalid UI hierarchy');
  const nodes = [];
  for (const token of xml.matchAll(/<node\b(?:"[^"]*"|'[^']*'|[^'">])*>/g)) {
    const fields = Object.fromEntries([...token[0].matchAll(/([\w-]+)=(?:"([^"]*)"|'([^']*)')/g)]
      .map(([,key,doubleQuoted,singleQuoted])=>[key,decode(doubleQuoted ?? singleQuoted)]));
    if (fields.package !== pkg) continue;
    const match = /^\[(-?\d+),(-?\d+)\]\[(-?\d+),(-?\d+)\]$/.exec(fields.bounds ?? '');
    if (!match) continue;
    const bounds = match.slice(1).map(Number);
    if (bounds[0]<0 || bounds[1]<0 || bounds[2]>width || bounds[3]>height || bounds[2]<=bounds[0] || bounds[3]<=bounds[1]) continue;
    const password = fields.password === 'true';
    nodes.push({id:nodes.length+1,bounds,password,
      class:fields.class ?? '',resource_id:fields['resource-id'] || undefined,
      text:password ? undefined : fields.text?.slice(0,180),description:password ? undefined : fields['content-desc']?.slice(0,180),
      clickable:fields.clickable==='true',enabled:fields.enabled==='true',focused:fields.focused==='true',
      editable:fields.editable==='true' || /(?:^|\.)EditText$/.test(fields.class ?? ''),
      scrollable:fields.scrollable==='true'});
    if (nodes.length>=180) break;
  }
  return nodes;
}

async function screenImage(state,timeoutMs=12000) {
  const data = await deviceBytes('/system/bin/screencap -p',{maxBytes:8*1024*1024,timeoutMs});
  if (data.length<33 || !data.subarray(0,8).equals(pngSignature) ||
      data.subarray(12,16).toString()!=='IHDR' || data.readUInt32BE(16)!==state.width || data.readUInt32BE(20)!==state.height) {
    throw new Error('screenshot dimensions differ from the input display');
  }
  return data;
}

async function treeNodes(state,pkg,timeoutMs=15000) {
  const xml = await deviceText(`umask 077
dir=$(mktemp -d /data/local/tmp/vanta-ui-XXXXXXXX) || exit 1
trap 'rm -f -- "$dir/window.xml"; rmdir -- "$dir"' EXIT
uiautomator dump --compressed "$dir/window.xml" >/dev/null && cat "$dir/window.xml"`,{maxBytes:768*1024,timeoutMs});
  return uiNodes(xml,pkg,state.width,state.height);
}

const hash = data => createHash('sha256').update(data).digest('hex');
const same = (before,after) => !after.blocked && JSON.stringify(before)===JSON.stringify(after);
const attrs = node => JSON.stringify({...node,id:0});
const center = ([x1,y1,x2,y2]) => [Math.floor((x1+x2)/2),Math.floor((y1+y2)/2)];
const tap = (x,y) => `/system/bin/cmd input touchscreen -d 0 tap ${x} ${y}`;
const keyboard = '/system/bin/cmd input keyboard -d 0';
const modifierKeys = {CTRL:'CTRL_LEFT',SHIFT:'SHIFT_LEFT',ALT:'ALT_LEFT',META:'META_LEFT'};

function coordinates(state,x,y) {
  if (x<0 || y<0 || x>=state.width || y>=state.height) throw new Error('coordinate is outside the observed display');
}

export function gestureTiming(action) {
  const controls = [action.ms,action.duration_ms,action.speed_px_s].filter(value=>value!==undefined);
  if (controls.length>1) throw new Error('choose only one of ms, duration_ms or speed_px_s');
  const distance = action.kind==='long_press' ? 0 : Math.hypot(action.x2-action.x1,action.y2-action.y1);
  if (!distance && action.speed_px_s!==undefined) throw new Error('speed requires distinct swipe or drag endpoints');
  const duration = action.speed_px_s===undefined
    ? action.duration_ms ?? action.ms ?? (action.kind==='long_press' ? 650 : 500)
    : Math.round(distance*1000/action.speed_px_s);
  if (!Number.isInteger(duration) || duration<100 || duration>2000) {
    throw new Error('gesture duration must be 100–2000 ms; adjust speed or use duration_ms');
  }
  return {duration_ms:duration,...(action.kind==='long_press' ? {} : {speed_px_s:Math.round(distance*1000/duration)})};
}

export function keyboardCommand(action) {
  if (!ordinaryKeys.includes(action.key)) throw new Error('unsupported keyboard key');
  const modifiers = action.modifiers ?? [];
  if (new Set(modifiers).size!==modifiers.length || modifiers.some(key=>!Object.hasOwn(modifierKeys,key))) {
    throw new Error('invalid or duplicate keyboard modifier');
  }
  const key = 'KEYCODE_'+action.key;
  if (modifiers.length) {
    const duration = action.hold_ms===undefined ? '' : ` -t ${action.hold_ms}`;
    return `${keyboard} keycombination${duration} ${modifiers.map(value=>'KEYCODE_'+modifierKeys[value]).join(' ')} ${key}`;
  }
  const duration = action.hold_ms===undefined ? '' : ` --duration ${action.hold_ms}`;
  return `${keyboard} keyevent${duration} ${key}`;
}

function inputCommand(action,state,node,pkg) {
  if (action.kind==='tap_node' || action.kind==='tap_selector') return {command:tap(...center(node.bounds))};
  if (action.kind==='long_press_node' || action.kind==='long_press_selector') {
    const [x,y] = center(node.bounds);
    action = {...action,kind:'long_press',x,y};
  }
  if (['tap','double_tap','long_press'].includes(action.kind)) {
    coordinates(state,action.x,action.y);
    if (action.kind==='tap') return {command:tap(action.x,action.y)};
    if (action.kind==='double_tap') return {command:`${tap(action.x,action.y)} && ${tap(action.x,action.y)}`};
    const gesture = gestureTiming(action);
    return {command:`/system/bin/cmd input touchscreen -d 0 swipe ${action.x} ${action.y} ${action.x} ${action.y} ${gesture.duration_ms}`,gesture};
  }
  if (['drag','swipe'].includes(action.kind)) {
    coordinates(state,action.x1,action.y1);
    coordinates(state,action.x2,action.y2);
    const gesture = gestureTiming(action);
    const op = action.kind==='drag' ? 'draganddrop' : 'swipe';
    return {command:`/system/bin/cmd input touchscreen -d 0 ${op} ${action.x1} ${action.y1} ${action.x2} ${action.y2} ${gesture.duration_ms}`,gesture};
  }
  if (action.kind==='key') return {command:keyboardCommand(action)};
  if (action.kind==='type') return textInputPlan(action,state,pkg);
  throw new Error('unsupported Android input');
}

function response(value,image) {
  const content = [{type:'text',text:JSON.stringify(value)}];
  if (image) content.push({type:'image',mimeType:'image/png',data:image.toString('base64')});
  return {content};
}

async function sendInput(action,state,node,pkg,budget=limit=>limit) {
  const {command,gesture,textMethod,checkCommand}=inputCommand(action,state,node,pkg);
  if (checkCommand && !selectedVantaInput(await deviceText(checkCommand,{maxBytes:4096,timeoutMs:budget(5000)}))) {
    return {blocked:'vanta_input_not_selected',action_sent:false,
      error:'Select Vanta Device Input on Android, then focus the text field and observe again.'};
  }
  const timeoutMs = budget(5000);
  let output;
  try {
    output=await deviceText(command,{maxBytes:16384,timeoutMs});
  } catch (error) {
    return {action_outcome:'unknown',error:error.message};
  }
  if (textMethod==='ime') {
    const receipt=imeReceipt(output);
    if (!receipt) return {action_outcome:'unknown',error:'Vanta Device Input did not acknowledge the request'};
    if (!receipt.accepted) return {blocked:receipt.blocked,action_sent:false};
  }
  return {action_sent:true,kind:action.kind,gesture,text_method:textMethod};
}

async function loadFlow(args) {
  if (Boolean(args.flow)===Boolean(args.flow_file)) throw new Error('provide exactly one of flow or flow_file');
  if (args.flow) return args.flow;
  const limit = 128*1024;
  const file = await fs.stat(args.flow_file);
  if (!file.isFile() || file.size>limit) throw new Error('flow_file must be a regular JSON file up to 128 KiB');
  const handle = await fs.open(args.flow_file,'r');
  try {
    const info = await handle.stat();
    if (!info.isFile() || info.size>limit) throw new Error('flow_file must be a regular JSON file up to 128 KiB');
    const buffer = Buffer.alloc(limit+1);
    const {bytesRead} = await handle.read(buffer,0,buffer.length,0);
    if (bytesRead!==info.size) throw new Error('flow_file changed while being read');
    let parsed;
    try {
      parsed=JSON.parse(new TextDecoder('utf-8',{fatal:true}).decode(buffer.subarray(0,bytesRead)));
    } catch {
      throw new Error('flow_file must contain valid UTF-8 JSON');
    }
    return replaySchema.parse(parsed);
  } finally {
    await handle.close();
  }
}

async function targetPid(pkg,user) {
  const output = await deviceText('/system/bin/ps -A -o UID,PID,NAME',{maxBytes:256*1024,timeoutMs:3000});
  const rows = output.split('\n').map(line=>line.trim().split(/\s+/)).filter(([uid,pid,name])=>
    /^\d+$/.test(uid) && /^[1-9]\d*$/.test(pid) && Math.floor(Number(uid)/100000)===user && name===pkg);
  return rows.length===1 ? rows[0][1] : null;
}

async function replayEvidence(session,readState,directory,signal) {
  const evidence = {};
  if (signal?.aborted) return evidence;
  try {
    const state = await readState(4000);
    if (state.blocked || signal?.aborted) return evidence;
    const [tree,image] = await Promise.allSettled([
      treeNodes(state,session.pkg,6000),screenImage(state,6000),
    ]);
    if (signal?.aborted || !same(state,await readState(4000))) return evidence;
    if (tree.status==='fulfilled') {
      evidence.tree=await writeJson(directory,'ui.json',{package:session.pkg,display:{width:state.width,height:state.height},nodes:tree.value});
    }
    if (image.status==='fulfilled') {
      const file = path.join(directory,'screen.png');
      await fs.writeFile(file,image.value,{flag:'wx',mode:0o600});
      evidence.screenshot=file;
    }
    if (signal?.aborted) return evidence;
    const pid = await targetPid(session.pkg,state.user);
    if (!pid) return {...evidence,logs_status:'main_process_unavailable'};
    const log = await deviceText(logcatCommand({pid,lines:200,buffer:'main'}),{maxBytes:64*1024,timeoutMs:5000});
    if (!signal?.aborted && pid===await targetPid(session.pkg,state.user) && same(state,await readState(4000))) {
      const file = path.join(directory,'logcat.txt');
      await fs.writeFile(file,log,{flag:'wx',mode:0o600});
      evidence.logs=file;
    }
  } catch {
    evidence.collection_incomplete=true;
  }
  return evidence;
}

export function registerDeviceUse(register) {
  const sessions = new Map(), busy = new Map();
  const pos = z.number().int().min(0).max(8192);
  const point = {x:pos,y:pos};
  const ends = {x1:pos,y1:pos,x2:pos,y2:pos};
  const ms = z.number().int().min(100).max(2000).optional();
  const step = z.discriminatedUnion('kind',[
    z.object({kind:z.enum(['tap','double_tap']),...point}),
    z.object({kind:z.literal('tap_node'),node:z.number().int().min(1).max(180)}),
    z.object({kind:z.literal('tap_selector'),selector:deviceSelector}),
    z.object({kind:z.literal('long_press_selector'),selector:deviceSelector,duration_ms:ms}),
    z.object({kind:z.literal('long_press'),...point,ms,duration_ms:ms}),
    z.object({kind:z.enum(['swipe','drag']),...ends,ms,duration_ms:ms,speed_px_s:z.number().int().min(1).max(120000).optional()}),
    keyboardStep,
    z.object({kind:z.literal('type'),text:z.string().min(1).max(512),
      method:textMethod}),
  ]);

  function lookup(id,args) {
    const session = sessions.get(id);
    if (!session) throw new Error('Device Use session missing or expired');
    for (const name of bindings) {
      if (args[name]!==undefined && args[name]!==session.connection[name]) throw new Error('Device Use session is bound to its original device and privilege');
    }
    return session;
  }

  function readState(session,timeoutMs=10000) {
    return deviceText(stateCommand,{maxBytes:2*1024*1024,timeoutMs}).then(raw=>screenState(raw,session.pkg));
  }

  async function observe(session,args,begin) {
    session.frame = undefined;
    if (begin.blocked) return response({session:session.id,blocked:begin.blocked});
    // UI Automator waits for the layout to settle. Take the screenshot after it,
    // so coordinates are not based on an earlier frame of a window transition.
    const [nodes] = await Promise.allSettled([args.tree===false ? [] : treeNodes(begin,session.pkg)]);
    const [image] = await Promise.allSettled([args.image===false ? null : screenImage(begin)]);
    if (!same(begin,await readState(session))) return response({session:session.id,blocked:'screen_changed_during_observation'});
    const png = image.status==='fulfilled' ? image.value : null;
    const tree = nodes.status==='fulfilled' ? nodes.value : [];
    const frame = {id:randomUUID(),state:begin,expires:Date.now()+frameTTL,nodes:tree,digest:png ? hash(png) : null};
    if (png || tree.length) session.frame = frame;
    return response({session:session.id,frame:session.frame?.id,package:session.pkg,
      display:{width:begin.width,height:begin.height,rotation:begin.rotation},nodes:tree,
      tree_error:nodes.status==='rejected' ? nodes.reason.message.slice(0,180) : undefined,
      image_error:image.status==='rejected' ? image.reason.message.slice(0,180) : undefined},png);
  }

  register('device_use','观察和操作目标 Android 前台应用，回放 JSON 流程并查询或停止回放。',{
    action:z.enum(['open','observe','perform','replay','status','cancel','close']),
    package:devicePackage.optional(),
    session:z.uuid().optional(),frame:z.uuid().optional(),step:step.optional(),
    image:z.boolean().optional(),tree:z.boolean().optional(),
    flow:replaySchema.optional(),flow_file:z.string().min(1).max(1024).optional(),
    output:z.string().min(1).max(1024).optional(),
    timeout_ms:z.number().int().min(1000).max(120000).optional(),
  }, async (args, signal) => {
    for (const [id,session] of sessions) if (session.expires<=Date.now() && !busy.has(session.device)) sessions.delete(id);
    if (['status','cancel','close'].includes(args.action)) {
      const session=lookup(args.session,args);
      const operation = busy.get(session.device);
      if (args.action==='status') return response({session:session.id,package:session.pkg,connection:session.connection,
        active_action:operation?.action ?? null,progress:operation?.progress ?? null,cancel_requested:operation?.controller?.signal.aborted ?? false,
        frame:session.frame?.expires>Date.now() ? session.frame.id : null,last_replay:session.lastReplay ?? null});
      if (args.action==='cancel') {
        operation?.controller?.abort();
        return response({session:session.id,cancel_requested:Boolean(operation?.controller)});
      }
      if (operation) throw new Error('Device Use action is in progress');
      sessions.delete(session.id);
      return response({closed:session.id});
    }
    let session;
    if (args.action==='open') {
      if (!args.package) throw new Error('package is required to open Device Use');
      const connection = {...connectionOptions()};
      if (connection.privilege==='root') throw new Error('Device Use requires shell or authorized Shizuku');
      if (connection.transport==='adb' && !connection.serial) throw new Error('an explicit or configured ADB serial is required');
      const device = connection.transport+':'+(connection.serial ?? 'paired');
      if (sessions.size>=8 || [...sessions.values()].some(value=>value.device===device)) throw new Error('close the existing Device Use session for this target');
      session = {id:randomUUID(),connection,device,pkg:args.package,expires:Date.now()+sessionTTL};
    } else {
      session=lookup(args.session,args);
    }
    if (busy.has(session.device)) throw new Error('Device Use action is in progress');
    const controller = args.action==='replay' ? new AbortController() : null;
    const abort = () => controller.abort();
    if (controller) {
      if (signal?.aborted) abort();
      else signal?.addEventListener('abort',abort,{once:true});
    }
    const operation = {action:args.action,controller};
    busy.set(session.device,operation);
    try {
      return await withConnection(session.connection,async () => {
        if (args.action==='replay') {
          const flow = await loadFlow(args);
          if (flow.package!==session.pkg) throw new Error('replay package differs from the Device Use session');
          const directory = await outputDirectory(args.output,'device-replay');
          session.frame=undefined;
          const pinnedState = async timeout => {
            const state = await readState(session,timeout);
            if (!state.boot || (session.boot===state.boot && (state.blocked || session.user===state.user))) return state;
            return {blocked:'device_or_user_changed'};
          };
          const result = await replayFlow(flow,{
            signal:controller.signal,timeoutMs:args.timeout_ms,onProgress:progress=>{operation.progress=progress;},
            snapshot:async (budget,includeTree) => {
              const state = await pinnedState(budget(10000));
              if (state.blocked || !includeTree) return {state,nodes:[]};
              let nodes;
              try {
                nodes = await treeNodes(state,session.pkg,budget(15000));
              } catch (error) {
                // UI Automator can exit first when the screen locks or the app loses focus.
                const current = await pinnedState(budget(4000)).catch(()=>null);
                if (current?.blocked) throw new ReplayFailure(current.blocked);
                throw error;
              }
              const after = await pinnedState(budget(10000));
              if (!same(state,after)) throw new ReplayFailure(after.blocked ?? 'screen_changed_during_observation');
              return {state,nodes};
            },
            send:async (action,state,node,budget) => {
              const current = await pinnedState(budget(10000));
              if (!same(state,current)) return {blocked:current.blocked ?? 'screen_changed'};
              const sent = await sendInput(action,current,node,session.pkg,budget);
              if (sent.action_sent) await setTimeout(200);
              return sent;
            },
          });
          if (!result.passed) result.evidence=await replayEvidence(session,pinnedState,directory,controller.signal);
          const report = await writeJson(directory,'replay.json',result);
          session.lastReplay={passed:result.passed,reason:result.reason,failed_step:result.failed_step,report};
          return response({session:session.id,...result,report});
        }
        const begin = await readState(session);
        if (session.boot && begin.boot!==session.boot) {
          sessions.delete(session.id);
          throw new Error('Device Use target was disconnected or rebooted');
        }
        if (args.action==='open') {
          if (begin.blocked) return response({blocked:begin.blocked});
          if ([...sessions.values()].some(value=>value.boot===begin.boot)) throw new Error('the physical device already has a Device Use session');
          session.boot=begin.boot;
          session.user=begin.user;
          sessions.set(session.id,session);
          try { return await observe(session,args,begin); }
          catch (error) { sessions.delete(session.id); throw error; }
        }
        if (args.action==='observe') return observe(session,args,begin);
        const frame=session.frame;
        if (!frame || args.frame!==frame.id || frame.expires<=Date.now()) throw new Error('stale or missing observation; observe the screen again');
        if (!args.step) throw new Error('step is required');
        const action=args.step;
        session.frame=undefined;
        if (!same(frame.state,begin)) return response({session:session.id,blocked:begin.blocked ?? 'screen_changed',action_sent:false});
        let node;
        if (['tap_node','tap_selector','long_press_selector','type'].includes(action.kind)) {
          const now=await treeNodes(begin,session.pkg);
          if (action.kind==='type') {
            if (!now.some(value=>value.focused && value.editable && value.enabled && !value.password)) {
              throw new Error('text input requires a focused, non-password editable field');
            }
          } else {
            const old=action.selector ? matchNode(frame.nodes,action.selector) : frame.nodes.find(value=>value.id===action.node);
            if (!old?.enabled || old.password || (action.kind!=='long_press_selector' && !old.clickable)) {
              throw new Error('node is not an available control from this observation');
            }
            const candidates=action.selector ? [matchNode(now,action.selector)].filter(Boolean) : now.filter(value=>attrs(value)===attrs(old));
            if (candidates.length!==1 || attrs(candidates[0])!==attrs(old)) throw new Error('UI node changed or is ambiguous; observe again');
            [node]=candidates;
          }
        } else if (action.kind!=='key') {
          if (!frame.digest || hash(await screenImage(begin))!==frame.digest) throw new Error('screenshot changed; observe again before sending coordinates');
        }
        if (!same(begin,await readState(session))) return response({session:session.id,blocked:'screen_changed',action_sent:false});
        const sent = await sendInput(action,begin,node,session.pkg);
        if (!sent.action_sent) return response({session:session.id,...sent});
        await setTimeout(200);
        try {
          const result=await observe(session,args,await readState(session));
          result.content.unshift({type:'text',text:JSON.stringify(sent)});
          return result;
        } catch (error) {
          return response({session:session.id,...sent,observation_error:error.message});
        }
      });
    } finally {
      if (controller) signal?.removeEventListener('abort',abort);
      busy.delete(session.device);
    }
  });
}
