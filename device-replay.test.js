import assert from 'node:assert/strict';
import test from 'node:test';
import { replayFlow, replaySchema } from './device-replay.js';

const packageName = 'dev.example';
const field = {resource_id:packageName+':id/field',bounds:[0,0,300,100],editable:true,focused:true,enabled:true,clickable:true};
const container = {resource_id:packageName+':id/list',bounds:[0,100,400,800],scrollable:true,enabled:true};
const button = {resource_id:packageName+':id/submit',bounds:[20,200,200,350],enabled:true,clickable:true};
const selector = node => ({resource_id:node.resource_id});
const flow = steps => replaySchema.parse({version:1,package:packageName,steps});

test('UI replay validates selectors and performs a bounded scroll before tapping a newly visible control', async () => {
  assert.throws(()=>flow([{kind:'assert',selector:{}}]));
  assert.throws(()=>flow([{kind:'scroll_until',selector:selector(button),within:selector(container),max_scrolls:0}]));
  const frames = [[field],[field],[container],[container,button],[container,button],[{text:'Saved'}]];
  const commands = [];
  const result = await replayFlow(flow([
    {kind:'wait_for',selector:selector(field)},
    {kind:'type',selector:selector(field),text:'中文 ∑ 😀'},
    {kind:'scroll_until',selector:selector(button),within:selector(container),max_scrolls:2},
    {kind:'tap',selector:selector(button)},
    {kind:'assert',selector:{text:'Saved'}},
  ]),{
    snapshot:async()=>({state:{},nodes:frames.shift()}),
    send:async(input,_state,node)=>{commands.push({input,node});return {action_sent:true};},
  });
  assert.equal(result.passed,true);
  assert.deepEqual(commands.map(({input})=>input.kind),['type','swipe','tap_node']);
  const swipe = commands[1].input;
  assert.ok(swipe.y1>swipe.y2 && swipe.y2>container.bounds[1] && swipe.y1<container.bounds[3]);
  assert.equal(commands[2].node,button);
  assert.equal(result.steps[2].scrolls,1);
  assert.ok(!JSON.stringify(result).includes('中文'));
});

test('UI replay stops before ambiguous or password controls and never retries uncertain input', async () => {
  const action = {kind:'tap',selector:selector(button)};
  let sends = 0;
  const send = async()=>{sends++;return {action_outcome:'unknown'};};
  for (const [nodes,reason] of [
    [[button,button],'selector_ambiguous'],
    [[{...button,password:true}],'control_not_clickable'],
    [[button],'input_outcome_unknown'],
  ]) {
    const result = await replayFlow(flow([action,action]),{snapshot:async()=>({state:{},nodes}),send});
    assert.equal(result.passed,false);
    assert.equal(result.failed_step,1);
    assert.equal(result.reason,reason);
    assert.equal(result.steps.length,1);
  }
  assert.equal(sends,1);
});

test('UI replay distinguishes a blocked foreground from a missing control', async () => {
  const signal = AbortSignal.abort();
  const steps = flow([{kind:'assert',selector:{text:'Saved'}}]);
  const snapshot = async()=>({nodes:[],state:{blocked:'screen_not_awake'}});
  assert.equal((await replayFlow(steps,{snapshot})).reason,'screen_not_awake');
  assert.equal((await replayFlow(steps,{snapshot,signal})).reason,'cancelled');
});

test('UI replay waits within a step budget and stops at the scroll limit', async () => {
  let reads=0, sends=0;
  const ready = await replayFlow(flow([{kind:'wait_for',selector:selector(button),timeout_ms:1500}]),{
    snapshot:async budget=>{
      assert.ok(budget(2000)<=1500);
      return {state:{},nodes:++reads===2 ? [button] : []};
    },
  });
  assert.equal(ready.passed,true);
  assert.equal(reads,2);
  const timedOut = await replayFlow(flow([{kind:'wait_for',selector:selector(button),timeout_ms:500}]),{
    snapshot:async()=>({state:{},nodes:[]}),
  });
  assert.equal(timedOut.reason,'element_timeout');
  const stopped = await replayFlow(flow([{kind:'scroll_until',within:selector(container),selector:selector(button),max_scrolls:2}]),{
    snapshot:async()=>({state:{},nodes:[container,{...button,bounds:[20,20,80,80]}]}),
    send:async()=>{sends++;return {action_sent:true};},
  });
  assert.equal(stopped.reason,'scroll_limit_reached');
  assert.equal(sends,2);
});

test('UI replay reports the current step and stops before a follow-up input when cancelled', async () => {
  const controller = new AbortController(), progress=[];
  const result = await replayFlow(flow([
    {kind:'long_press',selector:selector(button),duration_ms:750},
    {kind:'tap',selector:selector(button)},
  ]),{
    signal:controller.signal,onProgress:value=>progress.push(value),snapshot:async()=>({state:{},nodes:[button]}),
    send:async(input,_state,node)=>{
      assert.deepEqual(input,{kind:'long_press_node',duration_ms:750});
      assert.equal(node,button);
      controller.abort();
      return {action_sent:true};
    },
  });
  assert.deepEqual(progress,[{step:1,kind:'long_press',total:2}]);
  assert.equal(result.reason,'cancelled');
  assert.equal(result.steps.length,1);
  assert.equal(result.steps[0].inputs_sent,1);
});

test('absence checks require a target UI tree and detect an unexpected visible control', async () => {
  const assertAbsent = flow([{kind:'assert_absent',selector:selector(button)}]);
  for (const [nodes,reason] of [[[],'ui_tree_empty'],[[button],'unexpected_element_present'],[[field],undefined]]) {
    assert.equal((await replayFlow(assertAbsent,{snapshot:async()=>({state:{},nodes})})).reason,reason);
  }
  const waitAbsent = flow([{kind:'wait_for_absent',selector:selector(button),timeout_ms:1500}]);
  const frames = [[button,field],[field]];
  assert.equal((await replayFlow(waitAbsent,{snapshot:async()=>({state:{},nodes:frames.shift()})})).passed,true);
});
