import { setTimeout as sleep } from 'node:timers/promises';
import { z } from 'zod';
import { keyboardStep, textMethod } from './device-input.js';

export const devicePackage = z.string().max(255).regex(/^[A-Za-z_]\w*(?:\.[A-Za-z_]\w*)+$/);
export const deviceSelector = z.strictObject({
  resource_id:z.string().min(1).max(300).optional(),
  text:z.string().min(1).max(180).optional(),
  description:z.string().min(1).max(180).optional(),
}).refine(value=>Object.values(value).some(Boolean),'provide resource_id, text or description');
const waitMs = z.number().int().min(500).max(20000).optional();
const selector = deviceSelector;

export const replaySchema = z.strictObject({
  version:z.literal(1),
  package:devicePackage,
  steps:z.array(z.discriminatedUnion('kind',[
    z.strictObject({kind:z.enum(['wait_for','wait_for_absent']),selector,timeout_ms:waitMs}),
    z.strictObject({kind:z.enum(['assert','assert_absent']),selector}),
    z.strictObject({kind:z.literal('tap'),selector}),
    z.strictObject({kind:z.literal('long_press'),selector,duration_ms:z.number().int().min(100).max(2000).optional()}),
    z.strictObject({kind:z.literal('type'),selector,text:z.string().min(1).max(512),method:textMethod}),
    keyboardStep,
    z.strictObject({
      kind:z.literal('scroll_until'),selector,within:selector,
      direction:z.enum(['up','down']).optional(),
      max_scrolls:z.number().int().min(1).max(8).optional(),
      duration_ms:z.number().int().min(100).max(2000).optional(),
    }),
  ])).min(1).max(20),
});

export class ReplayFailure extends Error {}

export function matchNode(nodes,selector) {
  const fields = Object.entries(selector);
  const matching = nodes.filter(node=>fields.every(([key,value])=>node[key]===value));
  if (matching.length>1) throw new ReplayFailure('selector_ambiguous');
  return matching[0];
}

function contained(node,container) {
  const [left,top,right,bottom] = container.bounds;
  const [x1,y1,x2,y2] = node.bounds;
  return x1>=left && y1>=top && x2<=right && y2<=bottom;
}

function scrollGesture(container,step) {
  const [left,top,right,bottom] = container.bounds;
  if (bottom-top<40 || right-left<20) throw new ReplayFailure('scroll_container_too_small');
  const x = Math.floor((left+right)/2);
  const low = Math.round(top+(bottom-top)*0.25);
  const high = Math.round(top+(bottom-top)*0.75);
  const up = step.direction==='up';
  return {kind:'swipe',x1:x,y1:up ? low : high,x2:x,y2:up ? high : low,duration_ms:step.duration_ms ?? 450};
}

export async function replayFlow(flow,{snapshot,send,signal,timeoutMs=45000,onProgress}) {
  const start = performance.now();
  const deadline = start+timeoutMs;
  const report = {version:flow.version,package:flow.package,passed:false,steps:[]};
  const budget = limit => {
    if (signal?.aborted) throw new ReplayFailure('cancelled');
    const remaining = Math.floor(deadline-performance.now());
    if (remaining<1) throw new ReplayFailure('replay_timeout');
    return Math.min(remaining,limit);
  };
  async function sendOnce(input,state,node,entry) {
    budget(1);
    const result = await send(input,state,node,budget);
    if (result.action_sent) {
      entry.inputs_sent = (entry.inputs_sent ?? 0)+1;
      if (result.text_method) entry.text_method=result.text_method;
      return;
    }
    if (result.action_outcome==='unknown') throw new ReplayFailure('input_outcome_unknown');
    throw new ReplayFailure(result.blocked ?? 'input_rejected');
  }

  for (const [index,step] of flow.steps.entries()) {
    onProgress?.({step:index+1,kind:step.kind,total:flow.steps.length});
    const started = performance.now();
    const waitDeadline = started+(step.timeout_ms ?? 5000);
    const waits = step.kind==='wait_for' || step.kind==='wait_for_absent';
    const absence = step.kind==='assert_absent' || step.kind==='wait_for_absent';
    const entry = {step:index+1,kind:step.kind,passed:false};
    const readBudget = limit => {
      const max = budget(limit);
      if (!waits) return max;
      const remaining = Math.floor(waitDeadline-performance.now());
      if (remaining<1) throw new ReplayFailure('element_timeout');
      return Math.min(max,remaining);
    };
    report.steps.push(entry);
    try {
      for (;;) {
        readBudget(1);
        let observed;
        try {
          observed = await snapshot(readBudget,step.kind!=='key');
        } catch (error) {
          if (!(error instanceof ReplayFailure)) readBudget(1);
          throw error;
        }
        readBudget(1);
        const {state,nodes} = observed;
        if (state.blocked) throw new ReplayFailure(state.blocked);
        if (step.kind==='scroll_until') {
          const container = matchNode(nodes,step.within);
          if (!container?.enabled || container.password) throw new ReplayFailure('scroll_container_unavailable');
          if (matchNode(nodes.filter(node=>node!==container && contained(node,container)),step.selector)) break;
          if (!container.scrollable) throw new ReplayFailure('scroll_container_unavailable');
          if ((entry.inputs_sent ?? 0)>=(step.max_scrolls ?? 4)) throw new ReplayFailure('scroll_limit_reached');
          await sendOnce(scrollGesture(container,step),state,undefined,entry);
          entry.scrolls=entry.inputs_sent;
          continue;
        }
        if (absence && !nodes.length) throw new ReplayFailure('ui_tree_empty');
        const node = step.selector ? matchNode(nodes,step.selector) : undefined;
        if (waits) {
          if (Boolean(node)!==absence) break;
          await sleep(readBudget(250),undefined,{signal});
          continue;
        }
        if (absence) {
          if (node) throw new ReplayFailure('unexpected_element_present');
          break;
        }
        if (step.selector && !node) throw new ReplayFailure('element_missing');
        if (step.kind==='tap') {
          if (!node.clickable || !node.enabled || node.password) throw new ReplayFailure('control_not_clickable');
          await sendOnce({kind:'tap_node'},state,node,entry);
        }
        if (step.kind==='type') {
          if (!node.editable || !node.focused || !node.enabled || node.password) throw new ReplayFailure('editor_not_focused_or_supported');
          await sendOnce(step,state,node,entry);
        }
        if (step.kind==='long_press') {
          if (!node.enabled || node.password) throw new ReplayFailure('control_not_pressable');
          await sendOnce({kind:'long_press_node',duration_ms:step.duration_ms},state,node,entry);
        }
        if (step.kind==='key') await sendOnce(step,state,undefined,entry);
        break;
      }
      if (signal?.aborted) throw new ReplayFailure('cancelled');
      entry.passed=true;
    } catch (error) {
      report.reason = error instanceof ReplayFailure ? error.message : signal?.aborted ? 'cancelled' : 'device_observation_failed';
      report.failed_step=entry.step;
      break;
    } finally {
      entry.elapsed_ms=Math.round(performance.now()-started);
    }
  }
  report.passed=report.failed_step===undefined;
  report.elapsed_ms=Math.round(performance.now()-start);
  return report;
}
