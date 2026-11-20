import { z } from 'zod';
import { shQuote } from './adb.js';

const pkg = 'dev.vanta.deviceinput';
const ime = pkg+'/.VantaKeyboard';
const receiver = pkg+'/.TextReceiver';
const action = pkg+'.COMMIT_TEXT';
const keyboard = '/system/bin/cmd input keyboard -d 0';
export const ordinaryKeys = [
  ...'ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789',
  'BACK','ENTER','TAB','ESCAPE','DEL','FORWARD_DEL','SPACE','DPAD_UP','DPAD_DOWN','DPAD_LEFT','DPAD_RIGHT',
  'DPAD_CENTER','PAGE_UP','PAGE_DOWN','MOVE_HOME','MOVE_END','INSERT','COMMA','PERIOD','MINUS','EQUALS',
  'LEFT_BRACKET','RIGHT_BRACKET','BACKSLASH','SEMICOLON','APOSTROPHE','SLASH','GRAVE',
];
export const keyboardStep = z.object({
  kind:z.literal('key'),key:z.enum(ordinaryKeys),modifiers:z.array(z.enum(['CTRL','SHIFT','ALT','META'])).max(4).optional(),
  hold_ms:z.number().int().min(1).max(2000).optional(),
});
export const textMethod = z.enum(['auto','keyboard','ime']).optional().describe('auto uses a visible Vanta input method for Unicode');
const packageName = /^[A-Za-z_]\w*(?:\.[A-Za-z_]\w*)+$/;
const statuses = new Set(['keyboard_not_visible','device_not_interactive','editor_changed',
  'protected_or_unsupported_editor','editor_disconnected','invalid_text','invalid_arguments']);

export function textInputPlan(step,state,target) {
  const text = step.text;
  if (typeof text!=='string' || !text.length || text.length>512 || /[\u0000-\u0008\u000b-\u001f\u007f-\u009f]/.test(text) ||
      Buffer.from(text,'utf8').toString('utf8')!==text) throw new Error('text contains malformed Unicode or unsupported control characters');
  if (step.method!==undefined && !['auto','keyboard','ime'].includes(step.method)) throw new Error('invalid text input method');
  const keyCharacterMap = /^[\x20-\x7e]+$/.test(text) && !text.includes('%s');
  if (step.method==='keyboard' && !keyCharacterMap) throw new Error('this string requires Vanta Device Input; use method=ime or auto');
  if (step.method!=='ime' && keyCharacterMap) {
    return {command:`${keyboard} text ${shQuote(text.replaceAll(' ','%s'))}`,textMethod:'keyboard'};
  }
  if (!Number.isInteger(state.user) || state.user<0 || state.user>21474 || !packageName.test(target)) {
    throw new Error('Unicode input requires a verified Android user and package');
  }
  const encoded = Buffer.from(text,'utf8').toString('base64url');
  return {
    textMethod:'ime',
    checkCommand:`/system/bin/settings --user ${state.user} get secure default_input_method`,
    command:`/system/bin/am broadcast --user ${state.user} --receiver-foreground -n ${receiver} -a ${action} --es target_package ${shQuote(target)} --es text_b64 ${shQuote(encoded)}`,
  };
}

export function selectedVantaInput(output) {
  const id = output.trim();
  return id===ime || id===pkg+'/'+pkg+'.VantaKeyboard';
}

export function imeReceipt(output) {
  const reply = /^Broadcast completed: result=(-?\d+), data="([a-z_]+)"\s*$/m.exec(output);
  if (!reply) return null;
  if (reply[1]==='1' && reply[2]==='accepted') return {accepted:true};
  if (reply[1]==='0' && statuses.has(reply[2])) return {accepted:false,blocked:reply[2]};
  return null;
}
