import { spawn } from 'node:child_process';
import { StringDecoder } from 'node:string_decoder';

export function clip(text, maxChars = 6000) {
  if (text.length <= maxChars) return text;
  const headLength = Math.ceil(maxChars / 2);
  const tailLength = maxChars - headLength;
  const head = text.slice(0, headLength);
  const tail = tailLength ? text.slice(-tailLength) : '';
  const omitted = text.length - head.length - tail.length;
  return `${head}\n… ${omitted} chars omitted …\n${tail}`;
}

export function deviceArgs(args, serial = process.env.VANTA_SERIAL || process.env.TABLET_SERIAL || process.env.ANDROID_SERIAL) {
  return serial ? ['-s', serial, ...args] : [...args];
}

export function shellArgs(command, root = false) {
  // Avoid interactive PTYs. Binary operations additionally use exec-out framing.
  return root ? ['shell', '-T', `su -c ${shQuote(command)}`] : ['shell', '-T', command];
}

export function shQuote(value) {
  return `'${String(value).replace(/'/g, `'"'"'`)}'`;
}

export function validName(value) {
  return typeof value === 'string' && /^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$/.test(value);
}

function makeCollector(limit) {
  const decoder = new StringDecoder('utf8');
  const side = Math.ceil(limit / 2);
  let head = '';
  let tail = '';
  let total = 0;

  function add(text) {
    if (!text) return;
    total += text.length;
    let rest = text;
    if (head.length < side) {
      const take = side - head.length;
      head += rest.slice(0, take);
      rest = rest.slice(take);
    }
    if (rest) {
      tail += rest;
      if (tail.length > side) tail = tail.slice(-side);
    }
  }

  return {
    write(chunk) {
      add(decoder.write(chunk));
    },
    end() {
      add(decoder.end());
    },
    value() {
      if (total <= limit) return head + tail;
      const omitted = total - head.length - tail.length;
      return `${head}\n… ${omitted} chars omitted …\n${tail}`;
    },
  };
}

function adbPath() {
  return process.env.ADB_PATH || 'adb';
}

export function runAdb(args, { timeoutMs = 20000, maxChars = 12000, serial } = {}) {
  return new Promise((resolve, reject) => {
    const child = spawn(adbPath(), deviceArgs(args, serial), { windowsHide: true, stdio: ['ignore', 'pipe', 'pipe'] });
    const stdout = makeCollector(maxChars);
    const stderr = makeCollector(Math.min(maxChars, 4000));
    let timedOut = false;
    const timer = setTimeout(() => {
      timedOut = true;
      child.kill();
    }, timeoutMs);

    child.stdout.on('data', (chunk) => stdout.write(chunk));
    child.stderr.on('data', (chunk) => stderr.write(chunk));
    child.on('error', (error) => {
      clearTimeout(timer);
      reject(error);
    });
    child.on('close', (code, signal) => {
      clearTimeout(timer);
      stdout.end();
      stderr.end();
      resolve({
        code,
        signal,
        timedOut,
        stdout: stdout.value(),
        stderr: stderr.value(),
      });
    });
  });
}

export function runAdbBuffer(args, { timeoutMs = 20000, maxBytes = 64 * 1024 * 1024, serial } = {}) {
  return new Promise((resolve, reject) => {
    const child = spawn(adbPath(), deviceArgs(args, serial), { windowsHide: true, stdio: ['ignore', 'pipe', 'pipe'] });
    const chunks = [];
    const stderr = makeCollector(4000);
    let size = 0;
    let timedOut = false;
    let tooLarge = false;
    const timer = setTimeout(() => {
      timedOut = true;
      child.kill();
    }, timeoutMs);

    child.stdout.on('data', (chunk) => {
      if (size + chunk.length > maxBytes) {
        tooLarge = true;
        child.kill();
        return;
      }
      size += chunk.length;
      chunks.push(chunk);
    });
    child.stderr.on('data', (chunk) => stderr.write(chunk));
    child.on('error', (error) => {
      clearTimeout(timer);
      reject(error);
    });
    child.on('close', (code, signal) => {
      clearTimeout(timer);
      stderr.end();
      resolve({
        code,
        signal,
        timedOut,
        tooLarge,
        stdout: Buffer.concat(chunks),
        stderr: stderr.value(),
      });
    });
  });
}

export function ensureAdb(result) {
  if (result.timedOut) throw new Error('adb timed out');
  if (result.tooLarge) throw new Error('adb output exceeded the binary size limit');
  if (result.code !== 0) {
    const detail = result.stderr.toString().trim() || result.stdout.toString().trim();
    throw new Error(detail || `adb exited with code ${result.code}`);
  }
  return result;
}
