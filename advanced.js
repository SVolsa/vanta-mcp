import fs from 'node:fs/promises';
import path from 'node:path';
import crypto from 'node:crypto';
import {jobScript,privateDirectory} from './job-scripts.js';
import { z } from 'zod';
import { ensureDevice as ensureAdb, runDevice as runAdb, runDeviceBuffer as runAdbBuffer,
  shellArgs, shQuote, validName } from './transport.js';

const PCAP_DIR = '/data/local/tmp/vanta-pcap-0';
const linesSchema = z.number().int().min(1).max(1000).optional();
const charsSchema = z.number().int().min(500).max(20000).optional();

function need(value, message) {
  if (value === undefined || value === null || value === '') throw new Error(message);
  return value;
}

function checkedName(value) {
  need(value, 'name is required');
  if (!validName(value)) throw new Error('name must match [A-Za-z0-9._-]+');
  return value;
}

async function remote(command, { root, maxChars = 6000, timeoutMs = 20000 } = {}) {
  const result = await runAdb(shellArgs(command, root), { timeoutMs, maxChars });
  ensureAdb(result);
  return result.stdout.trim();
}

async function jobStart(name, command, root) {
  return remote(jobScript('start',{name,command}), {root});
}
async function jobStop(name, root) {
  return remote(jobScript('stop',{name}), {root});
}
async function jobList(root) {
  return remote(jobScript('list'), {root});
}
async function jobLog(name, root, lines, maxChars) {
  return remote(jobScript('log',{name,lines}), {root,maxChars});
}
async function jobStatus(name, root, lines, maxChars) {
  return remote(jobScript('status',{name,lines}), {root,maxChars});
}

export function registerAdvancedTools(register) {
  register('job', '管理平板常驻任务：start/stop/list/log。', {
    action: z.enum(['start', 'stop', 'list', 'log']),
    name: z.string().optional(),
    command: z.string().optional(),
    root: z.boolean().optional(),
    lines: linesSchema,
    max_chars: charsSchema,
  }, async (args) => {
    if (args.action === 'list') return jobList(args.root);
    const name = checkedName(args.name);
    if (args.action === 'start') {
      return jobStart(name, need(args.command, 'command is required for start'), args.root);
    }
    if (args.action === 'stop') return jobStop(name, args.root);
    return jobLog(name, args.root, args.lines ?? 100, args.max_chars ?? 6000);
  });

  register('proc', '查看进程、内存映射、线程和文件描述符。', {
    action: z.enum(['list', 'maps', 'threads', 'fds']),
    pid: z.number().int().positive().optional(),
    query: z.string().optional(),
    root: z.boolean().optional(),
    lines: linesSchema,
    max_chars: charsSchema,
  }, async (args) => {
    const lines = args.lines ?? 100;
    const maxChars = args.max_chars ?? 6000;
    let command;
    if (args.action === 'list') {
      command = 'ps -A';
    } else {
      const pid = need(args.pid, 'pid is required');
      if (args.action === 'maps') command = `cat /proc/${pid}/maps`;
      if (args.action === 'threads') {
        command = `for t in /proc/${pid}/task/*; do [ -d "$t" ] || continue; printf '%s ' "\${t##*/}"; cat "$t/comm"; done`;
      }
      if (args.action === 'fds') command = `ls -l /proc/${pid}/fd`;
    }
    if (args.query) command += ` | grep -i -e ${shQuote(args.query)}`;
    command += ` | head -n ${lines}`;
    return remote(command, { root: args.root, maxChars });
  });

  register('kernel', '使用 root 查看内核模块和日志，或显式加载、卸载模块。', {
    action: z.enum(['modules', 'dmesg', 'load', 'unload']),
    path: z.string().optional(),
    name: z.string().optional(),
    confirm: z.boolean().optional(),
    lines: linesSchema,
    max_chars: charsSchema,
  }, async (args) => {
    const lines = args.lines ?? 100;
    const maxChars = args.max_chars ?? 6000;
    if (args.action === 'modules') return remote(`cat /proc/modules | head -n ${lines}`, { root: true, maxChars });
    if (args.action === 'dmesg') return remote(`dmesg | tail -n ${lines}`, { root: true, maxChars });
    if (args.confirm !== true) throw new Error('confirm:true is required for load/unload');
    if (args.action === 'load') {
      const modulePath = need(args.path, 'path is required for load');
      await remote(`insmod ${shQuote(modulePath)}`, { root: true, maxChars: 2000 });
      return `loaded ${modulePath}`;
    }
    const moduleName = checkedName(args.name);
    await remote(`rmmod ${shQuote(moduleName)}`, { root: true, maxChars: 2000 });
    return `unloaded ${moduleName}`;
  });

  register('pcap', '限时抓取网络报文；start/stop/status，支持 tcpdump 和 AF_PACKET。', {
    action: z.enum(['start', 'stop', 'status']),
    name: z.string().optional(),
    iface: z.string().optional(),
    filter: z.string().optional(),
    ports: z.string().optional(),
    duration: z.number().int().min(1).max(3600).optional(),
    count: z.number().int().min(1).max(1000000).optional(),
    snaplen: z.number().int().min(64).max(65535).optional(),
    lines: linesSchema,
    max_chars: charsSchema,
  }, async (args) => {
    const capture = checkedName(args.name ?? 'capture');
    const job = `pcap-${capture}`;
    const pcapFile = `${PCAP_DIR}/${capture}.pcap`;
    const afpktFile = `${PCAP_DIR}/${capture}.bin`;
    async function resultPath() {
      return remote(`${privateDirectory('/data/local/tmp/vanta-pcap',false)}; if [ -f ${shQuote(pcapFile)} ]; then echo ${shQuote(pcapFile)}; elif [ -f ${shQuote(afpktFile)} ]; then echo ${shQuote(afpktFile)}; else echo ${shQuote(pcapFile)}; fi`, { root: true, maxChars: 1000 });
    }
    if (args.action === 'stop') return `${await jobStop(job, true)}\nremote=${await resultPath()}`;
    if (args.action === 'status') return `${await jobStatus(job, true, args.lines ?? 20, args.max_chars ?? 4000)}\nremote=${await resultPath()}`;
    const tcpdump = await runAdb(shellArgs('command -v tcpdump', true), { maxChars: 1000 });
    let command;
    let file;
    let format;
    if (tcpdump.code === 0) {
      file = pcapFile;
      format = 'pcap';
      const filter = args.filter ? ` ${shQuote(args.filter)}` : '';
      command = `${privateDirectory('/data/local/tmp/vanta-pcap')}; exec timeout ${args.duration ?? 60} tcpdump -c ${args.count ?? 10000} -i ${shQuote(args.iface ?? 'any')} -s ${args.snaplen ?? 2048} -U -w ${shQuote(file)}${filter}`;
    } else {
      if (args.filter && args.filter.toLowerCase() !== 'udp') throw new Error('custom filter requires tcpdump; AF_PACKET supports ports instead');
      const afpkt = process.env.VANTA_AFPKT_PATH;
      if (!afpkt || !afpkt.startsWith('/') || /[\0\r\n]/.test(afpkt)) throw new Error('tcpdump is unavailable; install tcpdump or explicitly set VANTA_AFPKT_PATH to a compatible AF_PACKET helper');
      file = afpktFile;
      format = 'afpkt-bin';
      const ports = args.ports ? ` --af-ports ${shQuote(args.ports)}` : '';
      command = `${privateDirectory('/data/local/tmp/vanta-pcap')}; exec timeout ${args.duration ?? 60} ${shQuote(afpkt)} --afpkt-dump ${args.count ?? 10000} --af-iface ${shQuote(args.iface ?? 'any')} --af-snaplen ${args.snaplen ?? 2048} --afpkt-out ${shQuote(file)}${ports}`;
    }
    return `${await jobStart(job, command, true)}\nformat=${format}\nremote=${file}`;
  });

  register('memdump', '按地址从进程内存读二进制块到本机（root，用于抓解密后的段/运行时数据）。', {
    pid: z.number().int().positive(),
    addr: z.string(),
    length: z.number().int().min(1).max(8 * 1024 * 1024),
    local: z.string(),
  }, async (args) => {
    const addrText = args.addr.trim().toLowerCase();
    const addr = addrText.startsWith('0x') ? BigInt(addrText) : BigInt(args.addr);
    if (addr <= 0n || addr % 4096n !== 0n) throw new Error('addr must be a positive page-aligned integer or 0x hex');
    const local = path.resolve(args.local);
    await fs.mkdir(path.dirname(local), { recursive: true });
    const remotePath = `/proc/${args.pid}/mem`;
    const blocks = addr / 4096n;
    const cmd = `dd if=${shQuote(remotePath)} bs=4096 skip=${blocks.toString()} 2>/dev/null | head -c ${args.length}`;
    const result = ensureAdb(await runAdbBuffer(shellArgs(cmd,true), { timeoutMs: 60000, maxBytes: args.length + 4096 }));
    if (result.stdout.length !== args.length) throw new Error(`incomplete memory read: expected ${args.length}, got ${result.stdout.length}; no file was saved`);
    await fs.writeFile(local, result.stdout, { flag: 'wx' }).catch(async (error) => {
      if (error.code === 'EEXIST') throw new Error(`local file exists: ${local}`);
      throw error;
    });
    const sha = crypto.createHash('sha256').update(result.stdout).digest('hex');
    return `memdump ${result.stdout.length} bytes sha256:${sha}\n${local}`;
  });

  register('tunnel', '管理 adb forward/reverse 端口连接。', {
    action: z.enum(['list', 'forward', 'reverse', 'remove_forward', 'remove_reverse']),
    local: z.string().optional(),
    remote: z.string().optional(),
  }, async (args) => {
    if (args.action === 'list') {
      const [forward, reverse] = await Promise.all([
        runAdb(['forward', '--list'], { maxChars: 4000 }),
        runAdb(['reverse', '--list'], { maxChars: 4000 }),
      ]);
      ensureAdb(forward);
      ensureAdb(reverse);
      return `forward:\n${forward.stdout.trim()}\nreverse:\n${reverse.stdout.trim()}`;
    }
    if (args.action === 'forward' || args.action === 'reverse') {
      const local = need(args.local, 'local is required');
      const remoteAddress = need(args.remote, 'remote is required');
      const command = args.action === 'forward' ? ['forward', local, remoteAddress] : ['reverse', remoteAddress, local];
      ensureAdb(await runAdb(command, { maxChars: 2000 }));
      return `${args.action} ${local} <-> ${remoteAddress}`;
    }
    if (args.action === 'remove_forward') {
      const local = need(args.local, 'local is required');
      ensureAdb(await runAdb(['forward', '--remove', local], { maxChars: 2000 }));
      return `removed forward ${local}`;
    }
    const remoteAddress = need(args.remote, 'remote is required');
    ensureAdb(await runAdb(['reverse', '--remove', remoteAddress], { maxChars: 2000 }));
    return `removed reverse ${remoteAddress}`;
  });
}
