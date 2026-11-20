#!/usr/bin/env node
/**
 * [INPUT]: 接收 stdio MCP 请求、连接参数和客户端取消信号。
 * [OUTPUT]: 注册 Vanta 工具并返回文本、结构化内容或工具错误。
 * [POS]: 绑定主机工具和请求连接。仅向支持取消的工具转发信号。
 * [PROTOCOL]: Update this header on change, then check AGENTS.md
 */
import fs from 'node:fs/promises';
import path from 'node:path';
import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import { z } from 'zod';
import { ensureDevice as ensureAdb, runDevice as runAdb, runDeviceBuffer as runAdbBuffer,
  shellArgs, shQuote, transportName } from './transport.js';
import { registerAdvancedTools } from './advanced.js';
import { registerAndroidTools, statusCommand, logcatCommand } from './android-tools.js';
import { withConnection } from './connection.js';
import { runProgram, installApk } from './operations.js';
import { registerInspectionTools } from './inspection-tools.js';
import { registerDeviceUse } from './device-use.js';
import { registerForensicsTools } from './forensics.js';

const {version} = JSON.parse(await fs.readFile(new URL('./package.json',import.meta.url),'utf8'));
const server = new McpServer({ name:'vanta', version });

function text(value) {
  return { content: [{ type: 'text', text: value || '(no output)' }] };
}

function register(name, description, inputSchema, handler) {
  const schema = {
    transport: z.enum(['usb','adb']).optional().describe('显式选择传输；失败不自动切换'),
    serial: z.string().optional().describe('本次调用的 ADB 设备序列号，需 transport=adb'),
    privilege: z.enum(['shell','shizuku','root']).optional().describe('默认 shell；Shizuku 需已配置 rish，root 需明确选择'),
    ...inputSchema,
  };
  server.registerTool(name, { description, inputSchema:schema }, async (args, extra) => {
    try {
      return await withConnection(args, async () => {
        if (args.serial !== undefined && transportName() !== 'adb') throw new Error('serial is only supported with transport=adb');
        if (['kernel','memdump','pcap'].includes(name) && args.privilege && args.privilege !== 'root') throw new Error(`${name} requires privilege=root`);
        const result = await handler(args, extra.signal);
        return typeof result === 'string' ? text(result) : result;
      });
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      return { isError: true, content: [{ type: 'text', text: `error: ${message}` }] };
    }
  });
}

register('status', '读取 Android 型号、版本、ABI、当前 UID 与 SELinux；默认不申请 root/Shizuku 权限。', {}, async () => {
  const result = ensureAdb(await runAdb(shellArgs(statusCommand()), { timeoutMs: 12000, maxChars: 5000 }));
  return `transport=${transportName()}\n${result.stdout.trim()}`;
});

register('shell', '在平板执行 shell，可选 root；适合内核、逆向和测试命令。', {
  command: z.string(),
  root: z.boolean().optional(),
  timeout_ms: z.number().int().min(1000).max(120000).optional(),
  max_chars: z.number().int().min(500).max(20000).optional(),
}, async (args) => {
  const result = await runAdb(shellArgs(args.command, args.root), {
    timeoutMs: args.timeout_ms ?? 20000,
    maxChars: args.max_chars ?? 6000,
  });
  let output = `exit=${result.timedOut ? 'timeout' : result.code}\n${result.stdout}`;
  if (result.tooLarge) output += '\n[device output exceeded the size limit]';
  if (result.stderr.trim()) output += `\nstderr:\n${result.stderr}`;
  return output;
});

register('push', '推送本机文件到平板；USB 模式分块传输并校验 SHA256。', {
  local: z.string(),
  remote: z.string(),
}, async (args) => {
  const local = path.resolve(args.local);
  const stat = await fs.stat(local);
  const result=ensureAdb(await runAdb(['push', local, args.remote], { timeoutMs: 120000, maxChars: 2000 }));
  const size = stat.isFile() ? ` ${stat.size} bytes` : '';
  return `pushed${size}\n${local} -> ${args.remote}${result.transfer ? `\nSHA256 ${result.transfer.sha256}\nchunks=${result.transfer.chunks}` : ''}`;
});

register('pull', '拉取平板文件到本机，默认不覆盖。', {
  remote: z.string(),
  local: z.string(),
  overwrite: z.boolean().optional(),
}, async (args) => {
  const local = path.resolve(args.local);
  if (!args.overwrite) {
    try {
      await fs.access(local);
      throw new Error(`local file exists: ${local}`);
    } catch (error) {
      if (error.code !== 'ENOENT') throw error;
    }
  }
  await fs.mkdir(path.dirname(local), { recursive: true });
  const result=ensureAdb(await runAdb(['pull', args.remote, local], { timeoutMs: 120000, maxChars: 2000, overwrite:args.overwrite===true }));
  const stat = await fs.stat(local);
  const size = stat.isFile() ? ` ${stat.size} bytes` : '';
  return `pulled${size}\n${args.remote} -> ${local}${result.transfer ? `\nSHA256 ${result.transfer.sha256}\nchunks=${result.transfer.chunks}` : ''}`;
});

register('run', '推送本机程序到平板并限时执行，回传输出与退出码。exit=124 表示超时杀。', {
  local: z.string(),
  args: z.string().optional(),
  argv: z.array(z.string()).max(128).optional().describe('逐项转义的程序参数；与旧 args 二选一'),
  root: z.boolean().optional(),
  timeout_ms: z.number().int().min(1000).max(60000).optional(),
  keep: z.boolean().optional(),
  max_chars: z.number().int().min(500).max(20000).optional(),
  forensics: z.boolean().optional().describe('记录子进程 PID、启动 tick、主机耗时和退出收据。歧义退出保留原始 shell 状态。参数使用 argv。'),
}, args=>runProgram(args));

register('install_apk', '安装 APK：普通 ADB 默认不提权；USB/Shizuku/root 使用私有临时文件，失败也清理。', {
  local: z.string(),
  replace: z.boolean().optional(),
  root: z.boolean().optional(),
  user: z.number().int().min(0).optional(),
}, args=>installApk(args));

register('logcat', '读取限额 logcat，可按标签过滤。', {
  lines: z.number().int().min(1).max(1000).optional(),
  tag: z.string().optional(),
  pid: z.number().int().positive().optional(),
  buffer: z.enum(['main','system','crash','events','radio','all']).optional(),
  priority: z.enum(['V','D','I','W','E','F','S']).optional(),
  max_chars: z.number().int().min(500).max(20000).optional(),
}, async (args) => {
  const result = ensureAdb(await runAdb(shellArgs(logcatCommand(args)), { timeoutMs: 15000, maxChars: args.max_chars ?? 6000 }));
  return result.stdout;
});

register('screenshot', '截图保存到本机 PNG，只返回路径与大小。', {
  local: z.string().optional(),
}, async (args) => {
  const stamp = new Date().toISOString().replace(/[:.]/g, '-');
  const local = path.resolve(args.local || path.join(process.cwd(), 'out', `vanta-${stamp}.png`));
  await fs.mkdir(path.dirname(local), { recursive: true });
  const result = ensureAdb(await runAdbBuffer(['exec-out', 'screencap', '-p'], { timeoutMs: 20000 }));
  const png = Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]);
  if (result.stdout.length < 8 || !result.stdout.subarray(0, 8).equals(png)) {
    throw new Error('device did not return a valid PNG screenshot');
  }
  await fs.writeFile(local, result.stdout, { flag: 'wx' });
  return `screenshot ${result.stdout.length} bytes\n${local}`;
});

registerAdvancedTools(register);
registerAndroidTools(register);
registerInspectionTools(register);
registerDeviceUse(register);
registerForensicsTools(register);

await server.connect(new StdioServerTransport());
