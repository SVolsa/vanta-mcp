import fs from 'node:fs/promises';
import { existsSync } from 'node:fs';
import { homedir } from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { createHash } from 'node:crypto';
import { createReadStream } from 'node:fs';
import { runDeviceBuffer, ensureDevice, shellArgs } from './transport.js';

const execute = promisify(execFile);
export const here = path.dirname(fileURLToPath(import.meta.url));
const root = path.dirname(here);
const win = process.platform === 'win32';
const exe = name => win ? name + '.exe' : name;

export function validationAdb() {
  const bundled = path.join(root,'.tools','platform-tools',exe('adb'));
  return existsSync(bundled) ? bundled : 'adb';
}

async function newest(directory) {
  const entries = await fs.readdir(directory, {withFileTypes:true}).catch(error => {
    if (error.code === 'ENOENT') return [];
    throw error;
  });
  return entries.filter(entry => entry.isDirectory() && /^\d+(?:\.\d+)*$/.test(entry.name))
    .map(entry => entry.name).sort((a,b) => b.localeCompare(a,'en',{numeric:true}))[0];
}

export async function toolchain() {
  const sdk = process.env.ANDROID_HOME || process.env.ANDROID_SDK_ROOT ||
    (process.env.LOCALAPPDATA ? path.join(process.env.LOCALAPPDATA, 'Android', 'Sdk') : '');
  const buildRoot = sdk && path.join(sdk, 'build-tools');
  const buildVersion = buildRoot && await newest(buildRoot);
  const build = process.env.VANTA_BUILD_TOOLS || (buildVersion && path.join(buildRoot, buildVersion));
  const ndkRoot = sdk && path.join(sdk, 'ndk');
  const ndkVersion = ndkRoot && await newest(ndkRoot);
  const ndk = process.env.ANDROID_NDK_HOME || (ndkVersion && path.join(ndkRoot, ndkVersion)) ||
    path.join(root, '.tools', 'android-ndk-r26b');
  const llvm = path.join(ndk, 'toolchains', 'llvm', 'prebuilt', (win ? 'windows' : process.platform === 'darwin' ? 'darwin' : 'linux') + '-x86_64', 'bin');
  const bundledJava = path.join(root, '.tools', 'jdk17', 'jdk-17.0.20.1+1', 'bin', exe('java'));
  return {
    aapt2: process.env.VANTA_AAPT2 || (build && path.join(build, exe('aapt2'))) || exe('aapt2'),
    apksignerJar: process.env.VANTA_APKSIGNER_JAR || (build && path.join(build, 'lib', 'apksigner.jar')),
    java: process.env.JAVA_HOME ? path.join(process.env.JAVA_HOME, 'bin', exe('java')) :
      existsSync(bundledJava) ? bundledJava : exe('java'),
    python: process.env.VANTA_PYTHON || (win ? 'python.exe' : 'python3'),
    readelf: process.env.VANTA_READELF || (existsSync(path.join(llvm, exe('llvm-readelf'))) ? path.join(llvm,exe('llvm-readelf')) : exe('llvm-readelf')),
    symbolizer: process.env.VANTA_SYMBOLIZER || (existsSync(path.join(llvm, exe('llvm-symbolizer'))) ? path.join(llvm,exe('llvm-symbolizer')) : exe('llvm-symbolizer')),
    objdump: process.env.VANTA_OBJDUMP || (existsSync(path.join(llvm, exe('llvm-objdump'))) ? path.join(llvm,exe('llvm-objdump')) : exe('llvm-objdump')),
  };
}

export async function host(binary, argv, {maxBuffer = 4*1024*1024, timeout = 45000, allowFailure = false} = {}) {
  if (!binary) throw new Error('required host tool is not configured');
  try {
    const result = await execute(binary, argv, {maxBuffer, timeout, windowsHide:true, encoding:'utf8'});
    return {code:0, ...result};
  } catch (error) {
    if (allowFailure && Number.isInteger(error.code) && !error.killed) {
      return {code:error.code, stdout:error.stdout, stderr:error.stderr};
    }
    const location = path.basename(binary);
    if (error.code === 'ENOENT') throw new Error(`host tool not found: ${location}`);
    if (error.killed || error.code === 'ERR_CHILD_PROCESS_STDIO_MAXBUFFER') throw new Error(`host tool exceeded time or output budget: ${location}`);
    throw new Error(`${location}: ${(error.stderr || error.message).trim().slice(0,1800)}`);
  }
}

export async function deviceBytes(command, {maxBytes = 256*1024, timeoutMs = 12000, privilege} = {}) {
  const result = ensureDevice(await runDeviceBuffer(shellArgs(command, privilege),{maxBytes, timeoutMs}));
  return result.stdout;
}

export async function deviceText(command, options) {
  return (await deviceBytes(command,options)).toString('utf8').replaceAll('\r\n','\n');
}

export async function localFile(file, max, label = 'input') {
  const absolute = path.resolve(file);
  const stat = await fs.stat(absolute);
  if (!stat.isFile() || stat.size > max) throw new Error(`${label} must be a regular file of at most ${max} bytes`);
  return absolute;
}

export async function sha256(file) {
  const hash = createHash('sha256');
  for await (const chunk of createReadStream(file)) hash.update(chunk);
  return hash.digest('hex');
}

export async function outputDirectory(base, prefix) {
  const installed = path.basename(root) === 'node_modules';
  const defaultParent = installed ? path.join(homedir(), '.vanta-mcp', 'inspection') : path.join(here, 'out', 'inspection');
  const parent = path.resolve(base || process.env.VANTA_INSPECTION_DIR || defaultParent);
  await fs.mkdir(parent,{recursive:true,mode:0o700});
  const directory = await fs.mkdtemp(path.join(parent, prefix + '-'));
  await fs.chmod(directory,0o700);
  return directory;
}

export async function writeJson(directory, name, value) {
  const file = path.join(directory,name);
  await fs.writeFile(file, JSON.stringify(value,null,2)+'\n',{flag:'wx',mode:0o600});
  return file;
}

export function elfIdentity(output) {
  const field = name => new RegExp(`^\\s*${name}:\\s*(.+)$`,'m').exec(output)?.[1].trim() ?? null;
  return {
    type:field('Type')?.split(/\s+/)[0] ?? null,
    machine:field('Machine'),
    class:field('Class'),
    data:field('Data'),
    build_id:/Build ID:\s*([a-f0-9]+)\b/i.exec(output)?.[1].toLowerCase() ?? null,
  };
}
