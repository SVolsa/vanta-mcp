import fs from 'node:fs/promises';
import path from 'node:path';
import {createHash, randomUUID} from 'node:crypto';
import {shQuote} from './adb.js';

export const CHUNK_BYTES=4*1024*1024;
const commandOptions={timeoutMs:120000,maxBytes:CHUNK_BYTES};

function remotePath(value) {
  if(typeof value!=='string'||!value||value.includes('\0'))throw new Error('invalid remote file path');
  return shQuote(value);
}
async function metadata(file,remote) {
  const quoted=remotePath(file);
  const output=(await remote(`test -f ${quoted} && stat -c '%s' -- ${quoted} && sha256sum < ${quoted}`,commandOptions)).toString('utf8');
  const match=/^(\d+)\r?\n([a-fA-F0-9]{64})\s/.exec(output);
  if(!match||!Number.isSafeInteger(Number(match[1])))throw new Error('invalid remote file metadata');
  return {bytes:Number(match[1]),sha256:match[2].toLowerCase()};
}
function sameSource(a,b) {
  return a.size===b.size&&a.mtimeMs===b.mtimeMs&&a.ctimeMs===b.ctimeMs&&a.ino===b.ino&&a.dev===b.dev;
}
function verify(expected,actual) {
  if(expected.bytes!==actual.bytes||expected.sha256!==actual.sha256)throw new Error('file size/SHA256 verification failed');
}

// remote(command, options, stdin) must reject nonzero, truncated, or timed-out commands.
// Appends are deliberately never replayed after an ambiguous connection failure.
export async function uploadFile(local,device,remote) {
  remotePath(device);
  const temporary=`${device}.vanta-upload-${randomUUID()}`;
  const quoted=remotePath(temporary);
  const source=await fs.open(local,'r');
  let committed=false;
  try {
    const before=await source.stat();
    if(!before.isFile()||!Number.isSafeInteger(before.size))throw new Error('upload requires a regular file with a safe integer size');
    await remote(`umask 077; set -C; : > ${quoted}`,commandOptions);
    const hash=createHash('sha256'),buffer=Buffer.allocUnsafe(CHUNK_BYTES);
    let bytes=0,chunks=0;
    while(bytes<before.size) {
      const {bytesRead}=await source.read(buffer,0,Math.min(buffer.length,before.size-bytes),bytes);
      if(!bytesRead)throw new Error('upload source changed during transfer');
      const chunk=buffer.subarray(0,bytesRead);
      hash.update(chunk);
      await remote(`cat >> ${quoted}`,commandOptions,chunk);
      bytes+=bytesRead;chunks++;
    }
    if(!sameSource(before,await source.stat())||!sameSource(before,await fs.stat(local)))throw new Error('upload source changed during transfer');
    const result={bytes,sha256:hash.digest('hex'),chunks};
    verify(result,await metadata(temporary,remote));
    await remote(`test ! -d ${remotePath(device)} && mv -f -- ${quoted} ${remotePath(device)}`,commandOptions);
    committed=true;
    return result;
  } finally {
    await source.close();
    if(!committed)await remote(`rm -f -- ${quoted}`,commandOptions).catch(()=>{});
  }
}

export async function downloadFile(device,local,remote,{overwrite=false,maxFileBytes=Infinity}={}) {
  remotePath(device);
  const before=await metadata(device,remote);
  if (before.bytes > maxFileBytes) throw new Error('remote file exceeds the configured size limit');
  const destination=path.resolve(local),temporary=`${destination}.vanta-pull-${randomUUID()}`;
  await fs.mkdir(path.dirname(destination),{recursive:true});
  let output;
  try {
    output=await fs.open(temporary,'wx',0o600);
    const hash=createHash('sha256');let bytes=0,chunks=0;
    while(bytes<before.bytes) {
      const chunk=await remote(`dd if=${remotePath(device)} bs=${CHUNK_BYTES} skip=${chunks} count=1 2>/dev/null`,commandOptions);
      if(chunk.length!==Math.min(CHUNK_BYTES,before.bytes-bytes))throw new Error('download source changed or returned an incomplete chunk');
      hash.update(chunk);await output.writeFile(chunk);
      bytes+=chunk.length;chunks++;
    }
    const result={bytes,sha256:hash.digest('hex'),chunks};
    verify(before,result);
    verify(before,await metadata(device,remote));
    await output.sync();await output.close();output=undefined;
    if(overwrite)await fs.rename(temporary,destination);
    else await fs.link(temporary,destination);
    return result;
  } finally {
    if(output)await output.close();
    await fs.rm(temporary,{force:true});
  }
}
