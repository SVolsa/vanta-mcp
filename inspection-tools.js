import {z} from 'zod';
import {apkInspection,directorySchema,packageSchema,userSchema} from './apk-inspection.js';
import {binaryInspection,modulePreflight} from './binary-inspection.js';
import {collectCrash,symbolizeCrash} from './crash-inspection.js';
import {inspectVMTrace} from './vm-trace.js';
import {diagnoseNative,nativeABIs} from './native-diagnosis.js';

export function registerInspectionTools(register) {
  const file = z.string().min(1).max(1024);
  const json = handler => async args => JSON.stringify(await handler(args),null,2);
  const output = directorySchema;
  register('apk_inspect','导出和检查 APK，比较签名、文件与 Manifest 声明，或诊断 native 依赖、ABI 和 16 KB 对齐问题。',{
    action:z.enum(['export','inspect','compare','diagnose_native']), package:packageSchema.optional(),user:userSchema.optional(),
    apks:z.array(file).min(1).max(128).optional(),left:file.optional(),right:file.optional(),output,
    abi:z.enum(nativeABIs).optional(),page_size:z.union([z.literal(4096),z.literal(16384)]).optional(),
    minutes:z.number().int().min(1).max(1440).optional(),
  },json(args=>args.action==='diagnose_native' ? diagnoseNative(args) : apkInspection(args)));
  register('crash_report','按包名和时间收集崩溃，或用匹配 ABI/Build ID 的本地符号还原 native 堆栈。',{
    action:z.enum(['collect','symbolize']),package:packageSchema.optional(),user:userSchema.optional(),
    minutes:z.number().int().min(1).max(1440).optional(),trace:file.optional(),symbols:z.array(file).min(1).max(80).optional(),
    abi:z.enum(['arm64','arm64-v8a','arm','armeabi-v7a','x86_64','x86','riscv64']).optional(),output,
  },json(args=>args.action==='collect' ? collectCrash(args) : symbolizeCrash(args)));
  register('kernel_preflight','只读核对本地 .ko 的架构、KMI、vermagic、依赖和可选的符号 CRC。',{
    local:file,kernel_release:z.string().min(1).max(180).optional(),kernel_machine:z.string().min(1).max(64).optional(),
    module_symvers:file.optional(),log_path:file.optional(),device_logs:z.boolean().optional(),output,
  },json(modulePreflight));
  register('elf_inspect','本地分析 Android ELF 或 .ko 的结构、依赖、符号与重定位，可反汇编一个指定地址区间。',{
    local:file,symbols:z.boolean().optional(),start_address:z.string().regex(/^0x[\da-f]{1,16}$/i).optional(),
    byte_count:z.number().int().min(1).max(16384).optional(),section:z.string().regex(/^[.\w$-]{1,128}$/).optional(),output,
  },json(binaryInspection));
  register('vm_trace','汇总或比对本地 VM JSONL 执行轨迹，报告 opcode、控制流边及首次执行差异。可用对应 ELF 定位差异。',{
    action:z.enum(['summarize','compare']),trace:file,other:file.optional(),left_elf:file.optional(),right_elf:file.optional(),output,
  },json(inspectVMTrace));
}
