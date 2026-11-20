import {shQuote,validName} from './adb.js';

export function privateDirectory(prefix, create = true) {
  return [
    'umask 077',
    'uid=$(id -u)',
    `dir=${shQuote(prefix)}-"$uid"`,
    create ? 'if [ ! -e "$dir" ] && [ ! -L "$dir" ]; then mkdir -m 700 "$dir" || exit 1; fi' : 'if [ ! -e "$dir" ] && [ ! -L "$dir" ]; then exit 0; fi',
    '[ ! -L "$dir" ] && [ -d "$dir" ] && [ "$(stat -c %u "$dir")" = "$uid" ] && [ "$(stat -c %a "$dir")" = 700 ] || { echo "unsafe private directory" >&2; exit 1; }',
  ].join('; ');
}

export function jobScript(action, {name,command,lines = 100} = {}) {
  if (!['start','stop','list','log','status'].includes(action)) throw new Error('invalid job action');
  if (action !== 'list' && !validName(name)) throw new Error('invalid job name');
  if (action === 'start' && !command) throw new Error('command is required');
  if (!Number.isInteger(lines) || lines < 1 || lines > 1000) throw new Error('invalid log line count');
  const prelude = [
    privateDirectory('/data/local/tmp/vanta-jobs', action === 'start'),
    'birth() { case "$1" in ""|*[!0-9]*) return 1;; esac; [ "$1" -gt 1 ] || return 1; sed "s/.*) //" "/proc/$1/stat" 2>/dev/null | awk \'NF>=20 {print $20}\'; }',
    'live() { case "$pid:$born" in *[!0-9:]*|:*|*:) return 1;; esac; [ "$pid" -gt 1 ] && [ "$(birth "$pid")" = "$born" ]; }',
  ];
  if (action === 'list') return [...prelude,
    'for f in "$dir"/*.pid; do [ -f "$f" ] && [ ! -L "$f" ] || continue; read -r pid born < "$f"; state=stale; live && state=running; name=${f##*/}; printf "%s %s %s\\n" "${name%.pid}" "$pid" "$state"; done',
  ].join('; ');
  prelude.push(`pidfile="$dir/${name}.pid"`, `logfile="$dir/${name}.log"`,
    '[ ! -L "$pidfile" ] && [ ! -L "$logfile" ] || { echo "unsafe job file" >&2; exit 1; }');
  if (action === 'log') return [...prelude,`tail -n ${lines} "$logfile"`].join('; ');
  if (action === 'status') return [...prelude,
    'if [ -f "$pidfile" ]; then read -r pid born < "$pidfile"; if live; then echo "running pid=$pid"; else echo "stale pid=$pid"; fi; else echo "not started"; fi',
    `if [ -f "$logfile" ]; then tail -n ${lines} "$logfile"; fi`,
  ].join('; ');
  prelude.push(`lock="$dir/${name}.lock"`,
    'mkdir -m 700 "$lock" 2>/dev/null || { echo "job is busy or has a stale lock; inspect it before removal" >&2; exit 1; }',
    'trap \'rmdir "$lock" 2>/dev/null\' EXIT',
  );
  if (action === 'start') return [...prelude,
    `if [ -f "$pidfile" ]; then read -r pid born < "$pidfile"; if live; then echo "${name} running pid=$pid"; exit 0; fi; fi`,
    `nohup sh -c ${shQuote(command)} >"$logfile" 2>&1 < /dev/null & pid=$!`,
    'born=$(birth "$pid")',
    'case "$born" in ""|*[!0-9]*) wait "$pid"; rc=$?; echo "job completed exit=$rc before identity capture"; exit "$rc";; esac',
    'printf "%s %s\\n" "$pid" "$born" > "$pidfile"',
    `echo "${name} started pid=$pid"`,
  ].join('; ');
  return [...prelude,
    `if [ ! -f "$pidfile" ]; then echo "${name} not running"; exit 0; fi`,
    'read -r pid born < "$pidfile"',
    'live || { echo "stale job identity; no process was stopped" >&2; exit 1; }',
    'kill "$pid" || exit 1; sleep 1',
    'if live; then kill -9 "$pid" || exit 1; fi',
    'rm -f -- "$pidfile"',
    `echo "${name} stopped"`,
  ].join('; ');
}
