package main

import (
	"bytes"
	"context"
	"os/exec"
	"strings"
	"syscall"
)

const runconPath = "/system/bin/runcon"
const legacyShellPrefix = "exec /system/bin/runcon " + shellContext + " /system/bin/sh -c "

// This fixed script runs after runcon, before any request text is interpreted.
// Check the bootstrap process, not the root daemon or a forked child.
const verifyShell = `
if [ "$(/system/bin/id -u)" != 2000 ] ||
   [ "$(/system/bin/id -g)" != 2000 ] ||
   [ "$(/system/bin/id -Z)" != u:r:shell:s0 ] ||
   ! /system/bin/grep -q '^CapEff:[[:space:]]*0\{16\}$' "/proc/$$/status"; then
    printf '%s\n' 'Vanta: restricted Android shell identity check failed' >&2
    exit 126
fi
exec /system/bin/sh -c "$1"
`

func unwrapLegacyShell(command string) string {
	quoted, found := strings.CutPrefix(command, legacyShellPrefix)
	if !found || len(quoted) < 2 || quoted[0] != '\'' || quoted[len(quoted)-1] != '\'' {
		return command
	}
	// Match the old host's exact quoting. Never consume a suffix or shell syntax
	// outside the original single positional argument.
	const quotedApostrophe = `'"'"'`
	decoded := strings.ReplaceAll(quoted[1:len(quoted)-1], quotedApostrophe, "'")
	if "'"+strings.ReplaceAll(decoded, "'", quotedApostrophe)+"'" != quoted {
		return command
	}
	return decoded
}

func commandFor(shell, runcon string, q request) *exec.Cmd {
	if q.Root {
		cmd := exec.Command(shell, "-c", q.Command)
		cmd.Env = []string{"PATH=/data/adb/ksu/bin:/system/bin:/system/xbin:/vendor/bin", "HOME=/data/local/tmp", "TMPDIR=/data/local/tmp"}
		cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
		return cmd
	}
	cmd := exec.Command(runcon, shellContext, shell, "-c", verifyShell, "vanta-restricted-shell", unwrapLegacyShell(q.Command))
	cmd.Env = []string{"PATH=/system/bin:/system/xbin:/vendor/bin", "HOME=/data/local/tmp", "TMPDIR=/data/local/tmp"}
	cmd.SysProcAttr = &syscall.SysProcAttr{
		Setpgid:    true,
		Credential: &syscall.Credential{Uid: 2000, Gid: 2000, Groups: []uint32{2000}},
	}
	return cmd
}

func execute(ctx context.Context, shell string, q request) result {
	return executeWithRuncon(ctx, shell, runconPath, q)
}

func executeWithRuncon(ctx context.Context, shell, runcon string, q request) result {
	out, diagnostic := &bounded{limit: q.MaxBytes}, &bounded{limit: 4096}
	cmd := commandFor(shell, runcon, q)
	cmd.Dir = "/data/local/tmp"
	cmd.Stdin = bytes.NewReader(q.Stdin)
	cmd.Stdout = out
	cmd.Stderr = diagnostic
	answer := result{Code: 0}
	if err := cmd.Start(); err != nil {
		answer.Code = 126
		answer.Stderr = []byte("command could not start: " + err.Error())
		return answer
	}
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	select {
	case err := <-done:
		if err != nil {
			answer.Code = cmd.ProcessState.ExitCode()
			if answer.Code < 0 {
				answer.Code = 128
			}
		}
	case <-ctx.Done():
		syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
		<-done
		answer.Code = 124
		answer.TimedOut = true
	}
	answer.Stdout = out.data.Bytes()
	answer.Stderr = diagnostic.data.Bytes()
	answer.TooLarge = out.exceeded || diagnostic.exceeded
	return answer
}
