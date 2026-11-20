package main

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"
)

func TestNonRootUsesFixedSELinuxBootstrap(t *testing.T) {
	input := request{Command: "printf '%s' \"$0\"; exit 7"}
	cmd := commandFor("/system/bin/sh", runconPath, input)
	if cmd.Path != runconPath || cmd.Args[1] != shellContext || cmd.Args[len(cmd.Args)-1] != input.Command ||
		strings.Contains(cmd.Args[4], input.Command) || cmd.SysProcAttr.Credential == nil ||
		cmd.SysProcAttr.Credential.Uid != 2000 || cmd.SysProcAttr.Credential.Gid != 2000 ||
		len(cmd.SysProcAttr.Credential.Groups) != 1 || cmd.SysProcAttr.Credential.Groups[0] != 2000 {
		t.Fatal("user text must be a positional argument to a verified shell, with fixed Android credentials")
	}
	input.Root = true
	if root := commandFor("/system/bin/sh", runconPath, input); root.Path != "/system/bin/sh" || root.SysProcAttr.Credential != nil {
		t.Fatal("explicit root execution must retain the paired device service's identity")
	}
	const literal = `printf '%s' "a;b"`
	if decoded := unwrapLegacyShell(legacyShellPrefix + `'printf '"'"'%s'"'"' "a;b"'`); decoded != literal {
		t.Fatalf("legacy quoting changed command data: %q", decoded)
	}
	unsafe := legacyShellPrefix + "'id'; printf 'outside'"
	if unwrapLegacyShell(unsafe) != unsafe {
		t.Fatal("unexpected text outside a single quote argument")
	}
}

func TestAndroidDirectExecIdentity(t *testing.T) {
	const shell = "/system/bin/sh"
	if _, err := os.Stat(runconPath); err != nil || os.Getuid() != 0 {
		t.Skip("requires the paired Android service's root execution context")
	}
	call := func(command string, root bool, input []byte) result {
		t.Helper()
		body, err := json.Marshal(request{Command: command, Root: root, Stdin: input, TimeoutMS: 5000, MaxBytes: 2048})
		if err != nil {
			t.Fatal(err)
		}
		response := httptest.NewRecorder()
		handler(shell).ServeHTTP(response, httptest.NewRequest(http.MethodPost, "/v1/exec", bytes.NewReader(body)))
		var answer result
		if response.Code != http.StatusOK || json.Unmarshal(response.Body.Bytes(), &answer) != nil {
			t.Fatalf("bad response: HTTP %d", response.Code)
		}
		return answer
	}
	plain := call("id -u; id -g; id -Z; grep '^CapEff:' /proc/$$/status", false, nil)
	if plain.Code != 0 || strings.TrimSpace(string(plain.Stdout)) != "2000\n2000\n"+shellContext+"\nCapEff:\t0000000000000000" {
		t.Fatalf("ordinary direct request returned code=%d stdout=%q stderr=%q", plain.Code, plain.Stdout, plain.Stderr)
	}
	explicit := call("id -u", true, nil)
	if explicit.Code != 0 || strings.TrimSpace(string(explicit.Stdout)) != "0" {
		t.Fatalf("explicit root returned code=%d stdout=%q", explicit.Code, explicit.Stdout)
	}
	binary := []byte{0, 255, 13, 10, 128}
	passthrough := call("cat; exit 7", false, binary)
	if passthrough.Code != 7 || !bytes.Equal(passthrough.Stdout, binary) {
		t.Fatal("restricted shell did not preserve stdin, binary stdout or exit code")
	}
	legacy := call("exec /system/bin/runcon u:r:shell:s0 /system/bin/sh -c 'id -Z'", false, nil)
	if legacy.Code != 0 || strings.TrimSpace(string(legacy.Stdout)) != shellContext {
		t.Fatalf("legacy wrapped client command failed: %q", legacy.Stderr)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if failure := executeWithRuncon(ctx, shell, "/system/bin/false", request{Command: "echo should-not-run", MaxBytes: 2048}); failure.Code == 0 || len(failure.Stdout) != 0 {
		t.Fatal("failed SELinux launcher executed request")
	}
	guard := exec.CommandContext(ctx, shell, "-c", verifyShell, "vanta-test", "echo should-not-run")
	out, err := guard.CombinedOutput()
	if err == nil || strings.Contains(string(out), "should-not-run") {
		t.Fatal("restricted-shell bootstrap executed user input in the wrong identity")
	}
}
