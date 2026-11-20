package main

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

func TestUSBRecoveryRebuildsModeAndMissingAddress(t *testing.T) {
	var calls []string
	mode := "mtp"
	links := []usbLink{}
	r := usbRecovery{
		command: func(_ context.Context, name string, args ...string) (string, error) {
			call := name + " " + strings.Join(args, " ")
			calls = append(calls, call)
			if call == "/system/bin/getprop sys.usb.config" {
				return mode, nil
			}
			if call == "/system/bin/ip rule show" {
				return "10500: from 169.254.77.1 to 169.254.0.0/16 lookup main", nil
			}
			return "", nil
		},
		links: func() ([]usbLink, error) { return links, nil },
	}
	now := time.Unix(100, 0)
	if err := r.step(context.Background(), now); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(calls, []string{"/system/bin/getprop sys.usb.config", "/system/bin/setprop sys.usb.config rndis"}) {
		t.Fatalf("USB mode was not restored: %v", calls)
	}
	mode = "rndis,adb"
	links = []usbLink{{name: "rndis0"}}
	calls = nil
	if err := r.step(context.Background(), now.Add(2*time.Second)); err != nil {
		t.Fatal(err)
	}
	want := []string{"/system/bin/getprop sys.usb.config", "/system/bin/ip link set rndis0 up", "/system/bin/ip addr add 169.254.77.1/16 dev rndis0", "/system/bin/ip rule show"}
	if !reflect.DeepEqual(calls, want) {
		t.Fatalf("USB link/address not repaired: %v", calls)
	}
	links = []usbLink{{name: "rndis0", up: true, addresses: []string{"169.254.77.1/16"}}}
	calls = nil
	if err := r.step(context.Background(), now.Add(4*time.Second)); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(calls, []string{"/system/bin/getprop sys.usb.config", "/system/bin/ip rule show"}) {
		t.Fatalf("healthy link changed: %v", calls)
	}
}

func TestUSBReturnRuleExactMatch(t *testing.T) {
	for _, rule := range []string{
		"10500: from 169.254.77.1 to 169.254.0.0/16 lookup main",
		"0: from all lookup local\n10500: from 169.254.77.1/32 to 169.254.0.0/16 lookup 254\n",
	} {
		if !usbRulePresent(rule) {
			t.Fatalf("valid rule rejected: %q", rule)
		}
	}
	valid := "10500: from 169.254.77.1 to 169.254.0.0/16 lookup main"
	for _, rule := range []string{"", strings.Replace(valid, "10500:", "10501:", 1), strings.Replace(valid, "169.254.77.1", "169.254.77.2", 1), strings.Replace(valid, "169.254.0.0/16", "all", 1), strings.Replace(valid, "main", "100", 1), valid + " suppress_prefixlength 0"} {
		if usbRulePresent(rule) {
			t.Fatalf("unrelated rule accepted: %q", rule)
		}
	}
}

func TestUSBReturnRuleRepairAndFailure(t *testing.T) {
	for _, failure := range []string{"", "show", "add"} {
		t.Run(failure, func(t *testing.T) {
			present, additions := false, 0
			r := usbRecovery{
				links: func() ([]usbLink, error) {
					return []usbLink{{name: "usb0", up: true, addresses: []string{"169.254.77.1/16"}}}, nil
				},
				command: func(_ context.Context, name string, args ...string) (string, error) {
					if name == "/system/bin/getprop" {
						return "rndis", nil
					}
					if name != "/system/bin/ip" || len(args) < 2 || args[0] != "rule" {
						t.Fatalf("unexpected command %s %v", name, args)
					}
					if args[1] == failure {
						return "", errors.New("injected rule failure")
					}
					if args[1] == "show" {
						if present {
							return "10500: from 169.254.77.1 to 169.254.0.0/16 lookup main", nil
						}
						return "", nil
					}
					want := []string{"rule", "add", "priority", "10500", "from", "169.254.77.1/32", "to", "169.254.0.0/16", "lookup", "main"}
					if !reflect.DeepEqual(args, want) {
						t.Fatalf("broad rule: %v", args)
					}
					additions++
					present = true
					return "", nil
				},
			}
			if err := r.step(context.Background(), time.Now()); failure != "" {
				if err == nil || r.ownedRule {
					t.Fatal("failed rule operation accepted")
				}
				return
			} else if err != nil {
				t.Fatal(err)
			}
			if err := r.step(context.Background(), time.Now()); err != nil {
				t.Fatal(err)
			}
			if additions != 1 || !r.ownedRule {
				t.Fatal("rule duplicated or ownership missing")
			}
		})
	}
}

func TestUSBRecoveryDisconnectCooldownAndFailure(t *testing.T) {
	var calls []string
	mode := "rndis,adb"
	fail := false
	r := usbRecovery{
		command: func(_ context.Context, name string, args ...string) (string, error) {
			call := name + " " + strings.Join(args, " ")
			calls = append(calls, call)
			if fail {
				return "", errors.New("framework unavailable")
			}
			if strings.HasSuffix(call, "sys.usb.config") {
				return mode, nil
			}
			return "", nil
		},
		links: func() ([]usbLink, error) { return nil, nil },
	}
	now := time.Unix(100, 0)
	for i := 0; i < 3; i++ {
		if err := r.step(context.Background(), now.Add(time.Duration(i)*time.Second)); err != nil {
			t.Fatal(err)
		}
	}
	for _, call := range calls {
		if !strings.HasSuffix(call, "sys.usb.config") {
			t.Fatalf("unplugged gadget reset: %v", calls)
		}
	}
	mode = "mtp"
	calls = nil
	for _, offset := range []time.Duration{0, 2 * time.Second, 10 * time.Second} {
		if err := r.step(context.Background(), now.Add(offset)); err != nil {
			t.Fatal(err)
		}
	}
	switches := 0
	for _, call := range calls {
		if strings.HasPrefix(call, "/system/bin/setprop ") {
			switches++
		}
	}
	if switches != 2 {
		t.Fatalf("mode-switch retries not bounded: %v", calls)
	}
	fail = true
	if err := r.step(context.Background(), now.Add(20*time.Second)); err == nil {
		t.Fatal("command failure ignored")
	}
	calls = nil
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := r.step(ctx, now); !errors.Is(err, context.Canceled) || len(calls) != 0 {
		t.Fatal("canceled recovery performed commands")
	}
}

func TestUSBRecoveryOnlyUSBAndAddressErrors(t *testing.T) {
	for _, name := range []string{"rndis0", "usb0", "ncm12"} {
		if !usbInterfaceName(name) {
			t.Fatal(name)
		}
	}
	for _, name := range []string{"wlan0", "eth0", "usb", "rndis_bad", "usb0;id", "ncm-1"} {
		if usbInterfaceName(name) {
			t.Fatal(name)
		}
	}
	var calls []string
	r := usbRecovery{
		command: func(_ context.Context, name string, args ...string) (string, error) {
			call := name + " " + strings.Join(args, " ")
			calls = append(calls, call)
			if strings.HasSuffix(call, "sys.usb.config") {
				return "ncm,adb", nil
			}
			return "", errors.New("address rejected")
		},
		links: func() ([]usbLink, error) { return []usbLink{{name: "wlan0"}, {name: "ncm0", up: true}}, nil },
	}
	if err := r.step(context.Background(), time.Now()); err == nil {
		t.Fatal("address error ignored")
	}
	if len(calls) != 2 || !strings.HasSuffix(calls[1], "dev ncm0") {
		t.Fatalf("wrong interface changed: %v", calls)
	}
	r.links = func() ([]usbLink, error) { return nil, errors.New("netlink failure") }
	if err := r.step(context.Background(), time.Now()); err == nil {
		t.Fatal("interface read error ignored")
	}
}

func TestUSBRecoveryModuleStop(t *testing.T) {
	for _, flag := range []string{"disable", "remove"} {
		dir := t.TempDir()
		if inactive, err := moduleInactive(dir); err != nil || inactive {
			t.Fatal("enabled module refused")
		}
		if err := os.WriteFile(filepath.Join(dir, flag), nil, 0600); err != nil {
			t.Fatal(err)
		}
		if inactive, err := moduleInactive(dir); err != nil || !inactive {
			t.Fatal("module stop ignored")
		}
		ctx, cancel := context.WithCancel(context.Background())
		done := make(chan struct{})
		go func() { watchUSB(ctx, dir, cancel); close(done) }()
		select {
		case <-done:
		case <-time.After(time.Second):
			cancel()
			t.Fatal("disabled recovery did not stop")
		}
		if ctx.Err() == nil {
			t.Fatal("module disable did not stop daemon context")
		}
	}
	if _, err := moduleInactive(filepath.Join(t.TempDir(), "missing")); err == nil {
		t.Fatal("missing module ignored")
	}
}

func TestUSBRecoveryUnknownModeDoesNotReset(t *testing.T) {
	calls := 0
	r := usbRecovery{
		command: func(_ context.Context, _ string, _ ...string) (string, error) { calls++; return "", nil },
		links:   func() ([]usbLink, error) { t.Fatal("unknown mode inspected interfaces"); return nil, nil },
	}
	if err := r.step(context.Background(), time.Now()); err == nil || calls != 1 {
		t.Fatal("unknown USB state reset the gadget")
	}
}

func TestUSBRecoveryPreservesDebugFunction(t *testing.T) {
	for mode, want := range map[string]string{"mtp": "rndis", "mtp,adb": "rndis,adb", "none": "rndis", "none,adb": "rndis,adb"} {
		t.Run(mode, func(t *testing.T) {
			var written []string
			r := usbRecovery{
				command: func(_ context.Context, name string, args ...string) (string, error) {
					if name == "/system/bin/getprop" {
						return mode, nil
					}
					if name != "/system/bin/setprop" {
						t.Fatalf("unexpected command: %s", name)
					}
					written = args
					return "", nil
				},
			}
			if err := r.step(context.Background(), time.Now()); err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(written, []string{"sys.usb.config", want}) {
				t.Fatalf("changed debugging choice: %v", written)
			}
		})
	}
}
