package main

import (
	"context"
	"fmt"
	"log"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

type usbLink struct {
	name      string
	up        bool
	addresses []string
}

type usbRecovery struct {
	command    func(context.Context, string, ...string) (string, error)
	links      func() ([]usbLink, error)
	lastSwitch time.Time
	ownedRule  bool
}

func (r *usbRecovery) step(ctx context.Context, now time.Time) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	functions, err := r.command(ctx, "/system/bin/getprop", "sys.usb.config")
	if err != nil {
		return fmt.Errorf("read USB functions: %w", err)
	}
	if strings.TrimSpace(functions) == "" {
		return fmt.Errorf("USB configuration property unavailable")
	}
	configured := false
	debugFunction := false
	for _, function := range strings.Split(strings.TrimSpace(functions), ",") {
		if function == "rndis" || function == "ncm" {
			configured = true
		}
		if function == "adb" {
			debugFunction = true
		}
	}
	if !configured {
		if !r.lastSwitch.IsZero() && now.Sub(r.lastSwitch) < 10*time.Second {
			return nil
		}
		r.lastSwitch = now
		functions := "rndis"
		if debugFunction {
			functions += ",adb"
		}
		// Vendor svc usb may return success without performing any operation.
		// init's runtime property is observable and does not change the saved mode.
		_, err = r.command(ctx, "/system/bin/setprop", "sys.usb.config", functions)
		if err != nil {
			return fmt.Errorf("restore USB function: %w", err)
		}
		return nil // USB enumeration is asynchronous.
	}
	links, err := r.links()
	if err != nil {
		return fmt.Errorf("inspect USB links: %w", err)
	}
	for _, link := range links {
		if !usbInterfaceName(link.name) {
			continue
		}
		if !link.up {
			if _, err = r.command(ctx, "/system/bin/ip", "link", "set", link.name, "up"); err != nil {
				return fmt.Errorf("bring USB link up: %w", err)
			}
		}
		addressed := false
		for _, address := range link.addresses {
			if address == "169.254.77.1/16" {
				addressed = true
			}
		}
		if !addressed {
			if _, err = r.command(ctx, "/system/bin/ip", "addr", "add", "169.254.77.1/16", "dev", link.name); err != nil {
				return fmt.Errorf("restore USB address: %w", err)
			}
		}
		rules, err := r.command(ctx, "/system/bin/ip", "rule", "show")
		if err != nil {
			return fmt.Errorf("inspect USB return route: %w", err)
		}
		if !usbRulePresent(rules) {
			if _, err = r.command(ctx, "/system/bin/ip", "rule", "add", "priority", "10500", "from", "169.254.77.1/32", "to", "169.254.0.0/16", "lookup", "main"); err != nil {
				return fmt.Errorf("restore USB return route: %w", err)
			}
		}
		r.ownedRule = true
		return nil // Only this USB source/subnet, never default routes or NAT.
	}
	// Do not repeatedly reset a configured gadget while its cable is unplugged.
	return nil
}

func usbRulePresent(rules string) bool {
	for _, line := range strings.Split(rules, "\n") {
		f := strings.Fields(line)
		if len(f) == 7 && f[0] == "10500:" && f[1] == "from" && (f[2] == "169.254.77.1" || f[2] == "169.254.77.1/32") &&
			f[3] == "to" && f[4] == "169.254.0.0/16" && f[5] == "lookup" && (f[6] == "main" || f[6] == "254") {
			return true
		}
	}
	return false
}

func usbInterfaceName(name string) bool {
	for _, prefix := range []string{"rndis", "usb", "ncm"} {
		if strings.HasPrefix(name, prefix) {
			suffix := strings.TrimPrefix(name, prefix)
			if suffix == "" {
				return false
			}
			for _, c := range suffix {
				if c < '0' || c > '9' {
					return false
				}
			}
			return true
		}
	}
	return false
}

func inspectUSBLinks() ([]usbLink, error) {
	interfaces, err := net.Interfaces()
	if err != nil {
		return nil, err
	}
	var links []usbLink
	for _, iface := range interfaces {
		if !usbInterfaceName(iface.Name) {
			continue
		}
		addresses, err := iface.Addrs()
		if err != nil {
			return nil, err
		}
		link := usbLink{name: iface.Name, up: iface.Flags&net.FlagUp != 0}
		for _, address := range addresses {
			link.addresses = append(link.addresses, address.String())
		}
		links = append(links, link)
	}
	return links, nil
}

func moduleInactive(dir string) (bool, error) {
	info, err := os.Stat(dir)
	if err != nil {
		return false, err
	}
	if !info.IsDir() {
		return false, fmt.Errorf("module path is not a directory")
	}
	for _, flag := range []string{"disable", "remove"} {
		_, err := os.Stat(filepath.Join(dir, flag))
		if err == nil {
			return true, nil
		}
		if !os.IsNotExist(err) {
			return false, err
		}
	}
	return false, nil
}

func usbSystemCommand(ctx context.Context, name string, args ...string) (string, error) {
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.WaitDelay = time.Second
	out, err := cmd.CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("%s: %w: %s", name, err, strings.TrimSpace(string(out)))
	}
	return string(out), nil
}

// Recovery is part of the daemon, not an independent respawning watchdog.
func watchUSB(ctx context.Context, module string, stop context.CancelFunc) {
	defer stop()
	r := usbRecovery{command: usbSystemCommand, links: inspectUSBLinks}
	defer func() {
		if r.ownedRule {
			cleanup, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()
			_, _ = r.command(cleanup, "/system/bin/ip", "rule", "del", "priority", "10500", "from", "169.254.77.1/32", "to", "169.254.0.0/16", "lookup", "main")
		}
	}()
	previousError := ""
	for ctx.Err() == nil {
		inactive, err := moduleInactive(module)
		if err != nil || inactive {
			log.Printf("USB module stopped (disabled/removed or state unavailable): %v", err)
			return
		}
		stepContext, cancel := context.WithTimeout(ctx, 5*time.Second)
		err = r.step(stepContext, time.Now())
		cancel()
		message := ""
		if err != nil {
			message = err.Error()
		}
		if message != previousError {
			if message != "" {
				log.Printf("USB recovery: %s", message)
			}
			previousError = message
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(2 * time.Second):
		}
	}
}
