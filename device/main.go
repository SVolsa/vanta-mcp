// Vanta's owner-paired USB management endpoint. No passwords or anonymous mode.
package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"
)

const version = "0.4.4"
const shellContext = "u:r:shell:s0"
const maxTransfer = 64 << 20

type config struct {
	Listen string `json:"listen"`
	Shell  string `json:"shell"`
}
type request struct {
	Command   string `json:"command"`
	Root      bool   `json:"root"`
	TimeoutMS int    `json:"timeout_ms"`
	MaxBytes  int    `json:"max_bytes"`
	Stdin     []byte `json:"stdin"`
}
type result struct {
	Code     int    `json:"code"`
	TimedOut bool   `json:"timedOut"`
	TooLarge bool   `json:"tooLarge"`
	Stdout   []byte `json:"stdout"`
	Stderr   []byte `json:"stderr"`
}
type bounded struct {
	sync.Mutex
	data     bytes.Buffer
	limit    int
	exceeded bool
}

func (b *bounded) Write(p []byte) (int, error) {
	b.Lock()
	defer b.Unlock()
	n := len(p)
	room := b.limit - b.data.Len()
	if len(p) > room {
		b.exceeded = true
		p = p[:room]
	}
	b.data.Write(p)
	return n, nil
}

func decode(r io.Reader) (request, error) {
	var q request
	d := json.NewDecoder(r)
	d.DisallowUnknownFields()
	if err := d.Decode(&q); err != nil {
		return q, err
	}
	if d.Decode(new(any)) != io.EOF {
		return q, errors.New("expected one JSON object")
	}
	if len(q.Command) == 0 || len(q.Command) > 65536 || bytes.IndexByte([]byte(q.Command), 0) >= 0 {
		return q, errors.New("command length or encoding invalid")
	}
	if q.TimeoutMS < 100 || q.TimeoutMS > 120000 || q.MaxBytes < 1 || q.MaxBytes > maxTransfer || len(q.Stdin) > maxTransfer {
		return q, errors.New("request exceeds execution limits")
	}
	return q, nil
}

func handler(shell string) http.Handler {
	slots := make(chan struct{}, 4)
	mux := http.NewServeMux()
	mux.HandleFunc("GET /v1/health", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{"version": version, "uid": os.Geteuid(), "transport": "usb-mtls", "non_root_context": shellContext})
	})
	mux.HandleFunc("POST /v1/exec", func(w http.ResponseWriter, r *http.Request) {
		select {
		case slots <- struct{}{}:
			defer func() { <-slots }()
		default:
			http.Error(w, "busy", http.StatusTooManyRequests)
			return
		}
		q, err := decode(http.MaxBytesReader(w, r.Body, 96<<20))
		if err != nil {
			http.Error(w, "invalid execution request", http.StatusBadRequest)
			return
		}
		ctx, cancel := context.WithTimeout(r.Context(), time.Duration(q.TimeoutMS)*time.Millisecond)
		defer cancel()
		answer := execute(ctx, shell, q)
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(answer)
	})
	return mux
}

func usbAddress() string {
	interfaces, _ := net.Interfaces()
	fallback := ""
	for _, iface := range interfaces {
		if iface.Flags&net.FlagUp == 0 || !(strings.HasPrefix(iface.Name, "usb") || strings.HasPrefix(iface.Name, "rndis") || strings.HasPrefix(iface.Name, "ncm")) {
			continue
		}
		addresses, _ := iface.Addrs()
		for _, address := range addresses {
			ip, _, err := net.ParseCIDR(address.String())
			if err != nil || ip.To4() == nil {
				continue
			}
			if ip.IsPrivate() {
				return ip.String()
			}
			if ip.IsLinkLocalUnicast() {
				fallback = ip.String()
			}
		}
	}
	return fallback
}

func serve(dir, module string) error {
	data, err := os.ReadFile(filepath.Join(dir, "server.json"))
	if err != nil {
		return err
	}
	var c config
	if err = json.Unmarshal(data, &c); err != nil {
		return err
	}
	host, port, err := net.SplitHostPort(c.Listen)
	// Bind only a dynamically resolved USB address, never Wi-Fi or all interfaces.
	if err != nil || host != "usb" || port != "22445" {
		return errors.New("USB endpoint must use usb:22445")
	}
	if c.Shell != "/system/bin/sh" {
		return errors.New("invalid Android shell")
	}
	if os.Geteuid() != 0 {
		return errors.New("module service requires root")
	}
	if module != "" && module != "/data/adb/modules/vanta_mcp" && module != "/data/adb/modules_update/vanta_mcp" {
		return errors.New("invalid module directory")
	}
	ca, err := os.ReadFile(filepath.Join(dir, "ca.pem"))
	if err != nil {
		return err
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(ca) {
		return errors.New("invalid paired CA")
	}
	// Check credentials before changing the USB function.
	if _, err := tls.LoadX509KeyPair(filepath.Join(dir, "server.pem"), filepath.Join(dir, "server.key")); err != nil {
		return err
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if module != "" {
		done := make(chan struct{})
		go func() { defer close(done); watchUSB(ctx, module, stop) }()
		defer func() { stop(); <-done }()
	}
	for ctx.Err() == nil {
		ip := usbAddress()
		if ip == "" {
			select {
			case <-ctx.Done():
				return nil
			case <-time.After(time.Second):
				continue
			}
		}
		address := net.JoinHostPort(ip, port)
		server := &http.Server{Addr: address, Handler: handler(c.Shell), ReadHeaderTimeout: 5 * time.Second,
			ReadTimeout: 45 * time.Second, WriteTimeout: 135 * time.Second, IdleTimeout: 30 * time.Second, MaxHeaderBytes: 8192,
			TLSConfig: &tls.Config{MinVersion: tls.VersionTLS13, ClientAuth: tls.RequireAndVerifyClientCert, ClientCAs: pool}}
		done := make(chan error, 1)
		go func() {
			done <- server.ListenAndServeTLS(filepath.Join(dir, "server.pem"), filepath.Join(dir, "server.key"))
		}()
		log.Printf("Vanta USB %s starting endpoint %s (paired certificates required)", version, address)
		ticker := time.NewTicker(2 * time.Second)
		listening := true
		finished := false
		for listening {
			select {
			case <-ctx.Done():
				listening = false
			case err := <-done:
				finished = true
				if err != http.ErrServerClosed && ctx.Err() == nil {
					log.Printf("USB listener interrupted; will reopen: %v", err)
				}
				listening = false
			case <-ticker.C:
				if usbAddress() != ip {
					listening = false
				}
			}
		}
		ticker.Stop()
		shutdown, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		server.Shutdown(shutdown)
		server.Close()
		cancel()
		if !finished {
			<-done
		}
		select {
		case <-ctx.Done():
			return nil
		case <-time.After(time.Second):
		}
	}
	return nil
}

func main() {
	if len(os.Args) > 1 && os.Args[1] == "pair" {
		if err := pair(os.Args[2:]); err != nil {
			log.Fatal(err)
		}
		return
	}
	directory := flag.String("state", "/data/adb/vanta-mcp", "root-owned pairing state")
	module := flag.String("module", "", "KernelSU module directory; enables USB link recovery")
	flag.Parse()
	if err := serve(*directory, *module); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
