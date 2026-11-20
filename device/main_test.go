package main

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestDecodeLimits(t *testing.T) {
	for _, input := range []string{`{}`, `{"command":"id","timeout_ms":120001,"max_bytes":1}`,
		`{"command":"id","timeout_ms":1000,"max_bytes":0}`, `{"command":"id","timeout_ms":1000,"max_bytes":1,"extra":true}`,
		`{"command":"id","timeout_ms":1000,"max_bytes":1} {}`, `{"command":"a\u0000b","timeout_ms":1000,"max_bytes":1}`} {
		if _, err := decode(strings.NewReader(input)); err == nil {
			t.Fatalf("accepted %s", input)
		}
	}
	if _, err := decode(strings.NewReader(`{"command":"id","root":true,"timeout_ms":1000,"max_bytes":1}`)); err != nil {
		t.Fatal(err)
	}
}
func TestOutputBound(t *testing.T) {
	b := &bounded{limit: 3}
	b.Write([]byte("abcdef"))
	b.Write([]byte("x"))
	if b.data.String() != "abc" || !b.exceeded {
		t.Fatal("output not bounded")
	}
}

func TestPairingDirectoryHasOneCreator(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "nested", "pair")
	const attempts = 24
	start := make(chan struct{})
	result := make(chan error, attempts)
	for i := 0; i < attempts; i++ {
		go func() {
			<-start
			result <- pair([]string{"--dir", dir})
		}()
	}
	close(start)
	succeeded := 0
	for i := 0; i < attempts; i++ {
		if err := <-result; err == nil {
			succeeded++
		} else if !strings.Contains(err.Error(), "must not already exist") {
			t.Fatal(err)
		}
	}
	if succeeded != 1 {
		t.Fatalf("expected one pairing creator, got %d", succeeded)
	}
}

func TestPairingMTLS(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "pair")
	if err := pair([]string{"--dir", dir}); err != nil {
		t.Fatal(err)
	}
	if err := pair([]string{"--dir", dir}); err == nil {
		t.Fatal("overwrote pairing")
	}
	read := func(name string) []byte {
		d, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			t.Fatal(err)
		}
		return d
	}
	certificate, err := tls.X509KeyPair(read("server.pem"), read("server.key"))
	if err != nil {
		t.Fatal(err)
	}
	ca := x509.NewCertPool()
	ca.AppendCertsFromPEM(read("ca.pem"))
	server := httptest.NewUnstartedServer(handler("/system/bin/sh"))
	server.TLS = &tls.Config{Certificates: []tls.Certificate{certificate}, MinVersion: tls.VersionTLS13, ClientAuth: tls.RequireAndVerifyClientCert, ClientCAs: ca}
	server.StartTLS()
	defer server.Close()
	transport := &http.Transport{TLSClientConfig: &tls.Config{RootCAs: ca, ServerName: "vanta-usb", MinVersion: tls.VersionTLS13}}
	client := &http.Client{Transport: transport}
	if r, err := client.Get(server.URL + "/v1/health"); err == nil {
		r.Body.Close()
		t.Fatal("anonymous access accepted")
	}
	cert, err := tls.X509KeyPair(read("client.pem"), read("client.key"))
	if err != nil {
		t.Fatal(err)
	}
	transport.TLSClientConfig.Certificates = []tls.Certificate{cert}
	response, err := client.Get(server.URL + "/v1/health")
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	var health map[string]any
	if json.NewDecoder(response.Body).Decode(&health) != nil || health["version"] != version {
		t.Fatal("health failed")
	}
	r, err := client.Post(server.URL+"/v1/exec", "application/json", bytes.NewBufferString(`{}`))
	if err != nil {
		t.Fatal(err)
	}
	r.Body.Close()
	if r.StatusCode != 400 {
		t.Fatal("malformed request accepted")
	}
}
