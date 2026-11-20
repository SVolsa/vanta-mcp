package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"flag"
	"math/big"
	"os"
	"path/filepath"
	"time"
)

func pair(args []string) error {
	flags := flag.NewFlagSet("pair", flag.ContinueOnError)
	directory := flags.String("dir", "", "new private pairing directory")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if *directory == "" {
		return errors.New("--dir is required")
	}
	dir, err := filepath.Abs(*directory)
	if err != nil {
		return err
	}
	if err = os.MkdirAll(filepath.Dir(dir), 0700); err != nil {
		return err
	}
	if err = os.Mkdir(dir, 0700); err != nil {
		if os.IsExist(err) {
			return errors.New("pairing directory must not already exist")
		}
		return err
	}
	serial := func() *big.Int { n, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128)); return n }
	caPub, caKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return err
	}
	ca := &x509.Certificate{SerialNumber: serial(), Subject: pkix.Name{CommonName: "Vanta owner pairing"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().AddDate(3, 0, 0), IsCA: true, BasicConstraintsValid: true,
		KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature}
	caDER, err := x509.CreateCertificate(rand.Reader, ca, ca, caPub, caKey)
	if err != nil {
		return err
	}
	write := func(name string, data []byte) error { return os.WriteFile(filepath.Join(dir, name), data, 0600) }
	if err = write("ca.pem", pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER})); err != nil {
		return err
	}
	for _, name := range []string{"server", "client"} {
		pub, key, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			return err
		}
		c := &x509.Certificate{SerialNumber: serial(), Subject: pkix.Name{CommonName: "vanta-" + name},
			NotBefore: ca.NotBefore, NotAfter: ca.NotAfter, KeyUsage: x509.KeyUsageDigitalSignature}
		if name == "server" {
			c.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
			c.DNSNames = []string{"vanta-usb"}
		}
		if name == "client" {
			c.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}
		}
		der, err := x509.CreateCertificate(rand.Reader, c, ca, pub, caKey)
		if err != nil {
			return err
		}
		if err = write(name+".pem", pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})); err != nil {
			return err
		}
		raw, err := x509.MarshalPKCS8PrivateKey(key)
		if err != nil {
			return err
		}
		if err = write(name+".key", pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: raw})); err != nil {
			return err
		}
	}
	server, _ := json.MarshalIndent(config{Listen: "usb:22445", Shell: "/system/bin/sh"}, "", "  ")
	if err = write("server.json", server); err != nil {
		return err
	}
	client, _ := json.MarshalIndent(map[string]string{"endpoint": "usb:auto", "servername": "vanta-usb",
		"ca": filepath.Join(dir, "ca.pem"), "cert": filepath.Join(dir, "client.pem"), "key": filepath.Join(dir, "client.key")}, "", "  ")
	return write("client.json", client)
}
