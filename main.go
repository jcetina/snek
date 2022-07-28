package main

import (
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"strings"

	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"net/http"
	"time"
)

func LoadX509KeyPair(certFile, keyFile string) (tls.Certificate, error) {
	var cert tls.Certificate

	certPEMBlock, _ := os.ReadFile(certFile)
	keyPEMBlock, _ := os.ReadFile(keyFile)
	var skippedBlockTypes []string
	for {
		var certDERBlock *pem.Block
		certDERBlock, certPEMBlock = pem.Decode(certPEMBlock)
		if certDERBlock == nil {
			break
		}
		if certDERBlock.Type == "CERTIFICATE" {
			cert.Certificate = append(cert.Certificate, certDERBlock.Bytes)
		} else {
			skippedBlockTypes = append(skippedBlockTypes, certDERBlock.Type)
		}
	}

	skippedBlockTypes = skippedBlockTypes[:0]
	var keyDERBlock *pem.Block
	for {
		keyDERBlock, keyPEMBlock = pem.Decode(keyPEMBlock)
		if keyDERBlock == nil {
			if len(skippedBlockTypes) == 0 {
				_ = errors.New("tls: failed to find any PEM data in key input")
			}
			if len(skippedBlockTypes) == 1 && skippedBlockTypes[0] == "CERTIFICATE" {
				_ = errors.New("tls: found a certificate rather than a key in the PEM for the private key")
			}
			_ = fmt.Errorf("tls: failed to find PEM block with type ending in \"PRIVATE KEY\" in key input after skipping PEM blocks of the following types: %v", skippedBlockTypes)
		}
		if keyDERBlock.Type == "PRIVATE KEY" || strings.HasSuffix(keyDERBlock.Type, " PRIVATE KEY") {
			break
		}
		skippedBlockTypes = append(skippedBlockTypes, keyDERBlock.Type)
	}

	pk, err := x509.ParseECPrivateKey(keyDERBlock.Bytes)
	if err != nil {
		fmt.Println(err)
	}
	cert.PrivateKey = pk

	return cert, nil
}

func loadX509Certificate(filename string) (*x509.Certificate, error) {
	certPEMBlock, err := os.ReadFile(filename)
	if err != nil {
		return nil, fmt.Errorf("loadX509Certificate read: ")
	}
	block, _ := pem.Decode([]byte(certPEMBlock))
	if block == nil {
		return nil, fmt.Errorf("failed to parse certificate PEM")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse certificate: " + err.Error())
	}
	return cert, nil
}

func VerifyConnection(cs tls.ConnectionState) error {
	matchingCert, _ := loadX509Certificate("testdata/matching-cert.pem")
	cs.PeerCertificates[0] = matchingCert
	return nil
}

func main() {
	http.HandleFunc("/", func(w http.ResponseWriter, req *http.Request) {
		io.WriteString(w, "Hello, TLS!\n")
	})

	// mismatch, err := LoadX509KeyPair("testdata/gh-cert.pem", "testdata/key.pem")

	matched, err := tls.LoadX509KeyPair("testdata/matching-cert.pem", "testdata/key.pem")
	if err != nil {
		log.Fatal(err)
	}
	cfg := &tls.Config{
		Certificates: []tls.Certificate{matched},
	}

	srv := &http.Server{
		Addr:         ":8443",
		TLSConfig:    cfg,
		ReadTimeout:  time.Minute,
		WriteTimeout: time.Minute,
	}

	go func() {
		log.Fatal(srv.ListenAndServeTLS("", ""))

	}()

	fakeCert, _ := loadX509Certificate("testdata/gh-cert.pem")
	cfg.Certificates[0].Certificate[0] = fakeCert.Raw

	time.Sleep(5 * time.Second)
	good_cfg := &tls.Config{
		VerifyConnection:   VerifyConnection,
		InsecureSkipVerify: true,
		MaxVersion:         tls.VersionTLS12,
	}

	tr := &http.Transport{}
	tr.TLSClientConfig = good_cfg
	client := &http.Client{Transport: tr}
	resp, err := client.Get("https://127.0.0.1:8443")
	if err != nil {
		panic("failed to connect: " + err.Error())
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		panic("failed to read: " + err.Error())
	}
	fmt.Printf("%s", body)
}
