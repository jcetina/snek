package main

import (
	"flag"
	"fmt"
	"io"
	"log"
	"os"

	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"net/http"
)

type verifier func(cs tls.ConnectionState) error

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
func make_verifier(path string) (verifier, error) {
	matchingCert, err := loadX509Certificate(path)
	if err != nil {
		return nil, fmt.Errorf("failed to load certificate: " + err.Error())
	}
	return func(cs tls.ConnectionState) error {
		cs.PeerCertificates[0] = matchingCert
		return nil
	}, nil
}

func main() {
	ourCert := flag.String("our-cert", "../certs/our-cert.pem", "certificate to use for actual encryption")
	fakedFqdn := flag.String("faked-fqdn", "", "fqdn we want to appear as")
	ourUrl := flag.String("our-url", "", "real url we want to connect to")

	flag.Parse()
	if *fakedFqdn == "" {
		log.Fatal("faked-fqdn is required")
	}
	if *ourUrl == "" {
		log.Fatal("our-url is required")
	}
	VerifyConnection, err := make_verifier(*ourCert)
	if err != nil {
		log.Fatal("failed to make verifier: " + err.Error())
	}
	client_config := &tls.Config{
		VerifyConnection:   VerifyConnection,
		InsecureSkipVerify: true,
		MaxVersion:         tls.VersionTLS12,
		ServerName:         *fakedFqdn,
	}

	tr := &http.Transport{}
	tr.TLSClientConfig = client_config
	client := &http.Client{Transport: tr}
	resp, err := client.Get(*ourUrl)
	if err != nil {
		log.Fatal("failed to connect: " + err.Error())
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		log.Fatal("failed to read: " + err.Error())
	}
	fmt.Printf("%s", body)
}
