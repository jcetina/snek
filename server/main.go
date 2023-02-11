package main

import (
	"errors"
	"flag"
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

func main() {
	ourCert := flag.String("our-cert", "../certs/our-cert.pem", "certificate to use for actual encryption")
	ourKey := flag.String("our-key", "../certs/our-key.pem", "key to use for actual encryption")
	theirCert := flag.String("their-cert", "../certs/their-cert.pem", "certificate we want to impersonate")
	listenPort := flag.Int("listen-port", 8443, "port to listen on")

	flag.Parse()

	matched, err := tls.LoadX509KeyPair(*ourCert, *ourKey)
	if err != nil {
		log.Fatal(err)
	}
	cfg := &tls.Config{
		Certificates: []tls.Certificate{matched},
	}

	theirX509Cert, _ := loadX509Certificate(*theirCert)
	cfg.Certificates[0].Certificate[0] = theirX509Cert.Raw
	http.HandleFunc("/", func(w http.ResponseWriter, req *http.Request) {
		io.WriteString(w, fmt.Sprintf("Hello from %s!\n", *&theirX509Cert.Subject.CommonName))
	})
	srv := &http.Server{
		Addr:         fmt.Sprintf(":%d", *listenPort),
		TLSConfig:    cfg,
		ReadTimeout:  time.Minute,
		WriteTimeout: time.Minute,
	}

	log.Fatal(srv.ListenAndServeTLS("", ""))

}
