package main

import (
	"crypto/tls"
	"crypto/x509"
	"flag"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/kabouelrous/distributed-secrets/internal/playground"
)

func main() {
	addr := flag.String("addr", "127.0.0.1:3000", "loopback UI address")
	service := flag.String("service", "https://127.0.0.1:8443", "secrets HTTPS service")
	ca := flag.String("ca", "", "trusted service CA PEM file")
	labDir := flag.String("cluster-dir", "", "run three disposable local processes using this data directory")
	binary := flag.String("server-binary", "./bin/secrets-server", "service executable for managed cluster")
	flag.Parse()
	host, _, err := net.SplitHostPort(*addr)
	if err != nil || net.ParseIP(host) == nil || !net.ParseIP(host).IsLoopback() {
		log.Fatal("UI address must be a loopback IP and port")
	}
	upstream, err := url.Parse(*service)
	if err != nil || upstream.Scheme != "https" || upstream.Host == "" {
		log.Fatal("service must be an HTTPS URL")
	}
	pool, err := x509.SystemCertPool()
	if err != nil {
		pool = x509.NewCertPool()
	}
	if *ca != "" {
		pem, err := os.ReadFile(*ca)
		if err != nil {
			log.Fatal(err)
		}
		if !pool.AppendCertsFromPEM(pem) {
			log.Fatal("invalid CA certificate")
		}
	}
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.TLSClientConfig = &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}
	transport.ResponseHeaderTimeout = 30 * time.Second
	var lab *playground.Lab
	if *labDir != "" {
		lab, err = playground.NewLab(*labDir, *binary)
		if err != nil {
			log.Fatal(err)
		}
		defer lab.Close()
	}
	server := &http.Server{Addr: *addr, Handler: playground.Handler(upstream, transport, lab), ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 15 * time.Second, WriteTimeout: 35 * time.Second, IdleTimeout: 60 * time.Second}
	log.Printf("Secrets playground: http://%s (service: %s)", *addr, *service)
	signals := make(chan os.Signal, 1)
	signal.Notify(signals, os.Interrupt, syscall.SIGTERM)
	go func() { <-signals; _ = server.Close() }()
	if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		log.Print(err)
	}
}
