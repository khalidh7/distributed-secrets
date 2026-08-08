package main

import (
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"time"

	"github.com/example/distributed-secrets/internal/api"
	secretcrypto "github.com/example/distributed-secrets/internal/crypto"
	"github.com/example/distributed-secrets/internal/storage"
)

func main() {
	addr := flag.String("addr", "127.0.0.1:8443", "HTTPS listen address")
	dataDir := flag.String("data-dir", "./data", "persistent data directory")
	certFile := flag.String("tls-cert", "", "PEM TLS certificate")
	keyFile := flag.String("tls-key", "", "PEM TLS private key")
	flag.Parse()

	if *certFile == "" || *keyFile == "" {
		fatal("--tls-cert and --tls-key are required")
	}
	encodedKey := os.Getenv("SECRETS_MASTER_KEY")
	if encodedKey == "" {
		fatal("SECRETS_MASTER_KEY is required")
	}
	masterKey, err := secretcrypto.DecodeKey(encodedKey)
	if err != nil {
		fatal(err.Error())
	}
	store, err := storage.Open(*dataDir, masterKey)
	if err != nil {
		fatal(err.Error())
	}

	server := &http.Server{
		Addr:              *addr,
		Handler:           api.New(store, slog.Default()),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      15 * time.Second,
		IdleTimeout:       60 * time.Second,
	}
	slog.Info("secrets server listening", "addr", *addr)
	if err := server.ListenAndServeTLS(*certFile, *keyFile); err != nil && err != http.ErrServerClosed {
		fatal(err.Error())
	}
}

func fatal(message string) {
	_, _ = fmt.Fprintln(os.Stderr, "error:", message)
	os.Exit(1)
}
