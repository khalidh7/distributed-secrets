package main

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
)

func main() {
	global := flag.NewFlagSet("secretsctl", flag.ExitOnError)
	address := global.String("address", envOr("SECRETS_ADDR", "https://127.0.0.1:8443"), "server URL")
	caFile := global.String("ca-cert", os.Getenv("SECRETS_CA_CERT"), "trusted CA certificate")
	_ = global.Parse(os.Args[1:])
	args := global.Args()
	if len(args) < 2 {
		fatal("usage: secretsctl [flags] put|get|delete PATH [key=value ...]")
	}
	client, err := newClient(*caFile)
	if err != nil {
		fatal(err.Error())
	}
	command, path := args[0], args[1]
	endpoint := strings.TrimRight(*address, "/") + "/v1/secrets/" + escapePath(path)
	var method string
	var body io.Reader
	switch command {
	case "put":
		if len(args) < 3 {
			fatal("put requires at least one key=value")
		}
		value := make(map[string]string)
		for _, pair := range args[2:] {
			key, val, ok := strings.Cut(pair, "=")
			if !ok || key == "" {
				fatal("invalid key=value: " + pair)
			}
			value[key] = val
		}
		encoded, _ := json.Marshal(value)
		method, body = http.MethodPut, bytes.NewReader(encoded)
	case "get":
		method = http.MethodGet
	case "delete":
		method = http.MethodDelete
	default:
		fatal("unknown command: " + command)
	}
	req, _ := http.NewRequest(method, endpoint, body)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := client.Do(req)
	if err != nil {
		fatal(err.Error())
	}
	defer resp.Body.Close()
	response, _ := io.ReadAll(io.LimitReader(resp.Body, 2<<20))
	if resp.StatusCode >= 300 {
		fatal(fmt.Sprintf("server returned %s: %s", resp.Status, strings.TrimSpace(string(response))))
	}
	if len(response) > 0 {
		var pretty bytes.Buffer
		if json.Indent(&pretty, response, "", "  ") == nil {
			fmt.Println(pretty.String())
		} else {
			fmt.Print(string(response))
		}
	}
}

func newClient(caFile string) (*http.Client, error) {
	if caFile == "" {
		return nil, errors.New("--ca-cert or SECRETS_CA_CERT is required")
	}
	pem, err := os.ReadFile(caFile)
	if err != nil {
		return nil, err
	}
	pool, err := x509.SystemCertPool()
	if err != nil || pool == nil {
		pool = x509.NewCertPool()
	}
	if !pool.AppendCertsFromPEM(pem) {
		return nil, errors.New("CA certificate contains no certificates")
	}
	return &http.Client{Timeout: 15 * time.Second, Transport: &http.Transport{TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: pool}}}, nil
}

func escapePath(path string) string {
	parts := strings.Split(path, "/")
	for i := range parts {
		parts[i] = url.PathEscape(parts[i])
	}
	return strings.Join(parts, "/")
}

func envOr(name, fallback string) string {
	if value := os.Getenv(name); value != "" {
		return value
	}
	return fallback
}

func fatal(message string) {
	_, _ = fmt.Fprintln(os.Stderr, "error:", message)
	os.Exit(1)
}
