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
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

func main() {
	global := flag.NewFlagSet("secretsctl", flag.ExitOnError)
	address := global.String("address", envOr("SECRETS_ADDR", "https://127.0.0.1:8443"), "server URL")
	caFile := global.String("ca-cert", os.Getenv("SECRETS_CA_CERT"), "trusted CA certificate")
	_ = global.Parse(os.Args[1:])
	args := global.Args()
	if len(args) == 0 {
		usage()
	}
	if args[0] == "login" {
		if len(args) != 2 {
			fatal("usage: secretsctl login TOKEN")
		}
		if err := saveToken(args[1]); err != nil {
			fatal(err.Error())
		}
		fmt.Println("Token saved.")
		return
	}
	client, err := newClient(*caFile)
	if err != nil {
		fatal(err.Error())
	}
	token := loadToken()
	command := args[0]
	var method, path string
	var payload any
	switch command {
	case "init":
		method, path, payload = "POST", "/v1/sys/init", map[string]int{"shares": argInt(args, 1, 5), "threshold": argInt(args, 2, 3)}
	case "unseal":
		require(args, 2, "unseal KEY")
		method, path, payload = "POST", "/v1/sys/unseal", map[string]string{"key": args[1]}
	case "status":
		method, path = "GET", "/v1/sys/seal-status"
	case "seal":
		method, path = "POST", "/v1/sys/seal"
	case "put":
		require(args, 3, "put PATH key=value...")
		method, path, payload = "PUT", "/v1/secrets/"+escapePath(args[1]), pairs(args[2:])
	case "get":
		require(args, 2, "get PATH [VERSION]")
		method, path = "GET", "/v1/secrets/"+escapePath(args[1])
		if len(args) > 2 {
			path += "?version=" + url.QueryEscape(args[2])
		}
	case "delete":
		require(args, 2, "delete PATH [VERSION]")
		method, path = "DELETE", "/v1/secrets/"+escapePath(args[1])
		if len(args) > 2 {
			path += "?version=" + url.QueryEscape(args[2])
		}
	case "versions":
		require(args, 2, "versions PATH")
		method, path = "GET", "/v1/metadata/"+escapePath(args[1])
	case "token":
		require(args, 4, "token PRINCIPAL TTL POLICY[,POLICY]")
		method, path, payload = "POST", "/v1/auth/tokens", map[string]any{"principal": map[string]any{"id": args[1], "policies": strings.Split(args[3], ",")}, "ttl": args[2]}
	case "policy":
		require(args, 3, "policy NAME FILE.json")
		data, err := os.ReadFile(args[2])
		if err != nil {
			fatal(err.Error())
		}
		if err = json.Unmarshal(data, &payload); err != nil {
			fatal(err.Error())
		}
		method, path = "PUT", "/v1/policies/"+url.PathEscape(args[1])
	case "lease":
		require(args, 3, "lease PATH TTL")
		method, path, payload = "POST", "/v1/leases/"+escapePath(args[1]), map[string]any{"ttl": args[2], "renewable": true}
	case "renew":
		require(args, 3, "renew LEASE_ID TTL")
		method, path, payload = "POST", "/v1/lease-renew/"+url.PathEscape(args[1]), map[string]string{"ttl": args[2]}
	case "revoke":
		require(args, 2, "revoke LEASE_ID")
		method, path, payload = "POST", "/v1/lease-revoke/"+url.PathEscape(args[1]), map[string]string{}
	case "dynamic-postgres":
		require(args, 3, "dynamic-postgres ROLE TTL")
		method, path, payload = "POST", "/v1/dynamic/postgres/"+url.PathEscape(args[1]), map[string]string{"ttl": args[2]}
	case "rotate":
		require(args, 2, "rotate PATH")
		method, path, payload = "POST", "/v1/rotate/"+escapePath(args[1]), map[string]string{}
	case "rotation-retry":
		require(args, 2, "rotation-retry ID")
		method, path, payload = "POST", "/v1/rotations/"+url.PathEscape(args[1])+"/retry", map[string]string{}
	default:
		fatal("unknown command: " + command)
	}
	var body io.Reader
	if payload != nil {
		encoded, err := json.Marshal(payload)
		if err != nil {
			fatal(err.Error())
		}
		body = bytes.NewReader(encoded)
	}
	req, err := http.NewRequest(method, strings.TrimRight(*address, "/")+path, body)
	if err != nil {
		fatal(err.Error())
	}
	if payload != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
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
	pool, err := x509.SystemCertPool()
	if err != nil || pool == nil {
		pool = x509.NewCertPool()
	}
	if caFile != "" {
		pem, err := os.ReadFile(caFile)
		if err != nil {
			return nil, err
		}
		if !pool.AppendCertsFromPEM(pem) {
			return nil, errors.New("CA certificate contains no certificates")
		}
	}
	return &http.Client{Timeout: 30 * time.Second, Transport: &http.Transport{TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: pool}}}, nil
}
func tokenFile() string {
	if value := os.Getenv("SECRETS_TOKEN_FILE"); value != "" {
		return value
	}
	config, err := os.UserConfigDir()
	if err != nil {
		return ""
	}
	return filepath.Join(config, "distributed-secrets", "token")
}
func saveToken(value string) error {
	path := tokenFile()
	if path == "" {
		return errors.New("cannot determine token file")
	}
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return err
	}
	return os.WriteFile(path, []byte(value), 0600)
}
func loadToken() string {
	if value := os.Getenv("SECRETS_TOKEN"); value != "" {
		return value
	}
	data, _ := os.ReadFile(tokenFile())
	return strings.TrimSpace(string(data))
}
func pairs(args []string) map[string]string {
	value := map[string]string{}
	for _, pair := range args {
		key, val, ok := strings.Cut(pair, "=")
		if !ok || key == "" {
			fatal("invalid key=value: " + pair)
		}
		value[key] = val
	}
	return value
}
func escapePath(value string) string {
	parts := strings.Split(value, "/")
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
func argInt(args []string, index, fallback int) int {
	if len(args) <= index {
		return fallback
	}
	value, err := strconv.Atoi(args[index])
	if err != nil {
		fatal("expected integer: " + args[index])
	}
	return value
}
func require(args []string, count int, usage string) {
	if len(args) < count {
		fatal("usage: secretsctl " + usage)
	}
}
func usage() {
	fmt.Fprintln(os.Stderr, "usage: secretsctl [flags] init|unseal|status|login|put|get|delete|versions|token|policy|lease|renew|revoke|dynamic-postgres|rotate ...")
	os.Exit(2)
}
func fatal(message string) { _, _ = fmt.Fprintln(os.Stderr, "error:", message); os.Exit(1) }
