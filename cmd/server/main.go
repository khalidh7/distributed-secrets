package main

import (
	"crypto/tls"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/kabouelrous/distributed-secrets/internal/api"
	"github.com/kabouelrous/distributed-secrets/internal/cluster"
	"github.com/kabouelrous/distributed-secrets/internal/dynamic"
	"github.com/kabouelrous/distributed-secrets/internal/raft"
)

func main() {
	addr := flag.String("addr", "127.0.0.1:8443", "public HTTPS listen address")
	dataDir := flag.String("data-dir", "./data", "persistent data directory")
	sealDir := flag.String("seal-dir", "", "seal metadata directory (defaults to data-dir)")
	certFile := flag.String("tls-cert", "", "public PEM TLS certificate")
	keyFile := flag.String("tls-key", "", "public PEM TLS private key")
	nodeID := flag.String("node-id", "", "cluster node ID")
	raftAddr := flag.String("raft-addr", "", "mTLS Raft listen address")
	peersFlag := flag.String("peers", "", "comma-separated id=https://host:port peers")
	nodeCert := flag.String("node-cert", "", "node certificate")
	nodeKey := flag.String("node-key", "", "node private key")
	clusterCA := flag.String("cluster-ca", "", "cluster CA")
	postgresURL := flag.String("postgres-url", os.Getenv("SECRETS_POSTGRES_URL"), "PostgreSQL provider URL")
	electionMin := flag.Duration("election-min", 350*time.Millisecond, "minimum Raft election timeout")
	electionMax := flag.Duration("election-max", 700*time.Millisecond, "maximum Raft election timeout")
	heartbeat := flag.Duration("heartbeat", 100*time.Millisecond, "Raft heartbeat interval")
	flag.Parse()
	if *heartbeat <= 0 || *electionMin <= *heartbeat || *electionMax <= *electionMin {
		fatal("require 0 < heartbeat < election-min < election-max")
	}
	if *certFile == "" || *keyFile == "" {
		fatal("--tls-cert and --tls-key are required")
	}
	runtime, err := api.NewRuntime(api.Config{DataDir: *dataDir, SealDir: *sealDir, Logger: slog.Default(), NodeID: *nodeID})
	if err != nil {
		fatal(err.Error())
	}
	if *postgresURL != "" {
		if err = runtime.SetPostgres(&dynamic.Postgres{URL: *postgresURL, Prefix: "ds"}); err != nil {
			fatal(err.Error())
		}
	}
	var node *raft.Node
	var nodeMu sync.Mutex
	if *nodeID != "" {
		if *raftAddr == "" || *nodeCert == "" || *nodeKey == "" || *clusterCA == "" {
			fatal("cluster mode requires --raft-addr, --node-cert, --node-key, and --cluster-ca")
		}
		peers, peerIDs, identities, err := parsePeers(*peersFlag)
		if err != nil {
			fatal(err.Error())
		}
		serverTLS, clientTLS, err := cluster.LoadMTLS(*nodeCert, *nodeKey, *clusterCA, identities)
		if err != nil {
			fatal(err.Error())
		}
		client := &http.Client{Timeout: 2 * time.Second, Transport: &http.Transport{TLSClientConfig: clientTLS.Config}}
		startRaft := func() error {
			nodeMu.Lock()
			defer nodeMu.Unlock()
			if node != nil {
				return nil
			}
			listener, err := tls.Listen("tcp", *raftAddr, serverTLS)
			if err != nil {
				return err
			}
			started, err := raft.NewNode(raft.Config{ID: *nodeID, Peers: peerIDs, DataDir: filepath.Join(*dataDir, "raft"), Transport: raft.NewHTTPTransport(peers, client), FSM: fsmAdapter{runtime}, ElectionMin: *electionMin, ElectionMax: *electionMax, Heartbeat: *heartbeat})
			if err != nil {
				_ = listener.Close()
				return fmt.Errorf("start raft: %w", err)
			}
			node = started
			runtime.SetProposer(node)
			node.Start()
			raftServer := &http.Server{Addr: *raftAddr, Handler: node.Handler(), TLSConfig: serverTLS, ReadHeaderTimeout: 5 * time.Second}
			go func() {
				slog.Info("raft mTLS listening", "addr", *raftAddr, "node", *nodeID)
				if serveErr := raftServer.Serve(listener); serveErr != nil && serveErr != http.ErrServerClosed {
					fatal(serveErr.Error())
				}
			}()
			return nil
		}
		if err = runtime.SetUnsealHook(startRaft); err != nil {
			fatal(err.Error())
		}
	}
	defer func() {
		nodeMu.Lock()
		current := node
		nodeMu.Unlock()
		if current != nil {
			current.Stop()
		}
	}()
	if supplied := os.Getenv("SECRETS_UNSEAL_KEYS"); supplied != "" {
		if err = runtime.OperatorUnseal(strings.Split(supplied, ",")); err != nil {
			fatal("startup unseal: " + err.Error())
		}
	}
	server := &http.Server{Addr: *addr, Handler: runtime, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 15 * time.Second, WriteTimeout: 30 * time.Second, IdleTimeout: 60 * time.Second}
	slog.Info("secrets HTTPS listening", "addr", *addr, "node", *nodeID)
	if err = server.ListenAndServeTLS(*certFile, *keyFile); err != nil && err != http.ErrServerClosed {
		fatal(err.Error())
	}
}

type fsmAdapter struct{ server *api.Server }

func (f fsmAdapter) Apply(data []byte) error   { return f.server.ApplyRaft(data) }
func (f fsmAdapter) Snapshot() ([]byte, error) { return f.server.Snapshot() }
func (f fsmAdapter) Restore(data []byte) error { return f.server.Restore(data) }
func parsePeers(raw string) (map[string]string, []string, map[string]bool, error) {
	peers := map[string]string{}
	ids := []string{}
	identities := map[string]bool{}
	if raw == "" {
		return peers, ids, identities, nil
	}
	for _, item := range strings.Split(raw, ",") {
		id, address, ok := strings.Cut(item, "=")
		if !ok || id == "" || !strings.HasPrefix(address, "https://") {
			return nil, nil, nil, fmt.Errorf("invalid peer %q", item)
		}
		peers[id] = address
		ids = append(ids, id)
		host := strings.TrimPrefix(address, "https://")
		host = strings.Split(host, ":")[0]
		identities[host] = true
	}
	return peers, ids, identities, nil
}
func fatal(message string) { _, _ = fmt.Fprintln(os.Stderr, "error:", message); os.Exit(1) }
