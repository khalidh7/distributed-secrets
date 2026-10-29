package playground

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/kabouelrous/distributed-secrets/internal/auth"
	clustertls "github.com/kabouelrous/distributed-secrets/internal/cluster"
	"github.com/kabouelrous/distributed-secrets/internal/policy"
	"github.com/kabouelrous/distributed-secrets/internal/raft"
	"github.com/kabouelrous/distributed-secrets/internal/seal"
	"github.com/kabouelrous/distributed-secrets/internal/secretcrypto"
)

type labCredentials struct {
	RootToken string   `json:"root_token"`
	Shares    []string `json:"unseal_keys"`
}
type labProcess struct {
	cmd        *exec.Cmd
	done       chan struct{}
	generation uint64
}
type LabNode struct {
	raft.Status
	Online     bool   `json:"online"`
	Running    bool   `json:"running"`
	Generation uint64 `json:"generation"`
	API        string `json:"api"`
	Error      string `json:"error,omitempty"`
}
type LabSnapshot struct {
	Nodes           []LabNode `json:"nodes"`
	Leader          string    `json:"leader"`
	Online          int       `json:"online"`
	Quorum          int       `json:"quorum"`
	Writable        bool      `json:"writable"`
	Unlocked        bool      `json:"unlocked"`
	UnlockProgress  int       `json:"unlock_progress"`
	UnlockThreshold int       `json:"unlock_threshold"`
	ObservedAt      time.Time `json:"observed_at"`
}

// Lab owns only the three child processes it creates, never arbitrary system PIDs.
type Lab struct {
	mu                sync.Mutex
	pollMu            sync.Mutex
	directory, binary string
	credentials       labCredentials
	client            *http.Client
	processes         map[string]*labProcess
	generations       map[string]uint64
	provided          map[string]bool
	unlocked          bool
	snapshot          LabSnapshot
	cancel            context.CancelFunc
}

var labIDs = []string{"node1", "node2", "node3"}

func NewLab(directory, binary string) (*Lab, error) {
	absolute, err := filepath.Abs(binary)
	if err != nil {
		return nil, err
	}
	l := &Lab{directory: directory, binary: absolute, processes: map[string]*labProcess{}, generations: map[string]uint64{}, provided: map[string]bool{}}
	// Fail before creating or touching state if any required port is already in use.
	for _, port := range []int{8441, 8442, 8443, 7441, 7442, 7443} {
		listener, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", port))
		if err != nil {
			return nil, fmt.Errorf("cluster port %d is unavailable: %w", port, err)
		}
		listener.Close()
	}
	if err := l.bootstrap(); err != nil {
		return nil, err
	}
	certs := filepath.Join(directory, "certs")
	_, clientTLS, err := clustertls.LoadMTLS(filepath.Join(certs, "node1.pem"), filepath.Join(certs, "node1-key.pem"), filepath.Join(certs, "ca.pem"), nil)
	if err != nil {
		return nil, err
	}
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.TLSClientConfig = clientTLS.Config.Clone()
	transport.TLSClientConfig.MinVersion = tls.VersionTLS13
	l.client = &http.Client{Transport: transport, Timeout: 700 * time.Millisecond}
	for _, id := range labIDs {
		if err := l.Start(id); err != nil {
			l.Close()
			return nil, err
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	l.cancel = cancel
	go func() {
		ticker := time.NewTicker(200 * time.Millisecond)
		defer ticker.Stop()
		for {
			l.poll(ctx)
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
			}
		}
	}()
	return l, nil
}
func (l *Lab) bootstrap() error {
	if err := os.MkdirAll(l.directory, 0700); err != nil {
		return err
	}
	manager, err := seal.Open(filepath.Join(l.directory, "seal"))
	if err != nil {
		return err
	}
	defer manager.Seal()
	credentialsPath := filepath.Join(l.directory, "recovery.json")
	data, err := os.ReadFile(credentialsPath)
	if errors.Is(err, os.ErrNotExist) {
		if manager.Status().Initialized {
			return errors.New("lab seal already exists but recovery.json is missing; restore the recovery file or choose a new SECRETS_CLUSTER_DIR")
		}
		result, err := manager.Initialize(5, 3)
		if err != nil {
			return err
		}
		l.credentials = labCredentials{Shares: result.Shares}
		data, err = json.Marshal(l.credentials)
		if err != nil {
			return err
		}
		if err = os.WriteFile(credentialsPath, data, 0600); err != nil {
			return err
		}
	} else if err != nil {
		return err
	} else {
		if err = json.Unmarshal(data, &l.credentials); err != nil {
			return err
		}
		if len(l.credentials.Shares) < 3 || l.credentials.RootToken == "" {
			return errors.New("invalid lab recovery file")
		}
		for _, share := range l.credentials.Shares[:3] {
			if _, err = manager.Unseal(share); err != nil {
				return err
			}
		}
	}
	key, err := manager.Key()
	if err != nil {
		return err
	}
	defer secretcrypto.Zero(key)
	// Keep the operator token stable: Raft recovery restores authentication from
	// its snapshot, so replacing only auth.json on startup would be discarded.
	if l.credentials.RootToken == "" {
		token, err := auth.GenerateToken()
		if err != nil {
			return err
		}
		l.credentials.RootToken = token
	}
	credentialsData, err := json.Marshal(l.credentials)
	if err != nil {
		return err
	}
	if err = os.WriteFile(credentialsPath, credentialsData, 0600); err != nil {
		return err
	}
	for _, id := range labIDs {
		dir := filepath.Join(l.directory, id)
		if err = os.MkdirAll(dir, 0700); err != nil {
			return err
		}
		if _, statErr := os.Stat(filepath.Join(dir, "auth.json")); statErr == nil {
			continue
		} else if !errors.Is(statErr, os.ErrNotExist) {
			return statErr
		}
		identity, openErr := auth.Open(dir, key)
		if openErr != nil {
			return openErr
		}
		err = identity.PutPolicy(policy.Policy{Name: "root", Rules: []policy.Rule{{Path: "**", Capabilities: []string{"sudo"}}}})
		if err == nil {
			err = identity.AddToken(l.credentials.RootToken, auth.Principal{ID: "portfolio-demo", Policies: []string{"root"}}, 12*time.Hour)
		}
		identity.Close()
		if err != nil {
			return err
		}
	}
	return nil
}
func labNumber(id string) int {
	for i, known := range labIDs {
		if id == known {
			return i + 1
		}
	}
	return 0
}
func (l *Lab) Start(id string) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	number := labNumber(id)
	if number == 0 {
		return errors.New("unknown node")
	}
	if process := l.processes[id]; process != nil {
		select {
		case <-process.done:
		default:
			return nil
		}
	}
	certs := filepath.Join(l.directory, "certs")
	peers := []string{}
	for i, peer := range labIDs {
		if peer != id {
			peers = append(peers, fmt.Sprintf("%s=https://localhost:%d", peer, 7441+i))
		}
	}
	cmd := exec.Command(l.binary,
		fmt.Sprintf("--addr=127.0.0.1:%d", 8440+number), "--data-dir="+filepath.Join(l.directory, id), "--seal-dir="+filepath.Join(l.directory, "seal"),
		"--tls-cert="+filepath.Join(certs, id+".pem"), "--tls-key="+filepath.Join(certs, id+"-key.pem"), "--node-id="+id,
		fmt.Sprintf("--raft-addr=127.0.0.1:%d", 7440+number), "--peers="+strings.Join(peers, ","), "--node-cert="+filepath.Join(certs, id+".pem"),
		"--node-key="+filepath.Join(certs, id+"-key.pem"), "--cluster-ca="+filepath.Join(certs, "ca.pem"), "--election-min=1600ms", "--election-max=2800ms", "--heartbeat=300ms")
	// Do not inherit external providers or unrelated unseal material into the sandbox.
	for _, entry := range os.Environ() {
		if !strings.HasPrefix(entry, "SECRETS_UNSEAL_KEYS=") && !strings.HasPrefix(entry, "SECRETS_POSTGRES_URL=") {
			cmd.Env = append(cmd.Env, entry)
		}
	}
	if l.unlocked {
		cmd.Env = append(cmd.Env, "SECRETS_UNSEAL_KEYS="+strings.Join(l.credentials.Shares[:3], ","))
	}
	output, err := os.OpenFile(filepath.Join(l.directory, id, "process.log"), os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	cmd.Stdout = output
	cmd.Stderr = output
	if err = cmd.Start(); err != nil {
		output.Close()
		return err
	}
	l.generations[id]++
	process := &labProcess{cmd: cmd, done: make(chan struct{}), generation: l.generations[id]}
	l.processes[id] = process
	go func() { _ = cmd.Wait(); output.Close(); close(process.done) }()
	return nil
}
func (l *Lab) Stop(id string) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if labNumber(id) == 0 {
		return errors.New("unknown node")
	}
	if process := l.processes[id]; process != nil {
		select {
		case <-process.done:
		default:
			if err := process.cmd.Process.Kill(); err != nil && !errors.Is(err, os.ErrProcessDone) {
				return err
			}
			<-process.done
		}
		delete(l.processes, id)
	}
	// Immediately invalidate cached leadership so requests cannot route to a killed process.
	for i := range l.snapshot.Nodes {
		if l.snapshot.Nodes[i].ID == id {
			l.snapshot.Nodes[i].Online = false
			l.snapshot.Nodes[i].Running = false
		}
	}
	l.snapshot = summarizeLab(l.snapshot.Nodes)
	l.decorateSnapshotLocked()
	return nil
}

func (l *Lab) decorateSnapshotLocked() {
	l.snapshot.Unlocked = l.unlocked
	l.snapshot.UnlockProgress = len(l.provided)
	l.snapshot.UnlockThreshold = 3
}

func (l *Lab) validShare(share string) bool {
	for _, candidate := range l.credentials.Shares {
		if share == candidate {
			return true
		}
	}
	return false
}

// Unlock submits one real Shamir share to each running sealed node. Every node
// reconstructs the root independently when the third distinct share arrives.
func (l *Lab) Unlock(share string) (int, bool, error) {
	share = strings.TrimSpace(share)
	if !l.validShare(share) {
		return 0, false, errors.New("share is not part of this demo recovery set")
	}
	l.mu.Lock()
	if l.unlocked {
		progress := len(l.provided)
		l.mu.Unlock()
		return progress, true, nil
	}
	if l.provided[share] {
		progress := len(l.provided)
		l.mu.Unlock()
		return progress, false, errors.New("that share was already submitted; choose a distinct share")
	}
	l.mu.Unlock()

	payload, _ := json.Marshal(map[string]string{"key": share})
	for i, id := range labIDs {
		request, err := http.NewRequest(http.MethodPost, fmt.Sprintf("https://localhost:%d/v1/sys/unseal", 8441+i), bytes.NewReader(payload))
		if err != nil {
			return 0, false, err
		}
		request.Header.Set("Content-Type", "application/json")
		response, err := l.client.Do(request)
		if err != nil {
			return 0, false, fmt.Errorf("submit share to %s: %w", id, err)
		}
		body, _ := io.ReadAll(io.LimitReader(response.Body, 4096))
		response.Body.Close()
		if response.StatusCode != http.StatusOK {
			return 0, false, fmt.Errorf("submit share to %s: %s: %s", id, response.Status, strings.TrimSpace(string(body)))
		}
	}

	l.mu.Lock()
	l.provided[share] = true
	if len(l.provided) >= 3 {
		l.unlocked = true
	}
	l.decorateSnapshotLocked()
	progress, unlocked := len(l.provided), l.unlocked
	l.mu.Unlock()
	return progress, unlocked, nil
}

// RestartDemo returns to the sealed operator-login screen while preserving all
// encrypted stores and WAL files. It is intended for repeated screen takes.
func (l *Lab) RestartDemo() error {
	for _, id := range labIDs {
		if err := l.Stop(id); err != nil {
			return err
		}
	}
	l.mu.Lock()
	l.unlocked = false
	l.provided = map[string]bool{}
	l.decorateSnapshotLocked()
	l.mu.Unlock()
	for _, id := range labIDs {
		if err := l.Start(id); err != nil {
			return err
		}
	}
	return nil
}
func (l *Lab) Close() {
	if l.cancel != nil {
		l.cancel()
	}
	for _, id := range labIDs {
		_ = l.Stop(id)
	}
	if l.client != nil {
		l.client.CloseIdleConnections()
	}
}
func summarizeLab(nodes []LabNode) LabSnapshot {
	snapshot := LabSnapshot{Nodes: nodes, Quorum: 2, ObservedAt: time.Now().UTC()}
	var term uint64
	for _, node := range nodes {
		if node.Online {
			snapshot.Online++
			term = max(term, node.Term)
		}
	}
	leaders := 0
	for _, node := range nodes {
		if node.Online && node.Role == raft.Leader && node.Term == term {
			snapshot.Leader = node.ID
			leaders++
		}
	}
	if leaders != 1 {
		snapshot.Leader = ""
	}
	snapshot.Writable = snapshot.Online >= 2 && snapshot.Leader != ""
	return snapshot
}
func (l *Lab) poll(ctx context.Context) {
	l.pollMu.Lock()
	defer l.pollMu.Unlock()
	nodes := make([]LabNode, 3)
	var wg sync.WaitGroup
	for i, id := range labIDs {
		l.mu.Lock()
		process := l.processes[id]
		generation := l.generations[id]
		previous := raft.Status{ID: id}
		for _, old := range l.snapshot.Nodes {
			if old.ID == id {
				previous = old.Status
				if old.Generation != generation {
					previous.Events = nil
				}
			}
		}
		l.mu.Unlock()
		nodes[i] = LabNode{Status: previous, Generation: generation, API: fmt.Sprintf("https://127.0.0.1:%d", 8441+i)}
		if process == nil {
			continue
		}
		select {
		case <-process.done:
			continue
		default:
			nodes[i].Running = true
		}
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			request, err := http.NewRequestWithContext(ctx, "GET", fmt.Sprintf("https://localhost:%d/internal/raft/status", 7441+i), nil)
			if err != nil {
				return
			}
			response, err := l.client.Do(request)
			if err != nil {
				nodes[i].Error = "Raft endpoint unavailable"
				return
			}
			defer response.Body.Close()
			var status raft.Status
			if response.StatusCode != 200 || json.NewDecoder(response.Body).Decode(&status) != nil {
				nodes[i].Error = "Raft status unavailable"
				return
			}
			nodes[i].Status = status
			nodes[i].Online = true
		}(i)
	}
	wg.Wait()
	l.mu.Lock()
	defer l.mu.Unlock()
	// A stop or restart may have happened while the network requests were in flight.
	for i, id := range labIDs {
		p := l.processes[id]
		if p == nil || p.generation != nodes[i].Generation {
			nodes[i].Online = false
			nodes[i].Running = p != nil
		}
	}
	l.snapshot = summarizeLab(nodes)
	l.decorateSnapshotLocked()
}
func (l *Lab) Snapshot() LabSnapshot {
	l.mu.Lock()
	defer l.mu.Unlock()
	snapshot := l.snapshot
	snapshot.Nodes = append([]LabNode(nil), snapshot.Nodes...)
	return snapshot
}
func labJSON(w http.ResponseWriter, code int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(value)
}
func (l *Lab) Register(mux *http.ServeMux, transport http.RoundTripper) {
	mux.HandleFunc("GET /playground/cluster", func(w http.ResponseWriter, r *http.Request) { labJSON(w, 200, l.Snapshot()) })
	mux.HandleFunc("GET /playground/session", func(w http.ResponseWriter, r *http.Request) {
		l.mu.Lock()
		response := map[string]any{"mode": "cluster", "shares": append([]string(nil), l.credentials.Shares...), "threshold": 3, "progress": len(l.provided), "unlocked": l.unlocked}
		if l.unlocked {
			response["token"] = l.credentials.RootToken
		}
		l.mu.Unlock()
		labJSON(w, 200, response)
	})
	mux.HandleFunc("POST /playground/unlock", func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasPrefix(r.Header.Get("Content-Type"), "application/json") {
			labJSON(w, 415, map[string]string{"error": "application/json required"})
			return
		}
		var body struct {
			Share string `json:"share"`
		}
		if json.NewDecoder(io.LimitReader(r.Body, 16<<10)).Decode(&body) != nil {
			labJSON(w, 400, map[string]string{"error": "invalid unlock request"})
			return
		}
		progress, unlocked, err := l.Unlock(body.Share)
		if err != nil {
			labJSON(w, 400, map[string]any{"error": err.Error(), "progress": progress})
			return
		}
		response := map[string]any{"progress": progress, "threshold": 3, "unlocked": unlocked}
		if unlocked {
			response["token"] = l.credentials.RootToken
		}
		labJSON(w, 200, response)
	})
	mux.HandleFunc("POST /playground/demo/restart", func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasPrefix(r.Header.Get("Content-Type"), "application/json") {
			labJSON(w, 415, map[string]string{"error": "application/json required"})
			return
		}
		if err := l.RestartDemo(); err != nil {
			labJSON(w, 500, map[string]string{"error": err.Error()})
			return
		}
		labJSON(w, 200, map[string]bool{"unlocked": false})
	})
	mux.HandleFunc("POST /playground/nodes/{id}/{action}", func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasPrefix(r.Header.Get("Content-Type"), "application/json") {
			labJSON(w, 415, map[string]string{"error": "application/json required"})
			return
		}
		id, action := r.PathValue("id"), r.PathValue("action")
		var err error
		switch action {
		case "stop":
			err = l.Stop(id)
		case "start":
			err = l.Start(id)
		default:
			err = errors.New("unknown action")
		}
		if err != nil {
			labJSON(w, 400, map[string]string{"error": err.Error()})
			return
		}
		labJSON(w, 200, map[string]string{"node": id, "action": action})
	})
	mux.Handle("/v1/", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/v1/sys/") && r.Method != "GET" {
			labJSON(w, 403, map[string]string{"error": "This disposable lab manages node initialization and unsealing automatically."})
			return
		}
		snapshot := l.Snapshot()
		if !snapshot.Unlocked {
			labJSON(w, 423, map[string]string{"error": "Cluster is sealed. Complete the 3-of-5 Shamir operator login first."})
			return
		}
		leader := snapshot.Leader
		if r.Method != "GET" && !snapshot.Writable {
			labJSON(w, 503, map[string]string{"error": "No writable majority. At least 2 of 3 nodes and an elected leader are required. This request was not submitted."})
			return
		}
		if leader == "" && r.Method == "GET" {
			for _, node := range snapshot.Nodes {
				if node.Online {
					leader = node.ID
					break
				}
			}
		}
		if leader == "" {
			labJSON(w, 503, map[string]string{"error": "No node available. Restart a node from the cluster controls."})
			return
		}
		upstream, _ := url.Parse(fmt.Sprintf("https://127.0.0.1:%d", 8440+labNumber(leader)))
		proxy := httputil.NewSingleHostReverseProxy(upstream)
		proxy.Transport = transport
		proxy.ErrorHandler = func(w http.ResponseWriter, r *http.Request, err error) {
			labJSON(w, 502, map[string]string{"error": "Node became unavailable. A write outcome may be uncertain; inspect version history before retrying."})
		}
		ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
		defer cancel()
		w.Header().Set("X-Playground-Node", leader)
		proxy.ServeHTTP(w, r.WithContext(ctx))
	}))
}
