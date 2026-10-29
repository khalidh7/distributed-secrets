package raft

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"sync"
	"testing"
	"time"
)

type memoryFSM struct {
	mu     sync.Mutex
	values [][]byte
}

func (f *memoryFSM) Apply(data []byte) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.values = append(f.values, append([]byte(nil), data...))
	return nil
}
func (f *memoryFSM) Snapshot() ([]byte, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []byte
	for _, value := range f.values {
		out = append(out, value...)
		out = append(out, '\n')
	}
	return out, nil
}
func (f *memoryFSM) Restore(data []byte) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.values = nil
	for len(data) > 0 {
		end := 0
		for end < len(data) && data[end] != '\n' {
			end++
		}
		if end > 0 {
			f.values = append(f.values, append([]byte(nil), data[:end]...))
		}
		if end == len(data) {
			break
		}
		data = data[end+1:]
	}
	return nil
}
func (f *memoryFSM) count() int { f.mu.Lock(); defer f.mu.Unlock(); return len(f.values) }

type memoryTransport struct {
	mu    sync.RWMutex
	nodes map[string]*Node
	down  map[string]bool
}

func (t *memoryTransport) node(id string) (*Node, error) {
	t.mu.RLock()
	defer t.mu.RUnlock()
	if t.down[id] {
		return nil, errors.New("node unavailable")
	}
	return t.nodes[id], nil
}
func (t *memoryTransport) RequestVote(_ context.Context, id string, r RequestVoteRequest) (RequestVoteResponse, error) {
	n, e := t.node(id)
	if e != nil {
		return RequestVoteResponse{}, e
	}
	return n.RequestVote(r), nil
}
func (t *memoryTransport) AppendEntries(_ context.Context, id string, r AppendEntriesRequest) (AppendEntriesResponse, error) {
	n, e := t.node(id)
	if e != nil {
		return AppendEntriesResponse{}, e
	}
	return n.AppendEntries(r), nil
}
func (t *memoryTransport) InstallSnapshot(_ context.Context, id string, r InstallSnapshotRequest) (InstallSnapshotResponse, error) {
	n, e := t.node(id)
	if e != nil {
		return InstallSnapshotResponse{}, e
	}
	return n.InstallSnapshot(r), nil
}

func TestElectionReplicationAndLeaderFailure(t *testing.T) {
	transport := &memoryTransport{nodes: map[string]*Node{}, down: map[string]bool{}}
	ids := []string{"a", "b", "c"}
	fsms := map[string]*memoryFSM{}
	for _, id := range ids {
		peers := []string{}
		for _, other := range ids {
			if other != id {
				peers = append(peers, other)
			}
		}
		fsm := &memoryFSM{}
		node, err := NewNode(Config{ID: id, Peers: peers, DataDir: t.TempDir(), Transport: transport, FSM: fsm, ElectionMin: 80 * time.Millisecond, ElectionMax: 160 * time.Millisecond, Heartbeat: 25 * time.Millisecond, SnapshotThreshold: 100})
		if err != nil {
			t.Fatal(err)
		}
		transport.nodes[id] = node
		fsms[id] = fsm
	}
	for _, node := range transport.nodes {
		node.Start()
	}
	defer func() {
		for id, node := range transport.nodes {
			transport.mu.RLock()
			down := transport.down[id]
			transport.mu.RUnlock()
			if !down {
				node.Stop()
			}
		}
	}()
	leader := waitLeader(t, transport, ids)
	if err := leader.Propose(context.Background(), []byte("one")); err != nil {
		t.Fatal(err)
	}
	waitFor(t, 2*time.Second, func() bool {
		for _, fsm := range fsms {
			if fsm.count() != 1 {
				return false
			}
		}
		return true
	})
	failedID := leader.config.ID
	transport.mu.Lock()
	transport.down[failedID] = true
	transport.mu.Unlock()
	leader.Stop()
	remaining := []string{}
	for _, id := range ids {
		if id != failedID {
			remaining = append(remaining, id)
		}
	}
	newLeader := waitLeader(t, transport, remaining)
	if err := newLeader.Propose(context.Background(), []byte("two")); err != nil {
		t.Fatal(err)
	}
	waitFor(t, 2*time.Second, func() bool { return fsms[remaining[0]].count() == 2 && fsms[remaining[1]].count() == 2 })
}
func TestWALRecoveryAndSnapshots(t *testing.T) {
	dir := t.TempDir()
	transport := &memoryTransport{nodes: map[string]*Node{}, down: map[string]bool{}}
	fsm := &memoryFSM{}
	node, err := NewNode(Config{ID: "one", DataDir: dir, Transport: transport, FSM: fsm, ElectionMin: 30 * time.Millisecond, ElectionMax: 60 * time.Millisecond, Heartbeat: 10 * time.Millisecond, SnapshotThreshold: 2})
	if err != nil {
		t.Fatal(err)
	}
	transport.nodes["one"] = node
	node.Start()
	waitLeader(t, transport, []string{"one"})
	for _, value := range []string{"a", "b", "c"} {
		if err = node.Propose(context.Background(), []byte(value)); err != nil {
			t.Fatal(err)
		}
	}
	node.Stop()
	recoveredFSM := &memoryFSM{}
	recovered, err := NewNode(Config{ID: "one", DataDir: dir, Transport: transport, FSM: recoveredFSM})
	if err != nil {
		t.Fatal(err)
	}
	if recoveredFSM.count() != 3 {
		t.Fatalf("restored %d entries", recoveredFSM.count())
	}
	_ = recovered.wal.Close()
}
func waitLeader(t *testing.T, transport *memoryTransport, ids []string) *Node {
	t.Helper()
	var leader *Node
	waitFor(t, 3*time.Second, func() bool {
		leader = nil
		for _, id := range ids {
			node, _ := transport.node(id)
			if node != nil && node.Status().Role == Leader {
				if leader != nil {
					return false
				}
				leader = node
			}
		}
		return leader != nil
	})
	return leader
}
func waitFor(t *testing.T, timeout time.Duration, condition func() bool) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if condition() {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("condition was not met before timeout")
}

func TestTelemetryMetadataIsBoundedAndDetached(t *testing.T) {
	transport := &memoryTransport{nodes: map[string]*Node{}, down: map[string]bool{}}
	node, err := NewNode(Config{ID: "test", DataDir: t.TempDir(), Transport: transport, FSM: &memoryFSM{}})
	if err != nil {
		t.Fatal(err)
	}
	node.Start()
	defer node.Stop()
	node.mu.Lock()
	for i := 0; i < 150; i++ {
		node.recordLocked("vote_granted", "peer", uint64(i))
	}
	node.entries = []Entry{{Index: 1, Term: 1, Data: []byte("must-not-appear-in-telemetry")}}
	node.mu.Unlock()
	status := node.Status()
	if len(status.Events) != 120 || status.Events[0].ID != 31 {
		t.Fatal("event history is not bounded")
	}
	encoded, err := json.Marshal(status)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(encoded, []byte("must-not-appear")) {
		t.Fatal("command payload leaked into telemetry")
	}
	status.Events[0].Kind = "mutated"
	status.Log[0].Term = 99
	fresh := node.Status()
	if fresh.Events[0].Kind == "mutated" || fresh.Log[0].Term == 99 {
		t.Fatal("status exposed mutable internal state")
	}
}
