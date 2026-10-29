package raft

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math/rand"
	"net/http"
	"sync"
	"time"
)

type Role string

const (
	Follower  Role = "follower"
	Candidate Role = "candidate"
	Leader    Role = "leader"
)

var ErrStopped = errors.New("raft node stopped")

type NotLeaderError struct{ LeaderID string }

func (e NotLeaderError) Error() string {
	if e.LeaderID == "" {
		return "not the leader"
	}
	return "not the leader; leader is " + e.LeaderID
}

type FSM interface {
	Apply([]byte) error
	Snapshot() ([]byte, error)
	Restore([]byte) error
}
type Config struct {
	ID                                  string
	Peers                               []string
	DataDir                             string
	Transport                           Transport
	FSM                                 FSM
	ElectionMin, ElectionMax, Heartbeat time.Duration
	SnapshotThreshold                   uint64
}
type RequestVoteRequest struct {
	Term         uint64 `json:"term"`
	CandidateID  string `json:"candidate_id"`
	LastLogIndex uint64 `json:"last_log_index"`
	LastLogTerm  uint64 `json:"last_log_term"`
}
type RequestVoteResponse struct {
	Term        uint64 `json:"term"`
	VoteGranted bool   `json:"vote_granted"`
}
type AppendEntriesRequest struct {
	Term         uint64  `json:"term"`
	LeaderID     string  `json:"leader_id"`
	PrevLogIndex uint64  `json:"prev_log_index"`
	PrevLogTerm  uint64  `json:"prev_log_term"`
	Entries      []Entry `json:"entries"`
	LeaderCommit uint64  `json:"leader_commit"`
}
type AppendEntriesResponse struct {
	Term       uint64 `json:"term"`
	Success    bool   `json:"success"`
	MatchIndex uint64 `json:"match_index"`
}
type InstallSnapshotRequest struct {
	Term     uint64   `json:"term"`
	LeaderID string   `json:"leader_id"`
	Snapshot Snapshot `json:"snapshot"`
}
type InstallSnapshotResponse struct {
	Term    uint64 `json:"term"`
	Success bool   `json:"success"`
}

// Event contains operational metadata only; never command payloads or keys.
type Event struct {
	ID    uint64    `json:"id"`
	At    time.Time `json:"at"`
	Kind  string    `json:"kind"`
	Node  string    `json:"node"`
	Peer  string    `json:"peer,omitempty"`
	Term  uint64    `json:"term"`
	Index uint64    `json:"index,omitempty"`
}
type LogPosition struct {
	Index    uint64 `json:"index"`
	Term     uint64 `json:"term"`
	Snapshot bool   `json:"snapshot,omitempty"`
}
type Status struct {
	VotedFor            string            `json:"voted_for"`
	ElectionRemainingMS int64             `json:"election_remaining_ms"`
	LastHeartbeat       time.Time         `json:"last_heartbeat"`
	Events              []Event           `json:"events"`
	Log                 []LogPosition     `json:"log"`
	MatchIndex          map[string]uint64 `json:"match_index"`
	ID                  string            `json:"id"`
	Role                Role              `json:"role"`
	Term                uint64            `json:"term"`
	LeaderID            string            `json:"leader_id"`
	CommitIndex         uint64            `json:"commit_index"`
	LastApplied         uint64            `json:"last_applied"`
	LastLogIndex        uint64            `json:"last_log_index"`
}

type Node struct {
	mu                       sync.Mutex
	proposalMu               sync.Mutex
	config                   Config
	wal                      *WAL
	role                     Role
	term                     uint64
	votedFor, leaderID       string
	entries                  []Entry
	commitIndex, lastApplied uint64
	snapshot                 *Snapshot
	nextIndex, matchIndex    map[string]uint64
	electionDeadline         time.Time
	stop                     chan struct{}
	done                     chan struct{}
	events                   []Event
	eventSequence            uint64
	lastHeartbeat            time.Time
}

func NewNode(config Config) (*Node, error) {
	if config.ID == "" || config.FSM == nil || config.Transport == nil {
		return nil, errors.New("raft id, transport, and FSM are required")
	}
	if config.ElectionMin == 0 {
		config.ElectionMin = 350 * time.Millisecond
	}
	if config.ElectionMax == 0 {
		config.ElectionMax = 700 * time.Millisecond
	}
	if config.Heartbeat == 0 {
		config.Heartbeat = 100 * time.Millisecond
	}
	if config.SnapshotThreshold == 0 {
		config.SnapshotThreshold = 1000
	}
	wal, entries, hard, snapshot, err := OpenWAL(config.DataDir)
	if err != nil {
		return nil, err
	}
	n := &Node{config: config, wal: wal, role: Follower, term: hard.CurrentTerm, votedFor: hard.VotedFor, entries: entries, commitIndex: hard.CommitIndex, snapshot: snapshot, nextIndex: map[string]uint64{}, matchIndex: map[string]uint64{}, stop: make(chan struct{}), done: make(chan struct{})}
	if snapshot != nil {
		if err = config.FSM.Restore(snapshot.Data); err != nil {
			wal.Close()
			return nil, err
		}
		n.lastApplied = snapshot.LastIndex
	}
	if n.commitIndex > n.lastIndex() {
		n.commitIndex = n.lastIndex()
	}
	if err = n.applyCommittedLocked(); err != nil {
		wal.Close()
		return nil, err
	}
	n.resetElectionLocked()
	return n, nil
}
func (n *Node) Start() { go n.run() }
func (n *Node) Stop() {
	select {
	case <-n.stop:
	default:
		close(n.stop)
	}
	<-n.done
	_ = n.wal.Close()
}
func (n *Node) run() {
	defer close(n.done)
	heartbeat := time.NewTicker(n.config.Heartbeat)
	tick := time.NewTicker(25 * time.Millisecond)
	defer heartbeat.Stop()
	defer tick.Stop()
	for {
		select {
		case <-n.stop:
			return
		case <-tick.C:
			n.mu.Lock()
			expired := n.role != Leader && time.Now().After(n.electionDeadline)
			n.mu.Unlock()
			if expired {
				go n.startElection()
			}
		case <-heartbeat.C:
			n.mu.Lock()
			leader := n.role == Leader
			n.mu.Unlock()
			if leader {
				go n.replicateAll()
			}
		}
	}
}
func (n *Node) startElection() {
	n.mu.Lock()
	if n.role == Leader || time.Now().Before(n.electionDeadline) {
		n.mu.Unlock()
		return
	}
	n.role = Candidate
	n.term++
	n.recordLocked("election_started", "", n.lastIndex())
	term := n.term
	n.votedFor = n.config.ID
	n.leaderID = ""
	n.resetElectionLocked()
	_ = n.persistHardLocked()
	lastIndex, lastTerm := n.lastIndex(), n.termAt(n.lastIndex())
	n.mu.Unlock()
	votes := 1
	var mu sync.Mutex
	var wg sync.WaitGroup
	for _, peer := range n.config.Peers {
		wg.Add(1)
		go func(peer string) {
			defer wg.Done()
			ctx, cancel := context.WithTimeout(context.Background(), n.config.ElectionMin)
			defer cancel()
			resp, err := n.config.Transport.RequestVote(ctx, peer, RequestVoteRequest{Term: term, CandidateID: n.config.ID, LastLogIndex: lastIndex, LastLogTerm: lastTerm})
			if err != nil {
				return
			}
			n.mu.Lock()
			defer n.mu.Unlock()
			if resp.Term > n.term {
				n.becomeFollowerLocked(resp.Term, "")
				return
			}
			if n.role == Candidate && n.term == term && resp.VoteGranted {
				mu.Lock()
				votes++
				mu.Unlock()
			}
		}(peer)
	}
	wg.Wait()
	n.mu.Lock()
	defer n.mu.Unlock()
	if n.role == Candidate && n.term == term && votes >= n.quorum() {
		n.role = Leader
		n.recordLocked("leader_elected", "", n.lastIndex())
		n.leaderID = n.config.ID
		last := n.lastIndex()
		for _, peer := range n.config.Peers {
			n.nextIndex[peer] = last + 1
			n.matchIndex[peer] = 0
		}
		go n.replicateAll()
	}
}
func (n *Node) Propose(ctx context.Context, data []byte) error {
	n.proposalMu.Lock()
	defer n.proposalMu.Unlock()
	n.mu.Lock()
	if n.role != Leader {
		leader := n.leaderID
		n.mu.Unlock()
		return NotLeaderError{leader}
	}
	entry := Entry{Index: n.lastIndex() + 1, Term: n.term, Data: append([]byte(nil), data...)}
	if err := n.wal.Append(entry); err != nil {
		n.mu.Unlock()
		return err
	}
	entry.Checksum = entryChecksum(entry)
	n.entries = append(n.entries, entry)
	n.recordLocked("log_appended", "", entry.Index)
	target := entry.Index
	n.mu.Unlock()
	ticker := time.NewTicker(20 * time.Millisecond)
	defer ticker.Stop()
	for {
		n.replicateAll()
		n.mu.Lock()
		if n.commitIndex >= target {
			err := n.applyCommittedLocked()
			n.mu.Unlock()
			return err
		}
		if n.role != Leader {
			leader := n.leaderID
			n.mu.Unlock()
			return NotLeaderError{leader}
		}
		n.mu.Unlock()
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-n.stop:
			return ErrStopped
		case <-ticker.C:
		}
	}
}
func (n *Node) replicateAll() {
	var wg sync.WaitGroup
	for _, peer := range n.config.Peers {
		wg.Add(1)
		go func(peer string) { defer wg.Done(); n.replicatePeer(peer) }(peer)
	}
	wg.Wait()
	n.mu.Lock()
	defer n.mu.Unlock()
	if n.role != Leader {
		return
	}
	for index := n.lastIndex(); index > n.commitIndex; index-- {
		if n.termAt(index) != n.term {
			continue
		}
		count := 1
		for _, peer := range n.config.Peers {
			if n.matchIndex[peer] >= index {
				count++
			}
		}
		if count >= n.quorum() {
			n.commitIndex = index
			n.recordLocked("quorum_commit", "", index)
			_ = n.persistHardLocked()
			_ = n.applyCommittedLocked()
			break
		}
	}
}
func (n *Node) replicatePeer(peer string) {
	n.mu.Lock()
	if n.role != Leader {
		n.mu.Unlock()
		return
	}
	next := n.nextIndex[peer]
	term := n.term
	if n.snapshot != nil && next <= n.snapshot.LastIndex {
		request := InstallSnapshotRequest{Term: term, LeaderID: n.config.ID, Snapshot: *n.snapshot}
		n.mu.Unlock()
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		resp, err := n.config.Transport.InstallSnapshot(ctx, peer, request)
		if err == nil {
			n.mu.Lock()
			defer n.mu.Unlock()
			if resp.Term > n.term {
				n.becomeFollowerLocked(resp.Term, "")
			} else if resp.Success && n.role == Leader && n.term == term {
				n.matchIndex[peer] = request.Snapshot.LastIndex
				n.nextIndex[peer] = request.Snapshot.LastIndex + 1
			}
		}
		return
	}
	prev := next - 1
	entries := n.entriesFrom(next)
	request := AppendEntriesRequest{Term: term, LeaderID: n.config.ID, PrevLogIndex: prev, PrevLogTerm: n.termAt(prev), Entries: entries, LeaderCommit: n.commitIndex}
	n.mu.Unlock()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	resp, err := n.config.Transport.AppendEntries(ctx, peer, request)
	if err != nil {
		return
	}
	n.mu.Lock()
	defer n.mu.Unlock()
	if resp.Term > n.term {
		n.becomeFollowerLocked(resp.Term, "")
		return
	}
	if n.role != Leader || n.term != term {
		return
	}
	if resp.Success {
		if len(entries) > 0 && resp.MatchIndex > n.matchIndex[peer] {
			n.recordLocked("replication_ack", peer, resp.MatchIndex)
		}
		n.matchIndex[peer] = resp.MatchIndex
		n.nextIndex[peer] = resp.MatchIndex + 1
	} else if n.nextIndex[peer] > 1 {
		n.nextIndex[peer]--
	}
}
func (n *Node) RequestVote(request RequestVoteRequest) RequestVoteResponse {
	n.mu.Lock()
	defer n.mu.Unlock()
	if request.Term < n.term {
		return RequestVoteResponse{Term: n.term}
	}
	if request.Term > n.term {
		n.becomeFollowerLocked(request.Term, "")
	}
	upToDate := request.LastLogTerm > n.termAt(n.lastIndex()) || (request.LastLogTerm == n.termAt(n.lastIndex()) && request.LastLogIndex >= n.lastIndex())
	if (n.votedFor == "" || n.votedFor == request.CandidateID) && upToDate {
		n.votedFor = request.CandidateID
		n.recordLocked("vote_granted", request.CandidateID, n.lastIndex())
		n.resetElectionLocked()
		_ = n.persistHardLocked()
		return RequestVoteResponse{Term: n.term, VoteGranted: true}
	}
	return RequestVoteResponse{Term: n.term}
}
func (n *Node) AppendEntries(request AppendEntriesRequest) AppendEntriesResponse {
	n.mu.Lock()
	defer n.mu.Unlock()
	if request.Term < n.term {
		return AppendEntriesResponse{Term: n.term}
	}
	n.becomeFollowerLocked(request.Term, request.LeaderID)
	n.lastHeartbeat = time.Now().UTC()
	n.resetElectionLocked()
	if request.PrevLogIndex > n.lastIndex() || n.termAt(request.PrevLogIndex) != request.PrevLogTerm {
		return AppendEntriesResponse{Term: n.term}
	}
	for _, entry := range request.Entries {
		if entry.Index <= n.lastIndex() {
			if n.termAt(entry.Index) == entry.Term {
				continue
			}
			n.truncateFromLocked(entry.Index)
		}
		entry.Checksum = entryChecksum(entry)
		if err := n.wal.Append(entry); err != nil {
			return AppendEntriesResponse{Term: n.term}
		}
		n.entries = append(n.entries, entry)
		n.recordLocked("entry_received", request.LeaderID, entry.Index)
	}
	if request.LeaderCommit > n.commitIndex {
		n.commitIndex = min(request.LeaderCommit, n.lastIndex())
		n.recordLocked("commit_applied", request.LeaderID, n.commitIndex)
		_ = n.persistHardLocked()
		if err := n.applyCommittedLocked(); err != nil {
			return AppendEntriesResponse{Term: n.term}
		}
	}
	return AppendEntriesResponse{Term: n.term, Success: true, MatchIndex: n.lastIndex()}
}
func (n *Node) InstallSnapshot(request InstallSnapshotRequest) InstallSnapshotResponse {
	n.mu.Lock()
	defer n.mu.Unlock()
	if request.Term < n.term {
		return InstallSnapshotResponse{Term: n.term}
	}
	n.becomeFollowerLocked(request.Term, request.LeaderID)
	if !validSnapshot(request.Snapshot) || request.Snapshot.LastIndex <= n.lastApplied {
		return InstallSnapshotResponse{Term: n.term, Success: false}
	}
	if err := n.config.FSM.Restore(request.Snapshot.Data); err != nil {
		return InstallSnapshotResponse{Term: n.term}
	}
	n.snapshot = &request.Snapshot
	n.entries = n.entriesFrom(request.Snapshot.LastIndex + 1)
	n.commitIndex = request.Snapshot.LastIndex
	n.lastApplied = request.Snapshot.LastIndex
	_ = n.wal.SaveSnapshot(request.Snapshot)
	_ = n.wal.Rewrite(n.entries)
	_ = n.persistHardLocked()
	return InstallSnapshotResponse{Term: n.term, Success: true}
}
func (n *Node) Status() Status {
	n.mu.Lock()
	defer n.mu.Unlock()
	positions := make([]LogPosition, 0, 12)
	if n.snapshot != nil && len(n.entries) < 12 {
		positions = append(positions, LogPosition{Index: n.snapshot.LastIndex, Term: n.snapshot.LastTerm, Snapshot: true})
	}
	start := max(0, len(n.entries)-12)
	for _, entry := range n.entries[start:] {
		positions = append(positions, LogPosition{Index: entry.Index, Term: entry.Term})
	}
	matches := make(map[string]uint64, len(n.matchIndex))
	if n.role == Leader {
		for peer, index := range n.matchIndex {
			matches[peer] = index
		}
	}
	remaining := max(int64(0), time.Until(n.electionDeadline).Milliseconds())
	if n.role == Leader {
		remaining = 0
	}
	return Status{ID: n.config.ID, Role: n.role, Term: n.term, LeaderID: n.leaderID, CommitIndex: n.commitIndex, LastApplied: n.lastApplied, LastLogIndex: n.lastIndex(), VotedFor: n.votedFor, ElectionRemainingMS: remaining, LastHeartbeat: n.lastHeartbeat, Events: append([]Event(nil), n.events...), Log: positions, MatchIndex: matches}
}
func (n *Node) recordLocked(kind, peer string, index uint64) {
	n.eventSequence++
	n.events = append(n.events, Event{ID: n.eventSequence, At: time.Now().UTC(), Kind: kind, Node: n.config.ID, Peer: peer, Term: n.term, Index: index})
	if len(n.events) > 120 {
		n.events = append([]Event(nil), n.events[len(n.events)-120:]...)
	}
}
func (n *Node) Leader() string { n.mu.Lock(); defer n.mu.Unlock(); return n.leaderID }
func (n *Node) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /internal/raft/vote", func(w http.ResponseWriter, r *http.Request) {
		var in RequestVoteRequest
		if json.NewDecoder(r.Body).Decode(&in) != nil {
			http.Error(w, "bad request", 400)
			return
		}
		_ = json.NewEncoder(w).Encode(n.RequestVote(in))
	})
	mux.HandleFunc("POST /internal/raft/append", func(w http.ResponseWriter, r *http.Request) {
		var in AppendEntriesRequest
		if json.NewDecoder(r.Body).Decode(&in) != nil {
			http.Error(w, "bad request", 400)
			return
		}
		_ = json.NewEncoder(w).Encode(n.AppendEntries(in))
	})
	mux.HandleFunc("POST /internal/raft/snapshot", func(w http.ResponseWriter, r *http.Request) {
		var in InstallSnapshotRequest
		if json.NewDecoder(r.Body).Decode(&in) != nil {
			http.Error(w, "bad request", 400)
			return
		}
		_ = json.NewEncoder(w).Encode(n.InstallSnapshot(in))
	})
	mux.HandleFunc("GET /internal/raft/status", func(w http.ResponseWriter, r *http.Request) { _ = json.NewEncoder(w).Encode(n.Status()) })
	return mux
}
func (n *Node) becomeFollowerLocked(term uint64, leader string) {
	changed := term > n.term
	if n.role != Follower {
		n.recordLocked("stepped_down", leader, n.lastIndex())
	}
	n.role = Follower
	n.leaderID = leader
	if changed {
		n.term = term
		n.votedFor = ""
		_ = n.persistHardLocked()
	}
	n.resetElectionLocked()
}
func (n *Node) resetElectionLocked() {
	spread := n.config.ElectionMax - n.config.ElectionMin
	if spread <= 0 {
		spread = time.Millisecond
	}
	n.electionDeadline = time.Now().Add(n.config.ElectionMin + time.Duration(rand.Int63n(int64(spread))))
}
func (n *Node) persistHardLocked() error {
	return n.wal.SaveHardState(HardState{CurrentTerm: n.term, VotedFor: n.votedFor, CommitIndex: n.commitIndex})
}
func (n *Node) quorum() int { return (len(n.config.Peers)+1)/2 + 1 }
func (n *Node) lastIndex() uint64 {
	if len(n.entries) > 0 {
		return n.entries[len(n.entries)-1].Index
	}
	if n.snapshot != nil {
		return n.snapshot.LastIndex
	}
	return 0
}
func (n *Node) termAt(index uint64) uint64 {
	if index == 0 {
		return 0
	}
	if n.snapshot != nil && index == n.snapshot.LastIndex {
		return n.snapshot.LastTerm
	}
	for _, e := range n.entries {
		if e.Index == index {
			return e.Term
		}
	}
	return 0
}
func (n *Node) entriesFrom(index uint64) []Entry {
	for i, e := range n.entries {
		if e.Index >= index {
			return append([]Entry(nil), n.entries[i:]...)
		}
	}
	return nil
}
func (n *Node) truncateFromLocked(index uint64) {
	kept := n.entries[:0]
	for _, e := range n.entries {
		if e.Index < index {
			kept = append(kept, e)
		}
	}
	n.entries = kept
	_ = n.wal.Rewrite(n.entries)
}
func (n *Node) applyCommittedLocked() error {
	for n.lastApplied < n.commitIndex {
		next := n.lastApplied + 1
		var data []byte
		for _, e := range n.entries {
			if e.Index == next {
				data = e.Data
				break
			}
		}
		if data == nil {
			return fmt.Errorf("committed entry %d missing", next)
		}
		if err := n.config.FSM.Apply(data); err != nil {
			return err
		}
		n.lastApplied = next
	}
	if n.lastApplied > 0 && (n.snapshot == nil || n.lastApplied-n.snapshot.LastIndex >= n.config.SnapshotThreshold) {
		data, err := n.config.FSM.Snapshot()
		if err == nil {
			snapshot := Snapshot{LastIndex: n.lastApplied, LastTerm: n.termAt(n.lastApplied), Data: data}
			snapshot.Checksum = snapshotChecksum(snapshot)
			if n.wal.SaveSnapshot(snapshot) == nil {
				n.snapshot = &snapshot
				n.entries = n.entriesFrom(snapshot.LastIndex + 1)
				_ = n.wal.Rewrite(n.entries)
			}
		}
	}
	return nil
}
func min(a, b uint64) uint64 {
	if a < b {
		return a
	}
	return b
}
