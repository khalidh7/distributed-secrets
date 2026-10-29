package raft

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

type Transport interface {
	RequestVote(context.Context, string, RequestVoteRequest) (RequestVoteResponse, error)
	AppendEntries(context.Context, string, AppendEntriesRequest) (AppendEntriesResponse, error)
	InstallSnapshot(context.Context, string, InstallSnapshotRequest) (InstallSnapshotResponse, error)
}
type HTTPTransport struct {
	Peers  map[string]string
	Client *http.Client
}

func NewHTTPTransport(peers map[string]string, client *http.Client) *HTTPTransport {
	if client == nil {
		client = &http.Client{Timeout: 2 * time.Second}
	}
	return &HTTPTransport{Peers: peers, Client: client}
}
func (t *HTTPTransport) RequestVote(ctx context.Context, peer string, in RequestVoteRequest) (out RequestVoteResponse, err error) {
	err = t.call(ctx, peer, "/internal/raft/vote", in, &out)
	return
}
func (t *HTTPTransport) AppendEntries(ctx context.Context, peer string, in AppendEntriesRequest) (out AppendEntriesResponse, err error) {
	err = t.call(ctx, peer, "/internal/raft/append", in, &out)
	return
}
func (t *HTTPTransport) InstallSnapshot(ctx context.Context, peer string, in InstallSnapshotRequest) (out InstallSnapshotResponse, err error) {
	err = t.call(ctx, peer, "/internal/raft/snapshot", in, &out)
	return
}
func (t *HTTPTransport) call(ctx context.Context, peer, path string, in, out any) error {
	base, ok := t.Peers[peer]
	if !ok {
		return fmt.Errorf("unknown peer %s", peer)
	}
	body, _ := json.Marshal(in)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, strings.TrimRight(base, "/")+path, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := t.Client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		message, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return fmt.Errorf("peer %s: %s: %s", peer, resp.Status, string(message))
	}
	return json.NewDecoder(resp.Body).Decode(out)
}
