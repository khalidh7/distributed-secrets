package audit

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"sync"
	"time"
)

type Event struct {
	Timestamp    time.Time `json:"timestamp"`
	Principal    string    `json:"principal"`
	Operation    string    `json:"operation"`
	Path         string    `json:"path,omitempty"`
	Result       string    `json:"result"`
	RequestID    string    `json:"request_id"`
	PreviousHash string    `json:"previous_hash,omitempty"`
	Hash         string    `json:"hash"`
}
type Log struct {
	mu       sync.Mutex
	file     *os.File
	previous string
}

func Open(path string) (*Log, error) {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_RDWR, 0600)
	if err != nil {
		return nil, err
	}
	l := &Log{file: f}
	info, _ := f.Stat()
	if info != nil && info.Size() > 0 {
		if err := Verify(path); err != nil {
			f.Close()
			return nil, err
		}
	}
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		var e Event
		if json.Unmarshal(scanner.Bytes(), &e) == nil {
			l.previous = e.Hash
		}
	}
	if err := scanner.Err(); err != nil {
		f.Close()
		return nil, err
	}
	return l, nil
}
func (l *Log) Append(e Event) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	e.Timestamp = time.Now().UTC()
	e.PreviousHash = l.previous
	e.Hash = ""
	canonical, _ := json.Marshal(e)
	sum := sha256.Sum256(canonical)
	e.Hash = hex.EncodeToString(sum[:])
	line, _ := json.Marshal(e)
	line = append(line, '\n')
	if _, err := l.file.Write(line); err != nil {
		return err
	}
	if err := l.file.Sync(); err != nil {
		return err
	}
	l.previous = e.Hash
	return nil
}
func (l *Log) Close() error { return l.file.Close() }
func Verify(path string) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	previous := ""
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		var e Event
		if json.Unmarshal(scanner.Bytes(), &e) != nil {
			return errors.New("invalid audit event")
		}
		stored := e.Hash
		if e.PreviousHash != previous {
			return errors.New("audit chain is broken")
		}
		e.Hash = ""
		canonical, _ := json.Marshal(e)
		sum := sha256.Sum256(canonical)
		if stored != hex.EncodeToString(sum[:]) {
			return errors.New("audit event was modified")
		}
		previous = stored
	}
	return scanner.Err()
}
