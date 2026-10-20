// Package store is the certificate lifecycle status store. It records issued,
// renewed, and revoked certificates and backs OCSP/CRL responses.
//
// The test tier uses a JSON-file store (zero external dependencies, easy to
// snapshot for rollback tests). Production maps this to RDS/DynamoDB/etc. behind
// the same interface.
package store

import (
	"encoding/json"
	"fmt"
	"os"
	"sync"
	"time"
)

// Status values for a certificate's lifecycle.
const (
	StatusValid   = "valid"
	StatusRenewed = "renewed"
	StatusRevoked = "revoked"
)

// Record is one certificate's lifecycle state.
type Record struct {
	ID         string    `json:"id"`
	Serial     string    `json:"serial"` // decimal string of the serial number
	Subject    string    `json:"subject"`
	Profile    string    `json:"profile"`
	IssuingCA  string    `json:"issuing_ca"`
	Status     string    `json:"status"`
	IssuedAt   time.Time `json:"issued_at"`
	RevokedAt  time.Time `json:"revoked_at,omitempty"`
	ReasonCode int       `json:"revocation_reason,omitempty"`
	PEM        string    `json:"pem"`
	RenewedTo  string    `json:"renewed_to,omitempty"`
}

// Store is a concurrency-safe JSON-backed status store.
type Store struct {
	mu   sync.RWMutex
	path string
	data map[string]*Record // keyed by ID
}

// Open loads (or creates) the store at path.
func Open(path string) (*Store, error) {
	s := &Store{path: path, data: map[string]*Record{}}
	if b, err := os.ReadFile(path); err == nil {
		var recs []*Record
		if err := json.Unmarshal(b, &recs); err != nil {
			return nil, fmt.Errorf("store: parse %s: %w", path, err)
		}
		for _, r := range recs {
			s.data[r.ID] = r
		}
	}
	return s, nil
}

// Put inserts or updates a record and flushes to disk.
func (s *Store) Put(r *Record) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.data[r.ID] = r
	return s.flushLocked()
}

// Get returns a record by ID.
func (s *Store) Get(id string) (*Record, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	r, ok := s.data[id]
	return r, ok
}

// BySerial returns a record by its decimal serial string.
func (s *Store) BySerial(serial string) (*Record, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, r := range s.data {
		if r.Serial == serial {
			return r, true
		}
	}
	return nil, false
}

// Revoke marks a certificate revoked (idempotent).
func (s *Store) Revoke(id string, reason int) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	r, ok := s.data[id]
	if !ok {
		return fmt.Errorf("store: unknown certificate id %q", id)
	}
	if r.Status != StatusRevoked {
		r.Status = StatusRevoked
		r.RevokedAt = time.Now().UTC()
		r.ReasonCode = reason
	}
	return s.flushLocked()
}

// Revoked returns all revoked records (for CRL/OCSP).
func (s *Store) Revoked() []*Record {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var out []*Record
	for _, r := range s.data {
		if r.Status == StatusRevoked {
			out = append(out, r)
		}
	}
	return out
}

// All returns all records.
func (s *Store) All() []*Record {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]*Record, 0, len(s.data))
	for _, r := range s.data {
		out = append(out, r)
	}
	return out
}

// Snapshot writes the current store to a separate path (for rollback tests).
func (s *Store) Snapshot(path string) error {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.writeTo(path)
}

// Restore replaces current state from a snapshot file (rollback).
func (s *Store) Restore(path string) error {
	b, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	var recs []*Record
	if err := json.Unmarshal(b, &recs); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.data = map[string]*Record{}
	for _, r := range recs {
		s.data[r.ID] = r
	}
	return s.flushLocked()
}

func (s *Store) flushLocked() error { return s.writeTo(s.path) }

func (s *Store) writeTo(path string) error {
	recs := make([]*Record, 0, len(s.data))
	for _, r := range s.data {
		recs = append(recs, r)
	}
	b, err := json.MarshalIndent(recs, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, b, 0o644)
}
