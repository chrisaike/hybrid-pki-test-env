package httpapi

import (
	"os"
	"testing"

	"github.com/chrisaike/hybrid-pki-test-env/internal/store"
)

func mustStore(t *testing.T, path string) *store.Store {
	t.Helper()
	st, err := store.Open(path)
	if err != nil {
		t.Fatalf("store: %v", err)
	}
	return st
}

func readFile(path string) ([]byte, error) { return os.ReadFile(path) }
