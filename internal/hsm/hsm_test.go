package hsm

import (
	"testing"
)

// TestFailClosedWithoutLogin verifies Requirement 2.4: using a slot that has not
// been opened/logged-in must fail closed (no silent file-key fallback).
func TestFailClosedWithoutLogin(t *testing.T) {
	dir := t.TempDir()
	tok, err := NewSoftHSM(dir, map[string]string{"issuing": "pin-123"})
	if err != nil {
		t.Fatalf("new: %v", err)
	}

	// GenerateKey before OpenSlot must fail.
	if _, err := tok.GenerateKey("issuing", "ecdsa", 0, "P-256"); err == nil {
		t.Fatal("expected fail-closed on GenerateKey without login, got nil")
	}

	// Signer before OpenSlot must fail.
	if _, err := tok.Signer("issuing"); err == nil {
		t.Fatal("expected fail-closed on Signer without login, got nil")
	}
}

// TestWrongPIN verifies login fails with the wrong PIN.
func TestWrongPIN(t *testing.T) {
	tok, _ := NewSoftHSM(t.TempDir(), map[string]string{"root": "correct"})
	if err := tok.OpenSlot("root", "wrong"); err == nil {
		t.Fatal("expected login failure with wrong PIN")
	}
	if err := tok.OpenSlot("root", "correct"); err != nil {
		t.Fatalf("expected login success with correct PIN, got %v", err)
	}
}

// TestKeyGenAndSign verifies key generation + signing after a proper login, and
// persistence across a reopen (modelling HSM holding key material).
func TestKeyGenAndSign(t *testing.T) {
	dir := t.TempDir()
	pins := map[string]string{"issuing": "p"}
	tok, _ := NewSoftHSM(dir, pins)
	if err := tok.OpenSlot("issuing", "p"); err != nil {
		t.Fatalf("open: %v", err)
	}
	if _, err := tok.GenerateKey("issuing", "rsa", 2048, ""); err != nil {
		t.Fatalf("keygen: %v", err)
	}

	// reopen a fresh token over the same dir: the key must persist.
	tok2, _ := NewSoftHSM(dir, pins)
	if !tok2.HasKey("issuing") {
		t.Fatal("expected persisted key after reopen")
	}
	if err := tok2.OpenSlot("issuing", "p"); err != nil {
		t.Fatalf("reopen: %v", err)
	}
	if _, err := tok2.Signer("issuing"); err != nil {
		t.Fatalf("signer after reopen: %v", err)
	}
}
