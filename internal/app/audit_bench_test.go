package app

import (
	"bytes"
	"net/http"
	"path/filepath"
	"testing"
	"time"
)

func BenchmarkAuthenticateClientKey(b *testing.B) {
	path := filepath.Join(b.TempDir(), "keys.json")
	store := newAPIKeyStore(path, "bench-secret-key-123456")
	var lastPlain string
	for i := 0; i < 10; i++ {
		_, plain, err := store.createClientKey("client-" + string(rune('a'+i)))
		if err != nil {
			b.Fatal(err)
		}
		lastPlain = plain
	}
	// Disable disk persistence path to isolate pure CPU/alloc overhead of authentication,
	// and benchmark full path separately below.
	store.path = ""

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		if _, ok := store.authenticateClientKey(lastPlain); !ok {
			b.Fatal("expected valid client key")
		}
	}
}

func BenchmarkRecordResultHealthyDisk(b *testing.B) {
	path := filepath.Join(b.TempDir(), "keys.json")
	store := newAPIKeyStore(path, "bench-secret-key-123456")
	view, err := store.add("Primary", "sk-benchmark-secret-key-1234", true)
	if err != nil {
		b.Fatal(err)
	}

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		store.recordResult(view.ID, http.StatusOK, "OK", 5*time.Minute)
	}
}

func BenchmarkComputeCacheKey(b *testing.B) {
	payload := []byte(`{"model":"gpt-4o","temperature":0,"messages":[{"role":"system","content":"Be concise."},{"role":"user","content":"Explain Go memory model in 3 sentences."}],"max_completion_tokens":256,"reasoning_effort":"low"}`)
	obj, err := decodeObject(bytes.Clone(payload))
	if err != nil {
		b.Fatal(err)
	}

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		if _, err := computeCacheKey(obj); err != nil {
			b.Fatal(err)
		}
	}
}
