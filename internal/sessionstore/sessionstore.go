// Package sessionstore is where the Telegram session (the MTProto auth key) is
// kept: a file in the state directory, or, on macOS, an item in the login
// Keychain.
package sessionstore

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/gotd/td/session"
)

// The values telegram.session_storage takes.
const (
	KindFile     = "file"
	KindKeychain = "keychain"
)

// Store is a place a session lives. LoadSession reports session.ErrNotFound
// when there is none.
type Store interface {
	session.Storage
	// Remove deletes the session; one that is already gone is not an error.
	Remove(ctx context.Context) error
}

// File keeps the session in the file at path, as tele always has.
func File(path string) Store {
	return &fileStore{inner: session.FileStorage{Path: path}}
}

type fileStore struct {
	inner session.FileStorage
}

func (s *fileStore) LoadSession(ctx context.Context) ([]byte, error) {
	return s.inner.LoadSession(ctx)
}

func (s *fileStore) StoreSession(ctx context.Context, data []byte) error {
	if err := os.MkdirAll(filepath.Dir(s.inner.Path), 0o700); err != nil {
		return err
	}
	return s.inner.StoreSession(ctx, data)
}

func (s *fileStore) Remove(context.Context) error {
	if err := os.Remove(s.inner.Path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("remove %s: %w", s.inner.Path, err)
	}
	return nil
}

// Open returns the store telegram.session_storage names. A file store lives at
// sessionFile; a Keychain one is filed under the state directory's absolute
// path, so two state directories never share a session.
func Open(kind, stateDir, sessionFile string) Store {
	if kind != KindKeychain {
		return File(sessionFile)
	}
	account, err := filepath.Abs(stateDir)
	if err != nil {
		account = stateDir
	}
	return NewKeychain(account, nil)
}

// Prepare gets the store ready before the account opens: with the Keychain, a
// session.json from an earlier run is imported into it and removed, so
// nothing downstream sees the account as logged out. It does nothing for a
// file store. The caller holds the state directory.
func Prepare(ctx context.Context, store Store, sessionFile string) (imported bool, err error) {
	kc, ok := store.(*Keychain)
	if !ok {
		return false, nil
	}
	return kc.ImportFile(ctx, sessionFile)
}
