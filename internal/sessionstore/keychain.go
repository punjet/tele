package sessionstore

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"

	"github.com/gotd/td/session"
)

// keychainService is the generic-password service every tele item is filed
// under; the account (the state directory) tells them apart.
const keychainService = "tele"

const securityBin = "/usr/bin/security"

// exitNotFound is what security exits with when the item does not exist
// (errSecItemNotFound).
const exitNotFound = 44

// maxSecretLen is how long the encoded secret may be. `security -i` reads one
// line of about 4000 characters and silently cuts the rest off, and a session
// is around 4 KB, so it is compressed first; one that still does not fit is
// refused rather than stored truncated.
const maxSecretLen = 3900

// compressedPrefix marks an item holding gzip, then base64. An item without it
// is plain base64.
const compressedPrefix = "z:"

// Runner runs the security tool: stdin is fed to it, and it returns stdout and
// the exit status. A tool that could not be started returns an error and a
// status of -1. A test replaces it so the real Keychain is never touched.
type Runner func(ctx context.Context, stdin string, args ...string) (stdout []byte, exit int, err error)

// RunSecurity runs /usr/bin/security.
func RunSecurity(ctx context.Context, stdin string, args ...string) ([]byte, int, error) {
	cmd := exec.CommandContext(ctx, securityBin, args...)
	if stdin != "" {
		cmd.Stdin = strings.NewReader(stdin)
	}
	var out, errOut bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &errOut
	err := cmd.Run()
	var ee *exec.ExitError
	switch {
	case err == nil:
		return out.Bytes(), 0, nil
	case errors.As(err, &ee):
		return out.Bytes(), ee.ExitCode(), fmt.Errorf("security: %w: %s", err, strings.TrimSpace(errOut.String()))
	default:
		return nil, -1, fmt.Errorf("security: %w", err)
	}
}

// Keychain keeps the session as a generic-password item in the login Keychain,
// gzipped and base64-encoded, under service "tele" and the state directory as the account.
//
// It goes through /usr/bin/security rather than the Security framework so the
// build stays free of cgo. The secret never appears in argv, where ps would
// show it: a write feeds its command to `security -i` on stdin.
type Keychain struct {
	service string
	account string
	run     Runner
}

// NewKeychain returns the store for the state directory account. A nil run is
// RunSecurity.
func NewKeychain(account string, run Runner) *Keychain {
	return newKeychain(keychainService, account, run)
}

func newKeychain(service, account string, run Runner) *Keychain {
	if run == nil {
		run = RunSecurity
	}
	return &Keychain{service: service, account: account, run: run}
}

func (k *Keychain) LoadSession(ctx context.Context) ([]byte, error) {
	out, exit, err := k.run(ctx, "", "find-generic-password", "-s", k.service, "-a", k.account, "-w")
	if exit == exitNotFound {
		return nil, session.ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("read session from keychain: %w", err)
	}
	data, err := decodeSecret(strings.TrimSpace(string(out)))
	if err != nil {
		return nil, fmt.Errorf("read session from keychain: %w", err)
	}
	if len(data) == 0 {
		return nil, session.ErrNotFound
	}
	return data, nil
}

func (k *Keychain) StoreSession(ctx context.Context, data []byte) error {
	secret, err := encodeSecret(data)
	if err != nil {
		return fmt.Errorf("write session to keychain: %w", err)
	}
	cmd := "add-generic-password -U -s " + quote(k.service) + " -a " + quote(k.account) +
		" -w " + quote(secret) + "\n"
	if _, _, err := k.run(ctx, cmd, "-i"); err != nil {
		return fmt.Errorf("write session to keychain: %w", err)
	}
	// security -i reports a failed command on its output, not always through
	// its exit status, so the write is checked by reading it back.
	got, err := k.LoadSession(ctx)
	if err != nil {
		return fmt.Errorf("write session to keychain: not readable afterwards: %w", err)
	}
	if !bytes.Equal(got, data) {
		return errors.New("write session to keychain: item read back differs from what was written")
	}
	return nil
}

func (k *Keychain) Remove(ctx context.Context) error {
	_, exit, err := k.run(ctx, "", "delete-generic-password", "-s", k.service, "-a", k.account)
	if exit == exitNotFound {
		return nil
	}
	if err != nil {
		return fmt.Errorf("remove session from keychain: %w", err)
	}
	return nil
}

// ImportFile moves a session out of the file at path into the Keychain, once:
// when the Keychain has none and the file does. The file goes only after the
// item reads back as the file's bytes, so a failed import leaves the session
// where it was. It reports whether it imported.
func (k *Keychain) ImportFile(ctx context.Context, path string) (bool, error) {
	if _, err := k.LoadSession(ctx); err == nil {
		return false, nil
	} else if !errors.Is(err, session.ErrNotFound) {
		return false, err
	}
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("import session: %w", err)
	}
	if len(data) == 0 {
		return false, nil
	}
	if err := k.StoreSession(ctx, data); err != nil {
		return false, fmt.Errorf("import session: %w", err)
	}
	if err := os.Remove(path); err != nil {
		return true, fmt.Errorf("import session: imported, but removing %s: %w", path, err)
	}
	return true, nil
}

// quote makes s one word of a `security -i` command line: in double quotes,
// with backslash and quote escaped.
func quote(s string) string {
	r := strings.NewReplacer(`\`, `\\`, `"`, `\"`)
	return `"` + r.Replace(s) + `"`
}

func encodeSecret(data []byte) (string, error) {
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	if _, err := zw.Write(data); err != nil {
		return "", err
	}
	if err := zw.Close(); err != nil {
		return "", err
	}
	secret := compressedPrefix + base64.StdEncoding.EncodeToString(buf.Bytes())
	if len(secret) > maxSecretLen {
		return "", fmt.Errorf("session is %d bytes encoded, more than the %d the keychain tool takes", len(secret), maxSecretLen)
	}
	return secret, nil
}

func decodeSecret(secret string) ([]byte, error) {
	raw, ok := strings.CutPrefix(secret, compressedPrefix)
	b, err := base64.StdEncoding.DecodeString(raw)
	if err != nil {
		return nil, fmt.Errorf("item is not base64: %w", err)
	}
	if !ok {
		return b, nil
	}
	zr, err := gzip.NewReader(bytes.NewReader(b))
	if err != nil {
		return nil, fmt.Errorf("item is not gzip: %w", err)
	}
	data, err := io.ReadAll(zr)
	if err != nil {
		return nil, fmt.Errorf("item is not gzip: %w", err)
	}
	return data, nil
}
