//go:build darwin

package sessionstore

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"testing"
	"time"

	"github.com/gotd/td/session"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestKeychain_Real talks to the real login Keychain through /usr/bin/security,
// under a throwaway service that it deletes afterwards. It is off unless
// TELE_KEYCHAIN_IT=1, since it can raise a Keychain prompt.
func TestKeychain_Real(t *testing.T) {
	if os.Getenv("TELE_KEYCHAIN_IT") != "1" {
		t.Skip("set TELE_KEYCHAIN_IT=1 to run against the real keychain")
	}
	service := fmt.Sprintf("tele-test-%d", time.Now().UnixNano())
	account := "/tmp/tele test \"dir\"/state"
	k := newKeychain(service, account, nil)
	ctx := context.Background()
	t.Cleanup(func() {
		_ = exec.Command(securityBin, "delete-generic-password", "-s", service, "-a", account).Run()
	})

	_, err := k.LoadSession(ctx)
	require.ErrorIs(t, err, session.ErrNotFound)

	data := realisticSession()
	require.NoError(t, k.StoreSession(ctx, data))
	got, err := k.LoadSession(ctx)
	require.NoError(t, err)
	assert.Equal(t, data, got)

	// -U replaces the item rather than adding a second.
	require.NoError(t, k.StoreSession(ctx, []byte("second")))
	got, err = k.LoadSession(ctx)
	require.NoError(t, err)
	assert.Equal(t, []byte("second"), got)

	require.NoError(t, k.Remove(ctx))
	_, err = k.LoadSession(ctx)
	assert.ErrorIs(t, err, session.ErrNotFound)
	assert.NoError(t, k.Remove(ctx))
}
