package sessionstore

import (
	"context"
	"crypto/rand"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/gotd/td/session"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// fakeSecurity stands in for /usr/bin/security: an in-memory keychain that
// understands the three commands the store sends, and records every argv.
type fakeSecurity struct {
	items map[string]string // service\x00account -> secret
	argv  [][]string
	stdin []string
	// lineLimit cuts a `security -i` line the way the real tool does.
	lineLimit int
	// failAdd makes a write succeed without storing anything.
	failAdd bool
}

func newFake() *fakeSecurity {
	return &fakeSecurity{items: map[string]string{}, lineLimit: 4039}
}

func (f *fakeSecurity) run(_ context.Context, stdin string, args ...string) ([]byte, int, error) {
	f.argv = append(f.argv, args)
	if stdin != "" {
		f.stdin = append(f.stdin, stdin)
	}
	flag := func(name string) string {
		for i, a := range args {
			if a == name && i+1 < len(args) {
				return args[i+1]
			}
		}
		return ""
	}
	switch {
	case args[0] == "-i":
		if f.failAdd {
			return nil, 0, nil
		}
		line := strings.TrimSuffix(stdin, "\n")
		if len(line) > f.lineLimit {
			line = line[:f.lineLimit]
		}
		words := splitQuoted(line)
		// add-generic-password -U -s S -a A -w W
		var s, a, w string
		for i, word := range words {
			switch word {
			case "-s":
				s = words[i+1]
			case "-a":
				a = words[i+1]
			case "-w":
				w = words[i+1]
			}
		}
		f.items[s+"\x00"+a] = w
		return nil, 0, nil
	case args[0] == "find-generic-password":
		v, ok := f.items[flag("-s")+"\x00"+flag("-a")]
		if !ok {
			return nil, 44, errors.New("not found")
		}
		return []byte(v + "\n"), 0, nil
	case args[0] == "delete-generic-password":
		key := flag("-s") + "\x00" + flag("-a")
		if _, ok := f.items[key]; !ok {
			return nil, 44, errors.New("not found")
		}
		delete(f.items, key)
		return nil, 0, nil
	}
	return nil, 1, errors.New("unknown command")
}

// splitQuoted undoes quote for a line of double-quoted words and bare flags.
func splitQuoted(line string) []string {
	var words []string
	var cur strings.Builder
	inQuote, escaped, started := false, false, false
	flush := func() {
		if started {
			words = append(words, cur.String())
			cur.Reset()
			started = false
		}
	}
	for _, r := range line {
		switch {
		case escaped:
			cur.WriteRune(r)
			escaped = false
		case r == '\\' && inQuote:
			escaped = true
		case r == '"':
			inQuote = !inQuote
			started = true
		case r == ' ' && !inQuote:
			flush()
		default:
			cur.WriteRune(r)
			started = true
		}
	}
	flush()
	return words
}

// realisticSession is about the size and shape of what gotd keeps: some
// random bytes and a good deal of repetitive JSON.
func realisticSession() []byte {
	var b strings.Builder
	b.WriteString(`{"Version":1,"Data":{"AuthKey":"`)
	for i := 0; i < 344; i++ {
		b.WriteByte("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789+/"[(i*7+i*i)%64])
	}
	b.WriteString(`","Config":{"DCOptions":[`)
	for i := 0; i < 24; i++ {
		b.WriteString(`{"Flags":8,"ID":2,"IPAddress":"149.154.167.50","Port":443,"Secret":null},`)
	}
	b.WriteString(`{}]}}}`)
	return []byte(b.String())
}

func TestKeychain_LoadAbsentIsNotFound(t *testing.T) {
	k := newKeychain("tele-test", "/state", newFake().run)

	_, err := k.LoadSession(context.Background())

	assert.ErrorIs(t, err, session.ErrNotFound)
}

func TestKeychain_StoreThenLoad(t *testing.T) {
	k := newKeychain("tele-test", "/state dir/with \"quotes\" and \\", newFake().run)
	data := realisticSession()

	require.NoError(t, k.StoreSession(context.Background(), data))
	got, err := k.LoadSession(context.Background())

	require.NoError(t, err)
	assert.Equal(t, data, got)
}

func TestKeychain_TheSecretIsNeverInArgv(t *testing.T) {
	f := newFake()
	k := newKeychain("tele-test", "/state", f.run)
	data := []byte(`{"key":"hunter2hunter2"}`)

	require.NoError(t, k.StoreSession(context.Background(), data))

	secret, err := encodeSecret(data)
	require.NoError(t, err)
	for _, argv := range f.argv {
		for _, a := range argv {
			assert.NotContains(t, a, secret)
		}
	}
	require.Len(t, f.stdin, 1)
	assert.Contains(t, f.stdin[0], secret)
}

func TestKeychain_StoreRefusesASessionTooLongForTheTool(t *testing.T) {
	k := newKeychain("tele-test", "/state", newFake().run)
	random := make([]byte, 6000)
	_, err := rand.Read(random) // incompressible, so it stays long once gzipped
	require.NoError(t, err)

	err = k.StoreSession(context.Background(), random)

	assert.Error(t, err)
}

func TestKeychain_StoreNoticesAWriteThatDidNotLand(t *testing.T) {
	f := newFake()
	f.failAdd = true
	k := newKeychain("tele-test", "/state", f.run)

	err := k.StoreSession(context.Background(), []byte("x"))

	assert.Error(t, err)
}

func TestKeychain_AccountsDoNotCollide(t *testing.T) {
	f := newFake()
	a := newKeychain("tele-test", "/a", f.run)
	b := newKeychain("tele-test", "/b", f.run)
	require.NoError(t, a.StoreSession(context.Background(), []byte("one")))

	_, err := b.LoadSession(context.Background())

	assert.ErrorIs(t, err, session.ErrNotFound)
}

func TestKeychain_Remove(t *testing.T) {
	k := newKeychain("tele-test", "/state", newFake().run)
	require.NoError(t, k.StoreSession(context.Background(), []byte("x")))

	require.NoError(t, k.Remove(context.Background()))
	_, err := k.LoadSession(context.Background())
	assert.ErrorIs(t, err, session.ErrNotFound)
	assert.NoError(t, k.Remove(context.Background()), "removing what is gone is fine")
}

func TestKeychain_ImportMovesTheFileIn(t *testing.T) {
	path := filepath.Join(t.TempDir(), "session.json")
	data := realisticSession()
	require.NoError(t, os.WriteFile(path, data, 0o600))
	k := newKeychain("tele-test", "/state", newFake().run)

	imported, err := k.ImportFile(context.Background(), path)

	require.NoError(t, err)
	assert.True(t, imported)
	got, err := k.LoadSession(context.Background())
	require.NoError(t, err)
	assert.Equal(t, data, got)
	assert.NoFileExists(t, path)
}

func TestKeychain_ImportKeepsTheFileWhenTheWriteFails(t *testing.T) {
	path := filepath.Join(t.TempDir(), "session.json")
	require.NoError(t, os.WriteFile(path, []byte("payload"), 0o600))
	f := newFake()
	f.failAdd = true
	k := newKeychain("tele-test", "/state", f.run)

	imported, err := k.ImportFile(context.Background(), path)

	assert.Error(t, err)
	assert.False(t, imported)
	assert.FileExists(t, path)
}

func TestKeychain_ImportLeavesTheFileWhenTheItemExists(t *testing.T) {
	path := filepath.Join(t.TempDir(), "session.json")
	require.NoError(t, os.WriteFile(path, []byte("stale"), 0o600))
	k := newKeychain("tele-test", "/state", newFake().run)
	require.NoError(t, k.StoreSession(context.Background(), []byte("current")))

	imported, err := k.ImportFile(context.Background(), path)

	require.NoError(t, err)
	assert.False(t, imported)
	got, _ := k.LoadSession(context.Background())
	assert.Equal(t, []byte("current"), got)
}

func TestKeychain_ImportWithNoFileDoesNothing(t *testing.T) {
	k := newKeychain("tele-test", "/state", newFake().run)

	imported, err := k.ImportFile(context.Background(), filepath.Join(t.TempDir(), "session.json"))

	require.NoError(t, err)
	assert.False(t, imported)
}

func TestOpen_FileIsTheDefault(t *testing.T) {
	assert.IsType(t, &fileStore{}, Open("", "/state", "/state/session.json"))
	assert.IsType(t, &fileStore{}, Open(KindFile, "/state", "/state/session.json"))
	assert.IsType(t, &Keychain{}, Open(KindKeychain, "/state", "/state/session.json"))
}

func TestFile_LoadAbsentIsNotFound(t *testing.T) {
	s := File(filepath.Join(t.TempDir(), "session.json"))

	_, err := s.LoadSession(context.Background())

	assert.ErrorIs(t, err, session.ErrNotFound)
	assert.NoError(t, s.Remove(context.Background()))
}
