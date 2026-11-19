package ui

import (
	"runtime"
	"testing"
)

func TestUseQuickLook(t *testing.T) {
	tests := []struct {
		goos    string
		enabled bool
		want    bool
	}{
		{"darwin", true, true},
		{"darwin", false, false},
		{"linux", true, false},
		{"windows", true, false},
	}
	for _, tt := range tests {
		if got := useQuickLook(tt.goos, tt.enabled); got != tt.want {
			t.Errorf("useQuickLook(%q, %v) = %v, want %v", tt.goos, tt.enabled, got, tt.want)
		}
	}
}

func TestQuickLookCommand(t *testing.T) {
	cmd := quickLookCommand("/tmp/clip.mp4")
	want := []string{"/usr/bin/qlmanage", "-p", "/tmp/clip.mp4"}
	if len(cmd.Args) != len(want) {
		t.Fatalf("args = %v, want %v", cmd.Args, want)
	}
	for i := range want {
		if cmd.Args[i] != want[i] {
			t.Fatalf("args[%d] = %q, want %q", i, cmd.Args[i], want[i])
		}
	}
	if cmd.Stdout != nil || cmd.Stderr != nil || cmd.Stdin != nil {
		t.Fatal("qlmanage output must be discarded, not wired to the terminal")
	}
}

func TestOpenMediaRouting(t *testing.T) {
	var viaOpen, viaQuickLook []string
	restoreOpen := SetOpenPathForTest(func(p string) { viaOpen = append(viaOpen, p) })
	defer restoreOpen()
	prevQL := quickLookPath
	defer func() { quickLookPath = prevQL }()
	quickLookOK := true
	quickLookPath = func(p string) bool {
		viaQuickLook = append(viaQuickLook, p)
		return quickLookOK
	}

	openMedia("/tmp/off.mp4", false)
	if len(viaOpen) != 1 || len(viaQuickLook) != 0 {
		t.Fatalf("setting off: open=%v quicklook=%v, want open only", viaOpen, viaQuickLook)
	}

	viaOpen, viaQuickLook = nil, nil
	openMedia("/tmp/on.mp4", true)
	if runtime.GOOS == "darwin" {
		if len(viaQuickLook) != 1 || len(viaOpen) != 0 {
			t.Fatalf("darwin, on: open=%v quicklook=%v, want quicklook only", viaOpen, viaQuickLook)
		}
		// qlmanage failing to start falls back to the default application.
		viaOpen, viaQuickLook = nil, nil
		quickLookOK = false
		openMedia("/tmp/on.mp4", true)
		if len(viaQuickLook) != 1 || len(viaOpen) != 1 {
			t.Fatalf("darwin, qlmanage fails: open=%v quicklook=%v, want both", viaOpen, viaQuickLook)
		}
	} else if len(viaOpen) != 1 || len(viaQuickLook) != 0 {
		t.Fatalf("%s, on: open=%v quicklook=%v, want open only (setting ignored)", runtime.GOOS, viaOpen, viaQuickLook)
	}
}
