package ui

import (
	"os/exec"
	"runtime"
	"sync"
	"time"
)

// quickLookBin is the macOS Quick Look command-line previewer. Its absolute
// path is used so a lookalike earlier on PATH is never run.
const quickLookBin = "/usr/bin/qlmanage"

// quickLookCrashWindow is how long after start an abnormal qlmanage exit still
// counts as "could not preview this file" and hands the file to the default
// application instead. qlmanage aborts at once on file types its generators
// cannot draw (video does on some macOS releases); a panel that was shown and
// then killed or closed lasts longer than this.
const quickLookCrashWindow = 5 * time.Second

// useQuickLook reports whether non-photo media should open in Quick Look: only
// on macOS, and only when photos.quick_look asks for it.
func useQuickLook(goos string, enabled bool) bool {
	return goos == "darwin" && enabled
}

// quickLookCommand builds the command that shows name in the Quick Look panel,
// the preview Finder shows on Space. Stdin, stdout and stderr are left nil, so
// they are /dev/null: qlmanage prints a banner and framework noise that would
// scribble over the terminal UI.
func quickLookCommand(name string) *exec.Cmd {
	return exec.Command(quickLookBin, "-p", name)
}

// quickLook holds the panel that is currently open, so a second file replaces
// it instead of stacking a second panel.
var quickLook struct {
	mu  sync.Mutex
	cmd *exec.Cmd
}

// quickLookPath shows a file in Quick Look and returns at once; the panel runs
// until it is closed. It reports false when qlmanage could not be started, so
// the caller can use openPath. Variable so tests can stub it.
var quickLookPath = func(name string) bool {
	cmd := quickLookCommand(name)
	started := time.Now()
	quickLook.mu.Lock()
	defer quickLook.mu.Unlock()
	if prev := quickLook.cmd; prev != nil && prev.Process != nil {
		_ = prev.Process.Kill() // reaped by the goroutine that waits on it
	}
	if err := cmd.Start(); err != nil {
		quickLook.cmd = nil
		return false
	}
	quickLook.cmd = cmd
	go func() {
		err := cmd.Wait() // reaps the child
		quickLook.mu.Lock()
		replaced := quickLook.cmd != cmd
		if !replaced {
			quickLook.cmd = nil
		}
		quickLook.mu.Unlock()
		if err != nil && !replaced && time.Since(started) < quickLookCrashWindow {
			openPath(name)
		}
	}()
	return true
}

// openMedia opens a downloaded non-photo file: in Quick Look when asked for and
// possible, otherwise in the OS default application.
func openMedia(name string, quickLookOn bool) {
	if useQuickLook(runtime.GOOS, quickLookOn) && quickLookPath(name) {
		return
	}
	openPath(name)
}

// quickLookEnabled reports the photos.quick_look setting of the running config.
func (m RootModel) quickLookEnabled() bool {
	return m.cfg != nil && m.cfg.Photos.QuickLook
}
