//go:build darwin || linux

package agent

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLinkCommand(t *testing.T) {
	home := t.TempDir()
	bin := filepath.Join(home, "install", "bordercheck")
	link := commandLink(home)
	for range 2 { // the second time it is already there
		if err := linkCommand(home, bin); err != nil {
			t.Fatal(err)
		}
		if target, _ := os.Readlink(link); target != bin {
			t.Fatalf("link → %q", target)
		}
	}
	// A link to something else, or a file, is somebody else's.
	if err := linkCommand(home, filepath.Join(home, "other", "bordercheck")); err == nil {
		t.Error("replaced a link to another install")
	}
	if err := unlinkCommand(home, filepath.Join(home, "other", "bordercheck")); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(link); err != nil {
		t.Error("removed a link that was not that install's")
	}
	if err := unlinkCommand(home, bin); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(link); err == nil {
		t.Error("link not removed")
	}
	if err := os.WriteFile(link, []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := linkCommand(home, bin); err == nil {
		t.Error("replaced a file")
	}
}

func TestProfileLine(t *testing.T) {
	home := t.TempDir()
	profile := filepath.Join(home, ".zprofile")
	read := func() string { b, _ := os.ReadFile(profile); return string(b) }

	// Added once, after what is there, on a line of its own.
	if err := os.WriteFile(profile, []byte("export EDITOR=vim"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := addProfileLine(home); err != nil {
		t.Fatal(err)
	}
	if got := read(); got != "export EDITOR=vim\n"+profileLine+"\n" {
		t.Fatalf("profile:\n%s", got)
	}
	if err := addProfileLine(home); err != nil || strings.Count(read(), profileLine) != 1 {
		t.Fatalf("added twice: %v\n%s", err, read())
	}
	if st, _ := os.Stat(profile); st.Mode().Perm() != 0o600 {
		t.Errorf("mode changed to %o", st.Mode().Perm())
	}
	// Uninstall takes out exactly that line.
	if err := unlinkCommand(home, "/nowhere/bordercheck"); err != nil {
		t.Fatal(err)
	}
	if got := read(); got != "export EDITOR=vim\n" {
		t.Fatalf("after uninstall:\n%q", got)
	}

	// Someone who already has ~/.local/bin on PATH gets no line; no profile at all gets one.
	other := t.TempDir()
	if err := os.WriteFile(filepath.Join(other, ".zshrc"), []byte(`path+=("$HOME/.local/bin")`+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := addProfileLine(other); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(other, ".zprofile")); err == nil {
		t.Error("wrote a profile for someone who has .local/bin already")
	}
	fresh := t.TempDir()
	if err := addProfileLine(fresh); err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(filepath.Join(fresh, ".zprofile")); string(b) != profileLine+"\n" {
		t.Errorf("new profile: %q", b)
	}

	// A profile that is a link into a dotfiles folder stays a link.
	dot := t.TempDir()
	real := filepath.Join(dot, "dotfiles-zprofile")
	if err := os.WriteFile(real, []byte("# mine\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(real, filepath.Join(dot, ".zprofile")); err != nil {
		t.Fatal(err)
	}
	if err := addProfileLine(dot); err != nil {
		t.Fatal(err)
	}
	if err := unlinkCommand(dot, "/nowhere/bordercheck"); err != nil {
		t.Fatal(err)
	}
	if target, err := os.Readlink(filepath.Join(dot, ".zprofile")); err != nil || target != real {
		t.Errorf("the link was replaced: %v", err)
	}
	if b, _ := os.ReadFile(real); string(b) != "# mine\n" {
		t.Errorf("dotfile: %q", b)
	}
}
