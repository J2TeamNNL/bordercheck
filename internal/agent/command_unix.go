//go:build darwin || linux

package agent

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
)

// On macOS and Linux the command is a link, ~/.local/bin/bordercheck, to the
// installed program. Most Linux systems have ~/.local/bin on PATH. macOS does
// not, so there one line is added to ~/.zprofile (zsh is its default shell),
// unless the person's zsh files already mention .local/bin.

// profileLine is the line added to ~/.zprofile, whole and exact, so uninstall
// can find it. It appends to PATH: nothing a person already runs changes.
const profileLine = `export PATH="$PATH:$HOME/.local/bin" # added by BorderCheck so that "bordercheck" works; bordercheck uninstall removes this line`

func ensureCommand(env Env, st *State) error {
	home, err := os.UserHomeDir()
	if err != nil {
		return err
	}
	if err := linkCommand(home, filepath.Join(env.Dir, binName())); err != nil {
		return err
	}
	if st.CommandSetUp {
		return nil
	}
	if runtime.GOOS == "darwin" {
		if err := addProfileLine(home); err != nil {
			return err
		}
	}
	st.CommandSetUp = true
	return nil
}

func commandLink(home string) string { return filepath.Join(home, ".local", "bin", "bordercheck") }

// linkCommand makes ~/.local/bin/bordercheck a link to bin. It never replaces
// a file, or a link to something else, that is already there.
func linkCommand(home, bin string) error {
	link := commandLink(home)
	if target, err := os.Readlink(link); err == nil {
		if target == bin {
			return nil
		}
		return fmt.Errorf("%s points to %s, not to this install; leaving it alone", link, target)
	}
	if _, err := os.Lstat(link); err == nil {
		return fmt.Errorf("%s is not BorderCheck's link; leaving it alone", link)
	}
	if err := os.MkdirAll(filepath.Dir(link), 0o755); err != nil {
		return err
	}
	return os.Symlink(bin, link)
}

// addProfileLine appends profileLine to ~/.zprofile unless a zsh startup file
// already mentions .local/bin. It appends in place, so a ~/.zprofile that is a
// link into a dotfiles folder stays one.
func addProfileLine(home string) error {
	for _, name := range []string{".zprofile", ".zshrc", ".zshenv"} {
		if data, err := os.ReadFile(filepath.Join(home, name)); err == nil && bytes.Contains(data, []byte(".local/bin")) {
			return nil
		}
	}
	p := filepath.Join(home, ".zprofile")
	old, err := os.ReadFile(p)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	add := profileLine + "\n"
	if len(old) > 0 && !bytes.HasSuffix(old, []byte("\n")) {
		add = "\n" + add
	}
	f, err := os.OpenFile(p, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		return err
	}
	if _, err := f.WriteString(add); err != nil {
		f.Close()
		return err
	}
	return f.Close()
}

func removeCommand(env Env) error {
	home, err := os.UserHomeDir()
	if err != nil {
		return err
	}
	return unlinkCommand(home, filepath.Join(env.Dir, binName()))
}

// unlinkCommand removes the link if it is this install's, and the line this
// install added to ~/.zprofile.
func unlinkCommand(home, bin string) error {
	var errs []error
	link := commandLink(home)
	if target, err := os.Readlink(link); err == nil && target == bin {
		errs = append(errs, os.Remove(link))
	}
	p := filepath.Join(home, ".zprofile")
	if data, err := os.ReadFile(p); err == nil && bytes.Contains(data, []byte(profileLine)) {
		var keep []string
		for _, l := range strings.SplitAfter(string(data), "\n") {
			if strings.TrimRight(l, "\r\n") != profileLine {
				keep = append(keep, l)
			}
		}
		errs = append(errs, os.WriteFile(p, []byte(strings.Join(keep, "")), 0o644)) // in place: keeps a link and the file's mode
	}
	return errors.Join(errs...)
}
