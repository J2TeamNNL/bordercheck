package ignore

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestLoadSave(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "bordercheck")
	if es, err := Load(dir); err != nil || es != nil {
		t.Fatalf("missing file: %v %v", es, err)
	}
	in := []Entry{{Check: "secrets", Path: "~/a/.env", Reason: "test db", Since: "2026-11-11"}, {Check: "ssh-keys", Path: "~/.ssh/aur", Reason: "fake", Since: "2026-11-11"}}
	if err := Save(dir, in); err != nil {
		t.Fatal(err)
	}
	if runtime.GOOS != "windows" {
		if st, err := os.Stat(filepath.Join(dir, FileName)); err != nil || st.Mode().Perm() != 0o600 {
			t.Errorf("mode: %v %v", st.Mode(), err)
		}
	}
	out, err := Load(dir)
	if err != nil || len(out) != 2 || out[1] != in[1] {
		t.Fatalf("round trip: %+v %v", out, err)
	}
}

func TestLoadBadFiles(t *testing.T) {
	dir := t.TempDir()
	for name, body := range map[string]string{
		"corrupt":         `{"version": 1, "entries": [`,
		"unknown version": `{"version": 7, "entries": []}`,
		"not an object":   `[1, 2]`,
	} {
		if err := os.WriteFile(filepath.Join(dir, FileName), []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		if es, err := Load(dir); err == nil || es != nil {
			t.Errorf("%s: want an error and no entries, got %v %v", name, es, err)
		}
	}
	// Entries without a path or reason are dropped; fields are cut and kept on one line.
	long := strings.Repeat("x", 500)
	body := `{"version": 1, "entries": [{"path": "", "reason": "r"}, {"path": "~/a", "reason": ""}, {"check": "firewall", "path": "~/f", "reason": "r"},
	 {"path": "~/b", "reason": "line one\nline two\u001b[31m` + long + `", "unknown": true}]}`
	if err := os.WriteFile(filepath.Join(dir, FileName), []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	es, err := Load(dir)
	if err != nil || len(es) != 1 || es[0].Path != "~/b" || len([]rune(es[0].Reason)) != MaxReason || strings.ContainsAny(es[0].Reason, "\n\x1b") {
		t.Errorf("got %+v %v", es, err)
	}
}

func TestCheckReason(t *testing.T) {
	if CheckReason("  \n ") == nil || CheckReason(strings.Repeat("é", MaxReason+1)) == nil {
		t.Error("empty or too long reason accepted")
	}
	if err := CheckReason("local Docker database, not reachable from outside"); err != nil {
		t.Error(err)
	}
}

func TestShownAndCovers(t *testing.T) {
	home := filepath.Join(t.TempDir(), "home")
	env := filepath.Join(home, "proj", ".env")
	want := "~" + string(filepath.Separator) + filepath.Join("proj", ".env")
	for _, in := range []string{"~/proj/.env", env, filepath.Join(home, "proj", "..", "proj", ".env")} {
		if got, err := Shown(in, home); err != nil || got != want {
			t.Errorf("Shown(%q) = %q, %v; want %q", in, got, err, want)
		}
	}
	other := filepath.Join(t.TempDir(), "x.env")
	if got, _ := Shown(other, home); got != filepath.Clean(other) {
		t.Errorf("outside home: %q", got)
	}
	if !SamePath("~/proj/.env", env, home) || SamePath("~/proj/.env", "~/proj/.env.local", home) {
		t.Error("SamePath")
	}

	file := Entry{Check: "secrets", Path: "~/proj/.env", Reason: "r"}
	byName := Entry{Check: "secrets", Path: "~/proj/.env", Name: "POSTGRES_PASSWORD", Reason: "r"}
	byKind := Entry{Check: "secrets", Path: "~/proj/.env", Name: "private key", Reason: "r"}
	for _, c := range []struct {
		e                Entry
		path, name, kind string
		want             bool
	}{
		{file, want, "ANY", "Secret-looking variable", true},
		{file, "~/other/.env", "ANY", "Secret-looking variable", false},
		{byName, want, "POSTGRES_PASSWORD", "Secret-looking variable", true},
		{byName, want, "postgres_password", "Secret-looking variable", false}, // names are exact
		{byName, want, "API_KEY", "Secret-looking variable", false},
		{byKind, want, "", "Private key", true}, // kinds without case
	} {
		if got := c.e.Covers("secrets", c.path, []string{c.name, "other"}, c.kind, home); got != c.want {
			t.Errorf("%+v covers %s %s %s = %v", c.e, c.path, c.name, c.kind, got)
		}
	}
	if file.Covers("ai-agents", want, nil, "k", home) {
		t.Error("an entry covered another check's finding")
	}
}
