package checks

import (
	"bytes"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/binary"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"testing"
)

// idxEntry is one entry for a hand-built index.
type idxEntry struct {
	name    string
	content string // the blob whose ID the entry records
	mode    uint32 // 0 = 0o100644
	stage   uint16
	ext     uint16 // extended flags (v3+), e.g. 0x2000 intent-to-add
}

func blobID(format gitObjectFormat, content string) []byte {
	h := format.hasher()
	h.Write([]byte("blob " + strconv.Itoa(len(content)) + "\x00" + content))
	return h.Sum(nil)
}

// gitVarintEncode is the inverse of gitVarint (git's encode_varint).
func gitVarintEncode(v uint64) []byte {
	var buf [16]byte
	pos := len(buf) - 1
	buf[pos] = byte(v & 127)
	for v >>= 7; v != 0; v >>= 7 {
		v--
		pos--
		buf[pos] = 128 | byte(v&127)
	}
	return buf[pos:]
}

// buildIndex writes an index the way git does, with the given version,
// object format and extensions (signature + payload), and a checksum.
func buildIndex(version uint32, format gitObjectFormat, entries []idxEntry, exts ...[]byte) []byte {
	var b bytes.Buffer
	b.WriteString("DIRC")
	binary.Write(&b, binary.BigEndian, version)
	binary.Write(&b, binary.BigEndian, uint32(len(entries)))
	prev := ""
	for _, e := range entries {
		start := b.Len()
		b.Write(make([]byte, 24)) // ctime, mtime, dev, ino
		mode := e.mode
		if mode == 0 {
			mode = 0o100644
		}
		binary.Write(&b, binary.BigEndian, mode)
		b.Write(make([]byte, 8)) // uid, gid
		binary.Write(&b, binary.BigEndian, uint32(len(e.content)))
		b.Write(blobID(format, e.content))
		flags := e.stage<<12 | uint16(min(len(e.name), 0xfff))
		if e.ext != 0 {
			flags |= 0x4000
		}
		binary.Write(&b, binary.BigEndian, flags)
		if e.ext != 0 {
			binary.Write(&b, binary.BigEndian, e.ext)
		}
		if version == 4 {
			common := 0
			for common < len(prev) && common < len(e.name) && prev[common] == e.name[common] {
				common++
			}
			b.Write(gitVarintEncode(uint64(len(prev) - common)))
			b.WriteString(e.name[common:])
			b.WriteByte(0)
		} else {
			b.WriteString(e.name)
			n := b.Len() - start
			b.Write(make([]byte, (n+8)&^7-n))
		}
		prev = e.name
	}
	for _, x := range exts {
		b.Write(x)
	}
	h := format.hasher()
	h.Write(b.Bytes())
	return h.Sum(b.Bytes())
}

func ext(sig string, payload []byte) []byte {
	out := []byte(sig)
	out = binary.BigEndian.AppendUint32(out, uint32(len(payload)))
	return append(out, payload...)
}

func TestParseGitIndexVersions(t *testing.T) {
	entries := []idxEntry{
		{name: ".env.ci", content: "API_TOKEN=dummy1234567\n"},
		{name: "app/config/keys/dev.pem", content: "-----BEGIN PRIVATE KEY-----\n"},
		{name: "app/config/keys/dev2.pem", content: "other"},
		{name: "app/conflict.env", content: "a", stage: 2},
		{name: "app/link.pem", content: "target", mode: 0o120000},
		{name: "app/sub", content: "", mode: 0o160000},
		{name: "app/zz-added.env", content: "", ext: 0x2000}, // intent-to-add
	}
	want := map[string]bool{".env.ci": true, "app/config/keys/dev.pem": true, "app/config/keys/dev2.pem": true,
		"app/conflict.env": true, "app/link.pem": true, "app/sub": true, "app/zz-added.env": true, "missing": true}
	for _, tc := range []struct {
		version uint32
		format  gitObjectFormat
	}{{2, "sha1"}, {3, "sha1"}, {4, "sha1"}, {2, "sha256"}, {4, "sha256"}} {
		es := entries
		if tc.version == 2 { // extended flags need v3
			es = entries[:len(entries)-1]
		}
		data := buildIndex(tc.version, tc.format, es, ext("TREE", []byte("cached tree")))
		got, err := parseGitIndex(data, tc.format, want)
		if err != nil {
			t.Fatalf("v%d %s: %v", tc.version, tc.format, err)
		}
		if len(got) != 3 {
			t.Errorf("v%d %s: want the 3 stage-0 regular files, got %v", tc.version, tc.format, got)
		}
		if e := got["app/config/keys/dev.pem"]; !bytes.Equal(e.oid, blobID(tc.format, "-----BEGIN PRIVATE KEY-----\n")) {
			t.Errorf("v%d %s: wrong object ID", tc.version, tc.format)
		}
		// Read with the wrong object format: refused, never a wrong match.
		other := gitObjectFormat("sha256")
		if tc.format == "sha256" {
			other = "sha1"
		}
		if _, err := parseGitIndex(data, other, want); err == nil {
			t.Errorf("v%d %s read as %s should fail", tc.version, tc.format, other)
		}
	}
}

func TestParseGitIndexRefuses(t *testing.T) {
	es := []idxEntry{{name: "a/.env", content: "X=1"}}
	want := map[string]bool{"a/.env": true}
	good := buildIndex(2, "sha1", es)
	if got, err := parseGitIndex(good, "sha1", want); err != nil || len(got) != 1 {
		t.Fatalf("good index: %v %v", got, err)
	}
	cases := map[string][]byte{
		"split index":     buildIndex(2, "sha1", es, ext("link", make([]byte, 20))),
		"sparse index":    buildIndex(2, "sha1", es, ext("sdir", nil)),
		"unknown ext":     buildIndex(2, "sha1", es, ext("zzzz", []byte("x"))),
		"version 5":       func() []byte { d := buildIndex(2, "sha1", es); d[7] = 5; return rehash(d) }(),
		"bad checksum":    func() []byte { d := bytes.Clone(good); d[len(d)-1] ^= 1; return d }(),
		"truncated":       good[:30],
		"empty":           nil,
		"not an index":    []byte("hello, this is not a git index at all, really"),
		"too many claims": func() []byte { d := bytes.Clone(good); d[11] = 9; return rehash(d) }(),
		"ext overruns":    func() []byte { e := ext("TREE", []byte("x")); e[7] = 200; return buildIndex(2, "sha1", es, e) }(),
	}
	for name, data := range cases {
		if _, err := parseGitIndex(data, "sha1", want); err == nil {
			t.Errorf("%s: parsed", name)
		}
	}
	// Index files written with index.skipHash have a zero checksum: accepted.
	z := bytes.Clone(good)
	copy(z[len(z)-sha1.Size:], make([]byte, sha1.Size))
	if _, err := parseGitIndex(z, "sha1", want); err != nil {
		t.Errorf("skipHash index: %v", err)
	}
	// Random corruption never panics.
	for i := 12; i < len(good)-sha1.Size; i++ {
		for _, v := range []byte{0, 0xff, 0x80} {
			d := bytes.Clone(good)
			d[i] = v
			parseGitIndex(rehash(d), "sha1", want)
		}
	}
}

func rehash(d []byte) []byte {
	if len(d) < sha1.Size {
		return d
	}
	body := d[:len(d)-sha1.Size]
	s := sha1.Sum(body)
	return append(bytes.Clone(body), s[:]...)
}

func TestGitVarint(t *testing.T) {
	for _, v := range []uint64{0, 1, 127, 128, 255, 16383, 16511, 1 << 20, 1<<40 + 7} {
		got, n := gitVarint(gitVarintEncode(v))
		if got != v || n != len(gitVarintEncode(v)) {
			t.Errorf("%d: got %d (%d bytes)", v, got, n)
		}
	}
	if _, n := gitVarint([]byte{0x80}); n != 0 {
		t.Error("truncated varint accepted")
	}
}

func TestReadObjectFormat(t *testing.T) {
	dir := t.TempDir()
	for content, want := range map[string]gitObjectFormat{
		"":                         "sha1",
		"[core]\n\tbare = false\n": "sha1",
		"[extensions]\n\tobjectFormat = sha256\n":  "sha256",
		"[Extensions]\nobjectformat=SHA256 # x\n":  "sha256",
		"[core]\n\tobjectformat = sha256\n":        "sha1", // not the extensions section
		"[extensions]\n\tobjectformat = sha1\n":    "sha1",
		"[extensions] objectformat = \"sha256\"\n": "sha256",
	} {
		p := filepath.Join(dir, "config")
		os.WriteFile(p, []byte(content), 0o600)
		if got, err := readObjectFormat(p); err != nil || got != want {
			t.Errorf("%q: %q %v", content, got, err)
		}
	}
	os.WriteFile(filepath.Join(dir, "config"), []byte("[extensions]\nobjectformat = sha3\n"), 0o600)
	if _, err := readObjectFormat(filepath.Join(dir, "config")); err == nil {
		t.Error("unknown object format accepted")
	}
	if f, err := readObjectFormat(filepath.Join(dir, "none")); err != nil || f != "sha1" {
		t.Errorf("no config: %q %v", f, err)
	}
}

// writeRepo lays out a repository by hand: .git/index from entries, the
// files in the working tree as given.
func writeRepo(t *testing.T, root string, format gitObjectFormat, version uint32, entries []idxEntry, files map[string]string) {
	t.Helper()
	must(t, os.MkdirAll(filepath.Join(root, ".git"), 0o700))
	if format == "sha256" {
		must(t, os.WriteFile(filepath.Join(root, ".git", "config"), []byte("[core]\n\trepositoryformatversion = 1\n[extensions]\n\tobjectformat = sha256\n"), 0o600))
	}
	must(t, os.WriteFile(filepath.Join(root, ".git", "index"), buildIndex(version, format, entries), 0o600))
	for rel, content := range files {
		p := filepath.Join(root, filepath.FromSlash(rel))
		must(t, os.MkdirAll(filepath.Dir(p), 0o700))
		must(t, os.WriteFile(p, []byte(content), 0o600))
	}
}

func must(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}

func gitTrackedOn(t *testing.T, home string, shown ...string) map[string]bool {
	t.Helper()
	sc := newSampleClassifier(t.Context(), samplePolicy("git-tracked"), home)
	defer sc.cancel()
	sc.prepare(shown)
	out := map[string]bool{}
	for _, s := range shown {
		out[s] = sc.gitTracked(s)
	}
	return out
}

func TestGitTrackedHandBuilt(t *testing.T) {
	home := t.TempDir()
	sl := string(filepath.Separator)
	for _, tc := range []struct {
		name    string
		format  gitObjectFormat
		version uint32
	}{{"v2", "sha1", 2}, {"v4", "sha1", 4}, {"sha256", "sha256", 2}} {
		root := filepath.Join(home, tc.name)
		writeRepo(t, root, tc.format, tc.version, []idxEntry{
			{name: ".env", content: "API_TOKEN=Zk3nW8sQe4yU\n"},
			{name: "keys/dev.pem", content: "-----BEGIN PRIVATE KEY-----\nabc\n"},
		}, map[string]string{
			".env":         "API_TOKEN=Zk3nW8sQe4yU\n",
			"keys/dev.pem": "-----BEGIN PRIVATE KEY-----\nCHANGED\n",
			"new.pem":      "-----BEGIN PRIVATE KEY-----\n",
		})
		got := gitTrackedOn(t, home, "~"+sl+tc.name+sl+".env", "~"+sl+tc.name+sl+"keys"+sl+"dev.pem", "~"+sl+tc.name+sl+"new.pem")
		if !got["~"+sl+tc.name+sl+".env"] {
			t.Errorf("%s: tracked and unchanged should match", tc.name)
		}
		if got["~"+sl+tc.name+sl+"keys"+sl+"dev.pem"] || got["~"+sl+tc.name+sl+"new.pem"] {
			t.Errorf("%s: modified or untracked matched: %v", tc.name, got)
		}
	}

	// A linked worktree: .git is a file pointing at the real git dir.
	gd := filepath.Join(home, "elsewhere", "worktrees", "wt")
	must(t, os.MkdirAll(gd, 0o700))
	must(t, os.WriteFile(filepath.Join(gd, "index"), buildIndex(2, "sha1", []idxEntry{{name: "ci/.env.test", content: "DB_PASSWORD=ci-only-123\n"}}), 0o600))
	must(t, os.WriteFile(filepath.Join(gd, "commondir"), []byte("../..\n"), 0o600))
	wt := filepath.Join(home, "wt")
	must(t, os.MkdirAll(filepath.Join(wt, "ci"), 0o700))
	must(t, os.WriteFile(filepath.Join(wt, ".git"), []byte("gitdir: ../elsewhere/worktrees/wt\n"), 0o600))
	must(t, os.WriteFile(filepath.Join(wt, "ci", ".env.test"), []byte("DB_PASSWORD=ci-only-123\n"), 0o600))
	if p := "~" + sl + "wt" + sl + "ci" + sl + ".env.test"; !gitTrackedOn(t, home, p)[p] {
		t.Error("worktree gitdir: file should match")
	}

	// A corrupt index: no crash, no match.
	bad := filepath.Join(home, "bad")
	writeRepo(t, bad, "sha1", 2, []idxEntry{{name: ".env", content: "A_TOKEN=12345678\n"}}, map[string]string{".env": "A_TOKEN=12345678\n"})
	must(t, os.WriteFile(filepath.Join(bad, ".git", "index"), []byte("DIRC\x00\x00\x00\x02garbage"), 0o600))
	if p := "~" + sl + "bad" + sl + ".env"; gitTrackedOn(t, home, p)[p] {
		t.Error("corrupt index matched")
	}

	// A repository whose top is the home folder itself (a dotfiles repo) never counts.
	writeRepo(t, home, "sha1", 2, []idxEntry{{name: ".zshrc", content: "export GITHUB_TOKEN=x\n"}}, map[string]string{".zshrc": "export GITHUB_TOKEN=x\n"})
	if p := "~" + sl + ".zshrc"; gitTrackedOn(t, home, p)[p] {
		t.Error("a repository at the home folder matched")
	}
}

func TestGitTrackedNoSymlinks(t *testing.T) {
	home := t.TempDir()
	sl := string(filepath.Separator)
	writeRepo(t, filepath.Join(home, "repo"), "sha1", 2, []idxEntry{{name: "real/.env", content: "X_TOKEN=abcdefgh1\n"}, {name: "link.env", content: "X_TOKEN=abcdefgh1\n"}},
		map[string]string{"real/.env": "X_TOKEN=abcdefgh1\n"})
	if err := os.Symlink(filepath.Join(home, "repo", "real", ".env"), filepath.Join(home, "repo", "link.env")); err != nil {
		t.Skip("symlinks not available:", err)
	}
	must(t, os.Symlink(filepath.Join(home, "repo", "real"), filepath.Join(home, "repo", "dirlink")))
	got := gitTrackedOn(t, home, "~"+sl+"repo"+sl+"link.env", "~"+sl+"repo"+sl+"dirlink"+sl+".env", "~"+sl+"repo"+sl+"real"+sl+".env")
	if got["~"+sl+"repo"+sl+"link.env"] || got["~"+sl+"repo"+sl+"dirlink"+sl+".env"] || !got["~"+sl+"repo"+sl+"real"+sl+".env"] {
		t.Errorf("symlinks must not be followed: %v", got)
	}
}

// Fixtures made by the real git, in a temp folder with no user or system config.
func TestGitTrackedRealGit(t *testing.T) {
	gitBin, err := exec.LookPath("git")
	if err != nil {
		t.Skip("git not installed")
	}
	home := t.TempDir()
	root := filepath.Join(home, "proj")
	must(t, os.MkdirAll(root, 0o700))
	git := func(dir string, args ...string) {
		t.Helper()
		cmd := exec.Command(gitBin, append([]string{"-c", "user.name=t", "-c", "user.email=t@example.com", "-c", "commit.gpgsign=false",
			"-c", "core.autocrlf=false", "-c", "init.defaultBranch=main"}, args...)...)
		cmd.Dir = dir
		cmd.Env = append(os.Environ(), "HOME="+home, "GIT_CONFIG_NOSYSTEM=1", "GIT_CONFIG_GLOBAL="+filepath.Join(home, "nogitconfig"),
			"GIT_TERMINAL_PROMPT=0", "XDG_CONFIG_HOME="+home)
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Skipf("git %v: %v\n%s", args, err, out)
		}
	}
	write := func(rel, content string) {
		p := filepath.Join(root, filepath.FromSlash(rel))
		must(t, os.MkdirAll(filepath.Dir(p), 0o700))
		must(t, os.WriteFile(p, []byte(content), 0o600))
	}
	git(root, "init", "-q")
	write(".gitignore", "secret.env\n")
	write("ci/.env.ci", "API_TOKEN=ci-dummy-1234\n")
	write("modified.env", "API_TOKEN=first-value-1\n")
	write("staged.env", "API_TOKEN=staged-value-1\n")
	git(root, "add", ".")
	git(root, "commit", "-q", "-m", "init")
	write("modified.env", "API_TOKEN=second-value-2\n")
	write("staged.env", "API_TOKEN=staged-value-2\n")
	git(root, "add", "staged.env")
	write("staged.env", "API_TOKEN=staged-value-3\n") // staged, then changed again
	write("secret.env", "API_TOKEN=real-secret-99\n") // git-ignored
	write("untracked.env", "API_TOKEN=untracked-77\n")

	sl := string(filepath.Separator)
	p := func(rel string) string { return "~" + sl + "proj" + sl + filepath.FromSlash(rel) }
	check := func(label string) {
		t.Helper()
		got := gitTrackedOn(t, home, p("ci/.env.ci"), p("modified.env"), p("staged.env"), p("secret.env"), p("untracked.env"))
		want := map[string]bool{p("ci/.env.ci"): true}
		for k, v := range got {
			if v != want[k] {
				t.Errorf("%s: %s: got %v", label, k, v)
			}
		}
	}
	check("v2")
	git(root, "update-index", "--index-version", "4")
	check("v4")

	// A linked worktree made by git.
	git(root, "worktree", "add", "-q", filepath.Join(home, "wt"))
	wp := "~" + sl + "wt" + sl + "ci" + sl + ".env.ci"
	if !gitTrackedOn(t, home, wp)[wp] {
		t.Error("git worktree: tracked file should match")
	}

	// SHA-256 repository, if this git can make one.
	r256 := filepath.Join(home, "r256")
	must(t, os.MkdirAll(r256, 0o700))
	cmd := exec.Command(gitBin, "init", "-q", "--object-format=sha256")
	cmd.Dir = r256
	cmd.Env = append(os.Environ(), "GIT_CONFIG_NOSYSTEM=1", "GIT_CONFIG_GLOBAL="+filepath.Join(home, "nogitconfig"))
	if cmd.Run() == nil {
		must(t, os.WriteFile(filepath.Join(r256, ".env"), []byte("API_TOKEN=sha256-dummy-1\n"), 0o600))
		git(r256, "add", ".env")
		sp := "~" + sl + "r256" + sl + ".env"
		if !gitTrackedOn(t, home, sp)[sp] {
			t.Error("sha256 repository: tracked file should match")
		}
	}
}

func TestGitBlobID(t *testing.T) {
	p := filepath.Join(t.TempDir(), "f")
	must(t, os.WriteFile(p, []byte("hello\n"), 0o600))
	// git hash-object of "hello\n".
	id, ok := gitBlobID(p, "sha1")
	want := []byte{0xce, 0x01, 0x36, 0x25, 0x03, 0x0b, 0xa8, 0xdb, 0xa9, 0x06, 0xf7, 0x56, 0x96, 0x7f, 0x9e, 0x9c, 0xa3, 0x94, 0x46, 0x4a}
	if !ok || !bytes.Equal(id, want) {
		t.Errorf("blob id %x", id)
	}
	if id, ok := gitBlobID(p, "sha256"); !ok || len(id) != sha256.Size {
		t.Errorf("sha256 blob id %x", id)
	}
	if _, ok := gitBlobID(filepath.Join(t.TempDir(), "none"), "sha1"); ok {
		t.Error("missing file hashed")
	}
}
