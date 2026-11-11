package checks

import (
	"bufio"
	"bytes"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"hash"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// A hand-written reader for git's index file (Documentation/gitformat-index
// in git's source), so the secrets check can tell a file that a repository
// records unchanged without running git. Running git in a repository someone
// else wrote can run their code (core.fsmonitor, filters, hooks), so nothing
// from the repository is executed: the index and the config's
// extensions.objectformat are read as data, and anything this reader does
// not fully understand (split or sparse index, required extensions it does
// not know, a bad checksum) means "cannot tell", never a match.

const (
	gitIndexMaxSize  = 64 << 20 // a bigger index is not read: the rule just does not match
	gitConfigMaxSize = 1 << 20
	gitBlobMaxSize   = 10 << 20
)

var errGitIndex = errors.New("git index not understood")

// gitObjectFormat is a repository's hash: "sha1" (the default) or "sha256".
type gitObjectFormat string

func (f gitObjectFormat) size() int {
	if f == "sha256" {
		return sha256.Size
	}
	return sha1.Size
}

func (f gitObjectFormat) hasher() hash.Hash {
	if f == "sha256" {
		return sha256.New()
	}
	return sha1.New()
}

// gitRepo is a working tree and where its git data is.
type gitRepo struct {
	root   string // the working tree's top folder
	gitDir string // its .git folder, or what a .git file points to
	common string // where config lives (gitDir, or the commondir of a worktree)
}

// findGitRepo looks for the repository enclosing the file at abs, at most up
// to (and not including) stop, without following symlinks: every folder from
// the repository's top down to the file must be a real folder. ok is false
// when there is none, or anything about it looks odd.
func findGitRepo(abs, stop string) (repo gitRepo, ok bool) {
	abs = filepath.Clean(abs)
	stop = filepath.Clean(stop)
	for dir := filepath.Dir(abs); ; dir = filepath.Dir(dir) {
		if dir == stop || !within(dir, stop) {
			return gitRepo{}, false
		}
		if st, err := os.Lstat(dir); err != nil || !st.IsDir() {
			return gitRepo{}, false // a symlinked folder on the way: not followed
		}
		dotgit := filepath.Join(dir, ".git")
		if st, err := os.Lstat(dotgit); err == nil {
			switch {
			case st.IsDir():
				return gitRepo{root: dir, gitDir: dotgit, common: dotgit}, true
			case st.Mode().IsRegular() && st.Size() < 4096:
				gd, ok := readGitDirFile(dotgit, dir)
				if !ok {
					return gitRepo{}, false
				}
				return gitRepo{root: dir, gitDir: gd, common: commonDir(gd)}, true
			default:
				return gitRepo{}, false
			}
		}
		if parent := filepath.Dir(dir); parent == dir {
			return gitRepo{}, false
		}
	}
}

// within reports whether p is stop or below it.
func within(p, stop string) bool {
	rel, err := filepath.Rel(stop, p)
	return err == nil && rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator)) && !filepath.IsAbs(rel)
}

// readGitDirFile reads a "gitdir: <path>" file (a linked worktree or a
// submodule); a relative path is relative to the folder holding the file.
func readGitDirFile(p, dir string) (string, bool) {
	data, err := os.ReadFile(p)
	if err != nil {
		return "", false
	}
	line, _, _ := strings.Cut(string(data), "\n")
	gd, ok := strings.CutPrefix(strings.TrimRight(line, "\r"), "gitdir:")
	gd = strings.TrimSpace(gd)
	if !ok || gd == "" {
		return "", false
	}
	if !filepath.IsAbs(gd) {
		gd = filepath.Join(dir, gd)
	}
	if st, err := os.Stat(gd); err != nil || !st.IsDir() {
		return "", false
	}
	return filepath.Clean(gd), true
}

// commonDir is where a linked worktree's repository keeps its config.
func commonDir(gitDir string) string {
	p := filepath.Join(gitDir, "commondir")
	if st, err := os.Lstat(p); err != nil || !st.Mode().IsRegular() || st.Size() > 4096 {
		return gitDir
	}
	data, err := os.ReadFile(p)
	if err != nil {
		return gitDir
	}
	c := strings.TrimSpace(string(data))
	if c == "" {
		return gitDir
	}
	if !filepath.IsAbs(c) {
		c = filepath.Join(gitDir, c)
	}
	return filepath.Clean(c)
}

// readObjectFormat reads extensions.objectformat from a git config file: a
// plain INI reading of the one key, nothing else (includes are not followed;
// git only honours this key in the repository's own config anyway).
func readObjectFormat(configPath string) (gitObjectFormat, error) {
	st, err := os.Lstat(configPath)
	if err != nil {
		if os.IsNotExist(err) {
			return "sha1", nil
		}
		return "", err
	}
	if !st.Mode().IsRegular() || st.Size() > gitConfigMaxSize {
		return "", errGitIndex
	}
	f, err := os.Open(configPath)
	if err != nil {
		return "", err
	}
	defer f.Close()
	format := gitObjectFormat("sha1")
	section := ""
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || line[0] == '#' || line[0] == ';' {
			continue
		}
		if line[0] == '[' {
			end := strings.IndexByte(line, ']')
			if end < 0 {
				return "", errGitIndex
			}
			section = strings.ToLower(strings.TrimSpace(line[1:end]))
			line = strings.TrimSpace(line[end+1:])
			if line == "" {
				continue
			}
		}
		if section != "extensions" {
			continue
		}
		k, v, _ := strings.Cut(line, "=")
		if strings.ToLower(strings.TrimSpace(k)) != "objectformat" {
			continue
		}
		v, _, _ = strings.Cut(v, "#")
		v, _, _ = strings.Cut(v, ";")
		switch strings.ToLower(strings.Trim(strings.TrimSpace(v), `"`)) {
		case "sha1":
			format = "sha1"
		case "sha256":
			format = "sha256"
		default:
			return "", errGitIndex
		}
	}
	return format, sc.Err()
}

// gitIndexEntry is what the sample check needs from one index entry.
type gitIndexEntry struct {
	oid  []byte
	mode uint32
}

// parseGitIndex reads an index, keeping the stage-0 regular-file entries
// whose path (relative to the working tree, with /) is in want. Versions 2,
// 3 and 4; a split index (link), a sparse index (sdir) or any other required
// extension it does not know is an error, as is a bad checksum.
func parseGitIndex(data []byte, format gitObjectFormat, want map[string]bool) (map[string]gitIndexEntry, error) {
	hsz := format.size()
	if len(data) < 12+hsz || string(data[:4]) != "DIRC" {
		return nil, errGitIndex
	}
	body, sum := data[:len(data)-hsz], data[len(data)-hsz:]
	if !allZero(sum) { // index.skipHash writes zeros instead of a checksum
		h := format.hasher()
		h.Write(body)
		if !bytes.Equal(h.Sum(nil), sum) {
			return nil, errGitIndex
		}
	}
	version := binary.BigEndian.Uint32(body[4:8])
	if version < 2 || version > 4 {
		return nil, errGitIndex
	}
	count := binary.BigEndian.Uint32(body[8:12])
	out := map[string]gitIndexEntry{}
	pos := 12
	var prev []byte
	const statLen = 40 // ctime, mtime (8 each), dev, ino, mode, uid, gid, size (4 each)
	for i := uint32(0); i < count; i++ {
		start := pos
		if pos+statLen+hsz+2 > len(body) {
			return nil, errGitIndex
		}
		mode := binary.BigEndian.Uint32(body[pos+24 : pos+28])
		oid := body[pos+statLen : pos+statLen+hsz]
		flags := binary.BigEndian.Uint16(body[pos+statLen+hsz:])
		pos += statLen + hsz + 2
		var ext uint16
		if flags&0x4000 != 0 { // extended flags
			if version < 3 || pos+2 > len(body) {
				return nil, errGitIndex
			}
			ext = binary.BigEndian.Uint16(body[pos:])
			pos += 2
		}
		var name []byte
		if version == 4 {
			strip, n := gitVarint(body[pos:])
			if n == 0 || strip > uint64(len(prev)) {
				return nil, errGitIndex
			}
			pos += n
			end := bytes.IndexByte(body[pos:], 0)
			if end < 0 {
				return nil, errGitIndex
			}
			name = append(append([]byte{}, prev[:len(prev)-int(strip)]...), body[pos:pos+end]...)
			pos += end + 1
		} else {
			end := bytes.IndexByte(body[pos:], 0)
			if end < 0 {
				return nil, errGitIndex
			}
			if nl := int(flags & 0x0fff); nl < 0x0fff && nl != end {
				return nil, errGitIndex
			}
			name = body[pos : pos+end]
			// 1 to 8 NULs pad the entry to a multiple of 8 bytes.
			pos = start + ((pos - start + end + 8) &^ 7)
			if pos > len(body) {
				return nil, errGitIndex
			}
		}
		prev = name
		stage := (flags >> 12) & 3
		intentToAdd := ext&0x2000 != 0
		if stage == 0 && !intentToAdd && mode&0o170000 == 0o100000 && want[string(name)] {
			out[string(name)] = gitIndexEntry{oid: bytes.Clone(oid), mode: mode}
		}
	}
	// Extensions: an upper-case first letter is optional (a cache git can do
	// without); a lower-case one changes what the entries mean.
	for pos+8 <= len(body) {
		sig := body[pos : pos+4]
		size := binary.BigEndian.Uint32(body[pos+4 : pos+8])
		pos += 8
		if uint64(pos)+uint64(size) > uint64(len(body)) {
			return nil, errGitIndex
		}
		if sig[0] < 'A' || sig[0] > 'Z' {
			return nil, fmt.Errorf("%w: extension %q", errGitIndex, sig)
		}
		pos += int(size)
	}
	if pos != len(body) {
		return nil, errGitIndex
	}
	return out, nil
}

// gitVarint decodes git's offset varint (varint.c): 7 bits a byte, most
// significant first, adding one at each continuation. n is 0 when malformed.
func gitVarint(b []byte) (v uint64, n int) {
	if len(b) == 0 {
		return 0, 0
	}
	c := b[0]
	v = uint64(c & 127)
	n = 1
	for c&128 != 0 {
		v++
		if v == 0 || v>>57 != 0 || n >= len(b) || n > 9 {
			return 0, 0
		}
		c = b[n]
		n++
		v = v<<7 + uint64(c&127)
	}
	return v, n
}

func allZero(b []byte) bool {
	for _, c := range b {
		if c != 0 {
			return false
		}
	}
	return true
}

// gitBlobID is git's object ID of a file's content: the hash of
// "blob <size>\0" followed by the bytes. ok is false for anything that is not
// a regular file of a bounded size, or that changed while being read.
func gitBlobID(p string, format gitObjectFormat) (id []byte, ok bool) {
	st, err := os.Lstat(p)
	if err != nil || !st.Mode().IsRegular() || st.Size() > gitBlobMaxSize {
		return nil, false
	}
	f, err := os.Open(p)
	if err != nil {
		return nil, false
	}
	defer f.Close()
	h := format.hasher()
	h.Write([]byte("blob " + strconv.FormatInt(st.Size(), 10) + "\x00"))
	n, err := io.Copy(h, io.LimitReader(f, st.Size()+1))
	if err != nil || n != st.Size() {
		return nil, false
	}
	return h.Sum(nil), true
}

// readGitIndex reads a repository's index, if it is a regular file of a
// bounded size.
func readGitIndex(repo gitRepo) ([]byte, gitObjectFormat, error) {
	format, err := readObjectFormat(filepath.Join(repo.common, "config"))
	if err != nil {
		return nil, "", err
	}
	p := filepath.Join(repo.gitDir, "index")
	st, err := os.Lstat(p)
	if err != nil || !st.Mode().IsRegular() || st.Size() > gitIndexMaxSize {
		return nil, "", errGitIndex
	}
	data, err := os.ReadFile(p)
	if err != nil {
		return nil, "", err
	}
	return data, format, nil
}
