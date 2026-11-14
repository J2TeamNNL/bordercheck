package checks

import (
	"bufio"
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"io/fs"
	"os"
	"os/user"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"unicode/utf16"
)

// More places keys are left in: the Trash, key files saved anywhere (a
// Google service account key downloaded from the console), and API and
// database clients (Insomnia, Postman exports, DBeaver).

// osName is the OS the paths are for; tests replace it.
var osName = func() string { return runtime.GOOS }

// dbeaverKind is DBeaver's saved passwords file, reported by its presence.
const dbeaverKind = "DBeaver saved passwords (encrypted with a key every DBeaver install shares)"

// trashDir is where deleted files wait: on disk until the Trash is emptied.
// On Windows, the user's folder in the system drive's Recycle Bin
// (C:\$Recycle.Bin\<SID>); other drives' bins are not read.
func trashDir(home, goos string) string {
	switch goos {
	case "windows":
		u, err := user.Current()
		drive := os.Getenv("SystemDrive")
		if err != nil || drive == "" || !strings.HasPrefix(u.Uid, "S-1-") {
			return ""
		}
		return filepath.Join(drive+`\`, "$Recycle.Bin", u.Uid)
	case "darwin":
		return filepath.Join(home, ".Trash")
	case "linux":
		base := os.Getenv("XDG_DATA_HOME")
		if !filepath.IsAbs(base) {
			base = filepath.Join(home, ".local", "share")
		}
		return filepath.Join(base, "Trash", "files")
	}
	return ""
}

// trashDepth bounds the walk inside the Trash: a deleted project folder is
// looked into, not a deleted copy of a whole disk.
const trashDepth = 4

// sshKeyName: the names ssh-keygen gives private keys (id_ed25519, id_rsa,
// id_ecdsa…), which a deleted ~/.ssh leaves in the Trash.
var sshKeyName = regexp.MustCompile(`^id_[a-z0-9_-]+$`)

// keyJSONMax: a service account key file is about 2.4 KB; JSON files larger
// than this are not read for one.
const keyJSONMax = 16 << 10

// recycledName reads the original file name from a Windows Recycle Bin $I
// file: version (8 bytes), size (8), deletion time (8), then the path in
// UTF-16LE, either fixed at 520 bytes (version 1) or after its length in
// characters (version 2, 4 bytes).
func recycledName(iPath string) string {
	data, err := os.ReadFile(iPath)
	if err != nil || len(data) < 28 {
		return ""
	}
	var raw []byte
	switch binary.LittleEndian.Uint64(data[0:8]) {
	case 1:
		raw = data[24:min(len(data), 24+520)]
	case 2:
		n := int(binary.LittleEndian.Uint32(data[24:28]))
		raw = data[28:min(len(data), 28+2*n)]
	default:
		return ""
	}
	u := make([]uint16, 0, len(raw)/2)
	for i := 0; i+1 < len(raw); i += 2 {
		c := binary.LittleEndian.Uint16(raw[i:])
		if c == 0 {
			break
		}
		u = append(u, c)
	}
	full := string(utf16.Decode(u))
	if i := strings.LastIndexAny(full, `\/`); i >= 0 {
		full = full[i+1:]
	}
	return full
}

// lookAt sorts one file found by a walk: to scan (add), a certificate bundle,
// a JSON file that may be a key (jsonKeys), a Postman export (postman).
func (s *secretScanner) lookAt(p, name string, info fs.FileInfo, inTrash bool, add func(string), bundles *[]string) {
	switch strings.ToLower(filepath.Ext(name)) {
	case ".pem", ".key", ".p8":
		add(p)
		return
	case ".p12", ".pfx":
		*bundles = append(*bundles, p)
		return
	case ".json":
		if strings.HasSuffix(name, ".postman_environment.json") || strings.HasSuffix(name, ".postman_globals.json") {
			if s.loc.APIClients {
				s.postman = append(s.postman, p)
			}
			return
		}
		if s.loc.KeyFiles && info != nil && info.Size() <= keyJSONMax {
			s.jsonKeys = append(s.jsonKeys, p)
		}
		return
	}
	if isEnvFile(name) || inTrash && sshKeyName.MatchString(name) {
		add(p)
	}
}

// walkTrash looks in the Trash for what the home walk would report, and for
// SSH private keys by their usual names.
func (s *secretScanner) walkTrash(ctx context.Context, home string, add func(string), bundles *[]string) (incomplete bool) {
	top := trashDir(home, osName())
	if top == "" || !s.loc.Trash {
		return false
	}
	_ = filepath.WalkDir(top, func(p string, d fs.DirEntry, err error) error {
		if ctx.Err() != nil {
			incomplete = true
			return filepath.SkipAll
		}
		if err != nil || p == top {
			return nil // a Trash macOS will not let this program read is left alone
		}
		info, _ := d.Info()
		if info != nil && cloudPlaceholder(info) {
			if d.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}
		if d.IsDir() {
			rel, _ := filepath.Rel(top, p)
			if d.Name() == "node_modules" || d.Name() == ".git" || isPackageDir(d.Name()) ||
				strings.Count(rel, string(filepath.Separator)) >= trashDepth {
				return filepath.SkipDir
			}
			return nil
		}
		if d.Type().IsRegular() {
			name := d.Name()
			if filepath.Dir(p) == top && strings.HasPrefix(name, "$R") {
				// The Recycle Bin renames what it keeps ($R…); its $I… twin holds the name.
				if orig := recycledName(filepath.Join(top, "$I"+name[2:])); orig != "" {
					name = orig
				}
			}
			if !strings.HasPrefix(name, "$I") {
				s.lookAt(p, name, info, true, add, bundles)
			}
		}
		return nil
	})
	return incomplete
}

// scanLooseKeys reads the JSON files the walks found for Google service
// account keys, and Postman exports for secrets.
func (s *secretScanner) scanLooseKeys(home string) []secretFinding {
	var out []secretFinding
	for _, p := range s.jsonKeys {
		shown := tildePath(home, p)
		if s.ignored(shown) {
			continue
		}
		data, err := os.ReadFile(p)
		if err != nil || !bytes.Contains(data, []byte(`"service_account"`)) {
			continue
		}
		for _, h := range readGCloudADC(data) {
			out = append(out, s.fromHit(shown, h))
		}
	}
	for _, p := range s.postman {
		shown := tildePath(home, p)
		if st, err := os.Stat(p); s.ignored(shown) || err != nil || st.Size() > keyJSONMax*64 { // 1 MB: an export is a few KB
			continue
		}
		if data, err := os.ReadFile(p); err == nil {
			for _, h := range readPostmanEnv(data) {
				out = append(out, s.fromHit(shown, h))
			}
		}
	}
	return out
}

// secretKeyName: a variable or field whose value is a secret.
var secretKeyName = regexp.MustCompile(`(?i)(?:secret|token|password|passwd|api_?key|apikey|access_?key|private_?key|credential|auth)`)

// secretValue: a value worth reporting under such a name: long enough, not a
// template ({{var}}), a placeholder or another variable.
func secretValue(v string) bool {
	return len(v) >= 8 && !strings.Contains(v, "{{") && !isPlaceholder(v) && !codeValue(v)
}

// readPostmanEnv reads an exported Postman environment or globals file:
// {"values": [{"key": "API_KEY", "value": "…", "enabled": true}, …]}.
func readPostmanEnv(data []byte) []credHit {
	var env struct {
		Values []struct {
			Key   string `json:"key"`
			Value any    `json:"value"`
		} `json:"values"`
	}
	if json.Unmarshal(data, &env) != nil {
		return nil
	}
	var out []credHit
	for _, v := range env.Values {
		val, _ := v.Value.(string)
		if secretKeyName.MatchString(v.Key) && secretValue(val) {
			out = append(out, credHit{kind: "Postman environment secret", name: v.Key, value: val})
		}
	}
	return out
}

// readInsomnia reads Insomnia's data files (NeDB: one JSON document per line):
// environments' secret-looking variables, and requests' bearer tokens,
// passwords and Authorization headers.
func readInsomnia(data []byte) []credHit {
	var out []credHit
	sc := bufio.NewScanner(bytes.NewReader(data))
	sc.Buffer(make([]byte, 64<<10), 8<<20)
	for sc.Scan() {
		var doc struct {
			Type           string         `json:"type"`
			Name           string         `json:"name"`
			Data           map[string]any `json:"data"`
			Authentication map[string]any `json:"authentication"`
			Headers        []struct {
				Name  string `json:"name"`
				Value string `json:"value"`
			} `json:"headers"`
		}
		if json.Unmarshal(sc.Bytes(), &doc) != nil {
			continue
		}
		switch doc.Type {
		case "Environment":
			walkSecrets(doc.Data, "", func(name, v string) {
				out = append(out, credHit{kind: "Insomnia environment secret", name: name, value: v})
			})
		case "Request":
			for _, k := range []string{"token", "password", "accessToken", "refreshToken", "clientSecret"} {
				if v, _ := doc.Authentication[k].(string); secretValue(v) {
					out = append(out, credHit{kind: "Insomnia request credential", name: doc.Name + " (" + k + ")", value: v})
				}
			}
			for _, h := range doc.Headers {
				if strings.EqualFold(h.Name, "Authorization") && secretValue(h.Value) {
					out = append(out, credHit{kind: "Insomnia request credential", name: doc.Name + " (Authorization)", value: h.Value})
				}
			}
		}
	}
	return keep(out)
}

// walkSecrets calls found for each string under a secret-looking key, at any depth.
func walkSecrets(m map[string]any, prefix string, found func(name, value string)) {
	for k, v := range m {
		switch v := v.(type) {
		case string:
			if secretKeyName.MatchString(k) && secretValue(v) {
				found(prefix+k, v)
			}
		case map[string]any:
			walkSecrets(v, prefix+k+".", found)
		}
	}
}

// insomniaDir: where Insomnia keeps its data (Electron's user data folder).
func insomniaDir(home, goos string) string {
	switch goos {
	case "darwin":
		return filepath.Join(home, "Library", "Application Support", "Insomnia")
	case "windows":
		return filepath.Join(appData(home), "Insomnia")
	}
	if d := os.Getenv("XDG_CONFIG_HOME"); filepath.IsAbs(d) {
		return filepath.Join(d, "Insomnia")
	}
	return filepath.Join(home, ".config", "Insomnia")
}

// dbeaverCredentials: DBeaver's saved connection passwords, encrypted with a
// key that is the same in every DBeaver install, so as good as plain text.
func dbeaverCredentials(home, goos string) []string {
	var base string
	switch goos {
	case "darwin":
		base = filepath.Join(home, "Library", "DBeaverData")
	case "windows":
		base = filepath.Join(appData(home), "DBeaverData")
	default:
		base = filepath.Join(home, ".local", "share", "DBeaverData")
	}
	return []string{filepath.Join(base, "workspace6", "General", ".dbeaver", "credentials-config.json")}
}

// syncedBy names the cloud service a file is synced with, from its real path
// (links followed): Dropbox, OneDrive, Google Drive and other File Provider
// folders (~/Library/CloudStorage), iCloud Drive. "" when it is not, as far as
// the path tells: Desktop and Documents synced with iCloud are not recognised
// unless they are links into iCloud Drive. Nothing in those folders is read
// for this; only the path is.
func syncedBy(home, p string) string {
	real, err := filepath.EvalSymlinks(p)
	if err != nil {
		real = p
	}
	r := filepath.ToSlash(real)
	h := filepath.ToSlash(home)
	// The path may have its links followed and the home folder not, or the
	// other way round (/var is /private/var on macOS): put both the same way.
	if rh, err := filepath.EvalSymlinks(home); err == nil && !strings.HasPrefix(r, h+"/") {
		h = filepath.ToSlash(rh)
	}
	switch {
	case strings.Contains(r, "/Library/Mobile Documents/"):
		return "iCloud Drive"
	case strings.Contains(r, "/Library/CloudStorage/"):
		rest := r[strings.Index(r, "/Library/CloudStorage/")+len("/Library/CloudStorage/"):]
		name, _, _ := strings.Cut(rest, "/")
		name, _, _ = strings.Cut(name, "-")
		return name // GoogleDrive, OneDrive, Dropbox, Box…
	case strings.HasPrefix(r, h+"/Dropbox/") || strings.HasPrefix(r, h+"/Dropbox ("):
		return "Dropbox"
	case strings.HasPrefix(r, h+"/OneDrive"):
		return "OneDrive"
	case strings.HasPrefix(r, h+"/Google Drive/"):
		return "Google Drive"
	}
	return ""
}
