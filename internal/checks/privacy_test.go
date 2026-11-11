package checks

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/ptrinh/bordercheck/internal/check"
	"github.com/ptrinh/bordercheck/internal/policy"
)

func TestSensitiveSourcesRequireLocalConsent(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	paths := []string{".bash_history", "app/.env", ".aws/credentials", "custom.txt"}
	for _, rel := range paths {
		path := filepath.Join(home, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte("APP_TOKEN=Zk3nW8sQe4yU\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	pol := policy.Default()
	pol.Checks.Secrets.ExtraFiles = []string{"~/custom.txt", "~/.bash_history", "~/app/.env"}
	for _, c := range All(pol) {
		switch c.ID {
		case "secrets", "ai-agents", "ssh-keys", "browser-passwords", "package-managers":
			if r := c.Run(t.Context()); r.Status != check.Skip {
				t.Errorf("%s without consent: %v", c.ID, r)
			}
		}
	}
	pol.Checks.AIAgents.ExtraPaths = []string{"~/custom.txt"}
	for _, c := range AllWith(pol, Local{Privacy: Privacy{CredentialStores: true}}) {
		if c.ID == "ai-agents" {
			if r := c.Run(t.Context()); len(r.Evidence) != 0 {
				t.Errorf("AI check scanned a policy-defined path without all permissions: %v", r.Evidence)
			}
		}
	}
	for _, tc := range []struct {
		name    string
		privacy Privacy
		want    []string
	}{
		{"default", Privacy{}, nil},
		{"history", Privacy{ShellHistory: true}, paths[:1]},
		{"env", Privacy{ProjectEnv: true}, paths[1:2]},
		{"credentials", Privacy{CredentialStores: true}, paths[2:3]},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s, err := newSecretScanner(pol.Checks.Secrets, home)
			if err != nil {
				t.Fatal(err)
			}
			files, _, _ := s.find(t.Context(), home, tc.privacy)
			var got []string
			for _, path := range files {
				rel, err := filepath.Rel(home, path)
				if err != nil {
					t.Fatal(err)
				}
				got = append(got, filepath.ToSlash(rel))
			}
			if !reflect.DeepEqual(got, tc.want) {
				t.Errorf("scanned %v, want %v", got, tc.want)
			}
		})
	}
}
