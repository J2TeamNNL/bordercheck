package guard

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

const theirs = `{
  "model": "opus",
  "permissions": {"deny": ["Read(~/.ssh/**)"]},
  "hooks": {
    "PreToolUse": [{"matcher": "Bash", "hooks": [{"type": "command", "command": "~/bin/check-bash"}]}],
    "UserPromptSubmit": [{"hooks": [{"type": "command", "command": "~/bin/log-prompt"}]}]
  },
  "cleanupPeriodDays": 30
}`

func TestInstallKeepsEverythingElse(t *testing.T) {
	path := filepath.Join(t.TempDir(), ".claude", "settings.json")
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(theirs), 0o640); err != nil {
		t.Fatal(err)
	}
	bin := "/Users/an/Library/Application Support/bordercheck/bordercheck"
	if len(Installed(path)) != 0 {
		t.Fatal("installed before install")
	}
	changed, err := Install(path, bin)
	if on := Installed(path); err != nil || !changed || !on["prompt"] || !on["command"] || !on["output"] {
		t.Fatalf("install: %v %v %v", changed, err, on)
	}
	data, _ := os.ReadFile(path)
	s := string(data)
	// The person's settings and hooks are all there, in their order, and the guard comes after their prompt hook.
	order := []string{`"model"`, `"permissions"`, `"hooks"`, `"PreToolUse"`, `check-bash`,
		`"command": "\"/Users/an/Library/Application Support/bordercheck/bordercheck\" guard command"`,
		`"UserPromptSubmit"`, `log-prompt`,
		`"command": "\"/Users/an/Library/Application Support/bordercheck/bordercheck\" guard prompt"`,
		`"PostToolUse"`, `guard output"`, `"cleanupPeriodDays"`}
	last := -1
	for _, w := range order {
		i := strings.Index(s, w)
		if i <= last {
			t.Fatalf("%s missing or out of order in:\n%s", w, s)
		}
		last = i
	}
	if st, _ := os.Stat(path); runtime.GOOS != "windows" && st.Mode().Perm() != 0o640 {
		t.Errorf("mode %o", st.Mode().Perm())
	}
	// Again: nothing changes. After the program moved: replaced, not added.
	if changed, err := Install(path, bin); err != nil || changed {
		t.Errorf("second install: %v %v", changed, err)
	}
	if _, err := Install(path, "/opt/bordercheck"); err != nil {
		t.Fatal(err)
	}
	data, _ = os.ReadFile(path)
	if n := strings.Count(string(data), "/bordercheck"); n != 3 || !strings.Contains(string(data), `"\"/opt/bordercheck\" guard prompt"`) {
		t.Errorf("%d guard hooks:\n%s", n, data)
	}

	// Uninstall for another program leaves it; for this one, or any, takes out the guard and nothing else.
	if changed, _ := Uninstall(path, bin); changed {
		t.Error("removed a guard set up with another program")
	}
	if changed, err := Uninstall(path, "/opt/bordercheck"); err != nil || !changed || len(Installed(path)) != 0 {
		t.Fatalf("uninstall: %v %v", changed, err)
	}
	data, _ = os.ReadFile(path)
	for _, w := range []string{"check-bash", "log-prompt", `"cleanupPeriodDays": 30`, `"model": "opus"`, `"matcher": "Bash"`} {
		if !strings.Contains(string(data), w) {
			t.Errorf("%s lost:\n%s", w, data)
		}
	}
	if changed, _ := Uninstall(path, ""); changed {
		t.Error("second uninstall changed the file")
	}
}

func TestInstallIntoNothingAndBack(t *testing.T) {
	path := filepath.Join(t.TempDir(), ".claude", "settings.json")
	if changed, err := Install(path, "/usr/local/bin/bordercheck"); err != nil || !changed {
		t.Fatal(changed, err)
	}
	data, _ := os.ReadFile(path)
	want := `{
  "hooks": {
    "UserPromptSubmit": [
      {
        "hooks": [
          {
            "type": "command",
            "command": "\"/usr/local/bin/bordercheck\" guard prompt",
            "timeout": 10
          }
        ]
      }
    ],
    "PreToolUse": [
      {
        "matcher": "Bash",
        "hooks": [
          {
            "type": "command",
            "command": "\"/usr/local/bin/bordercheck\" guard command",
            "timeout": 10
          }
        ]
      }
    ],
    "PostToolUse": [
      {
        "matcher": "Bash",
        "hooks": [
          {
            "type": "command",
            "command": "\"/usr/local/bin/bordercheck\" guard output",
            "timeout": 10
          }
        ]
      }
    ]
  }
}
`
	if string(data) != want {
		t.Errorf("got\n%s", data)
	}
	if st, _ := os.Stat(path); runtime.GOOS != "windows" && st.Mode().Perm() != 0o600 {
		t.Errorf("mode %o", st.Mode().Perm())
	}
	if _, err := Uninstall(path, ""); err != nil {
		t.Fatal(err)
	}
	if data, _ := os.ReadFile(path); string(data) != "{}\n" {
		t.Errorf("after uninstall: %q", data)
	}
	if changed, err := Uninstall(filepath.Join(t.TempDir(), "none.json"), ""); changed || err != nil {
		t.Errorf("no file: %v %v", changed, err)
	}
}

func TestInstallRefusesWhatItCannotRead(t *testing.T) {
	for _, bad := range []string{`{"model": "opus",}`, `[1,2]`, `{"hooks": []}`, `{"hooks": {"UserPromptSubmit": "x"}}`, `{} trailing`} {
		path := filepath.Join(t.TempDir(), "settings.json")
		if err := os.WriteFile(path, []byte(bad), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := Install(path, "/x/bordercheck"); err == nil {
			t.Errorf("%s: installed", bad)
		}
		if data, _ := os.ReadFile(path); string(data) != bad {
			t.Errorf("%s: file changed to %s", bad, data)
		}
	}
}

func TestCommandQuoting(t *testing.T) {
	for bin, want := range map[string]string{
		`/a b/bordercheck`:   `"/a b/bordercheck" guard prompt`,
		`/a"b$c/bordercheck`: `"/a\"b\$c/bordercheck" guard prompt`,
		`C:\Users\An\AppData\Local\bordercheck\bordercheck.exe`: `"C:\\Users\\An\\AppData\\Local\\bordercheck\\bordercheck.exe" guard prompt`,
	} {
		if got := Command(bin, "prompt"); got != want {
			t.Errorf("%s: %s, want %s", bin, got, want)
		}
	}
	dir := t.TempDir()
	t.Setenv("CLAUDE_CONFIG_DIR", dir)
	if p := SettingsPath("/home/an"); p != filepath.Join(dir, "settings.json") {
		t.Errorf("CLAUDE_CONFIG_DIR: %s", p)
	}
}

func TestRiskyCommands(t *testing.T) {
	for _, c := range []string{
		"touchenv get OPENAI_API_KEY", "touchenv --intent x get KEY | pbcopy", "env", "env | sort", "printenv",
		"cd app && env", "export", "set", "printenv GITHUB_TOKEN", "printenv db_password",
		"cat .env", "cat app/.env.local", "grep KEY .env", "tail -n 5 ./.env.production", `cat "$HOME/proj/.env"`,
		"security find-generic-password -s x -w", "op read op://vault/item/password", "gh auth token", "pass show work/db",
		"/opt/homebrew/bin/touchenv get K", `echo "$(touchenv get K)"`, "x=`printenv API_TOKEN`", "sudo cat /srv/app/.env",
		"cd a\nenv",
		// A here-document is data, but what runs after it, and $( ) in an unquoted one, are commands.
		"cat <<EOF\n$(printenv API_TOKEN)\nEOF", "cat <<'EOF' >x\nexport\nEOF\nenv", "cat <<-EOF\n\tok\n\tEOF\ncat .env",
	} {
		if why, bad := Risky(c); !bad || !strings.HasPrefix(why, "BorderCheck refused this command: ") {
			t.Errorf("%q not refused", c)
		}
	}
	for _, c := range []string{
		"touchenv run --intent x KEY -- make deploy", "env FOO=1 go test ./...", "printenv PATH", "echo $HOME",
		"cat .env.example", "cat README.md", "ls -la .env", "git diff .env", "sed 's/=.*//' .env", "envsubst < a > b",
		"go test ./internal/env/...", "security find-generic-password -s x", "make set-version", "./setup.sh",
		// The same words inside quotes are not a command.
		"git commit -m \"1.8.1: touchenv get ends the line\n\nenv and cat .env are refused\"", `echo 'run env'`,
		`grep -n "touchenv get" README.md`, "python3 - <<'EOF'\nprint('| `export` / `import` | env |')\nEOF",
		"cat <<EOF | grep x\nenv and export are words here\nEOF\necho done", "cat <<< \"x\"", "git commit -F - <<\"END\"\ncat .env\nEND", "gh pr view 1", "op run -- make", "env > /dev/null 2>&1 && echo ok",
	} {
		if why, bad := Risky(c); bad {
			t.Errorf("%q refused: %s", c, why)
		}
	}
}
