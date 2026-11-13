package agent

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
)

// On Windows the install folder is added to the user's own PATH (the Path
// value under HKCU\Environment): no admin rights, and it holds nothing but
// bordercheck.exe and its files. Terminals opened afterwards see it.

// pathScript adds (BC_ADD=1) or removes the folder in BC_DIR, in the Path value
// of the key BC_KEY under HKCU (userEnvKey; tests use a key of their own). It reads the
// value without expanding it and writes it back with the kind it had, so
// entries such as %USERPROFILE%\bin stay as they were. Setting a variable
// through .NET afterwards is what tells Explorer the environment changed.
const pathScript = `$k = [Microsoft.Win32.Registry]::CurrentUser.OpenSubKey($env:BC_KEY, $true)
if ($null -eq $k) { throw "no HKCU\$($env:BC_KEY)" }
$old = [string]$k.GetValue('Path', '', 'DoNotExpandEnvironmentNames')
$kind = 'ExpandString'
if ($k.GetValueNames() -contains 'Path') { $kind = $k.GetValueKind('Path') }
$parts = @($old -split ';' | Where-Object { $_ -and ($_.TrimEnd('\') -ne $env:BC_DIR.TrimEnd('\')) })
if ($env:BC_ADD -eq '1') { $parts += $env:BC_DIR }
$new = $parts -join ';'
if ($new -ne $old) {
  $k.SetValue('Path', $new, $kind)
  [Environment]::SetEnvironmentVariable('BORDERCHECK_PATH_REFRESH', $null, 'User')
}`

// userEnvKey is where Windows keeps a user's own environment variables.
const userEnvKey = "Environment"

func setUserPath(dir string, add bool) error { return setPathIn(userEnvKey, dir, add) }

func setPathIn(key, dir string, add bool) error {
	cmd := exec.Command("powershell", "-NoProfile", "-NonInteractive", "-Command", pathScript)
	cmd.Env = append(os.Environ(), "BC_KEY="+key, "BC_DIR="+dir, map[bool]string{true: "BC_ADD=1", false: "BC_ADD=0"}[add])
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("changing your PATH: %s", bytes.TrimSpace(out))
	}
	return nil
}

func ensureCommand(env Env, st *State) error {
	if st.CommandSetUp {
		return nil
	}
	if err := setUserPath(env.Dir, true); err != nil {
		return err
	}
	st.CommandSetUp = true
	return nil
}

func removeCommand(env Env) error { return setUserPath(env.Dir, false) }
