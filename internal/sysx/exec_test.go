package sysx

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestFirstLine(t *testing.T) {
	progress := `#< CLIXML
<Objs Version="1.1.0.1" xmlns="http://schemas.microsoft.com/powershell/2004/04"><Obj S="progress" RefId="0"><TN RefId="0"><T>System.Management.Automation.PSCustomObject</T><T>System.Object</T></TN><MS><I64 N="SourceId">1</I64><PR N="Record"><AV>Preparing modules for first use.</AV><AI>0</AI><Nil /><PI>-1</PI><PC>-1</PC><T>Completed</T><SR>-1</SR><SD> </SD></PR></MS></Obj></Objs>`
	withError := `#< CLIXML
<Objs Version="1.1.0.1" xmlns="http://schemas.microsoft.com/powershell/2004/04"><Obj S="progress" RefId="0"><MS><PR N="Record"><AV>Preparing modules for first use.</AV></PR></MS></Obj><S S="Error">Get-HotFix : Access is denied. &amp; more_x000D__x000A_</S><S S="Error">At line:1 char:1_x000D__x000A_</S></Objs>`
	cases := []struct{ in, want string }{
		{"", ""},
		{"\n  first\nsecond", "first"},
		{progress, ""},
		{withError, "Get-HotFix : Access is denied. & more"},
	}
	for _, c := range cases {
		if got := firstLine(c.in); got != c.want {
			t.Errorf("firstLine(%.30q) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestRunForSaysWhenItTimedOut(t *testing.T) {
	defer func(p time.Duration) { retryPause = p }(retryPause)
	retryPause = 10 * time.Millisecond
	_, err := RunFor(context.Background(), time.Second, "sleep", "5")
	if err == nil || !strings.Contains(err.Error(), "no answer within 1 seconds") || !NoAnswer(err) {
		t.Fatalf("err = %v", err)
	}
	if _, err := RunFor(context.Background(), time.Second, "sh", "-c", "exit 3"); err == nil || NoAnswer(err) {
		t.Fatalf("a command that fails is not a command that did not answer: %v", err)
	}
}

func TestRunForTriesOnceMore(t *testing.T) {
	defer func(p time.Duration) { retryPause = p }(retryPause)
	retryPause = 10 * time.Millisecond
	// Hangs the first time, answers the second.
	mark := filepath.Join(t.TempDir(), "ran")
	script := `if [ -e "$1" ]; then echo ok; else : > "$1"; sleep 5; fi`
	out, err := RunFor(context.Background(), time.Second, "sh", "-c", script, "sh", mark)
	if err != nil || strings.TrimSpace(out) != "ok" {
		t.Fatalf("out = %q, err = %v", out, err)
	}

	// No retry when the caller's deadline leaves no room for one.
	os.Remove(mark)
	ctx, cancel := context.WithTimeout(context.Background(), 1500*time.Millisecond)
	defer cancel()
	start := time.Now()
	if _, err := RunFor(ctx, time.Second, "sh", "-c", script, "sh", mark); !NoAnswer(err) {
		t.Fatalf("err = %v", err)
	}
	if d := time.Since(start); d > 2500*time.Millisecond { // one try is 1s, plus up to 1s for sleep's pipe
		t.Fatalf("retried past the caller's deadline: %v", d)
	}
}
