package sysx

import (
	"context"
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
	_, err := RunFor(context.Background(), time.Second, "sleep", "5")
	if err == nil || !strings.Contains(err.Error(), "no answer within 1 seconds") {
		t.Fatalf("err = %v", err)
	}
}
