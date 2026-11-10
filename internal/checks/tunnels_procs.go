package checks

import "strings"

// parsePs joins `ps -o pid=,comm=` and `ps -o pid=,args=` on the pid.
func parsePs(comm, args string) []proc {
	exe := map[string]string{}
	for _, line := range strings.Split(comm, "\n") {
		if pid, c, ok := strings.Cut(strings.TrimSpace(line), " "); ok {
			exe[pid] = strings.TrimSpace(c)
		}
	}
	var out []proc
	for _, line := range strings.Split(args, "\n") {
		pid, a, ok := strings.Cut(strings.TrimSpace(line), " ")
		if !ok {
			continue
		}
		a = strings.TrimSpace(a)
		c, known := exe[pid]
		if !known {
			continue
		}
		rest, ok := strings.CutPrefix(a, c) // argv[0] is usually the exe path, which may hold spaces
		if !ok {
			f := strings.Fields(a)
			if len(f) == 0 {
				continue
			}
			rest = strings.TrimPrefix(a, f[0])
		}
		out = append(out, proc{exe: c, args: strings.Fields(rest)})
	}
	return out
}

// parseWinProcs reads lines of "name|command line".
func parseWinProcs(out string) []proc {
	var ps []proc
	for _, line := range strings.Split(out, "\n") {
		name, cmd, ok := strings.Cut(strings.TrimSpace(line), "|")
		if !ok || name == "" {
			continue
		}
		f := splitWinCommandLine(cmd)
		if len(f) > 0 {
			f = f[1:]
		}
		ps = append(ps, proc{exe: name, args: f})
	}
	return ps
}

// splitWinCommandLine splits a Windows command line, honouring double quotes.
func splitWinCommandLine(s string) []string {
	var out []string
	var b strings.Builder
	inQuote, have := false, false
	for _, r := range s {
		switch {
		case r == '"':
			inQuote, have = !inQuote, true
		case (r == ' ' || r == '\t') && !inQuote:
			if have {
				out = append(out, b.String())
				b.Reset()
				have = false
			}
		default:
			b.WriteRune(r)
			have = true
		}
	}
	if have {
		out = append(out, b.String())
	}
	return out
}
