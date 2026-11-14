package guard

import (
	"path/filepath"
	"regexp"
	"slices"
	"strings"
)

// Risky reports whether a shell command an AI assistant is about to run
// would print secrets wholesale, and why. The command is read the way the
// shell reads it: split into simple commands at unquoted ; & | ( ) and line
// breaks (and inside $(…) and `…`), each split into words with quotes
// removed. Only the command word and its arguments count, so the same words
// inside a quoted string (a commit message, an echo) are not a command.
func Risky(command string) (string, bool) {
	for _, words := range simpleCommands(command) {
		if why := riskyWords(words); why != "" {
			return "BorderCheck refused this command: " + why + ". (bordercheck guard: to allow it, the person can run it in their own terminal.)", true
		}
	}
	return "", false
}

var (
	secretName = regexp.MustCompile(`(?i)TOKEN|SECRET|PASSWORD|PASSWD|API_?KEY|ACCESS_?KEY|PRIVATE|CREDENTIAL`)
	envFile    = regexp.MustCompile(`^\.env(?:\.(?:local|development|dev|production|prod|staging|test))?$`)
	readers    = []string{"cat", "head", "tail", "less", "more", "bat", "nl", "strings", "grep", "rg"}
)

// riskyWords: why the simple command words would print secrets, or "".
func riskyWords(words []string) string {
	// Prefixes that run the rest as the command.
	for len(words) > 0 && slices.Contains([]string{"sudo", "command", "exec", "time", "nohup"}, words[0]) {
		words = words[1:]
	}
	if len(words) == 0 {
		return ""
	}
	cmd, args := filepath.Base(words[0]), words[1:]
	switch cmd {
	case "touchenv":
		// The first word that is not an option or an option's value is the subcommand.
		for i := 0; i < len(args); i++ {
			a := args[i]
			if strings.HasPrefix(a, "--") {
				if !strings.Contains(a, "=") && (a == "--intent" || a == "--to") {
					i++ // takes a value
				}
				continue
			}
			if a == "get" {
				return "touchenv get prints a secret, so it would be in this chat; use touchenv run --intent \"<why>\" NAME -- <command>, which hands it to the command only"
			}
			break
		}
	case "env", "printenv", "export", "set":
		if len(args) == 0 {
			return "it prints every environment variable, secrets included; print the one you need (printenv PATH), or test whether one is set ([ -n \"$NAME\" ])"
		}
		if cmd == "printenv" {
			for _, a := range args {
				if !strings.HasPrefix(a, "-") && secretName.MatchString(a) {
					return "it prints a secret; test whether it is set instead ([ -n \"$NAME\" ] && echo set)"
				}
			}
		}
	case "security":
		if len(args) > 0 && (args[0] == "find-generic-password" || args[0] == "find-internet-password") && slices.Contains(args, "-w") {
			return "it prints a password from the Keychain"
		}
	case "op", "secret-tool", "pass", "gh", "aws":
		if startsWith(args, "read") && cmd == "op" || startsWith(args, "lookup") && cmd == "secret-tool" ||
			startsWith(args, "show") && cmd == "pass" || startsWith(args, "auth", "token") && cmd == "gh" ||
			startsWith(args, "configure", "get", "aws_secret_access_key") && cmd == "aws" {
			return "it prints a secret from a password manager or credential store; pass it to the command that needs it instead (op run, or touchenv run)"
		}
	}
	if slices.Contains(readers, cmd) {
		for _, a := range args {
			if !strings.HasPrefix(a, "-") && envFile.MatchString(filepath.Base(a)) {
				return "it prints a .env file's secrets; list its variable names without values instead: sed 's/=.*//' .env"
			}
		}
	}
	return ""
}

func startsWith(args []string, want ...string) bool {
	return len(args) >= len(want) && slices.Equal(args[:len(want)], want)
}

// simpleCommands splits a shell command line into simple commands, each as
// its words with quotes removed. A best effort, not a shell: enough to tell a
// command word from the same word in a quoted string.
func simpleCommands(line string) [][]string {
	var out [][]string
	var words []string
	var word strings.Builder
	inWord := false
	endWord := func() {
		if inWord {
			words = append(words, word.String())
			word.Reset()
			inWord = false
		}
	}
	endCommand := func() {
		endWord()
		if len(words) > 0 {
			out = append(out, words)
			words = nil
		}
	}
	quote := byte(0)
	// Here-documents (cmd <<EOF … EOF) whose bodies start after the current line:
	// a body is data given to the command on its input, not commands, except
	// that $( … ) and `…` in an unquoted one still run.
	type heredoc struct {
		delim         string
		quoted, strip bool
	}
	var pending []heredoc
	for i := 0; i < len(line); i++ {
		c := line[i]
		switch {
		case quote == 0 && c == '<' && strings.HasPrefix(line[i:], "<<") && !strings.HasPrefix(line[i:], "<<<"):
			endWord()
			j := i + 2
			h := heredoc{}
			if j < len(line) && line[j] == '-' {
				h.strip = true
				j++
			}
			for j < len(line) && (line[j] == ' ' || line[j] == '\t') {
				j++
			}
			var d strings.Builder
			for ; j < len(line) && !strings.ContainsRune(" \t\n;|&<>()", rune(line[j])); j++ {
				switch line[j] {
				case '\'', '"', '\\':
					h.quoted = true
				default:
					d.WriteByte(line[j])
				}
			}
			if h.delim = d.String(); h.delim != "" {
				pending = append(pending, h)
			}
			i = j - 1
		case quote == 0 && c == '\n' && len(pending) > 0:
			endCommand()
			// The bodies follow, one after the other, each up to a line that is its delimiter.
			pos := i + 1
			for _, h := range pending {
				body := pos
				for pos < len(line) {
					end := strings.IndexByte(line[pos:], '\n')
					if end < 0 {
						end = len(line) - pos
					}
					l := line[pos : pos+end]
					if h.strip {
						l = strings.TrimLeft(l, "\t")
					}
					next := pos + end + 1
					if l == h.delim {
						if !h.quoted {
							out = append(out, substitutions(line[body:pos])...)
						}
						pos = next
						body = -1
						break
					}
					pos = next
				}
				if body >= 0 && !h.quoted { // no end line: the body runs to the end
					out = append(out, substitutions(line[body:min(pos, len(line))])...)
				}
			}
			pending = nil
			i = pos - 1
		case quote == '\'':
			if c == '\'' {
				quote = 0
			} else {
				word.WriteByte(c)
			}
		case quote == '"':
			switch {
			case c == '"':
				quote = 0
			case c == '\\' && i+1 < len(line):
				i++
				word.WriteByte(line[i])
			case c == '$' && i+1 < len(line) && line[i+1] == '(':
				// $( … ) inside double quotes is still run: read it as its own commands.
				end := matchParen(line, i+1)
				out = append(out, simpleCommands(line[i+2:end])...)
				word.WriteString(line[i:min(end+1, len(line))])
				i = end
			default:
				word.WriteByte(c)
			}
		case c == '\'' || c == '"':
			quote, inWord = c, true
		case c == '\\' && i+1 < len(line):
			i++
			word.WriteByte(line[i])
			inWord = true
		case c == '$' && i+1 < len(line) && line[i+1] == '(':
			end := matchParen(line, i+1)
			out = append(out, simpleCommands(line[i+2:end])...)
			i = end
			inWord = true
		case c == '`':
			end := strings.IndexByte(line[i+1:], '`')
			if end < 0 {
				end = len(line) - i - 1
			}
			out = append(out, simpleCommands(line[i+1:i+1+end])...)
			i += end + 1
			inWord = true
		case c == ';' || c == '&' || c == '|' || c == '(' || c == ')' || c == '\n':
			endCommand()
		case c == ' ' || c == '\t' || c == '\r':
			endWord()
		case c == '>' || c == '<':
			endWord() // a redirection: its target is a word, not the command
		default:
			word.WriteByte(c)
			inWord = true
		}
	}
	endCommand()
	return out
}

// substitutions are the commands that $( … ) and `…` in text (an unquoted
// here-document's body) run.
func substitutions(text string) [][]string {
	var out [][]string
	for i := 0; i < len(text); i++ {
		switch {
		case text[i] == '\\' && i+1 < len(text):
			i++
		case text[i] == '$' && i+1 < len(text) && text[i+1] == '(':
			end := matchParen(text, i+1)
			out = append(out, simpleCommands(text[i+2:end])...)
			i = end
		case text[i] == '`':
			end := strings.IndexByte(text[i+1:], '`')
			if end < 0 {
				end = len(text) - i - 1
			}
			out = append(out, simpleCommands(text[i+1:i+1+end])...)
			i += end + 1
		}
	}
	return out
}

// matchParen is the index of the ")" closing the "(" at open, or len(line).
func matchParen(line string, open int) int {
	depth := 0
	for i := open; i < len(line); i++ {
		switch line[i] {
		case '(':
			depth++
		case ')':
			depth--
			if depth == 0 {
				return i
			}
		}
	}
	return len(line)
}
