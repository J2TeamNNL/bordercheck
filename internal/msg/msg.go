// Package msg holds every sentence the checks write into a result's summary
// and fix, as a table of message keys and English templates.
//
// A check builds its summary and fix as a list of parts (key + parameters)
// and the English text from the same parts, so the two cannot drift. The
// report carries both: the English text for the CLI, old portals and machine
// consumers, and the parts so the portal can show the sentence in the
// reader's language. The table is exported to receiver/src/i18n/checks.en.json
// (go generate ./internal/msg); the portal's Chinese and Vietnamese catalogues
// translate the same keys.
//
// Template syntax, shared with the portal:
//   - {name} is a parameter: a string or a number, shown as is.
//   - {name:dur} is a duration in seconds ("5 minutes"), {name:ago} a number
//     of days in the past ("3 days ago", "today"), {name:date} a YYYY-MM-DD
//     date ("2 Jan 2006").
//   - [b]…[/b], [code]…[/code] and [kbd]…[/kbd] mark text up on the portal;
//     the English text drops them.
//   - An entry with a One form is plural: One is used when the parameter n
//     is 1, Other otherwise.
//
// A key never changes meaning or parameters: a sentence that needs other
// parameters gets a new key, so an older portal falls back to the English
// text instead of misrendering it.
package msg

//go:generate go test -run TestCatalogJSON -update .

import (
	"fmt"
	"math"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// Part is one sentence (or clause) of a summary or fix: a key in the table
// and the values of its parameters, each a string or an int.
type Part struct {
	Key    string         `json:"key"`
	Params map[string]any `json:"params,omitempty"`
}

// Text is a summary or fix as parts, joined with a space in English.
type Text []Part

// P makes a part from a key and name, value pairs: P("k", "n", 3, "name", "x").
func P(key string, kv ...any) Part {
	if len(kv)%2 != 0 {
		panic("msg.P: odd number of name/value arguments for " + key)
	}
	p := Part{Key: key}
	for i := 0; i < len(kv); i += 2 {
		name, ok := kv[i].(string)
		if !ok {
			panic(fmt.Sprintf("msg.P: parameter name %v of %s is not a string", kv[i], key))
		}
		if p.Params == nil {
			p.Params = map[string]any{}
		}
		switch v := kv[i+1].(type) {
		case string, int:
			p.Params[name] = v
		case int64:
			p.Params[name] = int(v)
		default:
			panic(fmt.Sprintf("msg.P: parameter %s of %s is a %T; only strings and ints are allowed", name, key, v))
		}
	}
	return p
}

// Of is a Text of one part.
func Of(key string, kv ...any) Text { return Text{P(key, kv...)} }

// English is the text in English: the parts rendered and joined with spaces.
func (t Text) English() string {
	out := make([]string, 0, len(t))
	for _, p := range t {
		if s := p.English(); s != "" {
			out = append(out, s)
		}
	}
	return strings.Join(out, " ")
}

// English renders one part. An unknown key renders as the key itself (the
// tests make sure no check uses one).
func (p Part) English() string {
	e, ok := Catalog[p.Key]
	if !ok {
		return p.Key
	}
	tmpl := e.Other
	if e.One != "" {
		if n, ok := p.Params["n"].(int); ok && n == 1 {
			tmpl = e.One
		}
	}
	return Render(tmpl, p.Params)
}

var (
	placeholderRe = regexp.MustCompile(`\{(\w+)(?::(dur|ago|date))?\}`)
	markupRe      = regexp.MustCompile(`\[/?(?:b|code|kbd)\]`)
)

// Render fills an English template with params and drops its markup.
func Render(tmpl string, params map[string]any) string {
	s := placeholderRe.ReplaceAllStringFunc(markupRe.ReplaceAllString(tmpl, ""), func(m string) string {
		g := placeholderRe.FindStringSubmatch(m)
		v, ok := params[g[1]]
		if !ok {
			return m
		}
		switch g[2] {
		case "dur":
			if n, ok := v.(int); ok {
				return Duration(time.Duration(n) * time.Second)
			}
		case "ago":
			if n, ok := v.(int); ok {
				return Ago(n)
			}
		case "date":
			if s, ok := v.(string); ok {
				if t, err := time.Parse("2006-01-02", s); err == nil {
					return t.Format("2 Jan 2006")
				}
			}
		}
		switch v := v.(type) {
		case int:
			return strconv.Itoa(v)
		case string:
			return v
		}
		return fmt.Sprint(v)
	})
	return s
}

// Placeholders lists the parameters a template uses, as name or name:type.
func Placeholders(tmpl string) []string {
	var out []string
	for _, m := range placeholderRe.FindAllStringSubmatch(tmpl, -1) {
		p := m[1]
		if m[2] != "" {
			p += ":" + m[2]
		}
		out = append(out, p)
	}
	return out
}

// Duration says how long d is: "45 seconds", "1 minute", "2.5 minutes".
func Duration(d time.Duration) string {
	if d < time.Minute {
		if s := int(d.Seconds()); s != 1 {
			return fmt.Sprintf("%d seconds", s)
		}
		return "1 second"
	}
	m := d.Minutes()
	if m == math.Trunc(m) {
		if m == 1 {
			return "1 minute"
		}
		return fmt.Sprintf("%d minutes", int(m))
	}
	return fmt.Sprintf("%.1f minutes", m)
}

// Ago says how many days ago something was: "today", "1 day ago", "3 days ago".
func Ago(days int) string {
	switch days {
	case 0:
		return "today"
	case 1:
		return "1 day ago"
	}
	return fmt.Sprintf("%d days ago", days)
}

// Error is an error whose message is a part, so a check that fails with it
// reports the message in the reader's language too.
type Error struct{ Part Part }

func (e Error) Error() string { return e.Part.English() }

// Err makes an Error.
func Err(key string, kv ...any) error { return Error{P(key, kv...)} }
