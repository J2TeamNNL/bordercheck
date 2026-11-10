package checks

import (
	"encoding/xml"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"
)

// parsePlist reads an XML property list (`plutil -convert xml1 -o - file`) into
// map[string]any, []any, string, int64, float64, bool and time.Time values.
func parsePlist(doc string) (any, error) {
	d := xml.NewDecoder(strings.NewReader(doc))
	d.Strict = false
	for {
		tok, err := d.Token()
		if err != nil {
			return nil, fmt.Errorf("reading plist: %w", err)
		}
		if se, ok := tok.(xml.StartElement); ok && se.Name.Local != "plist" {
			return plistValue(d, se)
		}
	}
}

func plistValue(d *xml.Decoder, se xml.StartElement) (any, error) {
	switch se.Name.Local {
	case "dict":
		m := map[string]any{}
		key := ""
		for {
			tok, err := d.Token()
			if err != nil {
				return nil, err
			}
			switch t := tok.(type) {
			case xml.EndElement:
				return m, nil
			case xml.StartElement:
				if t.Name.Local == "key" {
					if err := d.DecodeElement(&key, &t); err != nil {
						return nil, err
					}
					continue
				}
				v, err := plistValue(d, t)
				if err != nil {
					return nil, err
				}
				m[key] = v
			}
		}
	case "array":
		var a []any
		for {
			tok, err := d.Token()
			if err != nil {
				return nil, err
			}
			switch t := tok.(type) {
			case xml.EndElement:
				return a, nil
			case xml.StartElement:
				v, err := plistValue(d, t)
				if err != nil {
					return nil, err
				}
				a = append(a, v)
			}
		}
	case "true", "false":
		if err := d.Skip(); err != nil {
			return nil, err
		}
		return se.Name.Local == "true", nil
	}
	var s string
	if err := d.DecodeElement(&s, &se); err != nil {
		return nil, err
	}
	s = strings.TrimSpace(s)
	switch se.Name.Local {
	case "integer":
		return strconv.ParseInt(s, 10, 64)
	case "real":
		return strconv.ParseFloat(s, 64)
	case "date":
		return time.Parse(time.RFC3339, s)
	case "string", "data":
		return s, nil
	}
	return nil, errors.New("unknown plist element <" + se.Name.Local + ">")
}

// plistDict reads an XML property list whose top level is a dict.
func plistDict(doc string) (map[string]any, error) {
	v, err := parsePlist(doc)
	if err != nil {
		return nil, err
	}
	m, ok := v.(map[string]any)
	if !ok {
		return nil, errors.New("plist is not a dictionary")
	}
	return m, nil
}
