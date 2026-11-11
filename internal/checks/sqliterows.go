package checks

import (
	"encoding/binary"
	"errors"
	"io"
	"os"
)

// sqliteTableRows counts the rows of one table in an SQLite file by walking
// the table's b-tree and adding up the cells of its leaf pages. It reads the
// schema page and page headers only: no row of the table is decoded, so a
// file of saved logins can be counted without its contents ever being read
// into a value. Anything it does not understand is an error, never a guess.
//
// The file is read as it is on disk (no journal or write-ahead log is
// applied), which is enough to tell "none" from "some".
func sqliteTableRows(path, table string) (int, error) {
	f, err := os.Open(path)
	if err != nil {
		return 0, err
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		return 0, err
	}
	if !st.Mode().IsRegular() || st.Size() < 512 || st.Size() > 256<<20 {
		return 0, errors.New("sqlite: not a database this check reads")
	}
	return sqliteRows(f, st.Size(), table)
}

var errSQLite = errors.New("sqlite: unexpected file layout")

func sqliteRows(r io.ReaderAt, size int64, table string) (int, error) {
	head := make([]byte, 100)
	if _, err := r.ReadAt(head, 0); err != nil || string(head[:16]) != "SQLite format 3\x00" {
		return 0, errSQLite
	}
	pageSize := int64(binary.BigEndian.Uint16(head[16:18]))
	if pageSize == 1 {
		pageSize = 65536
	}
	if pageSize < 512 || pageSize&(pageSize-1) != 0 {
		return 0, errSQLite
	}
	if enc := binary.BigEndian.Uint32(head[56:60]); enc != 1 { // schema text must be UTF-8
		return 0, errSQLite
	}
	pages := size / pageSize
	page := func(n uint32) ([]byte, error) {
		if n == 0 || int64(n) > pages {
			return nil, errSQLite
		}
		b := make([]byte, pageSize)
		if _, err := r.ReadAt(b, int64(n-1)*pageSize); err != nil {
			return nil, errSQLite
		}
		return b, nil
	}
	budget := 200000 // pages this may visit in all

	// walk visits the leaf pages of the table b-tree rooted at n.
	var walk func(n uint32, depth int, leaf func(p []byte, hdr int) error) error
	walk = func(n uint32, depth int, leaf func(p []byte, hdr int) error) error {
		if budget--; budget < 0 || depth > 40 {
			return errSQLite
		}
		p, err := page(n)
		if err != nil {
			return err
		}
		hdr := 0
		if n == 1 {
			hdr = 100
		}
		cells := int(binary.BigEndian.Uint16(p[hdr+3 : hdr+5]))
		switch p[hdr] {
		case 0x0d: // table leaf
			return leaf(p, hdr)
		case 0x05: // table interior: a child before each cell, and one after the last
			if hdr+12+2*cells > len(p) {
				return errSQLite
			}
			for i := 0; i < cells; i++ {
				off := int(binary.BigEndian.Uint16(p[hdr+12+2*i:]))
				if off+4 > len(p) {
					return errSQLite
				}
				if err := walk(binary.BigEndian.Uint32(p[off:]), depth+1, leaf); err != nil {
					return err
				}
			}
			return walk(binary.BigEndian.Uint32(p[hdr+8:hdr+12]), depth+1, leaf)
		}
		return errSQLite
	}

	// The schema table lists every table with the page its b-tree starts on.
	var root uint32
	err := walk(1, 0, func(p []byte, hdr int) error {
		cells := int(binary.BigEndian.Uint16(p[hdr+3 : hdr+5]))
		if hdr+8+2*cells > len(p) {
			return errSQLite
		}
		for i := 0; i < cells; i++ {
			off := int(binary.BigEndian.Uint16(p[hdr+8+2*i:]))
			typ, name, rootPage, ok := sqliteSchemaRow(p, off)
			if !ok {
				return errSQLite
			}
			if typ == "table" && name == table {
				root = rootPage
			}
		}
		return nil
	})
	if err != nil {
		return 0, err
	}
	if root == 0 {
		return 0, errors.New("sqlite: no table " + table)
	}
	rows := 0
	err = walk(root, 0, func(p []byte, hdr int) error {
		rows += int(binary.BigEndian.Uint16(p[hdr+3 : hdr+5]))
		return nil
	})
	return rows, err
}

// sqliteSchemaRow reads type, name and rootpage from one cell of the schema
// table: the first, second and fourth columns of (type, name, tbl_name,
// rootpage, sql). They come first in the record, so they are on the page even
// when a long CREATE statement spills onto overflow pages.
func sqliteSchemaRow(p []byte, off int) (typ, name string, root uint32, ok bool) {
	next := func() (uint64, bool) { // one varint
		var v uint64
		for i := 0; i < 9; i++ {
			if off >= len(p) {
				return 0, false
			}
			b := p[off]
			off++
			if i == 8 {
				return v<<8 | uint64(b), true
			}
			v = v<<7 | uint64(b&0x7f)
			if b < 0x80 {
				return v, true
			}
		}
		return 0, false
	}
	if _, ok = next(); !ok { // payload length
		return
	}
	if _, ok = next(); !ok { // rowid
		return
	}
	start := off
	hdrLen, ok := next()
	if !ok || hdrLen < 2 || start+int(hdrLen) > len(p) {
		return "", "", 0, false
	}
	var types [4]uint64
	for i := range types {
		if types[i], ok = next(); !ok || off > start+int(hdrLen) {
			return "", "", 0, false
		}
	}
	off = start + int(hdrLen)
	text := func(t uint64) (string, bool) {
		if t < 13 || t%2 == 0 {
			return "", false
		}
		n := int((t - 13) / 2)
		if n > 4096 || off+n > len(p) {
			return "", false
		}
		s := string(p[off : off+n])
		off += n
		return s, true
	}
	if typ, ok = text(types[0]); !ok {
		return
	}
	if name, ok = text(types[1]); !ok {
		return
	}
	if _, ok = text(types[2]); !ok {
		return
	}
	// rootpage: an integer of 0 to 8 bytes (serial types 0-6), or the constants 0 and 1.
	width := map[uint64]int{0: 0, 1: 1, 2: 2, 3: 3, 4: 4, 5: 6, 6: 8, 8: 0, 9: 0}
	n, known := width[types[3]]
	if !known || off+n > len(p) {
		return "", "", 0, false
	}
	var v uint64
	for _, b := range p[off : off+n] {
		v = v<<8 | uint64(b)
	}
	if types[3] == 9 {
		v = 1
	}
	return typ, name, uint32(v), v <= 1<<31
}
