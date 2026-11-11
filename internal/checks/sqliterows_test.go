package checks

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

// A database made by sqlite3 with synthetic rows (no real login was ever in it).
func TestSQLiteTableRowsFixture(t *testing.T) {
	const f = "testdata/logins-3rows.sqlite"
	if n, err := sqliteTableRows(f, "logins"); err != nil || n != 3 {
		t.Errorf("logins: %d %v, want 3", n, err)
	}
	if n, err := sqliteTableRows(f, "meta"); err != nil || n != 0 {
		t.Errorf("meta: %d %v, want 0", n, err)
	}
	if _, err := sqliteTableRows(f, "nothing"); err == nil {
		t.Error("a missing table is an error")
	}
}

func TestSQLiteTableRowsRefusesWhatItDoesNotKnow(t *testing.T) {
	good, err := os.ReadFile("testdata/logins-3rows.sqlite")
	if err != nil {
		t.Fatal(err)
	}
	for name, change := range map[string]func([]byte){
		"not sqlite":    func(b []byte) { copy(b, "PK\x03\x04") },
		"odd page size": func(b []byte) { b[16], b[17] = 0x10, 0x01 },
		"utf-16 text":   func(b []byte) { b[59] = 2 },
		"bad page type": func(b []byte) { b[100] = 0x77 },
	} {
		b := bytes.Clone(good)
		change(b)
		if n, err := sqliteRows(bytes.NewReader(b), int64(len(b)), "logins"); err == nil {
			t.Errorf("%s: got %d rows and no error", name, n)
		}
	}
	// Truncated in the middle of a page, and an empty file: errors, not panics.
	for _, n := range []int{0, 50, 100, 4096 + 10} {
		if _, err := sqliteRows(bytes.NewReader(good[:n]), int64(n), "logins"); err == nil {
			t.Errorf("truncated to %d bytes: no error", n)
		}
	}
}

// Many rows (a b-tree several pages deep), then all deleted: the file keeps
// its size, which is why its size cannot tell whether logins are saved.
func TestSQLiteTableRowsAgainstSqlite3(t *testing.T) {
	sqlite3, err := exec.LookPath("sqlite3")
	if err != nil {
		t.Skip("sqlite3 is not installed")
	}
	db := filepath.Join(t.TempDir(), "Login Data")
	run := func(sql string) {
		t.Helper()
		if out, err := exec.Command(sqlite3, db, sql).CombinedOutput(); err != nil {
			t.Fatalf("sqlite3: %v\n%s", err, out)
		}
	}
	run("PRAGMA page_size=1024; CREATE TABLE logins (origin_url VARCHAR NOT NULL, password_value BLOB, id INTEGER PRIMARY KEY AUTOINCREMENT);" +
		"CREATE TABLE stats (a, b); CREATE INDEX logins_url ON logins (origin_url);")
	const rows = 3000
	run(fmt.Sprintf("WITH RECURSIVE n(i) AS (SELECT 1 UNION ALL SELECT i+1 FROM n WHERE i < %d) "+
		"INSERT INTO logins(origin_url, password_value) SELECT 'https://site' || i || '.example/', randomblob(80) FROM n;", rows))
	if n, err := sqliteTableRows(db, "logins"); err != nil || n != rows {
		t.Fatalf("after insert: %d %v, want %d", n, err, rows)
	}
	full, _ := os.Stat(db)
	run("DELETE FROM logins WHERE id % 2 = 0;")
	if n, err := sqliteTableRows(db, "logins"); err != nil || n != rows/2 {
		t.Fatalf("after deleting half: %d %v, want %d", n, err, rows/2)
	}
	run("DELETE FROM logins;")
	if n, err := sqliteTableRows(db, "logins"); err != nil || n != 0 {
		t.Fatalf("after deleting all: %d %v, want 0", n, err)
	}
	if after, _ := os.Stat(db); after.Size() != full.Size() {
		t.Logf("file went from %d to %d bytes", full.Size(), after.Size())
	} else if after.Size() < 100<<10 {
		t.Errorf("expected a large file that kept its size, got %d bytes", after.Size())
	}
}
