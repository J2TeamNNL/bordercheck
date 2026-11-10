package checks

import (
	"io/fs"
	"syscall"
)

// sfDataless is SF_DATALESS from <sys/stat.h>: the file or folder's content is
// not on this disk and is fetched (by iCloud Drive or another file provider)
// when something reads it.
const sfDataless = 0x40000000

// cloudPlaceholder reports whether reading this file or folder would make
// macOS download it first.
func cloudPlaceholder(info fs.FileInfo) bool {
	st, ok := info.Sys().(*syscall.Stat_t)
	return ok && st.Flags&sfDataless != 0
}
