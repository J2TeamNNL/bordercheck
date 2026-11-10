//go:build !darwin

package checks

import "io/fs"

// cloudPlaceholder reports whether reading this file or folder would make the
// OS download it first. Only macOS marks that in a way that can be read
// without touching the file.
func cloudPlaceholder(fs.FileInfo) bool { return false }
