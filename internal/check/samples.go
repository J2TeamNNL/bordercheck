package check

// LikelySample is one finding that looks like a sample key rather than a real
// one: a file a git repository records unchanged, a file an SDK ships to every
// user, or a file in a demo or example folder. It does not count toward the
// status; IT sees the list. Never holds a value or its last characters.
type LikelySample struct {
	Path string `json:"path"`
	Name string `json:"name,omitempty"` // the variable name, if the finding has one
	Kind string `json:"kind"`
	Rule string `json:"rule"` // git-tracked, sdk or sample-dir
}
