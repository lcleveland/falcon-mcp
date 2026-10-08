// Package guides embeds the query guides (FQL per area, CQL, the RTR
// workflow) extracted from CrowdStrike/falcon-mcp, MIT-licensed (see
// LICENSE). internal/falcon/gen writes the .md files; don't edit them.
package guides

import (
	"embed"
	"strings"
)

//go:embed *.md
var files embed.FS

// Text returns the guide at a falcon:// URI.
func Text(uri string) (string, bool) {
	name, ok := strings.CutPrefix(uri, "falcon://")
	if !ok {
		return "", false
	}
	b, err := files.ReadFile(strings.ReplaceAll(name, "/", ".") + ".md")
	return string(b), err == nil
}
