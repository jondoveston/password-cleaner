// Command password-cleaner removes lines containing known secrets from text.
package main

import (
	"os"

	"github.com/jondoveston/password-cleaner/internal/cli"
)

// Set at build time with -ldflags "-X main.version=...".
var (
	version = "dev"
	commit  = "none"
	date    = "unknown"
)

func main() {
	info := cli.BuildInfo{Version: version, Commit: commit, Date: date}
	os.Exit(cli.Execute(info, os.Args[1:], os.Stdin, os.Stdout, os.Stderr))
}
