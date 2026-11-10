// Command infrafier keeps servers in their desired state, kept in a git
// repository: each host pulls its branch on a timer, verifies the commit's
// signature against operator keys it holds itself, renders its modules and
// applies the difference. See README.md.
package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"runtime/debug"
	"syscall"

	"github.com/urfave/cli/v2"
)

// version is set by the release build (-ldflags -X main.version=…).
var version = "dev"

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	app := &cli.App{
		Name:     "infrafier",
		Usage:    "Keep servers in the desired state of a signed git repository",
		Version:  version,
		Commands: commands(),
	}
	if err := app.RunContext(ctx, os.Args); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

func versionCommand() *cli.Command {
	return &cli.Command{
		Name:  "version",
		Usage: "Print the version and the commit it was built from",
		Action: func(c *cli.Context) error {
			fmt.Println(versionString())
			return nil
		},
	}
}

func versionString() string {
	s := "infrafier " + version
	info, ok := debug.ReadBuildInfo()
	if !ok {
		return s
	}
	var rev, modified string
	for _, kv := range info.Settings {
		switch kv.Key {
		case "vcs.revision":
			rev = kv.Value
		case "vcs.modified":
			if kv.Value == "true" {
				modified = "+modified"
			}
		}
	}
	if rev != "" {
		s += " (" + rev + modified + ")"
	}
	return s + " " + info.GoVersion
}
