// Package infra configures servers from their desired state in a git
// repository. Each host runs `infrafier pull` from a timer: it fetches its
// ref, verifies the commit's signature, renders the host's modules, plans the
// changes against the live system and applies them.
//
//	host spec + modules ──Render──▶ []Resource ──MakePlan(System)──▶ Plan ──Apply──▶ host
//	   pure, golden tests                         reads only              writes, actions
//
// Rendering is pure, so `infrafier diff` and the golden test show a
// template change as a diff of the real config files. Planning and applying go
// through System, which tests back with a temp dir and a fake command runner.
package infra

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io/fs"
	"maps"
	"net/http"
	"slices"
	"strings"
)

// Resource is one piece of desired state.
type Resource interface {
	// Key identifies the resource; two resources with the same key are an error.
	Key() string
}

// File is a regular file with exact content. Owner and Group empty means they
// are left as they are; Render defaults them to root.
type File struct {
	Path    string
	Content []byte
	Mode    fs.FileMode
	Owner   string
	Group   string
	// Secret hides the content from plans, diffs and golden files.
	Secret bool
	// UsesSecrets is a file whose template reads secrets. Its golden file
	// is Content when it was rendered with placeholders (Placeholders: diff,
	// CI); rendered with the values, it is a fixed marker, never a digest
	// of content that holds a value.
	UsesSecrets  bool
	Placeholders bool
	OnChange     []Action
}

// Dir is a directory. With Purge, everything under it that no resource
// declares is removed, which is what keeps old files from piling up. OnChange
// runs when a purge removed something, so e.g. nginx stops serving a removed
// site; a removed file cannot be put back, so a failing check only reports.
type Dir struct {
	Path     string
	Mode     fs.FileMode
	Owner    string
	Group    string
	Purge    bool
	OnChange []Action
}

// Package is a Debian package that must be installed.
type Package struct {
	Name string
}

// Unit is a systemd unit. Enabled and Active only ever ensure the unit is
// enabled or running; false leaves it as it is.
type Unit struct {
	Name    string
	Enabled bool
	Active  bool
}

// Command is the escape hatch for one-off setup steps (creating a Postgres
// role, Influx setup): Run runs only when Check exits non-zero. Check must not
// change anything, since every plan runs it.
//
// Secret keeps Check and Run out of plans and golden files. While they run,
// their arguments are still in the process list for every user on the host,
// so a password belongs in a secret File the command reads (psql -f), not in
// its arguments.
type Command struct {
	Name   string
	Check  []string
	Run    []string
	Secret bool
}

// Download installs files from an https URL pinned by the sha256 that
// upstream publishes for it (Prometheus, Traefik and the exporters ship
// sha256sums.txt next to their tarballs), so review can check the pin
// against upstream. Files maps archive members to the paths they are
// installed at; a single File with no Member installs the download itself.
// Archives are .tar.gz.
//
// Fetched files go into a content-addressed cache under downloadCache, so a
// pull fetches nothing once the installed files match, and hashes only those
// whose Stamp changed since they were installed or last hashed. Unit files
// are refused: they belong in a File, which triggers the daemon-reload.
// A failed onChange check cannot put an installed file back (the old binary
// is not kept), so its action stays owed and its unit is not started, as
// after a purge: the running process keeps its old binary until a commit
// fixes it.
//
// PreInstallCheck is what the agent installs itself with: it runs on
// the new file before that replaces the old one, so a binary that fails it is
// never installed. KeepPrevious keeps the file it replaces as <path>.prev,
// what the pull unit falls back to when the new agent cannot plan a commit.
type Download struct {
	URL      string
	SHA256   string // hex
	Files    []DownloadFile
	Mode     fs.FileMode
	Owner    string
	Group    string
	OnChange []Action
	// PreInstallCheck is a command run on the new file, written next to
	// its path under a temporary name (stagedPath), with every
	// PreInstallFile in an argument replaced by that name. Only for a
	// download of one file. When it fails, the file is not installed and
	// the run fails.
	PreInstallCheck []string
	KeepPrevious    bool
	// Headers are sent with the request, and shown in golden files.
	Headers map[string]string
	// SecretHeaders maps a header to the host secret that holds its value,
	// e.g. Authorization → a secret "Bearer github_pat_…", for a release
	// asset of a private repository. Golden files and plans show the header
	// and the secret's name, never the value, and Fetch drops the header on
	// a redirect to another host (a signed download URL needs none).
	SecretHeaders map[string]string
	// secretValues are the values of SecretHeaders, read from the host's
	// secrets at render. placeholders: rendered without secrets (diff, CI),
	// so secretValues are placeholders and the download refuses to fetch.
	secretValues http.Header
	placeholders bool
	// leavePrevious: this run does not replace .prev, which stays declared
	// (a fallback run, see PullConfig.Fallback).
	leavePrevious bool
}

// PreInstallFile is what a download's preInstallCheck writes for the new
// file, e.g. ["{file}", "version"].
const PreInstallFile = "{file}"

// previousPath is where a download with KeepPrevious keeps the file it
// replaced.
func previousPath(p string) string { return p + ".prev" }

// DownloadFile is one file a Download installs.
type DownloadFile struct {
	Member string // path in the archive; empty for a download that is no archive
	Path   string
}

// User is a system user with a group of its own name, for a service that
// owns files (its data directory, a secret it reads). It is created with
// home Home (not created; /nonexistent by default) and no login shell, and
// made a member of Groups. An existing user is only given the groups it
// lacks: its home, shell and other groups are left as they are, and it is
// never removed, since a package or an operator may have set it up.
type User struct {
	Name   string
	Home   string
	Groups []string
}

// Action is a systemctl verb on a unit, run once after all changes were made.
// Checks run first (e.g. `nginx -t`); when one fails the files that triggered
// the action are put back and the action is skipped. On a unit that is
// stopped only the checks run: an action never starts a unit (that is what a
// Unit with Active is for), and a stopped unit reads its files when it
// starts. Rendered actions have at most one check; actions merged per unit,
// and kept pending in state.json, carry all of theirs.
type Action struct {
	Verb   string     `json:"verb"`
	Unit   string     `json:"unit,omitempty"`
	Checks [][]string `json:"checks,omitempty"`
}

// daemonReload is the pending Action (no unit) that a failed `systemctl
// daemon-reload` leaves owed, so the next run retries it even though the unit
// files on disk then already match.
const daemonReload = "daemon-reload"

// pathsAndActions returns the paths a resource writes and its onChange
// actions; no paths for the resources that write none.
func pathsAndActions(r Resource) (paths []string, onChange []Action) {
	switch r := r.(type) {
	case *File:
		return []string{r.Path}, r.OnChange
	case *Dir:
		return []string{r.Path}, r.OnChange
	case *Download:
		for _, f := range r.Files {
			paths = append(paths, f.Path)
			// Declared, so a purge of its directory leaves it and no
			// other resource may take the path.
			if r.KeepPrevious {
				paths = append(paths, previousPath(f.Path))
			}
		}
		return paths, r.OnChange
	}
	return nil, nil
}

func (f *File) Key() string     { return "file:" + f.Path }
func (d *Dir) Key() string      { return "dir:" + d.Path }
func (p *Package) Key() string  { return "package:" + p.Name }
func (u *Unit) Key() string     { return "unit:" + u.Name }
func (c *Command) Key() string  { return "command:" + c.Name }
func (d *Download) Key() string { return "download:" + d.URL }
func (u *User) Key() string     { return "user:" + u.Name }

func (a Action) String() string {
	if a.Unit == "" {
		return a.Verb
	}
	s := a.Verb + " " + a.Unit
	if len(a.Checks) > 0 {
		checks := make([]string, len(a.Checks))
		for i, c := range a.Checks {
			checks[i] = strings.Join(c, " ")
		}
		s += " (check: " + strings.Join(checks, " && ") + ")"
	}
	return s
}

var actionVerbs = map[string]bool{"restart": true, "reload": true, "try-restart": true}

func (a Action) validate() error {
	if !actionVerbs[a.Verb] {
		return fmt.Errorf("unknown action verb %q", a.Verb)
	}
	if a.Unit == "" {
		return fmt.Errorf("action %s without unit", a.Verb)
	}
	return nil
}

// describe is one line per resource for the golden _resources.txt and plans.
func describe(r Resource) string {
	switch r := r.(type) {
	case *File:
		s := fmt.Sprintf("file %s %04o %s:%s", r.Path, r.Mode, r.Owner, r.Group)
		if r.Secret {
			s += " secret"
		}
		return s + describeOnChange(r.OnChange)
	case *Dir:
		s := fmt.Sprintf("dir %s %04o %s:%s", r.Path, r.Mode, r.Owner, r.Group)
		if r.Purge {
			s += " purge"
		}
		return s + describeOnChange(r.OnChange)
	case *Package:
		return "package " + r.Name
	case *Unit:
		s := "unit " + r.Name
		if r.Enabled {
			s += " enabled"
		}
		if r.Active {
			s += " active"
		}
		return s
	case *Command:
		if r.Secret {
			argv := strings.Join(r.Check, "\x00") + "\x00\x00" + strings.Join(r.Run, "\x00")
			return fmt.Sprintf("command %s secret (%s)", r.Name, digest([]byte(argv)))
		}
		return fmt.Sprintf("command %s\n  check: %s\n  run: %s", r.Name, strings.Join(r.Check, " "), strings.Join(r.Run, " "))
	case *Download:
		// The first line keeps its five fields and only the file lines
		// have a "→": golden.go's downloadInstalls and downloadPaths read
		// them back.
		s := fmt.Sprintf("download %s sha256:%s %04o %s:%s", r.URL, r.SHA256, r.Mode, r.Owner, r.Group)
		for _, f := range r.Files {
			if f.Member == "" {
				s += "\n  → " + f.Path
			} else {
				s += "\n  " + f.Member + " → " + f.Path
			}
		}
		if r.KeepPrevious {
			for _, f := range r.Files {
				s += "\n  keep previous: " + previousPath(f.Path)
			}
		}
		if len(r.PreInstallCheck) > 0 {
			s += "\n  pre-install check: " + strings.Join(r.PreInstallCheck, " ")
		}
		// Quoted, so a value never holds the "→" of a file line.
		for _, h := range slices.Sorted(maps.Keys(r.Headers)) {
			s += fmt.Sprintf("\n  header %s: %q", h, r.Headers[h])
		}
		for _, h := range slices.Sorted(maps.Keys(r.SecretHeaders)) {
			s += fmt.Sprintf("\n  header %s: secret %q", h, r.SecretHeaders[h])
		}
		return s + describeOnChange(r.OnChange)
	case *User:
		s := "user " + r.Name + " home " + r.Home
		if len(r.Groups) > 0 {
			s += " groups " + strings.Join(r.Groups, ",")
		}
		return s
	}
	return r.Key()
}

func describeOnChange(acts []Action) string {
	var s string
	for _, a := range acts {
		s += "\n  on change: " + a.String()
	}
	return s
}

// digest stands in for a secret in golden files, so that a change to it still
// shows up in review (and `infrafier diff` lists the actions it triggers). It
// tells nothing the repo does not: the secret is rendered from the repo.
func digest(b []byte) string {
	sum := sha256.Sum256(b)
	return "sha256:" + hex.EncodeToString(sum[:])
}
