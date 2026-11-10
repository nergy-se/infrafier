package infra

import (
	"bytes"
	"errors"
	"fmt"
	"io/fs"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strings"
)

// The golden tree of a host is what review sees: every rendered file at its
// path under rendered/<host>/, plus _resources.txt with everything else
// (modes, owners, packages, units, commands, actions) in apply order. A
// template change in a PR then shows up as a diff of the real config files.

const resourcesFile = "_resources.txt"

// secretPlaceholder is what a secret file's golden file holds.
func secretPlaceholder(content []byte) []byte {
	return []byte("<secret: not rendered into golden files; " + digest(content) + ">\n")
}

// GoldenTree maps a slash path relative to rendered/<host>/ to its content.
// secretsLine (SecretsLine) goes last in _resources.txt; see GoldenDiff.
func GoldenTree(rs []Resource, secretsLine string) map[string][]byte {
	tree := map[string][]byte{}
	var list strings.Builder
	for _, r := range rs {
		list.WriteString(describe(r) + "\n")
		if f, ok := r.(*File); ok {
			content := f.Content
			switch {
			case f.UsesSecrets && f.Placeholders:
				// Content as rendered: placeholders, and possibly
				// empty (a nil slice, which is not "no golden file").
			case f.UsesSecrets:
				// A sha256 of content with a short password in it could be
				// brute-forced from the repo.
				content = []byte("<secret: rendered with this host's secret values; render without them for the golden file>\n")
			case f.Secret:
				content = secretPlaceholder(f.Content)
			}
			tree[strings.TrimPrefix(f.Path, "/")] = content
		}
	}
	if secretsLine != "" {
		list.WriteString(secretsLine + "\n")
	}
	tree[resourcesFile] = []byte(list.String())
	return tree
}

// SecretsLine is the _resources.txt line for the host's secrets file: its
// path and a sha256 of the ciphertext, which is in the repo anyway, so it
// tells nothing more. Empty when the host has none.
func SecretsLine(fsys fs.FS, host string) (string, error) {
	b, err := readSecretsFile(fsys, host)
	if err != nil || b == nil {
		return "", err
	}
	return "secrets " + SecretsFile(host) + " " + digest(b), nil
}

func secretsLineOf(resources []byte) string {
	for _, l := range strings.Split(string(resources), "\n") {
		if strings.HasPrefix(l, "secrets ") {
			return l
		}
	}
	return ""
}

// GoldenDiff compares a host's tree with dir (rendered/<host>) and returns a
// unified diff per differing file, sorted by path, plus the actions the
// changed files would trigger.
//
// The golden files show placeholders, so a change of the secrets file alone
// changes none of them. It changes the secrets line, and then every file
// that reads secrets counts as changed, with its actions: on the host it
// changes when a value it reads did, and review should see the restarts it
// may cause.
func GoldenDiff(dir string, rs []Resource, secretsLine string) (diffs []string, actions []Action, err error) {
	want := GoldenTree(rs, secretsLine)
	have, err := readTree(dir)
	if err != nil {
		return nil, nil, err
	}
	paths := map[string]bool{}
	for p := range want {
		paths[p] = true
	}
	for p := range have {
		paths[p] = true
	}
	sorted := slices.Sorted(maps.Keys(paths))

	changed := map[string]bool{}
	// A mode or owner change only shows in _resources.txt, but it triggers
	// the file's actions on a host just like a content change.
	oldResources := "\n" + string(have[resourcesFile])
	oldBlocks := resourceBlocks(have[resourcesFile])
	secretsChanged := secretsLineOf(have[resourcesFile]) != secretsLine
	for _, r := range rs {
		if f, ok := r.(*File); ok {
			line, _, _ := strings.Cut(describe(f), "\n")
			if !strings.Contains(oldResources, "\n"+line+"\n") || secretsChanged && f.UsesSecrets {
				changed[f.Path] = true
			}
		}
	}
	for _, p := range sorted {
		w, inWant := want[p]
		h, inHave := have[p]
		if inWant == inHave && bytes.Equal(w, h) {
			continue
		}
		changed["/"+p] = true
		diffs = append(diffs, unifiedDiff("/"+p, h, w))
	}
	oldInstalls := map[string]bool{}
	for b := range oldBlocks {
		for _, f := range downloadInstalls(b) {
			oldInstalls[f] = true
		}
	}
	var changes []*Change
	for _, r := range rs {
		switch r := r.(type) {
		case *File:
			if changed[r.Path] {
				changes = append(changes, &Change{file: r, actions: r.OnChange})
			}
		case *Download:
			// Its files have no golden file: a new pin, file list, mode or
			// owner only shows as its block in _resources.txt.
			for _, f := range downloadInstalls(describe(r)) {
				if !oldInstalls[f] {
					changes = append(changes, &Change{actions: r.OnChange})
					break
				}
			}
		}
	}
	// A file no longer rendered is removed on the host only by the purge of
	// the innermost declared directory holding it, which runs its actions.
	for _, p := range sorted {
		if _, inWant := want[p]; inWant || p == resourcesFile {
			continue
		}
		if d := innermostDir(rs, "/"+p); d != nil && d.Purge {
			changes = append(changes, &Change{removes: "/" + p, actions: d.OnChange})
		}
	}
	// Nor do a download's files: one no resource declares any more is
	// removed by the same purge, found from the old download blocks.
	declared := map[string]bool{}
	for _, r := range rs {
		paths, _ := pathsAndActions(r)
		for _, p := range paths {
			declared[p] = true
		}
	}
	for b := range oldBlocks {
		for _, p := range downloadPaths(b) {
			if declared[p] {
				continue
			}
			declared[p] = true // once, if two old blocks had it
			if d := innermostDir(rs, p); d != nil && d.Purge {
				changes = append(changes, &Change{removes: p, actions: d.OnChange})
			}
		}
	}
	return diffs, groupActions(changes, nil).actions(), nil
}

// downloadPaths are the paths a download's describe() block installs.
func downloadPaths(block string) []string {
	if !strings.HasPrefix(block, "download ") {
		return nil
	}
	var out []string
	for _, l := range strings.Split(block, "\n")[1:] {
		if p, ok := strings.CutPrefix(l, "  keep previous: "); ok {
			out = append(out, p) // not installed, but on the host all the same
		} else if _, p, ok := strings.Cut(l, "→ "); ok && !strings.HasPrefix(l, "  on change: ") {
			out = append(out, p)
		}
	}
	return out
}

// resourceBlocks splits _resources.txt into one describe() per resource: a
// line that starts with a space continues the block before it.
func resourceBlocks(b []byte) map[string]bool {
	blocks := map[string]bool{}
	var cur []string
	flush := func() {
		if len(cur) > 0 {
			blocks[strings.Join(cur, "\n")] = true
		}
		cur = nil
	}
	for _, l := range strings.Split(string(b), "\n") {
		if !strings.HasPrefix(l, " ") {
			flush()
		}
		if l != "" {
			cur = append(cur, l)
		}
	}
	flush()
	return blocks
}

// downloadInstalls is what a download's describe() block installs on a
// host, one line per file: pin, mode, owner, member and path. Its actions
// run only when one of those changes, so the URL (a new mirror) and the
// actions are left out, and a dropped file is not a change: nothing on the
// host is written for it. A new archive pin counts even if its members are
// the same; only the archive tells.
func downloadInstalls(block string) []string {
	lines := strings.Split(block, "\n")
	head := strings.Fields(lines[0]) // download <url> sha256:<sum> <mode> <owner>:<group>
	if len(head) != 5 || head[0] != "download" {
		return nil
	}
	attrs := strings.Join(head[2:], " ")
	var out []string
	for _, l := range lines[1:] {
		// A file line; not an action, a kept previous file or a
		// pre-install check, none of which installs anything.
		if strings.Contains(l, "→ ") && !strings.HasPrefix(l, "  on change: ") {
			out = append(out, attrs+" "+strings.TrimSpace(l))
		}
	}
	return out
}

func innermostDir(rs []Resource, p string) *Dir {
	var best *Dir
	for _, r := range rs {
		if d, ok := r.(*Dir); ok && strings.HasPrefix(p, d.Path+"/") && (best == nil || len(d.Path) > len(best.Path)) {
			best = d
		}
	}
	return best
}

// StaleGolden lists the directories under rendered/ (in dir) that belong to
// no host, e.g. one left behind when a host was renamed. Their golden files
// would otherwise sit in the repo for ever, unchecked.
func StaleGolden(dir string, hosts []string) ([]string, error) {
	entries, err := os.ReadDir(dir)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	known := map[string]bool{}
	for _, h := range hosts {
		known[h] = true
	}
	var stale []string
	for _, e := range entries {
		// Only host directories; a README or .gitkeep is not a host.
		if e.IsDir() && !strings.HasPrefix(e.Name(), ".") && !known[e.Name()] {
			stale = append(stale, e.Name())
		}
	}
	return stale, nil
}

// WriteGolden replaces dir with the host's tree.
func WriteGolden(dir string, rs []Resource, secretsLine string) error {
	if err := os.RemoveAll(dir); err != nil {
		return err
	}
	for p, content := range GoldenTree(rs, secretsLine) {
		full := filepath.Join(dir, filepath.FromSlash(p))
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			return err
		}
		if err := os.WriteFile(full, content, 0o644); err != nil {
			return err
		}
	}
	return nil
}

func readTree(dir string) (map[string][]byte, error) {
	tree := map[string][]byte{}
	err := filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
		if errors.Is(err, fs.ErrNotExist) && p == dir {
			return filepath.SkipAll
		}
		if err != nil || d.IsDir() {
			return err
		}
		rel, err := filepath.Rel(dir, p)
		if err != nil {
			return err
		}
		b, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		tree[filepath.ToSlash(rel)] = b
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", dir, err)
	}
	return tree, nil
}
