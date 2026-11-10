package infra

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io/fs"
	"path"
	"slices"
	"strconv"
	"strings"

	"github.com/pmezard/go-difflib/difflib"
)

// Plan is the ordered list of changes that brings a host to its rendered
// state. Changes run in the order the resources were rendered (a module lists
// a package before the files that configure it); the actions they trigger run
// once, after all changes.
type Plan struct {
	Changes []*Change
	// checks are the checks the rendered resources give each unit's
	// actions now. Owed actions take these instead of the ones stored when
	// they were owed, so a check a later commit replaced is not run forever.
	checks map[string][][]string
	// downloads is what the plan's downloads use of the download cache;
	// a clean Apply prunes the rest.
	downloads *downloadCacheUse
}

// Change is one step of a plan.
type Change struct {
	Key     string
	Summary string
	// Diff is a unified diff of a file's content, empty for secrets and for
	// changes that are not about content.
	Diff string

	do      func(ctx context.Context, sys System) error
	actions []Action
	// For File changes: the state before, so a failed check can put it back.
	file *File
	prev FileState
	// removes is the path a purge removes.
	removes string
	// enables and starts name the unit a Unit change enables or starts.
	// Both run after every write and the daemon-reload (see Apply).
	enables string
	starts  string
}

// touchesUnitFile tells whether the change wrote or removed a unit file, so
// systemd needs a daemon-reload.
func (c *Change) touchesUnitFile() bool {
	if c.file != nil {
		return isUnitFile(c.file.Path)
	}
	return c.removes != "" && isUnitFile(c.removes)
}

// MakePlan compares the rendered resources with the system. It only reads,
// apart from the Check of Command resources, which must not change anything,
// and the download cache, which it fills (so a dry run fetches too): nothing
// but Apply installs from it.
func MakePlan(ctx context.Context, sys System, rs []Resource) (*Plan, error) {
	p := &Plan{checks: map[string][][]string{}, downloads: newDownloadCacheUse()}
	declared := map[string]Resource{}
	for _, r := range rs {
		paths, onChange := pathsAndActions(r)
		for _, path := range paths {
			declared[path] = r
		}
		for _, a := range onChange {
			for _, c := range a.Checks {
				if !containsArgv(p.checks[a.Unit], c) {
					p.checks[a.Unit] = append(p.checks[a.Unit], c)
				}
			}
		}
	}
	update := &aptUpdate{}
	for _, r := range rs {
		var changes []*Change
		var err error
		switch r := r.(type) {
		case *File:
			changes, err = planFile(sys, r)
		case *Dir:
			changes, err = planDir(sys, r, declared)
		case *Package:
			changes, err = planPackage(ctx, sys, r, update)
		case *Unit:
			changes, err = planUnit(ctx, sys, r)
		case *Command:
			changes, err = planCommand(ctx, sys, r)
		case *Download:
			changes, err = planDownload(ctx, sys, r, p.downloads)
		case *User:
			changes, err = planUser(ctx, sys, r)
		default:
			err = fmt.Errorf("unknown resource type %T", r)
		}
		if err != nil {
			return nil, fmt.Errorf("%s: %w", r.Key(), err)
		}
		p.Changes = append(p.Changes, changes...)
	}
	return p, nil
}

func planFile(sys System, f *File) ([]*Change, error) {
	st, err := sys.Lstat(f.Path)
	if err != nil {
		return nil, err
	}
	if st.IsDir {
		return nil, fmt.Errorf("is a directory")
	}
	c := &Change{Key: f.Key(), file: f, prev: st, actions: f.OnChange}
	// What a failed check puts back is the file as it is right before the
	// write, not as planned: a package installed earlier in the run may have
	// created it (its default config), and that must not be deleted.
	before := func(sys System) {
		if now, err := sys.Lstat(f.Path); err == nil {
			c.prev = now
		}
	}
	c.do = func(ctx context.Context, sys System) error {
		before(sys)
		return sys.WriteFile(f.Path, f.Content, f.Mode, f.Owner, f.Group)
	}
	switch {
	case !st.Exists:
		c.Summary = "create " + f.Path
		c.Diff = fileDiff(f, nil)
	case st.IsSymlink:
		// prev keeps the link, so a failed check can put it back.
		c.Summary = "replace " + f.Path + " (a symlink to " + st.Link + ")"
		c.Diff = fileDiff(f, nil)
	case !st.IsRegular:
		return nil, fmt.Errorf("exists and is neither a regular file nor a symlink")
	case !bytes.Equal(st.Content, f.Content):
		c.Summary = "update " + f.Path + attrsChanged(st, f.Mode, f.Owner, f.Group)
		old := st.Content
		if st.Mode&0o004 == 0 {
			// Not world-readable: it may hold a secret (one a module no
			// longer marks secret: true), which must not reach the journal.
			old = nil
			c.Summary += " (old content not shown: not world-readable)"
		}
		c.Diff = fileDiff(f, old)
	default:
		attrs := attrsChanged(st, f.Mode, f.Owner, f.Group)
		if attrs == "" {
			return nil, nil
		}
		c.Summary = "update " + f.Path + attrs
		c.do = func(ctx context.Context, sys System) error {
			before(sys)
			return sys.SetAttrs(f.Path, f.Mode, f.Owner, f.Group)
		}
	}
	return []*Change{c}, nil
}

func attrsChanged(st FileState, mode fs.FileMode, owner, group string) string {
	var parts []string
	if st.Mode != mode {
		parts = append(parts, fmt.Sprintf("mode %04o → %04o", st.Mode, mode))
	}
	if owner != "" && !sameID(owner, st.Owner, st.UID) {
		parts = append(parts, fmt.Sprintf("owner %s → %s", st.Owner, owner))
	}
	if group != "" && !sameID(group, st.Group, st.GID) {
		parts = append(parts, fmt.Sprintf("group %s → %s", st.Group, group))
	}
	if len(parts) == 0 {
		return ""
	}
	return " (" + strings.Join(parts, ", ") + ")"
}

// sameID tells whether want, a user or group as a module gives it, is name
// (what Lstat resolved id to). A number is also compared with the id itself:
// setAttrs takes a number that names no one as the id, and Lstat then reports
// the name, so comparing names alone would chown (and restart) on every run.
func sameID(want, name string, id uint32) bool {
	if want == name {
		return true
	}
	n, err := strconv.ParseUint(want, 10, 32)
	return err == nil && uint32(n) == id
}

func fileDiff(f *File, old []byte) string {
	if f.Secret {
		return ""
	}
	return unifiedDiff(f.Path, old, f.Content)
}

func unifiedDiff(name string, old, new []byte) string {
	d, _ := difflib.GetUnifiedDiffString(difflib.UnifiedDiff{
		A:        diffLines(old),
		B:        diffLines(new),
		FromFile: "a" + name,
		ToFile:   "b" + name,
		Context:  3,
	})
	return d
}

// diffLines splits b into lines for difflib, each ending in a newline.
// difflib.SplitLines adds an empty line after the last newline, so a new
// file showed as replacing one blank line (-1 +1,n), with its first blank
// line as unchanged context and a stray "+" at the end. A last line without
// a newline is marked the way git and diff mark it.
func diffLines(b []byte) []string {
	if len(b) == 0 {
		return nil
	}
	lines := strings.SplitAfter(string(b), "\n")
	if last := lines[len(lines)-1]; last == "" {
		lines = lines[:len(lines)-1]
	} else {
		lines[len(lines)-1] = last + "\n\\ No newline at end of file\n"
	}
	return lines
}

func planDir(sys System, d *Dir, declared map[string]Resource) ([]*Change, error) {
	st, err := sys.Lstat(d.Path)
	if err != nil {
		return nil, err
	}
	var changes []*Change
	switch {
	case !st.Exists:
		changes = append(changes, &Change{Key: d.Key(), Summary: "create " + d.Path + "/", do: func(ctx context.Context, sys System) error {
			return sys.Mkdir(d.Path, d.Mode, d.Owner, d.Group)
		}})
		return changes, nil // nothing to purge yet
	case !st.IsDir:
		return nil, fmt.Errorf("exists and is not a directory")
	}
	if attrs := attrsChanged(st, d.Mode, d.Owner, d.Group); attrs != "" {
		changes = append(changes, &Change{Key: d.Key(), Summary: "update " + d.Path + "/" + attrs, do: func(ctx context.Context, sys System) error {
			return sys.SetAttrs(d.Path, d.Mode, d.Owner, d.Group)
		}})
	}
	if d.Purge {
		purged, err := planPurge(sys, d, d.Path, declared)
		if err != nil {
			return nil, err
		}
		changes = append(changes, purged...)
	}
	return changes, nil
}

// planPurge removes everything under dir that is neither declared nor on the
// way to something declared. A declared subdirectory is left to its own Dir
// resource (and its own Purge).
func planPurge(sys System, d *Dir, dir string, declared map[string]Resource) ([]*Change, error) {
	names, err := sys.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	var changes []*Change
	for _, name := range names {
		p := path.Join(dir, name)
		if _, ok := declared[p]; ok {
			continue
		}
		if hasDeclaredBelow(p, declared) {
			// Never recurse through a symlink: purging its target would
			// remove files outside the purged directory.
			st, err := sys.Lstat(p)
			if err != nil {
				return nil, err
			}
			if !st.IsDir {
				return nil, fmt.Errorf("purge %s: %s is not a directory, but resources are declared below it", d.Path, p)
			}
			sub, err := planPurge(sys, d, p, declared)
			if err != nil {
				return nil, err
			}
			changes = append(changes, sub...)
			continue
		}
		changes = append(changes, &Change{Key: "purge:" + p, Summary: "remove " + p + " (not declared)", removes: p, actions: d.OnChange, do: func(ctx context.Context, sys System) error {
			return sys.RemoveAll(p)
		}})
	}
	return changes, nil
}

func hasDeclaredBelow(p string, declared map[string]Resource) bool {
	for d := range declared {
		if strings.HasPrefix(d, p+"/") {
			return true
		}
	}
	return false
}

// aptUpdate runs `apt-get update` once per plan, before its first install:
// without it a package added months after bootstrap is fetched by an index
// that names versions the mirror no longer has.
type aptUpdate struct{ done bool }

func (u *aptUpdate) run(ctx context.Context, sys System) error {
	if u.done {
		return nil
	}
	u.done = true
	_, err := sys.Run(ctx, "env", "DEBIAN_FRONTEND=noninteractive", "apt-get", "update", "-q")
	return err
}

// installed tells whether dpkg has every architecture of the package
// installed (one status line each, for a multi-arch package). A name dpkg
// does not know (exit 1) is not installed.
func installed(ctx context.Context, sys System, name string) (bool, error) {
	out, err := sys.Run(ctx, "dpkg-query", "-W", "-f=${db:Status-Status}\n", name)
	if err != nil && !exitedNonZero(err) {
		return false, err
	}
	return err == nil && allInstalled(string(out)), nil
}

func planPackage(ctx context.Context, sys System, p *Package, update *aptUpdate) ([]*Change, error) {
	ok, err := installed(ctx, sys, p.Name)
	if ok || err != nil {
		return nil, err
	}
	return []*Change{{Key: p.Key(), Summary: "install package " + p.Name, do: func(ctx context.Context, sys System) error {
		// A failed update (a mirror down) need not fail the install, which
		// may well work from the index it has; if both fail, say both.
		uerr := update.run(ctx, sys)
		// confold: the files infra manages are written after the package,
		// and the package must never stop on a conffile prompt.
		_, err := sys.Run(ctx, "env", "DEBIAN_FRONTEND=noninteractive", "apt-get", "install", "-y", "--no-install-recommends",
			"-o", "Dpkg::Options::=--force-confdef", "-o", "Dpkg::Options::=--force-confold", p.Name)
		if err != nil && uerr != nil {
			return errors.Join(err, fmt.Errorf("apt-get update: %w", uerr))
		}
		if err != nil {
			return err
		}
		// apt-get also succeeds for a virtual package (one that is only
		// provided, like mail-transport-agent) by installing or keeping a
		// provider, but dpkg never knows the name itself: the plan would
		// install it on every run, with an apt-get update each time, and
		// never fail. Fail once, loudly, so the module names the provider.
		ok, err := installed(ctx, sys, p.Name)
		if err != nil {
			return err
		}
		if !ok {
			return fmt.Errorf("apt-get install succeeded, but dpkg does not have %s installed; is it a virtual package? Name the package that provides it instead", p.Name)
		}
		return nil
	}}}, nil
}

func allInstalled(out string) bool {
	lines := strings.Fields(out)
	for _, l := range lines {
		if l != "installed" {
			return false
		}
	}
	return len(lines) > 0
}

func planUnit(ctx context.Context, sys System, u *Unit) ([]*Change, error) {
	check := func(verb string) (bool, error) {
		_, err := sys.Run(ctx, "systemctl", verb, u.Name)
		if err != nil && !exitedNonZero(err) {
			return false, err
		}
		return err == nil, nil
	}
	var enable, start bool
	if u.Enabled {
		ok, err := check("is-enabled")
		if err != nil {
			return nil, err
		}
		enable = !ok
	}
	if u.Active {
		ok, err := check("is-active")
		if err != nil {
			return nil, err
		}
		start = !ok
	}
	if !enable && !start {
		return nil, nil
	}
	var verbs []string
	if enable {
		verbs = append(verbs, "enable")
	}
	if start {
		verbs = append(verbs, "start")
	}
	// Enable and start run in Apply, after every write and the daemon-reload:
	// enabling as a change would fail, and stop the run before the unit file
	// is written, whenever a module lists the unit before its unit file, and
	// so on every run after. The start also waits for every check, so a unit
	// never starts on a file a check is about to reject.
	c := &Change{Key: u.Key(), Summary: strings.Join(verbs, " and ") + " " + u.Name, do: func(context.Context, System) error { return nil }}
	if enable {
		c.enables = u.Name
	}
	if start {
		c.starts = u.Name
	}
	return []*Change{c}, nil
}

func planCommand(ctx context.Context, sys System, c *Command) ([]*Change, error) {
	if _, err := sys.Run(ctx, c.Check...); err == nil {
		return nil, nil
	}
	// The check may fail only because a package this plan installs is still
	// missing, so apply checks again right before running. By then it has to
	// run: Run only runs on a check that ran and said no.
	summary := "run " + c.Name + ": " + strings.Join(c.Run, " ")
	if c.Secret {
		summary = "run " + c.Name + " (secret command, not shown)"
	}
	return []*Change{{Key: c.Key(), Summary: summary, do: func(ctx context.Context, sys System) error {
		_, err := sys.Run(ctx, c.Check...)
		if err == nil {
			return nil
		}
		if !exitedNonZero(err) {
			return fmt.Errorf("check: %w", err)
		}
		if _, err := sys.Run(ctx, c.Run...); err != nil {
			return err
		}
		if _, err := sys.Run(ctx, c.Check...); err != nil {
			return fmt.Errorf("check still fails after run: %w", err)
		}
		return nil
	}}}, nil
}

// Actions lists, in order, the actions the plan would run.
func (p *Plan) Actions() []Action {
	return groupActions(p.Changes, nil).actions()
}

func (p *Plan) Empty() bool { return len(p.Changes) == 0 }

func (p *Plan) String() string {
	if p.Empty() {
		return "no changes\n"
	}
	var b strings.Builder
	for _, c := range p.Changes {
		b.WriteString(c.Summary + "\n")
		if c.Diff != "" {
			for _, l := range strings.SplitAfter(c.Diff, "\n") {
				if l != "" {
					b.WriteString("    " + l)
				}
			}
			if !strings.HasSuffix(c.Diff, "\n") {
				b.WriteString("\n")
			}
		}
	}
	for _, a := range p.Actions() {
		b.WriteString("then " + a.String() + "\n")
	}
	return b.String()
}

// isUnitFile tells whether writing path needs a systemctl daemon-reload.
func isUnitFile(p string) bool {
	for _, dir := range []string{"/etc/systemd/system/", "/usr/local/lib/systemd/system/", "/lib/systemd/system/", "/usr/lib/systemd/system/"} {
		if strings.HasPrefix(p, dir) {
			return true
		}
	}
	return false
}

// Apply runs the plan. pending are actions an earlier run owed (it wrote the
// files but the restart, or the daemon-reload, failed); they run along with
// this plan's actions. It returns the actions that still could not run, for
// the caller to keep until the next run, since that run will see no change in
// the files and would otherwise never restart the unit.
//
// A failing change stops the remaining changes, but the actions of the
// changes already made still run: the files are on disk either way.
func (p *Plan) Apply(ctx context.Context, sys System, pending []Action) ([]Action, error) {
	var errs []error
	reloadNeeded, reloadFailed := false, false
	var owed []Action
	for _, a := range pending {
		if a.Verb == daemonReload {
			reloadNeeded = true
			continue
		}
		a.Checks = p.checks[a.Unit]
		owed = append(owed, a)
	}
	systemctl := func(verb, unit string) error {
		_, err := sys.Run(ctx, "systemctl", verb, unit)
		if err != nil {
			errs = append(errs, fmt.Errorf("%s %s: %w", verb, unit, err))
		}
		return err
	}
	reload := func() bool {
		if !reloadNeeded {
			return true
		}
		if _, err := sys.Run(ctx, "systemctl", daemonReload); err != nil {
			errs = append(errs, fmt.Errorf("daemon-reload: %w", err))
			reloadFailed = true
			return false
		}
		reloadNeeded = false
		return true
	}

	var done []*Change
	var enables, starts []string // units to enable and start once the checks are through
	for _, c := range p.Changes {
		if err := c.do(ctx, sys); err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", c.Key, err))
			break
		}
		done = append(done, c)
		if c.touchesUnitFile() {
			reloadNeeded = true
		}
		if c.enables != "" {
			enables = append(enables, c.enables)
		}
		if c.starts != "" {
			starts = append(starts, c.starts)
		}
	}
	groups := groupActions(done, owed)
	if reloadFailed || !reload() {
		// Restarts would use the old unit definitions: owe them all, and the
		// reload, until a run gets the reload through.
		return append(groups.actions(), Action{Verb: daemonReload}), errors.Join(errs...)
	}

	// Every check runs before any unit is touched, so a file shared by two
	// units is never put back after one of them already runs it.
	var still []Action
	var run, failed actionGroups
	// blocked are units whose files no check approved, which a planned
	// start must not bring up.
	blocked := map[string]bool{}
	for _, g := range groups {
		st, err := g.state(ctx, sys)
		switch {
		case err != nil:
			// Unknown is not stopped: keep the action for the next run.
			// Its checks did not run, so neither does its start.
			errs = append(errs, fmt.Errorf("%s %s: %w", g.verb, g.unit, err))
			still = append(still, g.action())
			blocked[g.unit] = true
			continue
		case g.last == 0 && (st == "not-found" || (st == "inactive" && !slices.Contains(starts, g.unit))):
			// Owed for a unit that is gone, or for one that is stopped
			// (it reads its files when it starts). One this run starts
			// still has its checks run below, as the start reads its files.
			continue
		case st == "inactive":
			// Stopped, by an operator or never started: a restart would
			// start it, which only a Unit with Active does. Its checks
			// still run, since a start below would read these files.
			g.stopped = true
		case st == "failed":
			// A failed restart left it down; a reload can't bring it up.
			g.verb = "restart"
		}
		if err := g.check(ctx, sys); err != nil {
			errs = append(errs, fmt.Errorf("%s %s: check failed, files put back: %w", g.verb, g.unit, err))
			failed = append(failed, g)
			continue
		}
		run = append(run, g)
	}

	// A change a check rejected is put back for every unit it triggers, so
	// a group sharing it fails too, with all of its own changes: otherwise a
	// unit would run a mix of old and new files that no check approved.
	rejected := map[*Change]bool{}
	reject := func(g *actionGroup) {
		for _, c := range g.triggers {
			rejected[c] = true
		}
	}
	for _, g := range failed {
		reject(g)
	}
	for grew := true; grew; {
		grew = false
		var keep actionGroups
		for _, g := range run {
			if !g.sharesAny(rejected) {
				keep = append(keep, g)
				continue
			}
			errs = append(errs, fmt.Errorf("%s %s: not run, it shares a change another unit's check rejected; files put back", g.verb, g.unit))
			failed = append(failed, g)
			reject(g)
			grew = true
		}
		run = keep
	}
	var restoreErrs map[*Change]error
	if len(rejected) > 0 {
		restoreErrs = restore(sys, done, rejected)
		for _, c := range done {
			if err := restoreErrs[c]; err != nil {
				errs = append(errs, err)
			}
			if rejected[c] && c.file != nil && c.touchesUnitFile() {
				reloadNeeded = true // so systemd forgets the rejected unit file
			}
		}
	}
	for _, g := range failed {
		restoreFailed := slices.ContainsFunc(g.triggers, func(c *Change) bool { return restoreErrs[c] != nil })
		if g.owed || g.unrestorable || restoreFailed {
			// What an earlier run wrote, what a purge removed, or a file
			// that could not be put back is still on disk: the action stays
			// owed, and its check runs again next time. Nor is the unit
			// started on it: the next run starts it once a check passes.
			still = append(still, g.action())
			blocked[g.unit] = true
		}
	}
	if !reload() {
		return append(append(still, run.actions()...), Action{Verb: daemonReload}), errors.Join(errs...)
	}
	// A failed enable is retried by the next plan, which still sees the unit
	// disabled; the start goes ahead regardless.
	for _, unit := range enables {
		systemctl("enable", unit)
	}
	// Starts run after every write, check and restore, so a unit started
	// now runs exactly the files on disk and needs no restart for them. A
	// unit a package install already started (or is still starting, on the
	// config it read before the files were written) is not started now and
	// still gets its restart. A failed start is retried by the next plan.
	started := map[string]bool{}
	for _, unit := range starts {
		if blocked[unit] {
			errs = append(errs, fmt.Errorf("start %s: not started, its files did not pass their checks", unit))
			continue
		}
		st, err := activeState(ctx, sys, unit)
		if err == nil && (st == "active" || st == "activating" || st == "reloading") {
			continue
		}
		started[unit] = true
		systemctl("start", unit)
	}
	for _, g := range run {
		if started[g.unit] || g.stopped {
			continue
		}
		if systemctl(g.verb, g.unit) != nil {
			still = append(still, g.action())
		}
	}
	if p.downloads != nil {
		if err := p.downloads.saveIndex(sys); err != nil {
			errs = append(errs, fmt.Errorf("save %s: %w", indexPath, err))
		}
		if len(errs) == 0 && len(still) == 0 {
			if err := pruneDownloads(sys, p.downloads); err != nil {
				errs = append(errs, fmt.Errorf("prune %s: %w", downloadCache, err))
			}
		}
	}
	return still, errors.Join(errs...)
}

// activeState is what `systemctl is-active` says about unit: active,
// inactive, failed, activating, …. An error means it could not tell.
func activeState(ctx context.Context, sys System, unit string) (string, error) {
	out, err := sys.Run(ctx, "systemctl", "is-active", unit)
	if err == nil {
		return "active", nil
	}
	if !exitedNonZero(err) {
		return "", fmt.Errorf("systemctl is-active: %w", err)
	}
	if st := strings.TrimSpace(string(out)); st != "" {
		return st, nil
	}
	return "inactive", nil
}

// restore puts back the File changes in rejected, newest first. A change
// that is not a File (a purge) cannot be put back.
func restore(sys System, done []*Change, rejected map[*Change]bool) map[*Change]error {
	errs := map[*Change]error{}
	for i := len(done) - 1; i >= 0; i-- {
		c := done[i]
		if !rejected[c] || c.file == nil {
			continue
		}
		var err error
		switch {
		case c.prev.IsRegular:
			err = sys.WriteFile(c.file.Path, c.prev.Content, c.prev.Mode, c.prev.Owner, c.prev.Group)
		case c.prev.IsSymlink:
			if err = sys.RemoveAll(c.file.Path); err == nil {
				err = sys.Symlink(c.prev.Link, c.file.Path)
			}
		default:
			err = sys.RemoveAll(c.file.Path)
		}
		if err != nil {
			errs[c] = fmt.Errorf("restore %s: %w", c.file.Path, err)
		}
	}
	return errs
}

type actionGroup struct {
	unit     string
	verb     string
	checks   [][]string
	triggers []*Change // the changes of this run that asked for it
	// last is the position (1-based) of the last change that triggered it,
	// 0 when only earlier runs owe it; owed tells it includes an action an
	// earlier run owed; unrestorable that a change that triggered it (a
	// purge) cannot be put back.
	last         int
	owed         bool
	unrestorable bool
	// stopped: the unit is inactive, so the verb is not run.
	stopped bool
}

func (g *actionGroup) sharesAny(changes map[*Change]bool) bool {
	for _, c := range g.triggers {
		if changes[c] {
			return true
		}
	}
	return false
}

// state is "not-found" for a unit systemd doesn't know, else its active
// state.
func (g *actionGroup) state(ctx context.Context, sys System) (string, error) {
	out, err := sys.Run(ctx, "systemctl", "show", "--property=LoadState", "--value", g.unit)
	if err != nil {
		return "", fmt.Errorf("systemctl show: %w", err)
	}
	if strings.TrimSpace(string(out)) == "not-found" {
		return "not-found", nil
	}
	return activeState(ctx, sys, g.unit)
}

type actionGroups []*actionGroup

func (gs actionGroups) actions() []Action {
	out := make([]Action, len(gs))
	for i, g := range gs {
		out[i] = g.action()
	}
	return out
}

// groupActions merges the actions per unit, in the order they were first
// triggered: a restart wins over a reload, and every distinct check runs.
func groupActions(changes []*Change, pending []Action) actionGroups {
	var groups actionGroups
	byUnit := map[string]*actionGroup{}
	add := func(a Action, c *Change, pos int) {
		g := byUnit[a.Unit]
		if g == nil {
			g = &actionGroup{unit: a.Unit, verb: a.Verb}
			byUnit[a.Unit] = g
			groups = append(groups, g)
		}
		if verbRank[a.Verb] > verbRank[g.verb] {
			g.verb = a.Verb
		}
		for _, check := range a.Checks {
			if !containsArgv(g.checks, check) {
				g.checks = append(g.checks, check)
			}
		}
		if c == nil {
			g.owed = true
		} else if c.file == nil {
			g.unrestorable = true
		}
		if c != nil && (len(g.triggers) == 0 || g.triggers[len(g.triggers)-1] != c) {
			g.triggers = append(g.triggers, c)
		}
		g.last = max(g.last, pos)
	}
	for _, a := range pending {
		add(a, nil, 0)
	}
	for i, c := range changes {
		for _, a := range c.actions {
			add(a, c, i+1)
		}
	}
	return groups
}

var verbRank = map[string]int{"reload": 1, "try-restart": 2, "restart": 3}

func containsArgv(list [][]string, argv []string) bool {
	return slices.ContainsFunc(list, func(l []string) bool { return slices.Equal(l, argv) })
}

func (g *actionGroup) action() Action {
	return Action{Verb: g.verb, Unit: g.unit, Checks: g.checks}
}

func (g *actionGroup) check(ctx context.Context, sys System) error {
	for _, argv := range g.checks {
		if _, err := sys.Run(ctx, argv...); err != nil {
			return err
		}
	}
	return nil
}
