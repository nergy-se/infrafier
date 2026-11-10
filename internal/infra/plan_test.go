package infra

import (
	"context"
	"fmt"
	"os"
	"os/user"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// exitErr is a command that ran and exited non-zero.
type exitErr int

func (e exitErr) Error() string { return fmt.Sprintf("exit status %d", int(e)) }
func (e exitErr) ExitCode() int { return int(e) }

// fakeRunner records commands. A command in fail exits 1; one in out prints
// that. Everything else succeeds silently.
// A command in broken cannot run at all (not installed).
// A successful apt-get install makes dpkg-query report the package
// installed, as on a real host, unless it is in virtual.
type fakeRunner struct {
	calls   []string
	fail    map[string]bool
	broken  map[string]bool
	out     map[string]string
	virtual map[string]bool
}

func dpkgQuery(pkg string) string { return "dpkg-query -W -f=${db:Status-Status}\n " + pkg }

const aptInstall = "env DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends -o Dpkg::Options::=--force-confdef -o Dpkg::Options::=--force-confold "

func (f *fakeRunner) run(_ context.Context, argv ...string) ([]byte, error) {
	cmd := strings.Join(argv, " ")
	f.calls = append(f.calls, cmd)
	if f.broken[cmd] {
		return nil, fmt.Errorf("%s: executable file not found in $PATH", argv[0])
	}
	if f.fail[cmd] {
		return []byte(f.out[cmd]), exitErr(1)
	}
	if pkg, ok := strings.CutPrefix(cmd, aptInstall); ok && !f.virtual[pkg] {
		query := dpkgQuery(pkg)
		delete(f.fail, query)
		f.out[query] = "installed\n"
	}
	return []byte(f.out[cmd]), nil
}

// changing drops the read-only queries the planner makes, leaving what apply did.
func (f *fakeRunner) changing() []string {
	var out []string
	for _, c := range f.calls {
		if strings.HasPrefix(c, "systemctl is-") || strings.HasPrefix(c, "systemctl show") || strings.HasPrefix(c, "dpkg-query") {
			continue
		}
		out = append(out, c)
	}
	return out
}

func newTestSystem(t *testing.T) (*OS, *fakeRunner) {
	t.Helper()
	f := &fakeRunner{fail: map[string]bool{}, broken: map[string]bool{}, out: map[string]string{}, virtual: map[string]bool{}}
	return &OS{Root: t.TempDir(), Runner: f.run}, f
}

func planAndApply(t *testing.T, sys System, rs []Resource, pending []Action) (*Plan, []Action, error) {
	t.Helper()
	p, err := MakePlan(context.Background(), sys, rs)
	require.NoError(t, err)
	still, err := p.Apply(context.Background(), sys, pending)
	return p, still, err
}

func readRoot(t *testing.T, sys *OS, p string) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(sys.Root, p))
	require.NoError(t, err)
	return string(b)
}

func TestApplyWritesFilesAndIsIdempotent(t *testing.T) {
	sys, run := newTestSystem(t)
	restart := []Action{{Verb: "restart", Unit: "nginx.service"}}
	rs := []Resource{
		&Dir{Path: "/etc/nginx", Mode: 0o755},
		&File{Path: "/etc/nginx/a.conf", Content: []byte("a\n"), Mode: 0o644, OnChange: restart},
		&File{Path: "/etc/nginx/b.conf", Content: []byte("b\n"), Mode: 0o600, OnChange: restart},
	}

	p, still, err := planAndApply(t, sys, rs, nil)
	require.NoError(t, err)
	assert.Empty(t, still)
	assert.Len(t, p.Changes, 3)
	assert.Equal(t, "a\n", readRoot(t, sys, "/etc/nginx/a.conf"))
	fi, err := os.Stat(filepath.Join(sys.Root, "/etc/nginx/b.conf"))
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0o600), fi.Mode().Perm())
	// Two files changed, one restart.
	assert.Equal(t, []string{"systemctl restart nginx.service"}, run.changing())

	run.calls = nil
	p, _, err = planAndApply(t, sys, rs, nil)
	require.NoError(t, err)
	assert.True(t, p.Empty(), p.String())
	assert.Empty(t, run.changing())
}

func TestPlanShowsDiffAndModeChange(t *testing.T) {
	sys, _ := newTestSystem(t)
	f := &File{Path: "/etc/x.conf", Content: []byte("one\ntwo\n"), Mode: 0o644}
	_, _, err := planAndApply(t, sys, []Resource{f}, nil)
	require.NoError(t, err)

	f2 := &File{Path: "/etc/x.conf", Content: []byte("one\nthree\n"), Mode: 0o640}
	p, err := MakePlan(context.Background(), sys, []Resource{f2})
	require.NoError(t, err)
	require.Len(t, p.Changes, 1)
	assert.Equal(t, "update /etc/x.conf (mode 0644 → 0640)", p.Changes[0].Summary)
	assert.Contains(t, p.Changes[0].Diff, "-two\n+three\n")

	secret := &File{Path: "/etc/x.conf", Content: []byte("password\n"), Mode: 0o644, Secret: true}
	p, err = MakePlan(context.Background(), sys, []Resource{secret})
	require.NoError(t, err)
	assert.NotContains(t, p.String(), "password")
}

func TestApplyRestoresFilesWhenCheckFails(t *testing.T) {
	sys, run := newTestSystem(t)
	reload := []Action{{Verb: "reload", Unit: "nginx.service", Checks: [][]string{{"nginx", "-t"}}}}
	old := &File{Path: "/etc/nginx/site.conf", Content: []byte("good\n"), Mode: 0o644, OnChange: reload}
	_, _, err := planAndApply(t, sys, []Resource{old}, nil)
	require.NoError(t, err)

	run.calls = nil
	run.fail["nginx -t"] = true
	broken := &File{Path: "/etc/nginx/site.conf", Content: []byte("broken\n"), Mode: 0o644, OnChange: reload}
	added := &File{Path: "/etc/nginx/new.conf", Content: []byte("new\n"), Mode: 0o644, OnChange: reload}
	_, still, err := planAndApply(t, sys, []Resource{broken, added}, nil)
	require.ErrorContains(t, err, "check failed")
	// Put back, so the next run sees the change again and retries; nothing owed.
	assert.Empty(t, still)
	assert.Equal(t, "good\n", readRoot(t, sys, "/etc/nginx/site.conf"))
	assert.NoFileExists(t, filepath.Join(sys.Root, "/etc/nginx/new.conf"))
	assert.Equal(t, []string{"nginx -t"}, run.changing())
}

func TestApplyKeepsFailedActionPending(t *testing.T) {
	sys, run := newTestSystem(t)
	f := &File{Path: "/etc/x.conf", Content: []byte("x\n"), Mode: 0o644, OnChange: []Action{{Verb: "reload", Unit: "x.service"}}}
	run.fail["systemctl reload x.service"] = true
	_, still, err := planAndApply(t, sys, []Resource{f}, nil)
	require.Error(t, err)
	assert.Equal(t, []Action{{Verb: "reload", Unit: "x.service"}}, still)

	// The next run sees no change in the file but still owes the reload; a
	// restart triggered now wins over it.
	run.calls = nil
	delete(run.fail, "systemctl reload x.service")
	g := &File{Path: "/etc/y.conf", Content: []byte("y\n"), Mode: 0o644, OnChange: []Action{{Verb: "restart", Unit: "x.service"}}}
	_, still, err = planAndApply(t, sys, []Resource{f, g}, still)
	require.NoError(t, err)
	assert.Empty(t, still)
	assert.Equal(t, []string{"systemctl restart x.service"}, run.changing())
}

func TestApplyStopsAtFailingChangeButRunsActionsOfDoneOnes(t *testing.T) {
	sys, run := newTestSystem(t)
	require.NoError(t, os.MkdirAll(filepath.Join(sys.Root, "/etc/blocked.conf"), 0o755))
	rs := []Resource{
		&File{Path: "/etc/a.conf", Content: []byte("a\n"), Mode: 0o644, OnChange: []Action{{Verb: "restart", Unit: "a.service"}}},
		&Package{Name: "foo"},
		&File{Path: "/etc/c.conf", Content: []byte("c\n"), Mode: 0o644, OnChange: []Action{{Verb: "restart", Unit: "c.service"}}},
	}
	run.fail[dpkgQuery("foo")] = true
	run.fail[aptInstall+"foo"] = true
	_, _, err := planAndApply(t, sys, rs, nil)
	require.ErrorContains(t, err, "package:foo")
	assert.NoFileExists(t, filepath.Join(sys.Root, "/etc/c.conf"))
	assert.Contains(t, run.changing(), "systemctl restart a.service")
	assert.NotContains(t, run.changing(), "systemctl restart c.service")
}

func TestPlanRefusesFileOverDirectory(t *testing.T) {
	sys, _ := newTestSystem(t)
	require.NoError(t, os.MkdirAll(filepath.Join(sys.Root, "/etc/x.conf"), 0o755))
	_, err := MakePlan(context.Background(), sys, []Resource{&File{Path: "/etc/x.conf", Mode: 0o644}})
	require.ErrorContains(t, err, "is a directory")
}

func TestPurgeRemovesWhatIsNotDeclared(t *testing.T) {
	sys, _ := newTestSystem(t)
	for _, p := range []string{"/etc/site/old.conf", "/etc/site/keep.conf", "/etc/site/sub/old", "/etc/site/sub/keep", "/etc/site/own/anything", "/etc/site/stale/x"} {
		full := filepath.Join(sys.Root, p)
		require.NoError(t, os.MkdirAll(filepath.Dir(full), 0o755))
		require.NoError(t, os.WriteFile(full, []byte("x"), 0o644))
	}
	rs := []Resource{
		&Dir{Path: "/etc/site", Mode: 0o755, Purge: true},
		&File{Path: "/etc/site/keep.conf", Content: []byte("x"), Mode: 0o644},
		&File{Path: "/etc/site/sub/keep", Content: []byte("x"), Mode: 0o644},
		// A declared subdirectory without purge keeps its contents.
		&Dir{Path: "/etc/site/own", Mode: 0o755},
	}
	p, _, err := planAndApply(t, sys, rs, nil)
	require.NoError(t, err)
	var summaries []string
	for _, c := range p.Changes {
		summaries = append(summaries, c.Summary)
	}
	assert.ElementsMatch(t, []string{
		"remove /etc/site/old.conf (not declared)",
		"remove /etc/site/stale (not declared)",
		"remove /etc/site/sub/old (not declared)",
	}, summaries)
	assert.FileExists(t, filepath.Join(sys.Root, "/etc/site/own/anything"))
	assert.FileExists(t, filepath.Join(sys.Root, "/etc/site/sub/keep"))
	assert.NoDirExists(t, filepath.Join(sys.Root, "/etc/site/stale"))
}

func TestUnitFileDaemonReloadBeforeEnableAndNoRestartAfterStart(t *testing.T) {
	sys, run := newTestSystem(t)
	run.fail["systemctl is-enabled x.timer"] = true
	run.fail["systemctl is-active x.timer"] = true
	rs := []Resource{
		&File{Path: "/etc/systemd/system/x.timer", Content: []byte("[Timer]\n"), Mode: 0o644, OnChange: []Action{{Verb: "restart", Unit: "x.timer"}}},
		&Unit{Name: "x.timer", Enabled: true, Active: true},
	}
	p, _, err := planAndApply(t, sys, rs, nil)
	require.NoError(t, err)
	assert.Equal(t, "enable and start x.timer", p.Changes[1].Summary)
	// It just started with the new file, so the restart is skipped.
	assert.Equal(t, []string{"systemctl daemon-reload", "systemctl enable x.timer", "systemctl start x.timer"}, run.changing())
}

// A virtual package is installed by apt-get through a provider, but dpkg
// never knows its name: without the check after the install the plan would
// install it on every run without ever failing.
func TestVirtualPackageFailsInsteadOfInstallingEveryRun(t *testing.T) {
	sys, run := newTestSystem(t)
	query := dpkgQuery("mail-transport-agent")
	run.fail[query] = true // "no packages found matching"
	run.virtual["mail-transport-agent"] = true
	_, _, err := planAndApply(t, sys, []Resource{&Package{Name: "mail-transport-agent"}}, nil)
	require.ErrorContains(t, err, "is it a virtual package?")

	// A real package passes the same check and the next plan is empty.
	sys, run = newTestSystem(t)
	run.fail[dpkgQuery("postfix")] = true
	_, _, err = planAndApply(t, sys, []Resource{&Package{Name: "postfix"}}, nil)
	require.NoError(t, err)
	p, err := MakePlan(context.Background(), sys, []Resource{&Package{Name: "postfix"}})
	require.NoError(t, err)
	assert.True(t, p.Empty(), p.String())
}

// A module that lists the unit before its unit file must still converge: an
// enable run as a change would fail before the file is written, on every run.
func TestUnitListedBeforeItsUnitFileConverges(t *testing.T) {
	sys, run := newTestSystem(t)
	run.fail["systemctl is-enabled foo.service"] = true
	run.fail["systemctl is-active foo.service"] = true
	rs := []Resource{
		&Unit{Name: "foo.service", Enabled: true, Active: true},
		&File{Path: "/etc/systemd/system/foo.service", Content: []byte("[Service]\n"), Mode: 0o644},
	}
	_, _, err := planAndApply(t, sys, rs, nil)
	require.NoError(t, err)
	assert.Equal(t, "[Service]\n", readRoot(t, sys, "/etc/systemd/system/foo.service"))
	assert.Equal(t, []string{"systemctl daemon-reload", "systemctl enable foo.service", "systemctl start foo.service"}, run.changing())
}

func TestFailedEnableDoesNotStopTheRun(t *testing.T) {
	sys, run := newTestSystem(t)
	run.fail["systemctl is-enabled foo.service"] = true
	run.fail["systemctl enable foo.service"] = true
	rs := []Resource{
		&Unit{Name: "foo.service", Enabled: true},
		&File{Path: "/etc/foo.conf", Content: []byte("x\n"), Mode: 0o644},
	}
	_, _, err := planAndApply(t, sys, rs, nil)
	require.ErrorContains(t, err, "enable foo.service")
	assert.Equal(t, "x\n", readRoot(t, sys, "/etc/foo.conf"))
}

// A numeric owner resolves to a name on Lstat; the next plan must still be
// empty, or every run would chown and restart.
func TestNumericOwnerIsIdempotent(t *testing.T) {
	sys, run := newTestSystem(t)
	u, err := user.Current()
	require.NoError(t, err)
	g, err := user.LookupGroupId(u.Gid)
	require.NoError(t, err)
	rs := []Resource{&File{Path: "/etc/x", Content: []byte("x"), Mode: 0o644, Owner: u.Uid, Group: g.Gid,
		OnChange: []Action{{Verb: "restart", Unit: "x.service"}}}}
	_, _, err = planAndApply(t, sys, rs, nil)
	require.NoError(t, err)
	run.calls = nil
	p, _, err := planAndApply(t, sys, rs, nil)
	require.NoError(t, err)
	assert.True(t, p.Empty(), p.String())
	assert.Empty(t, run.changing())
}

func TestCommandRunsOnlyWhenCheckFails(t *testing.T) {
	sys, run := newTestSystem(t)
	c := &Command{Name: "role", Check: []string{"has-role"}, Run: []string{"create-role"}}
	p, _, err := planAndApply(t, sys, []Resource{c}, nil)
	require.NoError(t, err)
	assert.True(t, p.Empty())

	run.calls = nil
	run.fail["has-role"] = true
	_, _, err = planAndApply(t, sys, []Resource{c}, nil)
	require.ErrorContains(t, err, "check still fails after run")
	assert.Equal(t, []string{"has-role", "has-role", "create-role", "has-role"}, run.calls)
}

func TestPackageInstalledOnlyWhenMissing(t *testing.T) {
	sys, run := newTestSystem(t)
	run.out[dpkgQuery("nullmailer")] = "installed"
	p, _, err := planAndApply(t, sys, []Resource{&Package{Name: "nullmailer"}}, nil)
	require.NoError(t, err)
	assert.True(t, p.Empty())

	run.out[dpkgQuery("nullmailer")] = "not-installed"
	p, _, err = planAndApply(t, sys, []Resource{&Package{Name: "nullmailer"}}, nil)
	require.NoError(t, err)
	assert.Equal(t, "install package nullmailer", p.Changes[0].Summary)
}

func writeRoot(t *testing.T, sys *OS, p, content string) {
	t.Helper()
	full := filepath.Join(sys.Root, p)
	require.NoError(t, os.MkdirAll(filepath.Dir(full), 0o755))
	require.NoError(t, os.WriteFile(full, []byte(content), 0o644))
}

func TestPurgeDoesNotFollowSymlinks(t *testing.T) {
	sys, _ := newTestSystem(t)
	writeRoot(t, sys, "/srv/elsewhere/precious", "x")
	writeRoot(t, sys, "/srv/elsewhere/keep", "x")
	require.NoError(t, os.MkdirAll(filepath.Join(sys.Root, "/etc/site"), 0o755))
	// sub points outside the purged directory.
	require.NoError(t, os.Symlink(filepath.Join(sys.Root, "/srv/elsewhere"), filepath.Join(sys.Root, "/etc/site/sub")))
	rs := []Resource{
		&Dir{Path: "/etc/site", Mode: 0o755, Purge: true},
		&File{Path: "/etc/site/sub/keep", Content: []byte("x"), Mode: 0o644},
	}
	_, err := MakePlan(context.Background(), sys, rs)
	require.ErrorContains(t, err, "/etc/site/sub is not a directory")
	assert.FileExists(t, filepath.Join(sys.Root, "/srv/elsewhere/precious"))
}

func TestPurgeRunsDirActionsAndReloadsSystemd(t *testing.T) {
	sys, run := newTestSystem(t)
	writeRoot(t, sys, "/etc/nginx/sites-enabled/old", "x")
	writeRoot(t, sys, "/etc/systemd/system/old.service", "x")
	rs := []Resource{
		&Dir{Path: "/etc/nginx/sites-enabled", Mode: 0o755, Purge: true, OnChange: []Action{{Verb: "reload", Unit: "nginx.service", Checks: [][]string{{"nginx", "-t"}}}}},
		&Dir{Path: "/etc/systemd/system", Mode: 0o755, Purge: true},
	}
	_, _, err := planAndApply(t, sys, rs, nil)
	require.NoError(t, err)
	assert.Equal(t, []string{"systemctl daemon-reload", "nginx -t", "systemctl reload nginx.service"}, run.changing())
	assert.NoFileExists(t, filepath.Join(sys.Root, "/etc/nginx/sites-enabled/old"))
}

func TestApplyPutsBackReplacedSymlinkWhenCheckFails(t *testing.T) {
	sys, run := newTestSystem(t)
	require.NoError(t, os.MkdirAll(filepath.Join(sys.Root, "/etc/nginx/sites-enabled"), 0o755))
	link := filepath.Join(sys.Root, "/etc/nginx/sites-enabled/default")
	require.NoError(t, os.Symlink("/etc/nginx/sites-available/default", link))

	run.fail["nginx -t"] = true
	f := &File{Path: "/etc/nginx/sites-enabled/default", Content: []byte("broken\n"), Mode: 0o644,
		OnChange: []Action{{Verb: "reload", Unit: "nginx.service", Checks: [][]string{{"nginx", "-t"}}}}}
	p, _, err := planAndApply(t, sys, []Resource{f}, nil)
	require.ErrorContains(t, err, "check failed")
	assert.Equal(t, "replace /etc/nginx/sites-enabled/default (a symlink to /etc/nginx/sites-available/default)", p.Changes[0].Summary)
	target, err := os.Readlink(link)
	require.NoError(t, err)
	assert.Equal(t, "/etc/nginx/sites-available/default", target)
}

func TestCommandDoesNotRunWhenItsCheckCannotRun(t *testing.T) {
	sys, run := newTestSystem(t)
	// At plan time the check's binary may come with a package the plan
	// installs; at apply time it has to run.
	run.broken["has-role"] = true
	c := &Command{Name: "role", Check: []string{"has-role"}, Run: []string{"create-role"}}
	_, _, err := planAndApply(t, sys, []Resource{c}, nil)
	require.ErrorContains(t, err, "command:role: check")
	assert.NotContains(t, run.calls, "create-role")
}

func TestFailedDaemonReloadIsOwedAndHoldsBackUnitActions(t *testing.T) {
	sys, run := newTestSystem(t)
	run.fail["systemctl daemon-reload"] = true
	run.fail["systemctl is-active x.service"] = true
	rs := []Resource{
		&File{Path: "/etc/systemd/system/x.service", Content: []byte("[Service]\n"), Mode: 0o644, OnChange: []Action{{Verb: "restart", Unit: "x.service"}}},
		&File{Path: "/etc/x.conf", Content: []byte("x\n"), Mode: 0o644, OnChange: []Action{{Verb: "restart", Unit: "y.service"}}},
		&Unit{Name: "x.service", Active: true},
	}
	_, still, err := planAndApply(t, sys, rs, nil)
	require.ErrorContains(t, err, "daemon-reload")
	assert.Equal(t, []string{"systemctl daemon-reload"}, run.changing())
	assert.Equal(t, []Action{{Verb: "restart", Unit: "x.service"}, {Verb: "restart", Unit: "y.service"}, {Verb: daemonReload}}, still)

	// The files now match, but the reload and the restarts are still owed.
	run.calls = nil
	delete(run.fail, "systemctl daemon-reload")
	_, still, err = planAndApply(t, sys, rs, still)
	require.NoError(t, err)
	assert.Empty(t, still)
	assert.Equal(t, []string{"systemctl daemon-reload", "systemctl start x.service", "systemctl restart y.service"}, run.changing())
}

func TestUnitStartsAfterEveryWriteAndCheck(t *testing.T) {
	sys, run := newTestSystem(t)
	run.fail["systemctl is-active x.service"] = true
	// The unit comes first in the module, but starts only after its config
	// is written and checked, so it needs no restart for it.
	rs := []Resource{
		&Unit{Name: "x.service", Active: true},
		&File{Path: "/etc/x.conf", Content: []byte("x\n"), Mode: 0o644, OnChange: []Action{{Verb: "restart", Unit: "x.service", Checks: [][]string{{"x", "-t"}}}}},
	}
	_, _, err := planAndApply(t, sys, rs, nil)
	require.NoError(t, err)
	assert.Equal(t, []string{"x -t", "systemctl start x.service"}, run.changing())
}

func TestUnitStartedAfterARejectedConfigRunsTheRestoredOne(t *testing.T) {
	sys, run := newTestSystem(t)
	_, _, err := planAndApply(t, sys, []Resource{&File{Path: "/etc/x.conf", Content: []byte("good\n"), Mode: 0o644}}, nil)
	require.NoError(t, err)

	run.calls = nil
	run.fail["systemctl is-active x.service"] = true
	run.fail["x -t"] = true
	rs := []Resource{
		&Unit{Name: "x.service", Active: true},
		&File{Path: "/etc/x.conf", Content: []byte("bad\n"), Mode: 0o644, OnChange: []Action{{Verb: "restart", Unit: "x.service", Checks: [][]string{{"x", "-t"}}}}},
	}
	_, _, err = planAndApply(t, sys, rs, nil)
	require.ErrorContains(t, err, "check failed")
	// It starts on the file put back, never on the rejected one.
	assert.Equal(t, "good\n", readRoot(t, sys, "/etc/x.conf"))
	assert.Equal(t, []string{"x -t", "systemctl start x.service"}, run.changing())
}

func TestUnitIsNotStartedOnAPurgeItsCheckRejected(t *testing.T) {
	sys, run := newTestSystem(t)
	writeRoot(t, sys, "/etc/nginx/sites-enabled/old", "x")
	run.fail["systemctl is-active nginx.service"] = true
	run.fail["nginx -t"] = true
	act := Action{Verb: "reload", Unit: "nginx.service", Checks: [][]string{{"nginx", "-t"}}}
	rs := []Resource{
		&Dir{Path: "/etc/nginx/sites-enabled", Mode: 0o755, Purge: true, OnChange: []Action{act}},
		&Unit{Name: "nginx.service", Active: true},
	}
	_, still, err := planAndApply(t, sys, rs, nil)
	require.ErrorContains(t, err, "start nginx.service: not started")
	assert.Equal(t, []Action{act}, still)
	assert.NotContains(t, run.changing(), "systemctl start nginx.service")
}

func TestOwedActionIsCheckedBeforeItsUnitStarts(t *testing.T) {
	sys, run := newTestSystem(t)
	// An earlier run left a rejected file it could not put back, so the
	// files match now and only the owed action remembers it.
	act := Action{Verb: "restart", Unit: "x.service", Checks: [][]string{{"x", "-t"}}}
	rs := []Resource{
		&File{Path: "/etc/x.conf", Content: []byte("bad\n"), Mode: 0o644, OnChange: []Action{act}},
		&Unit{Name: "x.service", Active: true},
	}
	writeRoot(t, sys, "/etc/x.conf", "bad\n")
	run.fail["systemctl is-active x.service"] = true
	run.fail["x -t"] = true
	_, still, err := planAndApply(t, sys, rs, []Action{act})
	require.ErrorContains(t, err, "start x.service: not started")
	assert.Equal(t, []Action{act}, still)
	assert.Equal(t, []string{"x -t"}, run.changing())

	// Once the check passes it starts, which also settles the restart.
	run.calls = nil
	delete(run.fail, "x -t")
	_, still, err = planAndApply(t, sys, rs, still)
	require.NoError(t, err)
	assert.Empty(t, still)
	assert.Equal(t, []string{"x -t", "systemctl start x.service"}, run.changing())
}

func TestRejectedUnitFileIsReloadedAwayAfterRestore(t *testing.T) {
	sys, run := newTestSystem(t)
	act := []Action{{Verb: "restart", Unit: "x.service", Checks: [][]string{{"x", "--check"}}}}
	f := &File{Path: "/etc/systemd/system/x.service", Content: []byte("good\n"), Mode: 0o644, OnChange: act}
	_, _, err := planAndApply(t, sys, []Resource{f}, nil)
	require.NoError(t, err)

	run.calls = nil
	run.fail["x --check"] = true
	bad := &File{Path: "/etc/systemd/system/x.service", Content: []byte("bad\n"), Mode: 0o644, OnChange: act}
	_, _, err = planAndApply(t, sys, []Resource{bad}, nil)
	require.ErrorContains(t, err, "check failed")
	assert.Equal(t, "good\n", readRoot(t, sys, "/etc/systemd/system/x.service"))
	assert.Equal(t, []string{"systemctl daemon-reload", "x --check", "systemctl daemon-reload"}, run.changing())
}

func TestOwedActionTakesTodaysChecksAndStaysOwedWhenOneFails(t *testing.T) {
	sys, run := newTestSystem(t)
	rs := []Resource{
		&File{Path: "/etc/a.conf", Content: []byte("a\n"), Mode: 0o644, OnChange: []Action{{Verb: "reload", Unit: "nginx.service", Checks: [][]string{{"a"}}}}},
		&File{Path: "/etc/b.conf", Content: []byte("b\n"), Mode: 0o644, OnChange: []Action{{Verb: "reload", Unit: "nginx.service", Checks: [][]string{{"b"}}}}},
	}
	_, _, err := planAndApply(t, sys, rs, nil)
	require.NoError(t, err)

	// Owed with a check a later commit replaced: today's checks run instead,
	// all of them, and the action stays owed while one fails.
	run.calls = nil
	run.fail["b"] = true
	owed := []Action{{Verb: "reload", Unit: "nginx.service", Checks: [][]string{{"old-check"}}}}
	_, still, err := planAndApply(t, sys, rs, owed)
	require.ErrorContains(t, err, "check failed")
	assert.Equal(t, []Action{{Verb: "reload", Unit: "nginx.service", Checks: [][]string{{"a"}, {"b"}}}}, still)
	assert.Equal(t, []string{"a", "b"}, run.changing())
}

func TestOwedActionIsDroppedWhenItsUnitIsGoneOrStopped(t *testing.T) {
	sys, run := newTestSystem(t)
	run.out["systemctl show --property=LoadState --value gone.service"] = "not-found\n"
	run.fail["systemctl is-active stopped.service"] = true
	owed := []Action{{Verb: "restart", Unit: "gone.service"}, {Verb: "restart", Unit: "stopped.service"}, {Verb: "restart", Unit: "up.service"}}
	_, still, err := planAndApply(t, sys, nil, owed)
	require.NoError(t, err)
	assert.Empty(t, still)
	assert.Equal(t, []string{"systemctl restart up.service"}, run.changing())
}

func TestUnitAPackageAlreadyStartedIsStillRestartedForItsConfig(t *testing.T) {
	sys, run := newTestSystem(t)
	// At plan time nginx is not installed, so not running; installing it
	// starts it with the package's default config.
	run.out[dpkgQuery("nginx")] = "not-installed"
	run.fail["systemctl is-active nginx.service"] = true
	rs := []Resource{
		&Package{Name: "nginx"},
		&File{Path: "/etc/nginx/site", Content: []byte("x\n"), Mode: 0o644, OnChange: []Action{{Verb: "restart", Unit: "nginx.service"}}},
		&Unit{Name: "nginx.service", Active: true},
	}
	p, err := MakePlan(context.Background(), sys, rs)
	require.NoError(t, err)
	delete(run.fail, "systemctl is-active nginx.service")
	_, err = p.Apply(context.Background(), sys, nil)
	require.NoError(t, err)
	assert.Contains(t, run.changing(), "systemctl restart nginx.service")
}

func TestFailedCheckOfAPurgeKeepsTheActionOwed(t *testing.T) {
	sys, run := newTestSystem(t)
	writeRoot(t, sys, "/etc/nginx/sites-enabled/old", "x")
	run.fail["nginx -t"] = true
	act := Action{Verb: "reload", Unit: "nginx.service", Checks: [][]string{{"nginx", "-t"}}}
	rs := []Resource{&Dir{Path: "/etc/nginx/sites-enabled", Mode: 0o755, Purge: true, OnChange: []Action{act}}}
	_, still, err := planAndApply(t, sys, rs, nil)
	require.ErrorContains(t, err, "check failed")
	assert.Equal(t, []Action{act}, still)
}

func TestFailedRestoreKeepsTheActionOwed(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root ignores directory permissions")
	}
	sys, run := newTestSystem(t)
	act := Action{Verb: "reload", Unit: "x.service", Checks: [][]string{{"x", "-t"}}}
	_, _, err := planAndApply(t, sys, []Resource{&File{Path: "/etc/x/x.conf", Content: []byte("good\n"), Mode: 0o644, OnChange: []Action{act}}}, nil)
	require.NoError(t, err)

	// The check fails, and then the directory can't take the old file back.
	bad := &File{Path: "/etc/x/x.conf", Content: []byte("bad\n"), Mode: 0o644, OnChange: []Action{act}}
	p, err := MakePlan(context.Background(), sys, []Resource{bad})
	require.NoError(t, err)
	dir := filepath.Join(sys.Root, "/etc/x")
	sys.Runner = func(ctx context.Context, argv ...string) ([]byte, error) {
		if strings.Join(argv, " ") == "x -t" {
			require.NoError(t, os.Chmod(dir, 0o555))
			t.Cleanup(func() { os.Chmod(dir, 0o755) })
			return nil, exitErr(1)
		}
		return run.run(ctx, argv...)
	}
	still, err := p.Apply(context.Background(), sys, nil)
	require.ErrorContains(t, err, "restore /etc/x/x.conf")
	assert.Equal(t, []Action{act}, still)
}

func TestARejectedChangeIsPutBackForEveryUnitItTriggers(t *testing.T) {
	sys, run := newTestSystem(t)
	old := []Resource{
		&File{Path: "/etc/tls/cert.pem", Content: []byte("old cert\n"), Mode: 0o644},
		&File{Path: "/etc/tls/key.pem", Content: []byte("old key\n"), Mode: 0o600},
		&File{Path: "/etc/c.conf", Content: []byte("old c\n"), Mode: 0o644},
	}
	_, _, err := planAndApply(t, sys, old, nil)
	require.NoError(t, err)

	// a takes a new cert and key and its check passes; b rejects the cert.
	// Putting back only the cert would restart a with the old cert and the
	// new key, so a fails with it and both files go back. c shares nothing.
	run.calls = nil
	run.fail["b -t"] = true
	a := Action{Verb: "restart", Unit: "a.service", Checks: [][]string{{"a", "-t"}}}
	b := Action{Verb: "reload", Unit: "b.service", Checks: [][]string{{"b", "-t"}}}
	c := Action{Verb: "restart", Unit: "c.service"}
	rs := []Resource{
		&File{Path: "/etc/tls/cert.pem", Content: []byte("new cert\n"), Mode: 0o644, OnChange: []Action{a, b}},
		&File{Path: "/etc/tls/key.pem", Content: []byte("new key\n"), Mode: 0o600, OnChange: []Action{a}},
		&File{Path: "/etc/c.conf", Content: []byte("new c\n"), Mode: 0o644, OnChange: []Action{c}},
	}
	_, still, err := planAndApply(t, sys, rs, nil)
	require.ErrorContains(t, err, "b.service: check failed")
	require.ErrorContains(t, err, "a.service: not run, it shares a change")
	assert.Empty(t, still) // everything a and b asked for was put back
	assert.Equal(t, "old cert\n", readRoot(t, sys, "/etc/tls/cert.pem"))
	assert.Equal(t, "old key\n", readRoot(t, sys, "/etc/tls/key.pem"))
	assert.Equal(t, "new c\n", readRoot(t, sys, "/etc/c.conf"))
	// Every check runs before any unit is touched.
	assert.Equal(t, []string{"a -t", "b -t", "systemctl restart c.service"}, run.changing())
}

func TestOwedRestartOfAFailedUnitIsRetried(t *testing.T) {
	sys, run := newTestSystem(t)
	run.fail["systemctl is-active x.service"] = true
	run.out["systemctl is-active x.service"] = "failed\n"
	owed := []Action{{Verb: "reload", Unit: "x.service"}}
	_, still, err := planAndApply(t, sys, nil, owed)
	require.NoError(t, err)
	assert.Empty(t, still)
	// A reload can't bring a failed unit up.
	assert.Equal(t, []string{"systemctl restart x.service"}, run.changing())
}

func TestOwedActionIsKeptWhenSystemdCannotBeAsked(t *testing.T) {
	sys, run := newTestSystem(t)
	run.broken["systemctl is-active x.service"] = true
	owed := []Action{{Verb: "restart", Unit: "x.service"}}
	_, still, err := planAndApply(t, sys, nil, owed)
	require.ErrorContains(t, err, "systemctl is-active")
	assert.Equal(t, owed, still)
}

func TestMkdirGivesMissingParentsTheUsualMode(t *testing.T) {
	sys, _ := newTestSystem(t)
	u, err := user.Current()
	require.NoError(t, err)
	_, _, err = planAndApply(t, sys, []Resource{&Dir{Path: "/var/lib/app/data", Mode: 0o750, Owner: u.Username}}, nil)
	require.NoError(t, err)
	parent, err := os.Stat(filepath.Join(sys.Root, "/var/lib/app"))
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0o755), parent.Mode().Perm())
	leaf, err := os.Stat(filepath.Join(sys.Root, "/var/lib/app/data"))
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0o750), leaf.Mode().Perm())
}

func TestRejectedFileGoesBackToWhatThePackageInstalled(t *testing.T) {
	sys, run := newTestSystem(t)
	run.out[dpkgQuery("nginx")] = "not-installed"
	run.fail["nginx -t"] = true
	install := aptInstall + "nginx"
	sys.Runner = func(ctx context.Context, argv ...string) ([]byte, error) {
		if strings.Join(argv, " ") == install {
			writeRoot(t, sys, "/etc/nginx/nginx.conf", "package default\n")
		}
		return run.run(ctx, argv...)
	}
	rs := []Resource{
		&Package{Name: "nginx"},
		&File{Path: "/etc/nginx/nginx.conf", Content: []byte("broken\n"), Mode: 0o644, OnChange: []Action{{Verb: "reload", Unit: "nginx.service", Checks: [][]string{{"nginx", "-t"}}}}},
	}
	_, _, err := planAndApply(t, sys, rs, nil)
	require.ErrorContains(t, err, "check failed")
	assert.Equal(t, "package default\n", readRoot(t, sys, "/etc/nginx/nginx.conf"))
}

func TestAptGetUpdateRunsOnceBeforeTheFirstInstall(t *testing.T) {
	sys, run := newTestSystem(t)
	for _, p := range []string{"a", "b"} {
		run.out[dpkgQuery(p)] = "not-installed"
	}
	_, _, err := planAndApply(t, sys, []Resource{&Package{Name: "a"}, &Package{Name: "b"}}, nil)
	require.NoError(t, err)
	var apt []string
	for _, c := range run.changing() {
		apt = append(apt, strings.Fields(c)[2]+" "+strings.Fields(c)[len(strings.Fields(c))-1])
	}
	assert.Equal(t, []string{"apt-get -q", "apt-get a", "apt-get b"}, apt)
}

func TestMultiArchPackageCountsAsInstalled(t *testing.T) {
	sys, run := newTestSystem(t)
	run.out[dpkgQuery("libc6")] = "installed\ninstalled\n"
	p, _, err := planAndApply(t, sys, []Resource{&Package{Name: "libc6"}}, nil)
	require.NoError(t, err)
	assert.True(t, p.Empty())
	run.out[dpkgQuery("libc6")] = "installed\nhalf-installed\n"
	p, err = MakePlan(context.Background(), sys, []Resource{&Package{Name: "libc6"}})
	require.NoError(t, err)
	assert.False(t, p.Empty())
}

func TestPlanDoesNotShowOldContentThatIsNotWorldReadable(t *testing.T) {
	sys, _ := newTestSystem(t)
	_, _, err := planAndApply(t, sys, []Resource{&File{Path: "/etc/app.env", Content: []byte("PASSWORD=hunter2\n"), Mode: 0o600, Secret: true}}, nil)
	require.NoError(t, err)

	// The module no longer marks it secret.
	p, err := MakePlan(context.Background(), sys, []Resource{&File{Path: "/etc/app.env", Content: []byte("PLACEHOLDER\n"), Mode: 0o600}})
	require.NoError(t, err)
	assert.NotContains(t, p.String(), "hunter2")
	assert.Contains(t, p.String(), "old content not shown")
}

func TestUnitStillActivatingFromItsPackageIsRestartedForItsConfig(t *testing.T) {
	sys, run := newTestSystem(t)
	run.out[dpkgQuery("postgresql")] = "not-installed"
	run.fail["systemctl is-active postgresql.service"] = true
	rs := []Resource{
		&Package{Name: "postgresql"},
		&File{Path: "/etc/pg.conf", Content: []byte("x\n"), Mode: 0o644, OnChange: []Action{{Verb: "restart", Unit: "postgresql.service"}}},
		&Unit{Name: "postgresql.service", Active: true},
	}
	p, err := MakePlan(context.Background(), sys, rs)
	require.NoError(t, err)
	// The install left it starting, on the package's default config.
	run.out["systemctl is-active postgresql.service"] = "activating\n"
	_, err = p.Apply(context.Background(), sys, nil)
	require.NoError(t, err)
	assert.NotContains(t, run.changing(), "systemctl start postgresql.service")
	assert.Contains(t, run.changing(), "systemctl restart postgresql.service")
}

func TestRestartLeavesAStoppedUnitStoppedButStillChecks(t *testing.T) {
	sys, run := newTestSystem(t)
	run.fail["systemctl is-active grafana.service"] = true
	rs := []Resource{
		&File{Path: "/etc/grafana.ini", Content: []byte("x\n"), Mode: 0o644, OnChange: []Action{{Verb: "restart", Unit: "grafana.service", Checks: [][]string{{"grafana", "check"}}}}},
	}
	_, still, err := planAndApply(t, sys, rs, nil)
	require.NoError(t, err)
	assert.Empty(t, still)
	assert.Equal(t, []string{"grafana check"}, run.changing())
}

func TestSecretCommandIsNotShown(t *testing.T) {
	sys, run := newTestSystem(t)
	run.fail["has-role"] = true
	c := &Command{Name: "role", Check: []string{"has-role"}, Run: []string{"psql", "-c", "PASSWORD 'hunter2'"}, Secret: true}
	p, err := MakePlan(context.Background(), sys, []Resource{c})
	require.NoError(t, err)
	assert.NotContains(t, p.String(), "hunter2")
	assert.Contains(t, p.String(), "run role")
	assert.NotContains(t, describe(c), "hunter2")

	// A change of the secret argv still changes the golden file.
	c2 := *c
	c2.Run = []string{"psql", "-c", "PASSWORD 'hunter3'"}
	assert.NotEqual(t, describe(c), describe(&c2))
}

func TestExecRunnerKeepsStderrOutOfTheOutput(t *testing.T) {
	out, err := ExecRunner(context.Background(), "sh", "-c", "echo warning >&2; echo inactive")
	require.NoError(t, err)
	assert.Equal(t, "inactive\n", string(out))

	out, err = ExecRunner(context.Background(), "sh", "-c", "echo broken >&2; echo inactive; exit 3")
	require.ErrorContains(t, err, "broken")
	assert.True(t, exitedNonZero(err))
	assert.Equal(t, "inactive\n", string(out))
}

func TestLookupIDTakesANumberThatNamesNoOne(t *testing.T) {
	notFound := func(string) (string, error) { return "", user.UnknownUserError("x") }
	id, err := lookupID("999", notFound)
	require.NoError(t, err)
	assert.Equal(t, 999, id)
	_, err = lookupID("nobody-here", notFound)
	require.Error(t, err)
	id, err = lookupID("www-data", func(string) (string, error) { return "33", nil })
	require.NoError(t, err)
	assert.Equal(t, 33, id)
}

func TestUnifiedDiffOfANewFile(t *testing.T) {
	assert.Equal(t, "--- a/f\n+++ b/f\n@@ -0,0 +1,3 @@\n+a\n+\n+b\n", unifiedDiff("/f", nil, []byte("a\n\nb\n")))
}

func TestUnifiedDiffKeepsBlankLinesAndMarksAMissingNewline(t *testing.T) {
	assert.Equal(t, "--- a/f\n+++ b/f\n@@ -1,3 +1,3 @@\n a\n \n-b\n+c\n", unifiedDiff("/f", []byte("a\n\nb\n"), []byte("a\n\nc\n")))
	assert.Equal(t, "--- a/f\n+++ b/f\n@@ -1 +1 @@\n-a\n+a\n\\ No newline at end of file\n", unifiedDiff("/f", []byte("a\n"), []byte("a")))
	assert.Equal(t, "", unifiedDiff("/f", []byte("a\n"), []byte("a\n")))
}
