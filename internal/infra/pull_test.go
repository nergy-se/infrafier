package infra

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// gitFixture is an origin with SSH-signed commits, an operator's work tree
// pushing to it and a host's clone pulling from it, all in a temp dir with
// git's global and system config shut out.
type gitFixture struct {
	t        *testing.T
	dir      string
	work     string
	goodKey  string
	otherKey string
	cfg      PullConfig
	root     *OS
}

func newGitFixture(t *testing.T) *gitFixture {
	t.Helper()
	for _, bin := range []string{"git", "ssh-keygen"} {
		if _, err := exec.LookPath(bin); err != nil {
			t.Skipf("%s not installed", bin)
		}
	}
	dir := t.TempDir()
	t.Setenv("HOME", dir)
	t.Setenv("GIT_CONFIG_GLOBAL", filepath.Join(dir, "gitconfig"))
	t.Setenv("GIT_CONFIG_NOSYSTEM", "1")
	f := &gitFixture{t: t, dir: dir, work: filepath.Join(dir, "work"), goodKey: filepath.Join(dir, "good"), otherKey: filepath.Join(dir, "other")}

	f.sh(dir, "ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-C", "good", "-f", f.goodKey)
	f.sh(dir, "ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-C", "other", "-f", f.otherKey)
	pub, err := os.ReadFile(f.goodKey + ".pub")
	require.NoError(t, err)
	signers := filepath.Join(dir, "allowed_signers")
	require.NoError(t, os.WriteFile(signers, []byte(`operator@example.com namespaces="git" `+string(pub)), 0o644))

	f.sh(dir, "git", "init", "-q", "--bare", "-b", "main", "origin.git")
	f.sh(dir, "git", "init", "-q", "-b", "main", "work")
	f.sh(f.work, "git", "config", "user.name", "Operator")
	f.sh(f.work, "git", "config", "user.email", "operator@example.com")
	f.sh(f.work, "git", "config", "gpg.format", "ssh")
	f.sh(f.work, "git", "remote", "add", "origin", filepath.Join(dir, "origin.git"))

	f.write("hosts/h.jsonnet", `{ ref: 'main', modules: ['m'] }`)
	// Owner and group default to root, which a test cannot chown to.
	u, err := user.Current()
	require.NoError(t, err)
	g, err := user.LookupGroupId(u.Gid)
	require.NoError(t, err)
	f.write("modules/m/module.jsonnet", fmt.Sprintf(`{ resources: [{ file: { path: '/etc/motd', template: 'motd', owner: %q, group: %q } }] }`, u.Username, g.Name))

	f.root = &OS{Root: filepath.Join(dir, "root"), Runner: (&fakeRunner{}).run}
	f.cfg = PullConfig{
		Repo:           filepath.Join(dir, "hostrepo"),
		Remote:         "origin",
		Ref:            "main",
		Main:           "main",
		Host:           "h",
		StateDir:       filepath.Join(dir, "state"),
		TextfileDir:    filepath.Join(dir, "textfile"),
		AllowedSigners: signers,
		System:         f.root,
	}
	return f
}

func (f *gitFixture) sh(dir string, argv ...string) string {
	f.t.Helper()
	cmd := exec.Command(argv[0], argv[1:]...)
	cmd.Dir = dir
	out, err := cmd.CombinedOutput()
	require.NoError(f.t, err, "%s: %s", strings.Join(argv, " "), out)
	return strings.TrimSpace(string(out))
}

func (f *gitFixture) write(p, content string) {
	f.t.Helper()
	full := filepath.Join(f.work, p)
	require.NoError(f.t, os.MkdirAll(filepath.Dir(full), 0o755))
	require.NoError(f.t, os.WriteFile(full, []byte(content), 0o644))
}

// commit commits motd with the given content, signed with key (empty: unsigned).
func (f *gitFixture) commit(motd, key string) string {
	f.t.Helper()
	return f.commitFile("modules/m/motd", motd, key)
}

func (f *gitFixture) commitFile(p, content, key string) string {
	f.t.Helper()
	f.write(p, content)
	f.sh(f.work, "git", "add", "-A")
	msg := p + " " + strings.TrimSpace(content)
	args := []string{"git", "-c", "commit.gpgsign=false", "commit", "-q", "-m", msg}
	if key != "" {
		args = []string{"git", "-c", "user.signingkey=" + key, "commit", "-q", "-S", "-m", msg}
	}
	f.sh(f.work, args...)
	return f.sh(f.work, "git", "rev-parse", "HEAD")
}

// buttonMerge stands in for GitHub's "Create a merge commit" button: a
// --no-ff merge of branch into main, not signed by any key the hosts trust.
func (f *gitFixture) buttonMerge(branch string) string {
	f.t.Helper()
	f.sh(f.work, "git", "switch", "-q", "main")
	f.sh(f.work, "git", "-c", "commit.gpgsign=false", "merge", "-q", "--no-ff", "--no-edit", branch)
	return f.sh(f.work, "git", "rev-parse", "HEAD")
}

func (f *gitFixture) push(refspec string, force bool) {
	f.t.Helper()
	args := []string{"git", "push", "-q", "origin", refspec}
	if force {
		args = append(args, "--force")
	}
	f.sh(f.work, args...)
}

func (f *gitFixture) clone() {
	f.t.Helper()
	f.sh(f.dir, "git", "clone", "-q", filepath.Join(f.dir, "origin.git"), f.cfg.Repo)
}

func (f *gitFixture) motd() string {
	f.t.Helper()
	b, err := os.ReadFile(filepath.Join(f.root.Root, "etc/motd"))
	require.NoError(f.t, err)
	return string(b)
}

func (f *gitFixture) metrics() string {
	f.t.Helper()
	b, err := os.ReadFile(filepath.Join(f.cfg.TextfileDir, metricsFile))
	require.NoError(f.t, err)
	return string(b)
}

func TestPullAppliesOnlySignedFastForwards(t *testing.T) {
	f := newGitFixture(t)
	ctx := context.Background()
	v1 := f.commit("v1\n", f.goodKey)
	f.push("main", false)
	f.clone()

	require.NoError(t, Pull(ctx, f.cfg))
	assert.Equal(t, "v1\n", f.motd())
	m := f.metrics()
	assert.Contains(t, m, "infrafier_last_apply_success 1\n")
	assert.Contains(t, m, `infrafier_applied_commit_info{commit="`+v1+`",ref="main"} 1`)
	assert.Contains(t, m, "infrafier_behind_runs 0\n")
	assert.NotContains(t, m, "infrafier_ref_lag_seconds")

	// A file edited by hand is put back on the next run, same commit.
	require.NoError(t, os.WriteFile(filepath.Join(f.root.Root, "etc/motd"), []byte("edited\n"), 0o644))
	require.NoError(t, Pull(ctx, f.cfg))
	assert.Equal(t, "v1\n", f.motd())

	// Unsigned, or signed by a key that is not allowed: refused, and the
	// host stays on v1.
	f.commit("unsigned\n", "")
	f.push("main", false)
	require.ErrorContains(t, Pull(ctx, f.cfg), "refusing main")
	f.commit("other\n", f.otherKey)
	f.push("main", false)
	require.ErrorContains(t, Pull(ctx, f.cfg), "refusing main")
	assert.Equal(t, "v1\n", f.motd())
	m = f.metrics()
	assert.Contains(t, m, "infrafier_last_apply_success 0\n")
	assert.Contains(t, m, `commit="`+v1+`"`)
	assert.Contains(t, m, "infrafier_behind_runs 2\n")

	v4 := f.commit("v4\n", f.goodKey)
	f.push("main", false)
	require.NoError(t, Pull(ctx, f.cfg))
	assert.Equal(t, "v4\n", f.motd())
	assert.Contains(t, f.metrics(), `commit="`+v4+`"`)

	// Force-pushing the older, validly signed v1 does not roll the host back.
	f.push(v1+":refs/heads/main", true)
	require.ErrorContains(t, Pull(ctx, f.cfg), "not a descendant")
	assert.Equal(t, "v4\n", f.motd())
	cfg := f.cfg
	cfg.AllowRewind = true
	require.NoError(t, Pull(ctx, cfg))
	assert.Equal(t, "v1\n", f.motd())
}

func TestPullDryRunChangesNothing(t *testing.T) {
	f := newGitFixture(t)
	f.commit("v1\n", f.goodKey)
	f.push("main", false)
	f.clone()

	var out strings.Builder
	cfg := f.cfg
	cfg.DryRun = true
	cfg.Out = &out
	require.NoError(t, Pull(context.Background(), cfg))
	assert.Contains(t, out.String(), "create /etc/motd")
	assert.NoFileExists(t, filepath.Join(f.root.Root, "etc/motd"))
	assert.NoFileExists(t, filepath.Join(f.cfg.TextfileDir, metricsFile))
}

func TestPullDryRunLeavesTheCloneOnTheAppliedCommit(t *testing.T) {
	f := newGitFixture(t)
	v1 := f.commit("v1\n", f.goodKey)
	f.push("main", false)
	f.clone()
	require.NoError(t, Pull(context.Background(), f.cfg))
	untracked := filepath.Join(f.cfg.Repo, "keep-me")
	require.NoError(t, os.WriteFile(untracked, nil, 0o644))

	f.commit("v2\n", f.goodKey)
	f.push("main", false)
	var out strings.Builder
	cfg := f.cfg
	cfg.DryRun = true
	cfg.Out = &out
	require.NoError(t, Pull(context.Background(), cfg))
	assert.Contains(t, out.String(), "+v2")
	assert.Equal(t, v1, f.sh(f.cfg.Repo, "git", "rev-parse", "HEAD"))
	assert.FileExists(t, untracked)
	assert.Equal(t, "v1\n", f.motd())
	assert.NotContains(t, f.sh(f.cfg.Repo, "git", "worktree", "list"), "dry-run")
}

func TestPullReportsRefLag(t *testing.T) {
	f := newGitFixture(t)
	f.write("hosts/h.jsonnet", `{ ref: 'infra/host-a', modules: ['m'] }`)
	f.commit("v1\n", f.goodKey)
	f.push("main", false)
	f.push("main:infra/host-a", false)
	f.clone()

	cfg := f.cfg
	cfg.Ref = "infra/host-a"
	require.NoError(t, Pull(context.Background(), cfg))
	assert.Contains(t, f.metrics(), `infrafier_ref_lag_seconds{ref="infra/host-a"} 0`+"\n")

	// main moves on; host-a keeps applying infra/host-a and reports the lag.
	f.commit("v2\n", f.goodKey)
	f.push("main", false)
	committed, err := time.Parse(time.RFC3339, f.sh(f.work, "git", "log", "-1", "--format=%cI"))
	require.NoError(t, err)
	cfg.Now = func() time.Time { return committed.Add(25 * time.Hour) }
	require.NoError(t, Pull(context.Background(), cfg))
	assert.Equal(t, "v1\n", f.motd())
	assert.Contains(t, f.metrics(), `infrafier_ref_lag_seconds{ref="infra/host-a"} 90000`+"\n")
}

func TestPullAcceptsButtonMergeOfSignedPRHead(t *testing.T) {
	f := newGitFixture(t)
	ctx := context.Background()
	f.commit("v1\n", f.goodKey)
	f.push("main", false)
	f.clone()
	require.NoError(t, Pull(ctx, f.cfg))

	// A PR whose last commit is signed: someone else's unsigned commit,
	// approved with an empty signed commit on top.
	f.sh(f.work, "git", "switch", "-q", "-c", "pr1")
	f.commit("v2\n", "")
	f.sh(f.work, "git", "-c", "user.signingkey="+f.goodKey, "commit", "-q", "-S", "--allow-empty", "-m", "Approve")
	approved := f.sh(f.work, "git", "rev-parse", "HEAD")
	f.buttonMerge("pr1")
	f.push("main", false)

	var out strings.Builder
	cfg := f.cfg
	cfg.Out = &out
	require.NoError(t, Pull(ctx, cfg))
	assert.Equal(t, "v2\n", f.motd())
	assert.Contains(t, out.String(), "its tree is the one signed in "+short(approved))
}

func TestPullRefusesButtonMergeOfUnsignedPRHead(t *testing.T) {
	f := newGitFixture(t)
	ctx := context.Background()
	f.commit("v1\n", f.goodKey)
	f.push("main", false)
	f.clone()
	require.NoError(t, Pull(ctx, f.cfg))

	f.sh(f.work, "git", "switch", "-q", "-c", "pr1")
	f.commit("v2\n", f.goodKey)
	f.commit("v3\n", "") // pushed after the signed commit, not approved
	f.buttonMerge("pr1")
	f.push("main", false)
	require.ErrorContains(t, Pull(ctx, f.cfg), "is not signed by an operator either")
	assert.Equal(t, "v1\n", f.motd())
}

func TestPullRefusesStaleButtonMergeUntilMainIsSigned(t *testing.T) {
	f := newGitFixture(t)
	ctx := context.Background()
	f.commit("v1\n", f.goodKey)
	f.push("main", false)
	f.clone()
	require.NoError(t, Pull(ctx, f.cfg))

	// pr1 is signed, but main moves on before it is merged, so the merge's
	// tree is one nobody signed.
	f.sh(f.work, "git", "switch", "-q", "-c", "pr1")
	f.commit("v2\n", f.goodKey)
	f.sh(f.work, "git", "switch", "-q", "main")
	f.commitFile("modules/m/other", "x\n", f.goodKey)
	f.buttonMerge("pr1")
	f.push("main", false)
	require.ErrorContains(t, Pull(ctx, f.cfg), "tree differs from its second parent")
	assert.Equal(t, "v1\n", f.motd())

	// An operator looks at main and signs it.
	f.sh(f.work, "git", "-c", "user.signingkey="+f.goodKey, "commit", "-q", "-S", "--allow-empty", "-m", "Approve")
	f.push("main", false)
	require.NoError(t, Pull(ctx, f.cfg))
	assert.Equal(t, "v2\n", f.motd())
}

func TestPullAcceptsButtonMergeAfterSignedRebase(t *testing.T) {
	f := newGitFixture(t)
	ctx := context.Background()
	f.commit("v1\n", f.goodKey)
	f.push("main", false)
	f.clone()
	require.NoError(t, Pull(ctx, f.cfg))

	f.sh(f.work, "git", "switch", "-q", "-c", "pr1")
	f.commit("v2\n", "")
	f.sh(f.work, "git", "switch", "-q", "main")
	f.commitFile("modules/m/other", "x\n", f.goodKey)
	// Out of date: rebase it onto main, signing the rebased commits.
	f.sh(f.work, "git", "-c", "user.signingkey="+f.goodKey, "rebase", "-q", "--gpg-sign", "main", "pr1")
	f.buttonMerge("pr1")
	f.push("main", false)
	require.NoError(t, Pull(ctx, f.cfg))
	assert.Equal(t, "v2\n", f.motd())
}

func TestPullRefusesMergeThatReplaysAnOldSignedCommit(t *testing.T) {
	f := newGitFixture(t)
	ctx := context.Background()
	v1 := f.commit("v1\n", f.goodKey)
	f.commit("v2\n", f.goodKey)
	f.push("main", false)
	f.clone()
	require.NoError(t, Pull(ctx, f.cfg))

	// Anyone who can push crafts an unsigned merge of main and v1 with v1's
	// tree: its tree is v1's, v1 is signed, and the applied commit is its
	// first parent.
	replay := f.sh(f.work, "git", "commit-tree", v1+"^{tree}", "-p", "HEAD", "-p", v1, "-m", "replay")
	f.push(replay+":refs/heads/main", false)
	require.ErrorContains(t, Pull(ctx, f.cfg), "does not contain its first parent")
	assert.Equal(t, "v2\n", f.motd())
}

func TestPullRefLagCountsFromTheMerge(t *testing.T) {
	f := newGitFixture(t)
	f.write("hosts/h.jsonnet", `{ ref: 'infra/host-a', modules: ['m'] }`)
	f.commit("v1\n", f.goodKey)
	f.push("main", false)
	f.push("main:infra/host-a", false)
	f.clone()

	// A PR written a week ago, merged now.
	merged := time.Now().Truncate(time.Second)
	f.sh(f.work, "git", "switch", "-q", "-c", "pr1")
	t.Setenv("GIT_COMMITTER_DATE", merged.Add(-7*24*time.Hour).Format(time.RFC3339))
	f.commit("v2\n", f.goodKey)
	t.Setenv("GIT_COMMITTER_DATE", merged.Format(time.RFC3339))
	f.buttonMerge("pr1")
	f.push("main", false)

	cfg := f.cfg
	cfg.Ref = "infra/host-a"
	cfg.Now = func() time.Time { return merged.Add(time.Hour) }
	require.NoError(t, Pull(context.Background(), cfg))
	assert.Contains(t, f.metrics(), `infrafier_ref_lag_seconds{ref="infra/host-a"} 3600`+"\n")
}

func TestPullDeploysWhenTheLagCannotBeMeasured(t *testing.T) {
	f := newGitFixture(t)
	f.write("hosts/h.jsonnet", `{ ref: 'infra/host-a', modules: ['m'] }`)
	f.commit("v1\n", f.goodKey)
	f.push("main:infra/host-a", false)
	f.clone()

	var out strings.Builder
	cfg := f.cfg
	cfg.Ref = "infra/host-a"
	cfg.Main = "no-such-branch"
	cfg.Out = &out
	require.NoError(t, Pull(context.Background(), cfg))
	assert.Equal(t, "v1\n", f.motd())
	assert.Contains(t, out.String(), "note: no ref lag metric")
	assert.NotContains(t, f.metrics(), "infrafier_ref_lag_seconds")
}

func TestPullRollbackGuardCountsARunThatWroteButFailed(t *testing.T) {
	f := newGitFixture(t)
	ctx := context.Background()
	v1 := f.commit("v1\n", f.goodKey)
	f.push("main", false)
	f.clone()
	require.NoError(t, Pull(ctx, f.cfg))

	// v2 is a signed fix whose files get written, but the run fails after
	// that (here the restart it asks for), so v1 stays the applied commit.
	u, err := user.Current()
	require.NoError(t, err)
	g, err := user.LookupGroupId(u.Gid)
	require.NoError(t, err)
	f.write("modules/m/module.jsonnet", fmt.Sprintf(`{ resources: [{ file: { path: '/etc/motd', template: 'motd', owner: %q, group: %q, onChange: [{ restart: 'x' }] } }] }`, u.Username, g.Name))
	f.commit("v2\n", f.goodKey)
	f.push("main", false)
	runner := &fakeRunner{fail: map[string]bool{"systemctl restart x.service": true}}
	f.root.Runner = runner.run
	require.ErrorContains(t, Pull(ctx, f.cfg), "restart x.service")
	assert.Equal(t, "v2\n", f.motd())

	// A force-push back to v1 must not undo the fix.
	f.push(v1+":refs/heads/main", true)
	require.ErrorContains(t, Pull(ctx, f.cfg), "not a descendant")
	assert.Equal(t, "v2\n", f.motd())
}

func TestIsAncestorReportsAMissingCommitAsAnError(t *testing.T) {
	f := newGitFixture(t)
	f.commit("v1\n", f.goodKey)
	f.push("main", false)
	f.clone()
	g := gitCmd{repo: f.cfg.Repo}
	_, err := g.isAncestor(context.Background(), strings.Repeat("1", 40), "HEAD")
	require.Error(t, err)
}

func TestPullReportsFailureWhenStateCannotBeRead(t *testing.T) {
	f := newGitFixture(t)
	f.commit("v1\n", f.goodKey)
	f.push("main", false)
	f.clone()
	require.NoError(t, Pull(context.Background(), f.cfg))
	assert.Contains(t, f.metrics(), "infrafier_last_apply_success 1\n")

	require.NoError(t, os.WriteFile(filepath.Join(f.cfg.StateDir, stateFile), []byte("{"), 0o644))
	require.ErrorContains(t, Pull(context.Background(), f.cfg), stateFile)
	assert.Contains(t, f.metrics(), "infrafier_last_apply_success 0\n")
	// What the last good run reported stays, so alerts on it still fire.
	assert.Contains(t, f.metrics(), "infrafier_last_success_timestamp_seconds ")
	assert.Contains(t, f.metrics(), "infrafier_applied_commit_info{")
}

func TestPullFetchFailureDoesNotCountAsBehind(t *testing.T) {
	f := newGitFixture(t)
	f.commit("v1\n", f.goodKey)
	f.push("main", false)
	f.clone()
	require.NoError(t, Pull(context.Background(), f.cfg))

	cfg := f.cfg
	cfg.Remote = "no-such-remote"
	require.Error(t, Pull(context.Background(), cfg))
	m := f.metrics()
	assert.Contains(t, m, "infrafier_last_apply_success 0\n")
	assert.Contains(t, m, "infrafier_behind_runs 0\n")
}

// Another pull holding the lock is ErrPullRunning, which the timer's pull
// treats as a skipped run; the file left behind by an earlier run is not.
func TestPullFindsTheLockHeld(t *testing.T) {
	f := newGitFixture(t)
	f.commit("v1\n", f.goodKey)
	f.push("main", false)
	f.clone()

	require.NoError(t, os.MkdirAll(f.cfg.StateDir, 0o700))
	unlock, err := lock(filepath.Join(f.cfg.StateDir, "lock"))
	require.NoError(t, err)
	err = Pull(context.Background(), f.cfg)
	require.ErrorIs(t, err, ErrPullRunning)
	assert.ErrorContains(t, err, filepath.Join(f.cfg.StateDir, "lock"))

	unlock()
	require.NoError(t, Pull(context.Background(), f.cfg), "the lock file is still there, but nobody holds it")
}

// Only a commit that was verified but cannot be rendered or planned is
// ErrCannotPlan, the pull unit's cue to run the previous agent; a refused
// signature is not, or the old agent would get to judge what the new one
// refused.
func TestPullCannotPlanOnlyForAVerifiedCommit(t *testing.T) {
	f := newGitFixture(t)
	f.commit("v1\n", f.goodKey)
	f.push("main", false)
	f.clone()
	require.NoError(t, Pull(context.Background(), f.cfg))

	f.commitFile("modules/m/module.jsonnet", `{ resources: [{ file: { path: '/etc/motd', content: 'x', newField: true } }] }`, "")
	f.push("main", false)
	err := Pull(context.Background(), f.cfg)
	require.ErrorContains(t, err, "refusing main")
	assert.NotErrorIs(t, err, ErrCannotPlan)

	v3 := f.commit("v3\n", f.goodKey) // signed, and still has the unknown field
	f.push("main", false)
	err = Pull(context.Background(), f.cfg)
	require.ErrorIs(t, err, ErrCannotPlan)
	assert.ErrorContains(t, err, "newField")
	assert.Equal(t, "v1\n", f.motd())
	st, err := loadState(f.cfg.StateDir)
	require.NoError(t, err)
	assert.Equal(t, v3, st.CannotPlanCommit, "for the fallback run")

	// A plan that fails on the host, here a download that cannot be
	// fetched, is the host's problem, not the agent's.
	f.commitFile("modules/m/module.jsonnet", `{ resources: [{ download: { url: 'https://127.0.0.1:1/x', sha256: '`+strings.Repeat("0", 64)+`', path: '/usr/local/bin/x' } }] }`, f.goodKey)
	f.push("main", false)
	err = Pull(context.Background(), f.cfg)
	require.ErrorContains(t, err, "127.0.0.1:1")
	assert.NotErrorIs(t, err, ErrCannotPlan)
	st, err = loadState(f.cfg.StateDir)
	require.NoError(t, err)
	assert.Empty(t, st.CannotPlanCommit, "cleared by every other run")

	// A missing host file is the repo's error, not the agent's.
	cfg := f.cfg
	cfg.Host = "nope"
	err = Pull(context.Background(), cfg)
	require.ErrorContains(t, err, "nope")
	assert.NotErrorIs(t, err, ErrCannotPlan)
}

// A fallback run applies the commit the failed run recorded, even when a pull
// in between fetched a newer head, and says it was a fallback.
func TestPullFallbackAppliesTheRecordedCommit(t *testing.T) {
	f := newGitFixture(t)
	f.commit("v1\n", f.goodKey)
	f.push("main", false)
	f.clone()
	require.NoError(t, Pull(context.Background(), f.cfg))
	assert.Contains(t, f.metrics(), "infrafier_fallback 0\n")

	cfg := f.cfg
	cfg.Fallback = true
	require.ErrorContains(t, Pull(context.Background(), cfg), "nothing to fall back for")
	assert.Equal(t, "v1\n", f.motd())

	// The new agent's run fetched v2 and could not plan it. Both agents are
	// this code here, so the failure is written into the state by hand.
	v2 := f.commit("v2\n", f.goodKey)
	f.push("main", false)
	f.sh(f.cfg.Repo, "git", "fetch", "-q", "origin", "+refs/heads/main:refs/remotes/origin/main")
	st, err := loadState(f.cfg.StateDir)
	require.NoError(t, err)
	st.CannotPlanCommit = v2
	require.NoError(t, saveState(f.cfg.StateDir, st))
	// A pull by hand (a dry run) fetches v3 before the fallback starts.
	f.commit("v3\n", f.goodKey)
	f.push("main", false)
	dry := f.cfg
	dry.DryRun = true
	require.NoError(t, Pull(context.Background(), dry))

	require.NoError(t, Pull(context.Background(), cfg))
	assert.Equal(t, "v2\n", f.motd())
	m := f.metrics()
	assert.Contains(t, m, `commit="`+v2+`"`)
	assert.Contains(t, m, "infrafier_fallback 1\n")
	st, err = loadState(f.cfg.StateDir)
	require.NoError(t, err)
	assert.Empty(t, st.CannotPlanCommit, "applied once")
	require.ErrorContains(t, Pull(context.Background(), cfg), "nothing to fall back for")
}

// The pre-install check plans the clone's checked-out commit and writes
// nothing.
func TestCheckPlan(t *testing.T) {
	f := newGitFixture(t)
	f.commit("v1\n", f.goodKey)
	f.push("main", false)
	f.clone()
	require.NoError(t, Pull(context.Background(), f.cfg))

	// What a pull checks out before it installs a new agent.
	require.NoError(t, os.WriteFile(filepath.Join(f.cfg.Repo, "modules/m/motd"), []byte("v2\n"), 0o644))
	var out strings.Builder
	cfg := PlanCheckConfig{Repo: f.cfg.Repo, Host: "h", System: f.root, Out: &out}
	require.NoError(t, CheckPlan(context.Background(), cfg))
	assert.Contains(t, out.String(), "update /etc/motd")
	assert.Equal(t, "v1\n", f.motd())

	require.NoError(t, os.WriteFile(filepath.Join(f.cfg.Repo, "modules/m/module.jsonnet"), []byte(`{ resources: [{ file: { path: '/etc/motd', content: 'x', newField: true } }] }`), 0o644))
	assert.ErrorIs(t, CheckPlan(context.Background(), cfg), ErrCannotPlan)
}

// A reverted agent pin runs an older agent on the state a newer one wrote:
// it loads, and the fields it does not know are written back as they were.
func TestStateKeepsFieldsItDoesNotKnow(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, stateFile), []byte(`{"appliedCommit":"abc","behindRuns":2,"cannotPlanCommit":"def","fieldOfANewerAgent":{"x":1}}`), 0o600))
	st, err := loadState(dir)
	require.NoError(t, err)
	assert.Equal(t, "abc", st.AppliedCommit)
	assert.Equal(t, 2, st.BehindRuns)

	st.BehindRuns, st.CannotPlanCommit = 0, "" // a known field emptied stays empty
	require.NoError(t, saveState(dir, st))
	b, err := os.ReadFile(filepath.Join(dir, stateFile))
	require.NoError(t, err)
	assert.Contains(t, string(b), `"fieldOfANewerAgent": {`)
	assert.NotContains(t, string(b), "cannotPlanCommit")
	st, err = loadState(dir)
	require.NoError(t, err)
	assert.Equal(t, map[string]json.RawMessage{"fieldOfANewerAgent": json.RawMessage(`{"x":1}`)}, compactRaw(t, st.unknown))
}

func compactRaw(t *testing.T, m map[string]json.RawMessage) map[string]json.RawMessage {
	t.Helper()
	out := map[string]json.RawMessage{}
	for k, v := range m {
		var b bytes.Buffer
		require.NoError(t, json.Compact(&b, v))
		out[k] = b.Bytes()
	}
	return out
}
