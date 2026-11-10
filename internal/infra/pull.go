package infra

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"syscall"
	"time"
)

// PullConfig is what `infrafier pull` runs with. The defaults (see the
// CLI) are the paths `infrafier bootstrap` sets up on a host.
type PullConfig struct {
	// Repo is a clone of the desired-state repo.
	Repo   string
	Remote string
	// Ref is the branch this host applies. Main is fetched as well when it
	// differs, to report how far Ref lags behind it.
	Ref  string
	Main string
	Host string

	StateDir    string
	TextfileDir string // node_exporter's textfile collector; empty skips metrics
	// Signatures: git verify-commit checks GPG signatures against the keyring
	// in GnupgHome and SSH ones against AllowedSigners. Both live on the host,
	// outside the repo, so a commit cannot vouch for itself. They hold only
	// operator keys, never GitHub's web-flow key. An operator's signature is
	// the approval: anyone who can push may deploy any signed commit that
	// descends from the applied one, directly or wrapped in a merge commit
	// with the same tree (see verifyHead), but nothing an operator did not
	// sign, and nothing older.
	GnupgHome      string
	AllowedSigners string
	// AgeIdentity decrypts the host's secrets/<host>.age (see secrets.go).
	AgeIdentity string
	// AllowRewind applies a commit that is not a descendant of the last one
	// applied. Without it, re-pushing an old signed commit cannot roll a host
	// back to a config with a known hole.
	AllowRewind bool
	DryRun      bool
	// Fallback is a run of the previous agent (the .prev an agent download
	// keeps), which the pull unit starts when the new agent exited with
	// ErrCannotPlan. It fetches nothing and applies the commit that run
	// recorded (pullState.CannotPlanCommit), not whatever the ref points to
	// by now, so it only applies a commit the new agent verified too. It
	// leaves .prev as it is, since .prev is the agent running, and reports
	// itself in the fallback metric.
	Fallback bool

	System System
	Out    io.Writer
	Now    func() time.Time
}

// pullState is state.json. A reverted agent pin, or a fallback, runs an older
// agent on a file a newer one wrote, so fields are only ever added,
// never renamed or given a new meaning. The fields an agent does not know are
// kept in unknown and written back as they were, so an older agent's run
// does not drop a newer one's guard.
type pullState struct {
	AppliedCommit string `json:"appliedCommit"`
	// WrittenCommit is the last commit whose changes started to be written,
	// whether or not the run then failed. The rollback guard compares with
	// it, not AppliedCommit: a run that wrote a fix and then failed must
	// not let a force-push of the commit before it undo the fix.
	WrittenCommit  string    `json:"writtenCommit,omitempty"`
	LastSuccess    time.Time `json:"lastSuccess"`
	PendingActions []Action  `json:"pendingActions,omitempty"`
	// BehindRuns counts the runs in a row that ended with the host not on
	// its ref's head, for the "applied commit differs" alert.
	BehindRuns int `json:"behindRuns"`
	// CannotPlanCommit is the commit the last run verified but could not
	// plan (ErrCannotPlan), for the fallback run to apply, which clears it.
	// Every other run clears it too, so a fallback never applies a commit
	// an earlier failure left.
	CannotPlanCommit string `json:"cannotPlanCommit,omitempty"`

	unknown map[string]json.RawMessage
}

const (
	stateFile   = "state.json"
	metricsFile = metricPrefix + ".prom"
)

// Pull fetches the host's ref, verifies it, renders it and applies it. It
// applies on every run, even when the commit has not changed, so a file edited
// by hand is put back.
func Pull(ctx context.Context, cfg PullConfig) (err error) {
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	if cfg.Out == nil {
		cfg.Out = io.Discard
	}
	if err := os.MkdirAll(cfg.StateDir, 0o700); err != nil {
		return err
	}
	unlock, err := lock(filepath.Join(cfg.StateDir, "lock"))
	if err != nil {
		return err
	}
	defer unlock()

	st, err := loadState(cfg.StateDir)
	if err != nil {
		// Nothing below runs, so say so in the metrics; otherwise they
		// would keep the last run's success while the host stops applying.
		// The rest (last success, applied commit) keeps the last run's
		// values, so alerts on them still see the host.
		if !cfg.DryRun && cfg.TextfileDir != "" {
			p := filepath.Join(cfg.TextfileDir, metricsFile)
			old, _ := os.ReadFile(p)
			m := failedMetrics(old, cfg.Now())
			if m == nil {
				m = metrics(cfg, &pullState{}, false, cfg.Now(), -1)
			}
			if merr := writeAtomic(p, m); merr != nil {
				err = errors.Join(err, merr)
			}
		}
		return err
	}
	g := gitCmd{repo: cfg.Repo, gnupgHome: cfg.GnupgHome, allowedSigners: cfg.AllowedSigners}

	var commit string // the head of cfg.Ref, once fetched
	lag := -1.0
	// What a fallback applies; cleared either way (see CannotPlanCommit).
	recorded := st.CannotPlanCommit
	st.CannotPlanCommit = ""
	if !cfg.DryRun {
		defer func() {
			now := cfg.Now()
			if err == nil {
				st.AppliedCommit = commit
				st.LastSuccess = now
			}
			// With the head unknown (fetch failed) nothing says the host is
			// behind; last_apply_success reports the failure.
			switch {
			case commit == "":
			case st.AppliedCommit == commit:
				st.BehindRuns = 0
			default:
				st.BehindRuns++
			}
			if serr := saveState(cfg.StateDir, st); serr != nil {
				err = errors.Join(err, serr)
			}
			if cfg.TextfileDir != "" {
				m := metrics(cfg, st, err == nil, now, lag)
				if merr := writeAtomic(filepath.Join(cfg.TextfileDir, metricsFile), m); merr != nil {
					err = errors.Join(err, merr)
				}
			}
		}()
	}

	// Main is fetched with the ref, in one connection. The lag is only a
	// metric: when main can't be fetched (or compared), the ref is fetched
	// alone, and the run says so and leaves the metric out but deploys.
	withMain := cfg.Main != "" && cfg.Main != cfg.Ref
	var lerr error
	if withMain && !cfg.Fallback {
		lerr = g.fetch(ctx, cfg.Remote, cfg.Ref, cfg.Main)
	}
	if (!withMain || lerr != nil) && !cfg.Fallback {
		if err := g.fetch(ctx, cfg.Remote, cfg.Ref); err != nil {
			return err
		}
	}
	remoteRef := "refs/remotes/" + cfg.Remote + "/"
	if cfg.Fallback {
		if recorded == "" {
			return fmt.Errorf("--fallback: no run recorded a commit it could not plan, so there is nothing to fall back for")
		}
		commit = recorded
	} else if commit, err = g.revParse(ctx, remoteRef+cfg.Ref); err != nil {
		return err
	}
	if withMain {
		if lerr == nil {
			lag, lerr = g.lagSeconds(ctx, remoteRef+cfg.Ref, remoteRef+cfg.Main, cfg.Now())
		}
		if lerr != nil {
			lag = -1
			fmt.Fprintf(cfg.Out, "note: no ref lag metric: %v\n", lerr)
		}
	}
	signed, err := g.verifyHead(ctx, commit)
	if err != nil {
		return fmt.Errorf("refusing %s at %s: %w", cfg.Ref, commit, err)
	}
	if signed != commit {
		fmt.Fprintf(cfg.Out, "merge commit %s: its tree is the one signed in %s\n", short(commit), short(signed))
	}
	last := st.WrittenCommit
	if last == "" {
		last = st.AppliedCommit
	}
	if last != "" && last != commit && !cfg.AllowRewind {
		ok, err := g.isAncestor(ctx, last, commit)
		if err != nil {
			return err
		}
		if !ok {
			return fmt.Errorf("refusing %s at %s: not a descendant of %s, the last commit written to this host (use --allow-rewind if that is intended)", cfg.Ref, commit, last)
		}
	}
	// A dry run renders from a worktree of its own, so the clone stays on
	// the commit the host runs.
	tree := cfg.Repo
	if cfg.DryRun {
		dir, remove, err := g.tempWorktree(ctx, commit)
		if err != nil {
			return err
		}
		defer remove()
		tree = dir
	} else if err := g.checkout(ctx, commit); err != nil {
		return err
	}

	plan, err := renderAndPlan(ctx, tree, cfg.Host, cfg.Ref, cfg.AgeIdentity, cfg.System, cfg.Out, cfg.Fallback)
	if errors.Is(err, ErrCannotPlan) && !cfg.Fallback {
		st.CannotPlanCommit = commit
	}
	if err != nil {
		return err
	}
	fmt.Fprintf(cfg.Out, "%s at %s:\n%s", cfg.Ref, short(commit), plan)
	for _, a := range st.PendingActions {
		fmt.Fprintf(cfg.Out, "then %s (owed by an earlier run)\n", a)
	}
	if cfg.DryRun {
		return nil
	}

	st.WrittenCommit = commit
	pending, err := plan.Apply(ctx, cfg.System, st.PendingActions)
	st.PendingActions = pending
	return err
}

// ErrCannotPlan is what a pull returns when it verified the commit but could
// not render it, or panicked while rendering or planning it: nothing was
// applied (a panic in the plan may have left entries in the download cache,
// which is content-addressed, so they can only be missing, never wrong). The CLI exits with CannotPlanExitCode for it, and the pull unit
// then runs the previous agent with --fallback, since a new agent's bug, or a
// module field it does not know, is the likely cause. Any other error exits 1
// and gets no fallback: a fetch or a signature before it (the old agent would
// fail the same way, or would trust what the new one refused), a plan that
// failed on the host (a download that cannot be fetched, systemctl), or an
// apply.
var ErrCannotPlan = errors.New("cannot render or plan the commit")

// CannotPlanExitCode is the exit code of a pull that failed with
// ErrCannotPlan.
const CannotPlanExitCode = 3

// renderAndPlan renders the host from the work tree at tree and plans it
// against sys. A render error or a panic wraps ErrCannotPlan; a missing host
// file does not, it is the repo's error, not the agent's. With
// leavePrevious, no download replaces its .prev (see PullConfig.Fallback).
func renderAndPlan(ctx context.Context, tree, host, ref, ageIdentity string, sys System, out io.Writer, leavePrevious bool) (plan *Plan, err error) {
	defer func() {
		if r := recover(); r != nil {
			plan, err = nil, fmt.Errorf("%w: panic: %v", ErrCannotPlan, r)
		}
	}()
	cannot := func(err error) (*Plan, error) { return nil, fmt.Errorf("%w: %w", ErrCannotPlan, err) }
	fsys, closeRepo, err := OpenRepo(tree)
	if err != nil {
		return nil, err
	}
	defer closeRepo()
	h, file, err := LoadHostFile(fsys, host)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, err
	}
	if err != nil {
		return cannot(err)
	}
	if ref != "" && h.Ref != ref {
		fmt.Fprintf(out, "note: running with ref %s, but %s says %s; the pull unit switches after this run\n", ref, file, h.Ref)
	}
	// From the verified commit, like everything else that is rendered, and
	// only when a template asks for one.
	secrets := &LazySecrets{Load: func() (Secrets, error) {
		return LoadHostSecrets(fsys, host, sys, ageIdentity)
	}}
	rs, err := Render(fsys, h, secrets)
	if err != nil {
		return cannot(err)
	}
	if leavePrevious {
		for _, r := range rs {
			if d, ok := r.(*Download); ok {
				d.leavePrevious = true
			}
		}
	}
	return MakePlan(ctx, sys, rs)
}

// PlanCheckConfig is what `infrafier check-plan` runs with.
type PlanCheckConfig struct {
	Repo        string
	Host        string
	AgeIdentity string
	System      System
	Out         io.Writer
}

// CheckPlan renders the host from the clone's work tree as it is checked out
// and plans it, writing nothing: no lock, no fetch, no state, no metrics, and
// the System is read-only. It is the pre-install check of a new agent,
// which a pull runs with the commit it applies checked out: an agent
// that cannot render and plan that commit is not installed. The pull has
// filled the download cache for the commit, so the plan needs no fetch.
func CheckPlan(ctx context.Context, cfg PlanCheckConfig) error {
	if cfg.Out == nil {
		cfg.Out = io.Discard
	}
	plan, err := renderAndPlan(ctx, cfg.Repo, cfg.Host, "", cfg.AgeIdentity, readOnlySystem{cfg.System}, cfg.Out, false)
	if err != nil {
		return err
	}
	fmt.Fprint(cfg.Out, plan)
	return nil
}

// readOnlySystem refuses every write, so a plan check cannot change the host
// whatever a bug in it does (planning only writes to the download cache, and
// only when it fetches). It does not embed System: a method added to System
// later must be added here too, as a read or a refusal, or this stops
// compiling. Run passes through: planning queries systemctl and dpkg and runs
// the Command checks, which must not change anything in any plan.
type readOnlySystem struct{ sys System }

var _ System = readOnlySystem{}

func errReadOnly(op, p string) error {
	return fmt.Errorf("%s %s: refused, a plan check writes nothing", op, p)
}

func (r readOnlySystem) Lstat(p string) (FileState, error)     { return r.sys.Lstat(p) }
func (r readOnlySystem) LstatSum(p string) (FileState, error)  { return r.sys.LstatSum(p) }
func (r readOnlySystem) LstatMeta(p string) (FileState, error) { return r.sys.LstatMeta(p) }
func (r readOnlySystem) ReadDir(p string) ([]string, error)    { return r.sys.ReadDir(p) }
func (r readOnlySystem) Open(p string) (io.ReadCloser, error)  { return r.sys.Open(p) }
func (r readOnlySystem) Run(ctx context.Context, argv ...string) ([]byte, error) {
	return r.sys.Run(ctx, argv...)
}

func (readOnlySystem) WriteFile(p string, _ []byte, _ fs.FileMode, _, _ string) error {
	return errReadOnly("write", p)
}

func (readOnlySystem) WriteFileFrom(p string, _ io.Reader, _ fs.FileMode, _, _ string) error {
	return errReadOnly("write", p)
}

func (readOnlySystem) SetAttrs(p string, _ fs.FileMode, _, _ string) error {
	return errReadOnly("chmod", p)
}

func (readOnlySystem) Mkdir(p string, _ fs.FileMode, _, _ string) error {
	return errReadOnly("mkdir", p)
}
func (readOnlySystem) RemoveAll(p string) error  { return errReadOnly("remove", p) }
func (readOnlySystem) Symlink(_, p string) error { return errReadOnly("symlink", p) }
func (readOnlySystem) Rename(_, p string) error  { return errReadOnly("rename", p) }
func (readOnlySystem) Fetch(_ context.Context, url string) (io.ReadCloser, error) {
	return nil, errReadOnly("fetch", url)
}

func short(commit string) string {
	if len(commit) > 12 {
		return commit[:12]
	}
	return commit
}

func metrics(cfg PullConfig, st *pullState, success bool, now time.Time, lag float64) []byte {
	var b bytes.Buffer
	gauge := func(name, help, labels string, v float64) {
		fmt.Fprintf(&b, "# HELP %s %s\n# TYPE %s gauge\n%s%s %s\n", name, help, name, name, labels, strconv.FormatFloat(v, 'f', -1, 64))
	}
	ok := 0.0
	if success {
		ok = 1
	}
	gauge(metricPrefix+"_last_apply_success", "Whether the last "+agentCommand+" pull applied without error.", "", ok)
	gauge(metricPrefix+"_last_apply_timestamp_seconds", "When "+agentCommand+" pull last ran.", "", float64(now.Unix()))
	if !st.LastSuccess.IsZero() {
		gauge(metricPrefix+"_last_success_timestamp_seconds", "When "+agentCommand+" pull last applied without error.", "", float64(st.LastSuccess.Unix()))
	}
	if st.AppliedCommit != "" {
		gauge(metricPrefix+"_applied_commit_info", "The commit last applied without error.", fmt.Sprintf(`{commit=%q,ref=%q}`, st.AppliedCommit, cfg.Ref), 1)
	}
	gauge(metricPrefix+"_behind_runs", "Runs in a row that ended with the host not on the head of its ref.", "", float64(st.BehindRuns))
	gauge(metricPrefix+"_pending_actions", "Restarts or reloads owed by a failed run, retried on the next.", "", float64(len(st.PendingActions)))
	fallback := 0.0
	if cfg.Fallback {
		fallback = 1
	}
	gauge(metricPrefix+"_fallback", "Whether the last run was the previous agent's, because the installed one could not render or plan the commit.", "", fallback)
	if lag >= 0 {
		gauge(metricPrefix+"_ref_lag_seconds", "Age of the oldest commit on main that is not yet on this host's ref; 0 when they match.", fmt.Sprintf(`{ref=%q}`, cfg.Ref), lag)
	}
	return b.Bytes()
}

// failedMetrics is the last run's metrics file with last_apply_success set to
// 0 and the run's timestamp, or nil when there is none to start from.
func failedMetrics(old []byte, now time.Time) []byte {
	var b bytes.Buffer
	found := false
	for _, l := range strings.SplitAfter(string(old), "\n") {
		switch {
		case strings.HasPrefix(l, metricPrefix+"_last_apply_success "):
			l, found = metricPrefix+"_last_apply_success 0\n", true
		case strings.HasPrefix(l, metricPrefix+"_last_apply_timestamp_seconds "):
			l = fmt.Sprintf("%s_last_apply_timestamp_seconds %d\n", metricPrefix, now.Unix())
		}
		b.WriteString(l)
	}
	if !found {
		return nil
	}
	return b.Bytes()
}

func loadState(dir string) (*pullState, error) {
	st := &pullState{}
	b, err := os.ReadFile(filepath.Join(dir, stateFile))
	if errors.Is(err, fs.ErrNotExist) {
		return st, nil
	}
	if err != nil {
		return nil, err
	}
	if err := json.Unmarshal(b, st); err != nil {
		return nil, fmt.Errorf("%s: %w", stateFile, err)
	}
	var all map[string]json.RawMessage
	if err := json.Unmarshal(b, &all); err != nil {
		return nil, fmt.Errorf("%s: %w", stateFile, err)
	}
	known := stateFields()
	for k, v := range all {
		if !known[k] {
			if st.unknown == nil {
				st.unknown = map[string]json.RawMessage{}
			}
			st.unknown[k] = v
		}
	}
	return st, nil
}

func saveState(dir string, st *pullState) error {
	b, err := json.Marshal(st)
	if err != nil {
		return err
	}
	if len(st.unknown) > 0 {
		var all map[string]json.RawMessage
		if err := json.Unmarshal(b, &all); err != nil {
			return err
		}
		for k, v := range st.unknown {
			all[k] = v
		}
		if b, err = json.Marshal(all); err != nil {
			return err
		}
	}
	var out bytes.Buffer
	if err := json.Indent(&out, b, "", "  "); err != nil {
		return err
	}
	return writeAtomic(filepath.Join(dir, stateFile), append(out.Bytes(), '\n'))
}

// stateFields is the JSON names of pullState's fields, empty ones included,
// so loadState never takes one of them for a newer agent's.
func stateFields() map[string]bool {
	known := map[string]bool{}
	t := reflect.TypeFor[pullState]()
	for i := range t.NumField() {
		if name, _, _ := strings.Cut(t.Field(i).Tag.Get("json"), ","); name != "" && name != "-" {
			known[name] = true
		}
	}
	return known
}

// writeAtomic writes via a temp file, fsync and rename (OS.WriteFile), so
// node_exporter never reads half a file and a crash never leaves state.json
// empty.
func writeAtomic(p string, b []byte) error {
	return (&OS{}).WriteFile(p, b, 0o644, "", "")
}

// ErrPullRunning is what Pull returns when another pull holds the lock.
// The timer's `infrafier pull` treats it as a skipped run, not a
// failure: bootstrap starts the timer from inside its own first pull, and a
// pull by hand can overlap the timer's, and neither should leave a failed
// unit. A run that hangs holding the lock is still noticed, by
// infrafier_last_success_timestamp_seconds going stale.
var ErrPullRunning = errors.New("another " + agentCommand + " pull is running")

// lock keeps a pull by hand from running over the timer's. The lock is the
// flock on the open file, released by the kernel when the process exits; the
// file itself stays and never blocks a later run.
func lock(p string) (func(), error) {
	f, err := os.OpenFile(p, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, err
	}
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		f.Close()
		if errors.Is(err, syscall.EWOULDBLOCK) {
			return nil, fmt.Errorf("%w (%s)", ErrPullRunning, p)
		}
		return nil, fmt.Errorf("lock %s: %w", p, err)
	}
	return func() { f.Close() }, nil
}

type gitCmd struct {
	repo           string
	gnupgHome      string
	allowedSigners string
}

func (g gitCmd) run(ctx context.Context, args ...string) (string, error) {
	argv := append([]string{"-C", g.repo, "-c", "core.hooksPath=/dev/null"}, args...)
	cmd := exec.CommandContext(ctx, "git", argv...)
	cmd.Env = append(os.Environ(), "GIT_TERMINAL_PROMPT=0")
	if g.gnupgHome != "" {
		cmd.Env = append(cmd.Env, "GNUPGHOME="+g.gnupgHome)
	}
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	if err := runCmd(cmd); err != nil {
		return "", fmt.Errorf("git %s: %w: %s", strings.Join(args, " "), err, strings.TrimSpace(stderr.String()))
	}
	return strings.TrimSpace(stdout.String()), nil
}

func (g gitCmd) fetch(ctx context.Context, remote string, refs ...string) error {
	args := []string{"fetch", "--quiet", "--no-tags", remote}
	for _, r := range refs {
		args = append(args, fmt.Sprintf("+refs/heads/%s:refs/remotes/%s/%s", r, remote, r))
	}
	_, err := g.run(ctx, args...)
	return err
}

func (g gitCmd) revParse(ctx context.Context, ref string) (string, error) {
	return g.run(ctx, "rev-parse", "--verify", "--end-of-options", ref+"^{commit}")
}

func (g gitCmd) verifyCommit(ctx context.Context, commit string) error {
	args := []string{"verify-commit", commit}
	if g.allowedSigners != "" {
		args = append([]string{"-c", "gpg.ssh.allowedSignersFile=" + g.allowedSigners}, args...)
	}
	_, err := g.run(ctx, args...)
	return err
}

// verifyHead decides whether commit may be deployed, and returns the commit
// whose signature vouches for it. What a host deploys is the commit's tree,
// so it accepts:
//   - a commit an operator signed, or
//   - a merge commit (GitHub's "Create a merge commit" button, signed with
//     GitHub's key, which the hosts never trust) whose tree is exactly that of
//     its second parent, the PR head, which an operator signed, and which
//     contains its first parent. Without that last rule, a merge of the
//     current head with an old signed commit, given that commit's tree, would
//     roll a host back past Pull's descendant check.
//
// GitHub can then only put trees on the ref that an operator signed. Merging
// a stale PR gives a tree no one signed, so it is refused until the PR is
// brought up to date or an operator signs the result on main.
func (g gitCmd) verifyHead(ctx context.Context, commit string) (string, error) {
	headErr := g.verifyCommit(ctx, commit)
	if headErr == nil {
		return commit, nil
	}
	out, err := g.run(ctx, "rev-list", "--parents", "-n", "1", commit)
	if err != nil {
		return "", err
	}
	parents := strings.Fields(out)[1:]
	if len(parents) != 2 {
		return "", headErr
	}
	base, prHead := parents[0], parents[1]
	trees, err := g.run(ctx, "rev-parse", commit+"^{tree}", prHead+"^{tree}")
	if err != nil {
		return "", err
	}
	if t := strings.Fields(trees); len(t) != 2 || t[0] != t[1] {
		return "", fmt.Errorf("%w; and it is a merge whose tree differs from its second parent %s (a PR merged while out of date with main?)", headErr, short(prHead))
	}
	if err := g.verifyCommit(ctx, prHead); err != nil {
		return "", fmt.Errorf("%w; and the PR head it merges, %s, is not signed by an operator either: %w", headErr, short(prHead), err)
	}
	ok, err := g.isAncestor(ctx, base, prHead)
	if err != nil {
		return "", err
	}
	if !ok {
		return "", fmt.Errorf("%w; and the PR head it merges, %s, does not contain its first parent %s, so what was signed is not this merge", headErr, short(prHead), short(base))
	}
	return prHead, nil
}

func (g gitCmd) isAncestor(ctx context.Context, a, b string) (bool, error) {
	_, err := g.run(ctx, "merge-base", "--is-ancestor", a, b)
	if err == nil {
		return true, nil
	}
	// Only 1 means "not an ancestor"; 128 is a missing commit or a broken
	// clone, which must not read as a rewind (and push towards
	// --allow-rewind).
	var ee interface{ ExitCode() int }
	if errors.As(err, &ee) && ee.ExitCode() == 1 {
		return false, nil
	}
	return false, err
}

func (g gitCmd) checkout(ctx context.Context, commit string) error {
	if _, err := g.run(ctx, "-c", "advice.detachedHead=false", "checkout", "--quiet", "--force", "--detach", commit); err != nil {
		return err
	}
	_, err := g.run(ctx, "clean", "-ffdxq")
	return err
}

// tempWorktree checks commit out in a new temporary directory, leaving the
// clone's own work tree alone. remove deletes it again.
func (g gitCmd) tempWorktree(ctx context.Context, commit string) (string, func(), error) {
	dir, err := os.MkdirTemp("", agentName+"-dry-run-")
	if err != nil {
		return "", nil, err
	}
	remove := func() {
		// Without ctx: a cancelled run must still clean up.
		if _, err := g.run(context.Background(), "worktree", "remove", "--force", dir); err != nil {
			os.RemoveAll(dir)
			g.run(context.Background(), "worktree", "prune")
		}
	}
	if _, err := g.run(ctx, "worktree", "add", "--quiet", "--detach", dir, commit); err != nil {
		remove()
		return "", nil, err
	}
	return dir, remove, nil
}

// lagSeconds is how long the oldest commit on main that is missing from ref
// has been there, by its committer date; 0 when ref has all of main. It walks
// main's first parents only, so a PR's own commits (committed when the PR was
// written) don't count and a merge counts from when it was merged.
func (g gitCmd) lagSeconds(ctx context.Context, ref, main string, now time.Time) (float64, error) {
	out, err := g.run(ctx, "log", "--first-parent", "--format=%ct", "--reverse", ref+".."+main)
	if err != nil {
		return 0, err
	}
	if out == "" {
		return 0, nil
	}
	first, _, _ := strings.Cut(out, "\n")
	ts, err := strconv.ParseInt(first, 10, 64)
	if err != nil {
		return 0, err
	}
	return max(0, now.Sub(time.Unix(ts, 0)).Seconds()), nil
}
