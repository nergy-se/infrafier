package infra

import (
	"context"
	"fmt"
	"io"
)

// HostDiffConfig is what `infrafier diff --host` runs with.
type HostDiffConfig struct {
	// Dir is the operator's clone of the desired-state repo, for
	// hosts/<Host>.jsonnet (its ref and address).
	Dir  string
	Host string
	// Target is the ssh destination; when empty, the host file's address,
	// else Host (as for bootstrap).
	Target string
	// Ref is the branch to plan; when empty, the one the host follows. Any
	// other branch is planned the way the host would plan it if it followed
	// that branch (signatures and the rewind guard included), e.g. a PR's
	// before it is merged.
	Ref   string
	Local Local
	Out   io.Writer
}

// HostDiff shows what the next pull will change on a live host: it runs the
// host's own agent over ssh as `pull --dry-run`, which fetches the ref,
// verifies it as a pull does, renders it in a temporary worktree and prints
// the plan (unified diffs of the files, then the actions), writing no state,
// no metrics and nothing the host's config is made of. Planning may fill the
// download cache, which is content-addressed and only read by an apply.
//
// It is the host's installed agent that plans, not this one, since that is
// the agent the next pull starts with. A commit that pins a new agent is
// still planned by the old one; the new one runs from the pull after.
func HostDiff(ctx context.Context, cfg HostDiffConfig) error {
	out := cfg.Out
	if out == nil {
		out = io.Discard
	}
	fsys, closeRepo, err := OpenRepo(cfg.Dir)
	if err != nil {
		return err
	}
	defer closeRepo()
	h, err := LoadHost(fsys, cfg.Host)
	if err != nil {
		return err
	}
	ref := cfg.Ref
	if ref == "" {
		ref = h.Ref
	}
	target := sshTarget(cfg.Target, h)
	fmt.Fprintf(out, "planning %s at %s on %s (ssh %s), changing nothing\n", cfg.Host, ref, cfg.Host, target)
	if err := cfg.Local.Interactive(ctx, "ssh", "-t", target, hostDiffScript(cfg.Host, ref)); err != nil {
		return fmt.Errorf("on %s: %w", target, err)
	}
	return nil
}

// hostDiffScript runs the dry run as root, through sudo (which may ask for
// the password on the terminal ssh -t gives it) unless ssh already logs in as
// root. --host is explicit, so a host whose hostname has drifted from its
// spec is still planned with the spec diff was asked for.
func hostDiffScript(host, ref string) string {
	return fmt.Sprintf(`if [ "$(id -u)" = 0 ]; then s=; else s=sudo; fi; exec $s %s pull --dry-run --ref %s --host %s`,
		shellQuote(HostBinary), shellQuote(ref), shellQuote(host))
}
