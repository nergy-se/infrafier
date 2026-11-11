package main

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"syscall"
	"time"

	"github.com/nergy-se/infrafier/internal/infra"
	"github.com/urfave/cli/v2"
)

func commands() []*cli.Command {
	return []*cli.Command{
		{
			Name:  "diff",
			Usage: "Render every host and diff it against the golden files in rendered/, or plan one live host with --host",
			Description: `Run from the root of the desired-state repo. Exits non-zero when a host's
   rendered files differ from rendered/<host>; --update rewrites them.

   With --host <host> it shows what the next pull will change on that host
   instead: over your ssh (and sudo, which may ask for the password), the
   host's own agent fetches its ref, verifies it as a pull does and prints
   the plan against the live system, without applying anything or writing
   its state or metrics. --ref plans another branch, e.g. a PR's, the way the
   host would if it followed it (signed, and a descendant of what it runs).`,
			Flags: []cli.Flag{
				&cli.StringFlag{Name: "dir", Value: ".", Usage: "clone of the desired-state repo"},
				&cli.BoolFlag{Name: "update", Usage: "rewrite the golden files instead of diffing"},
				&cli.StringFlag{Name: "host", Usage: "plan this live host over ssh instead of diffing the golden files"},
				&cli.StringFlag{Name: "ref", Usage: "with --host: the branch to plan (default: the one the host follows)"},
				&cli.StringFlag{Name: "ssh", Usage: "with --host: ssh destination (default: the address in the host file, else the host name)"},
			},
			Action: infraDiff,
		},
		{
			Name:      "bootstrap",
			Usage:     "Set a host up for the pull loop over ssh: " + infra.BinaryName + ", the signing keys, a deploy key, the clone and a first pull",
			ArgsUsage: "<host>",
			Description: `Run from the root of the desired-state repo, with a static
   infrafier (a release, or CGO_ENABLED=0 go build). Uses your ssh (and asks
   for sudo on the host once) and gh (to add a read-only deploy key on the
   repo the clone's origin names). Safe to run again: it replaces the
   files, keeps the clone and the host's state, and leaves one deploy key.
   The host trusts the commit signers in --allowed-signers, by default your
   own git signing key, which must then be a file in ~/.ssh. With --dry-run
   it sets the host up but its first pull only prints the plan, so nothing
   is applied and no timer is installed until you run it again without.`,
			Flags: []cli.Flag{
				&cli.StringFlag{Name: "dir", Value: ".", Usage: "clone of the desired-state repo"},
				&cli.StringFlag{Name: "ssh", Usage: "ssh destination (default: the address in the host file, else the host name)"},
				&cli.StringFlag{Name: "allowed-signers", Usage: "allowed_signers file for the host (default: your git signing key, a file in ~/.ssh)"},
				&cli.StringFlag{Name: "github-repo", Usage: "owner/name the deploy key is added to (default: from the clone's origin)"},
				&cli.StringFlag{Name: "repo-url", Usage: "what the host clones, over ssh (default: the clone's origin, as git@github.com:owner/name.git)"},
				&cli.StringFlag{Name: "binary", Usage: infra.BinaryName + " to install (default: this one)"},
				&cli.BoolFlag{Name: "dry-run", Usage: "set the host up, but only print the first pull's plan"},
			},
			Action: infraBootstrap,
		},
		{
			Name:   "bootstrap-host",
			Usage:  "The host's half of bootstrap, run by it as root",
			Hidden: true,
			Flags: []cli.Flag{
				&cli.StringFlag{Name: "input", Required: true},
				&cli.StringFlag{Name: "host", Required: true},
				&cli.StringFlag{Name: "ref", Required: true},
				&cli.StringFlag{Name: "repo-url", Required: true},
				&cli.BoolFlag{Name: "dry-run"},
			},
			Action: func(c *cli.Context) error {
				return infra.BootstrapHost(c.Context, infra.HostSetup{
					Input:   c.String("input"),
					Host:    c.String("host"),
					Ref:     c.String("ref"),
					RepoURL: c.String("repo-url"),
					DryRun:  c.Bool("dry-run"),
					System:  &infra.OS{Root: "/"},
					Pull:    infra.Pull,
					Out:     os.Stdout,
				})
			},
		},
		{
			Name:  "pull",
			Usage: "Fetch this host's ref, verify its signature and apply it (run by " + infra.PullTimer + ")",
			Flags: []cli.Flag{
				&cli.StringFlag{Name: "ref", Usage: "branch this host follows", Required: true},
				&cli.StringFlag{Name: "main", Value: "main", Usage: "branch the ref is promoted from, fetched to report its lag"},
				&cli.StringFlag{Name: "host", Usage: "host spec to apply (default: the short hostname)"},
				&cli.StringFlag{Name: "repo", Value: infra.HostRepo, Usage: "clone of the desired-state repo"},
				&cli.StringFlag{Name: "remote", Value: "origin"},
				&cli.StringFlag{Name: "state-dir", Value: infra.HostStateDir},
				&cli.StringFlag{Name: "textfile-dir", Value: infra.HostTextfileDir, Usage: "node_exporter textfile collector directory, empty to skip metrics"},
				&cli.StringFlag{Name: "gnupghome", Value: infra.DefaultPullConfig().GnupgHome, Usage: "keyring of GPG keys allowed to sign"},
				&cli.StringFlag{Name: "allowed-signers", Value: infra.DefaultPullConfig().AllowedSigners, Usage: "SSH keys allowed to sign (gpg.ssh.allowedSignersFile)"},
				&cli.StringFlag{Name: "age-identity", Value: infra.HostAgeIdentity, Usage: "age identity that decrypts secrets/<host>.age"},
				&cli.BoolFlag{Name: "allow-rewind", Usage: "apply a commit that is not a descendant of the last applied one"},
				&cli.BoolFlag{Name: "dry-run", Usage: "print the plan without applying it"},
				&cli.BoolFlag{Name: "fallback", Usage: "this is the previous agent, run because the installed one exited " + fmt.Sprint(infra.CannotPlanExitCode) + ": apply the commit that run could not plan, without fetching"},
			},
			Action: infraPull,
		},
		{
			Name:   "check-plan",
			Usage:  "Render and plan the clone's checked-out commit for this host, writing nothing (a new agent's pre-install check)",
			Hidden: true,
			Flags: []cli.Flag{
				&cli.StringFlag{Name: "host", Usage: "host spec to plan (default: the short hostname)"},
				&cli.StringFlag{Name: "repo", Value: infra.HostRepo, Usage: "clone of the desired-state repo, with the commit to check checked out"},
				&cli.StringFlag{Name: "age-identity", Value: infra.HostAgeIdentity, Usage: "age identity that decrypts secrets/<host>.age"},
			},
			Action: func(c *cli.Context) error {
				host, err := hostFlag(c)
				if err != nil {
					return err
				}
				return infra.CheckPlan(c.Context, infra.PlanCheckConfig{
					Repo:        c.String("repo"),
					Host:        host,
					AgeIdentity: c.String("age-identity"),
					System:      &infra.OS{Root: "/"},
					Out:         os.Stdout,
				})
			},
		},
		secretsCommand(),
		versionCommand(),
	}
}

func secretsCommand() *cli.Command {
	identity := &cli.StringFlag{Name: "identity", Value: infra.DefaultOperatorIdentity(), Usage: "your age identity (env " + infra.OperatorIdentityEnv + ")"}
	dir := &cli.StringFlag{Name: "dir", Value: ".", Usage: "clone of the desired-state repo"}
	repo := func(c *cli.Context) (infra.SecretsRepo, string, error) {
		if c.NArg() != 1 {
			return infra.SecretsRepo{}, "", cli.Exit("usage: "+infra.AgentCommand+" secrets "+c.Command.Name+" <host>", 2)
		}
		return infra.SecretsRepo{Dir: c.String("dir"), Identity: c.String("identity")}, c.Args().First(), nil
	}
	return &cli.Command{
		Name:  "secrets",
		Usage: "Edit the age-encrypted host secrets in secrets/<host>.age",
		Description: `secrets/<host>.age is a YAML map of names to values, encrypted to the
   recipients in secrets/<host>.recipients: the host's age identity (made by
   bootstrap, which prints it) and the operators'. A template of a file with
   secret: true reads one as {{secret "name"}}.`,
		Subcommands: []*cli.Command{
			{
				Name:  "keygen",
				Usage: "Create your age identity and print its recipient, for the recipients files",
				Flags: []cli.Flag{identity},
				Action: func(c *cli.Context) error {
					p := c.String("identity")
					rec, err := infra.Keygen(p, infra.AgentName+" operator identity ("+infra.AgentCommand+" secrets keygen)")
					if err != nil {
						return err
					}
					fmt.Printf("wrote %s; your recipient:\n%s\n", p, rec)
					return nil
				},
			},
			{
				Name:      "edit",
				Usage:     "Decrypt a host's secrets into vim or nvim ($VISUAL or $EDITOR) and encrypt them again",
				ArgsUsage: "<host>",
				Flags:     []cli.Flag{dir, identity},
				Action: func(c *cli.Context) error {
					r, host, err := repo(c)
					if err != nil {
						return err
					}
					// Resolved (and probed) before any plaintext exists.
					edit, err := editorCommand()
					if err != nil {
						return err
					}
					return r.EditSecrets(host, edit, askYes, os.Stdout)
				},
			},
			{
				Name:      "rekey",
				Usage:     "Encrypt a host's secrets again to its recipients file, after changing it",
				ArgsUsage: "<host>",
				Flags:     []cli.Flag{dir, identity},
				Action: func(c *cli.Context) error {
					r, host, err := repo(c)
					if err != nil {
						return err
					}
					lines, err := r.Rekey(host)
					if err != nil {
						return err
					}
					fmt.Printf("wrote %s, encrypted to:\n  %s\n%s\n", infra.SecretsFile(host), strings.Join(lines, "\n  "), infra.SecretsNextStep(host))
					fmt.Println("note: this changes who can decrypt it from now on. git history keeps the earlier files, which a removed recipient still decrypts: if one was removed because its key may be known, change the values too")
					return nil
				},
			},
		},
	}
}

// editorCommand resolves the editor once, before EditSecrets writes the
// plaintext copy, and returns what runs it on that copy. Only vim and nvim:
// infrafier can keep their swap, undo and backup files from holding the
// plaintext, and knows they wait until the file is closed. Any other editor
// is refused, rather than run with a note: one that returns at once (gvim,
// neovide, code without --wait) loses what is typed, since edit sees no
// change and removes the file the editor still has open.
func editorCommand() (func(p string) error, error) {
	editor := os.Getenv("VISUAL")
	if editor == "" {
		editor = os.Getenv("EDITOR")
	}
	if editor == "" {
		editor = "vi"
	}
	words := editorWords(editor)
	if len(words) == 0 {
		return nil, fmt.Errorf("editor %q (VISUAL or EDITOR): cannot find the program it runs; give vim or nvim, with its path or arguments only (no VAR=value or wrapper before it)", editor)
	}
	name := filepath.Base(words[0])
	// vim picks its GUI by its own name (on Debian, vim and gvim are one
	// vim.gtk3), or by -g.
	if guiVims[name] || slices.Contains(words[1:], "-g") {
		return nil, fmt.Errorf("editor %q: a GUI vim is not supported, it returns before you are done; use vim or nvim in the terminal", editor)
	}
	if !isVim(words[0]) {
		return nil, fmt.Errorf("editor %q: secrets edit runs vim or nvim only (VISUAL or EDITOR), whose swap, undo and backup files it can keep from holding the plaintext", editor)
	}
	// vim and nvim keep swap, undo and backup files, nvim in ~/.local/state,
	// outside the temp dir that is removed; those would keep the plaintext.
	// -c runs after the user's vimrc/init.lua, which may turn them on
	// (LazyVim sets undofile), and before any write; but a VimEnter or
	// VeryLazy callback runs after -c and may turn them on again, so their
	// dirs are the file's own too, the temp dir that is removed.
	// silent!: vim.tiny (Debian's vi) has no persistent undo and would stop
	// at E518 on noundofile, skipping the rest of the line too.
	editor += ` -n -i NONE -c 'silent! setlocal noundofile' -c 'silent! setlocal noswapfile' -c 'silent! set nobackup nowritebackup'` +
		` -c 'silent! let &undodir = expand("%:p:h")' -c 'silent! let &backupdir = expand("%:p:h")' -c 'silent! let &directory = expand("%:p:h")'`
	return func(p string) error {
		// Through sh, so EDITOR may carry arguments and ~ or $HOME.
		cmd := exec.Command("sh", "-c", editor+` "$1"`, "sh", p)
		cmd.Stdin, cmd.Stdout, cmd.Stderr = os.Stdin, os.Stdout, os.Stderr
		return cmd.Run()
	}, nil
}

// guiVims are the names a vim takes to start its GUI.
var guiVims = map[string]bool{"gvim": true, "gview": true, "gvimdiff": true, "rgvim": true, "rgview": true, "evim": true, "eview": true}

// editorWords splits the editor command as sh will run it, ~, $HOME and
// quotes expanded, with the program's path first (nil when sh finds none):
// EDITOR='~/bin/nvim' must still be known for a vim. A timeout, since the
// command is the operator's own and might hang.
func editorWords(editor string) []string {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, "sh", "-c", `eval "set -- $1" && p=$(command -v "$1") && shift && printf '%s\0' "$p" "$@"`, "sh", editor).Output()
	if err != nil || len(out) == 0 {
		return nil
	}
	return strings.Split(strings.TrimSuffix(string(out), "\x00"), "\x00")
}

// isVim tells whether the editor at p is vim or nvim. By name first,
// symlinks resolved (Debian's vi is vim.basic or vim.tiny through
// alternatives); otherwise by what --version says, since a vim may have any
// name: Fedora's vi is vim-minimal, and lvim or a wrapper script (Arch's vi)
// run vim too. A vi that is busybox's or nvi says nothing of the kind, and
// is refused: it takes none of vim's flags.
func isVim(name string) bool {
	p, err := exec.LookPath(name)
	if err != nil {
		return false
	}
	if real, err := filepath.EvalSymlinks(p); err == nil {
		p = real
	}
	base := filepath.Base(p)
	if base == "nvim" || base == "vim" || strings.HasPrefix(base, "vim.") {
		return true
	}
	// No terminal and a timeout, so an editor that ignores --version and
	// opens cannot hang the command; in an empty dir that is removed, so
	// one that takes --version for a file name leaves nothing in the clone.
	dir, err := os.MkdirTemp("", infra.AgentName+"-editor-")
	if err != nil {
		return false
	}
	defer os.RemoveAll(dir)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, p, "--version")
	cmd.Dir = dir
	// A wrapper may leave a child holding stdout, which the context's kill
	// of the wrapper alone would not end: kill its whole process group, and
	// stop waiting for the pipe soon after.
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.Cancel = func() error { return syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL) }
	cmd.WaitDelay = time.Second
	out, _ := cmd.Output()
	return isVimVersion(out)
}

func isVimVersion(out []byte) bool {
	first, _, _ := strings.Cut(string(out), "\n")
	return strings.HasPrefix(first, "VIM - Vi IMproved") || strings.HasPrefix(first, "NVIM ")
}

func askYes(prompt string) bool { return ask(stdinLines, os.Stdout, prompt, true) }

func infraDiff(c *cli.Context) error {
	dir := c.String("dir")
	if host := c.String("host"); host != "" {
		if c.Bool("update") {
			return cli.Exit("--update rewrites the golden files; it does not go with --host", 2)
		}
		return infra.HostDiff(c.Context, infra.HostDiffConfig{
			Dir:    dir,
			Host:   host,
			Target: c.String("ssh"),
			Ref:    c.String("ref"),
			Local:  infra.ExecLocal(),
			Out:    os.Stdout,
		})
	}
	if c.IsSet("ref") || c.IsSet("ssh") {
		return cli.Exit("--ref and --ssh go with --host", 2)
	}
	fsys, closeRepo, err := infra.OpenRepo(dir)
	if err != nil {
		return err
	}
	defer closeRepo()
	hosts, err := infra.Hosts(fsys)
	if err != nil {
		return err
	}
	if len(hosts) == 0 {
		return fmt.Errorf("no hosts in %s/hosts", dir)
	}
	differs := false
	rendered := filepath.Join(dir, "rendered")
	stale, err := infra.StaleGolden(rendered, hosts)
	if err != nil {
		return err
	}
	for _, name := range stale {
		if c.Bool("update") {
			if err := os.RemoveAll(filepath.Join(rendered, name)); err != nil {
				return err
			}
			continue
		}
		differs = true
		fmt.Printf("%s: rendered/%s has no hosts/%s.jsonnet; --update removes it\n", name, name, name)
	}
	for _, name := range hosts {
		h, err := infra.LoadHost(fsys, name)
		if err != nil {
			return err
		}
		// Without secrets: diff and CI see placeholders, never values.
		rs, err := infra.Render(fsys, h, nil)
		if err != nil {
			return fmt.Errorf("%s: %w", name, err)
		}
		secretsLine, err := infra.SecretsLine(fsys, name)
		if err != nil {
			return err
		}
		golden := filepath.Join(dir, "rendered", name)
		if c.Bool("update") {
			if err := infra.WriteGolden(golden, rs, secretsLine); err != nil {
				return err
			}
			continue
		}
		diffs, actions, err := infra.GoldenDiff(golden, rs, secretsLine)
		if err != nil {
			return err
		}
		if len(diffs) == 0 {
			fmt.Printf("%s: no changes\n", name)
			continue
		}
		differs = true
		fmt.Printf("%s:\n%s", name, strings.Join(diffs, ""))
		for _, a := range actions {
			fmt.Printf("%s: then %s\n", name, a)
		}
	}
	if differs {
		return cli.Exit("rendered files differ from "+filepath.Join(dir, "rendered")+"; run "+infra.AgentCommand+" diff --update and commit the result", 1)
	}
	return nil
}

func infraBootstrap(c *cli.Context) error {
	if c.NArg() != 1 {
		return cli.Exit("usage: "+infra.AgentCommand+" bootstrap <host>", 2)
	}
	dir := c.String("dir")
	binary := c.String("binary")
	if binary == "" {
		var err error
		if binary, err = os.Executable(); err != nil {
			return err
		}
	}
	var signers []byte
	var err error
	if p := c.String("allowed-signers"); p != "" {
		signers, err = os.ReadFile(p)
	} else {
		signers, err = infra.OperatorAllowedSigners(c.Context, infra.ExecRunner, dir)
	}
	if err != nil {
		return err
	}
	repoURL, githubRepo := c.String("repo-url"), c.String("github-repo")
	if repoURL == "" || githubRepo == "" {
		origin, err := infra.ExecRunner(c.Context, "git", "-C", dir, "remote", "get-url", "origin")
		if err != nil {
			return fmt.Errorf("--repo-url and --github-repo default to the origin of %s: %w", dir, err)
		}
		u, r, err := infra.GitHubRemote(strings.TrimSpace(string(origin)))
		if err != nil {
			return fmt.Errorf("%w; give --repo-url and --github-repo", err)
		}
		if repoURL == "" {
			repoURL = u
		}
		if githubRepo == "" {
			githubRepo = r
		}
	}
	return infra.Bootstrap(c.Context, infra.BootstrapConfig{
		Dir:            dir,
		Host:           c.Args().First(),
		Target:         c.String("ssh"),
		GitHubRepo:     githubRepo,
		RepoURL:        repoURL,
		AllowedSigners: signers,
		Binary:         binary,
		DryRun:         c.Bool("dry-run"),
		Local:          infra.ExecLocal(),
		Out:            os.Stdout,
	})
}

// hostFlag is --host, by default the short hostname.
func hostFlag(c *cli.Context) (string, error) {
	if host := c.String("host"); host != "" {
		return host, nil
	}
	h, err := os.Hostname()
	if err != nil {
		return "", err
	}
	host, _, _ := strings.Cut(h, ".")
	return host, nil
}

func infraPull(c *cli.Context) error {
	host, err := hostFlag(c)
	if err != nil {
		return err
	}
	return pullExit(os.Stdout, infra.Pull(c.Context, infra.PullConfig{
		Repo:           c.String("repo"),
		Remote:         c.String("remote"),
		Ref:            c.String("ref"),
		Main:           c.String("main"),
		Host:           host,
		StateDir:       c.String("state-dir"),
		TextfileDir:    c.String("textfile-dir"),
		GnupgHome:      c.String("gnupghome"),
		AllowedSigners: c.String("allowed-signers"),
		AgeIdentity:    c.String("age-identity"),
		AllowRewind:    c.Bool("allow-rewind"),
		DryRun:         c.Bool("dry-run"),
		Fallback:       c.Bool("fallback"),
		System:         &infra.OS{Root: "/"},
		Out:            os.Stdout,
	}))
}

// pullExit makes a run that finds another one holding the lock a skipped
// run (exit 0), so the timer's unit does not fail (see
// infra.ErrPullRunning), and one that could not plan the commit exit
// infra.CannotPlanExitCode, for the pull unit's fallback.
func pullExit(out io.Writer, err error) error {
	switch {
	case errors.Is(err, infra.ErrPullRunning):
		fmt.Fprintf(out, "skipped: %v\n", err)
		return nil
	case errors.Is(err, infra.ErrCannotPlan):
		return cli.Exit(err.Error(), infra.CannotPlanExitCode)
	}
	return err
}

// stdinLines reads whole answer lines from stdin, one reader for every
// prompt, so nothing typed is left for whatever reads stdin next (secrets
// edit restarts the editor after a prompt).
var stdinLines = bufio.NewReader(os.Stdin)

// ask asks a yes/no question with a default, and asks again on an answer it
// does not know: secrets edit discards what was typed on a no, so a typo
// must not count as one. End of input (no terminal) is a no, or a loop that
// asks again would never end. Questions on stdin read from stdinLines.
func ask(r *bufio.Reader, out io.Writer, prompt string, def bool) bool {
	choices := "[y/N]"
	if def {
		choices = "[Y/n]"
	}
	for {
		fmt.Fprintf(out, "%s %s ", prompt, choices)
		line, err := r.ReadString('\n')
		switch strings.ToLower(strings.TrimSpace(line)) {
		case "y", "yes", "j", "ja":
			return true
		case "n", "no", "nej":
			return false
		case "":
			if err != nil {
				fmt.Fprintln(out)
				return false
			}
			return def
		}
		if err != nil {
			fmt.Fprintln(out)
			return false
		}
		fmt.Fprintln(out, "answer y or n")
	}
}
