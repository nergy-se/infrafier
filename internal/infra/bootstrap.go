package infra

import (
	"archive/tar"
	"bytes"
	"context"
	"crypto/sha256"
	"debug/elf"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

// Bootstrap sets a host up for the pull loop, from the operator's machine. It
// replaces the manual steps: install the agent, put the operator's signing
// keys and a read-only deploy key on the host, clone the desired-state repo
// and run the first pull, which installs the timer. After that the host keeps
// itself up to date.
//
//	operator's machine                         host (ssh, then sudo once)
//	  checks: static binary, arch, ref exists
//	  deploy key: ssh-keygen, gh api (read-only)
//	  tar: infrafier, allowed_signers, key ──▶  temp dir
//	                                            infrafier bootstrap-host:
//	                                              /usr/local/bin/infrafier
//	                                              /etc/infrafier/{allowed_signers,known_hosts,deploy_key}
//	                                              clone /var/lib/infrafier/repo
//	                                              pull
//	  remove older deploy keys of this host
//
// It runs the operator's own ssh, so their ssh config, agent and known hosts
// apply, and asks for the sudo password once, on the host's terminal. The
// deploy key is made locally, in a temp dir removed afterwards: it only reads
// a repo the operator can already write, and making it here means the host
// needs no way to reach GitHub's API. Running it again is safe: it replaces
// the files, keeps the clone and the host's state, and leaves one deploy key.

// The paths on a host, as bootstrap sets them up and pull expects them.
const (
	HostBinary      = "/usr/local/bin/" + binaryName
	HostConfigDir   = "/etc/" + agentName
	HostStateDir    = "/var/lib/" + agentName
	HostRepo        = HostStateDir + "/repo"
	HostTextfileDir = "/var/lib/node_exporter/textfile"

	hostAllowedSigners = HostConfigDir + "/allowed_signers"
	hostKnownHosts     = HostConfigDir + "/known_hosts"
	hostDeployKey      = HostConfigDir + "/deploy_key"
	hostDeployKeyPub   = hostDeployKey + ".pub"
)

// githubKnownHosts is GitHub's ed25519 host key. It was checked against the
// fingerprint GitHub publishes (SHA256:+DiY3wvvV6TuJJhbpZisF/zLDA0zPMSvHdkr4UvCOqU),
// so a host's first fetch trusts no key it is handed on the wire.
const githubKnownHosts = "github.com ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl\n"

// hostSSHCommand is the clone's core.sshCommand: only the deploy key, only
// GitHub's pinned host key, and never a prompt.
const hostSSHCommand = "ssh -i " + hostDeployKey + " -o IdentitiesOnly=yes -o UserKnownHostsFile=" + hostKnownHosts +
	" -o StrictHostKeyChecking=yes -o BatchMode=yes -o ConnectTimeout=30"

// DefaultPullConfig is what pull runs with on a host bootstrap set up.
func DefaultPullConfig() PullConfig {
	return PullConfig{
		Repo:           HostRepo,
		Remote:         "origin",
		Main:           "main",
		StateDir:       HostStateDir,
		TextfileDir:    HostTextfileDir,
		GnupgHome:      HostConfigDir + "/gnupg",
		AllowedSigners: hostAllowedSigners,
		AgeIdentity:    HostAgeIdentity,
		System:         &OS{Root: "/"},
	}
}

type BootstrapConfig struct {
	// Dir is the operator's clone of the desired-state repo, for
	// hosts/<Host>.jsonnet (its ref and the agent it pins).
	Dir  string
	Host string
	// Target is the ssh destination; when empty, the host file's address,
	// else Host.
	Target     string
	GitHubRepo string // owner/name, for the deploy key
	RepoURL    string // what the host clones
	// AllowedSigners becomes the host's trust root; see OperatorAllowedSigners.
	AllowedSigners []byte
	// Binary is the agent to install.
	Binary string
	// DryRun makes the first pull print its plan without applying it, so the
	// timer is not installed yet; run bootstrap again without it to apply.
	DryRun bool
	Local  Local
	Out    io.Writer
}

// Local runs commands on the operator's machine. Run captures the output;
// Upload feeds stdin to the command; Interactive gives it the terminal (for
// ssh -t and sudo's password prompt).
type Local struct {
	Run         Runner
	Upload      func(ctx context.Context, stdin io.Reader, argv ...string) ([]byte, error)
	Interactive func(ctx context.Context, argv ...string) error
}

func ExecLocal() Local {
	return Local{
		Run: ExecRunner,
		Upload: func(ctx context.Context, stdin io.Reader, argv ...string) ([]byte, error) {
			cmd := exec.CommandContext(ctx, argv[0], argv[1:]...)
			var stdout bytes.Buffer
			cmd.Stdin, cmd.Stdout, cmd.Stderr = stdin, &stdout, os.Stderr
			if err := runCmd(cmd); err != nil {
				return nil, fmt.Errorf("%s: %w", strings.Join(argv, " "), err)
			}
			return stdout.Bytes(), nil
		},
		Interactive: func(ctx context.Context, argv ...string) error {
			cmd := exec.CommandContext(ctx, argv[0], argv[1:]...)
			cmd.Stdin, cmd.Stdout, cmd.Stderr = os.Stdin, os.Stdout, os.Stderr
			return runCmd(cmd)
		},
	}
}

// sshTarget is where bootstrap connects: flag (--ssh) when given, else the
// host file's address, else the host name.
func sshTarget(flag string, h *HostSpec) string {
	switch {
	case flag != "":
		return flag
	case h.Address != "":
		return h.Address
	}
	return h.Name
}

// GitHubRemote is the ssh URL a host clones over its deploy key, and the
// owner/name the key is added to, from the remote URL of the operator's
// clone (ssh or https). Bootstrap only knows GitHub's deploy keys.
func GitHubRemote(remote string) (sshURL, repo string, err error) {
	rest, ok := "", false
	for _, prefix := range []string{"git@github.com:", "ssh://git@github.com/", "https://github.com/"} {
		if rest, ok = strings.CutPrefix(remote, prefix); ok {
			break
		}
	}
	rest = strings.TrimSuffix(strings.TrimSuffix(rest, "/"), ".git")
	if owner, name, found := strings.Cut(rest, "/"); !ok || !found || owner == "" || name == "" || strings.Contains(name, "/") {
		return "", "", fmt.Errorf("%q is not a GitHub repository URL", remote)
	}
	return "git@github.com:" + rest + ".git", rest, nil
}

func deployKeyTitle(host string) string { return agentName + " pull (" + host + ")" }

func Bootstrap(ctx context.Context, cfg BootstrapConfig) error {
	out := cfg.Out
	if out == nil {
		out = io.Discard
	}
	run := cfg.Local.Run
	fsys, closeRepo, err := OpenRepo(cfg.Dir)
	if err != nil {
		return err
	}
	defer closeRepo()
	h, err := LoadHost(fsys, cfg.Host)
	if err != nil {
		return err
	}
	target := sshTarget(cfg.Target, h)
	if cfg.Target == "" && h.Address != "" {
		fmt.Fprintf(out, "ssh to %s at its address, %s\n", cfg.Host, target)
	}
	if err := checkAgentPin(fsys, h, cfg.Binary, out); err != nil {
		return err
	}

	arch, err := binaryArch(cfg.Binary)
	if err != nil {
		return err
	}
	if _, err := run(ctx, "gh", "api", "repos/"+cfg.GitHubRepo+"/git/ref/heads/"+h.Ref, "--jq", ".object.sha"); err != nil {
		return fmt.Errorf("%s follows %s, which %s does not have (create it, e.g. git push origin main:%s): %w", cfg.Host, h.Ref, cfg.GitHubRepo, h.Ref, err)
	}
	b, err := run(ctx, "ssh", target, "uname -m && hostname")
	if err != nil {
		return err
	}
	answer := strings.Fields(string(b))
	if len(answer) < 2 {
		return fmt.Errorf("unexpected answer from %s to uname -m && hostname: %q", target, b)
	}
	// The last two words, so a shell rc that prints something does not matter.
	hostArch, hostname := answer[len(answer)-2], answer[len(answer)-1]
	if hostArch != arch {
		return fmt.Errorf("%s is %s, but %s is built for %s", target, hostArch, cfg.Binary, arch)
	}
	// The first pull applies hosts/<Host>.jsonnet, but the timer's pull goes by
	// the short hostname, as `infrafier pull` without --host does.
	if short, _, _ := strings.Cut(hostname, "."); short != cfg.Host {
		return fmt.Errorf("%s calls itself %s, but you are bootstrapping it as %s: its timer would apply the host file of %s; set its hostname first (hostnamectl set-hostname %s)", target, short, cfg.Host, short, cfg.Host)
	}

	bin, err := os.ReadFile(cfg.Binary)
	if err != nil {
		return err
	}
	keyDir, err := os.MkdirTemp("", agentName+"-bootstrap-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(keyDir)
	key := filepath.Join(keyDir, "deploy_key")
	title := deployKeyTitle(cfg.Host)
	if _, err := run(ctx, "ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-C", title, "-f", key); err != nil {
		return err
	}
	priv, err := os.ReadFile(key)
	if err != nil {
		return err
	}
	pub, err := os.ReadFile(key + ".pub")
	if err != nil {
		return err
	}
	b, err = run(ctx, "gh", "api", "-X", "POST", "repos/"+cfg.GitHubRepo+"/keys",
		"-f", "title="+title, "-f", "key="+strings.TrimSpace(string(pub)), "-F", "read_only=true", "--jq", ".id")
	if err != nil {
		return fmt.Errorf("add the deploy key to %s: %w", cfg.GitHubRepo, err)
	}
	keyID := strings.TrimSpace(string(b))
	fmt.Fprintf(out, "added read-only deploy key %q (id %s) to %s\n", title, keyID, cfg.GitHubRepo)
	keyLeft := func(err error) error {
		return fmt.Errorf("%w (the deploy key %s stays on %s; the next bootstrap removes the older ones)", err, keyID, cfg.GitHubRepo)
	}

	var payload bytes.Buffer
	if err := writeTar(&payload, []tarFile{
		{binaryName, 0o755, bin},
		{"allowed_signers", 0o644, cfg.AllowedSigners},
		{"deploy_key", 0o600, priv},
		{"deploy_key.pub", 0o644, pub},
	}); err != nil {
		return err
	}
	// mktemp -d is 0700, so the key is readable only by the ssh user (and
	// root) until bootstrap-host has installed it and the dir is removed. In
	// the home directory, since /tmp may be mounted noexec. A failed tar
	// removes the dir itself; the answer is the line after a marker, so a
	// shell rc that prints something, or a $HOME with a space, does not matter.
	b, err = cfg.Local.Upload(ctx, &payload, "ssh", target, uploadScript)
	if err != nil {
		return keyLeft(err)
	}
	uid, dir, ok := parseUploadAnswer(b)
	if !ok {
		return keyLeft(fmt.Errorf("unexpected answer from %s: %q", target, b))
	}
	sudo := "sudo "
	if uid == "0" {
		sudo = ""
	}
	dryRun := ""
	if cfg.DryRun {
		dryRun = " --dry-run"
	}
	script := fmt.Sprintf("%s%s bootstrap-host --input %s --host %s --ref %s --repo-url %s%s; rc=$?; rm -rf %s; exit $rc",
		sudo, shellQuote(dir+"/"+binaryName), shellQuote(dir), shellQuote(cfg.Host), shellQuote(h.Ref), shellQuote(cfg.RepoURL), dryRun, shellQuote(dir))
	hostErr := cfg.Local.Interactive(ctx, "ssh", "-t", target, script)
	if hostErr != nil {
		// The script removes the dir itself, but not when ssh never got as
		// far as running it; it holds the private deploy key.
		if _, rmErr := run(ctx, "ssh", target, "rm -rf "+shellQuote(dir)); rmErr != nil {
			hostErr = fmt.Errorf("%w; %s on %s may still hold the deploy key, remove it", hostErr, dir, target)
		}
		hostErr = fmt.Errorf("on %s: %w", target, hostErr)
	}
	// The recipient note also after a failed host step: the likeliest
	// failure of a first pull is a secrets file not encrypted to the
	// identity the host just made, and the note is what fixes it. Not when
	// ssh itself failed (exit 255): another connection would only wait for
	// the same timeout.
	if sshFailed(hostErr) {
		return keyLeft(hostErr)
	}
	if b, err := run(ctx, "ssh", target, "cat "+hostAgeRecipient); err != nil {
		fmt.Fprintf(out, "warning: could not read %s's age recipient: %v\n", target, err)
	} else if lines := strings.Fields(string(b)); len(lines) > 0 {
		noteRecipient(out, cfg.Dir, cfg.Host, lines[len(lines)-1])
	}
	// But no pruning then: a host step that failed between writing the
	// new deploy_key and its .pub would have the stale .pub read back, and
	// the key it now fetches with removed from GitHub.
	if hostErr != nil {
		return keyLeft(hostErr)
	}
	if err := pruneDeployKeys(ctx, run, out, cfg.GitHubRepo, target, title, keyID); err != nil {
		return err
	}
	if cfg.DryRun {
		fmt.Fprintf(out, "%s has "+binaryName+", its keys and the clone, but nothing was applied and no timer runs; bootstrap it again without --dry-run to apply that plan\n", cfg.Host)
		return nil
	}
	fmt.Fprintf(out, "%s is bootstrapped and follows %s\n", cfg.Host, h.Ref)
	return nil
}

const uploadMarker = agentName + "-bootstrap"

const uploadScript = `d=$(mktemp -d "$HOME/.` + uploadMarker + `.XXXXXX") || exit 1
if ! tar -x -C "$d"; then rm -rf "$d"; exit 1; fi
printf '` + uploadMarker + ` %s %s\n' "$(id -u)" "$d"`

// parseUploadAnswer finds the marker line uploadScript prints: the ssh
// user's uid and the dir (which may have spaces) it extracted to.
func parseUploadAnswer(b []byte) (uid, dir string, ok bool) {
	lines := strings.Split(strings.TrimRight(string(b), "\n"), "\n")
	for i := len(lines) - 1; i >= 0; i-- {
		rest, found := strings.CutPrefix(lines[i], uploadMarker+" ")
		if !found {
			continue
		}
		uid, dir, ok = strings.Cut(rest, " ")
		return uid, dir, ok && uid != "" && dir != ""
	}
	return "", "", false
}

// keyBody is the type and key of an authorized_keys-style line, without the
// comment, as GitHub lists deploy keys.
func keyBody(line string) string {
	f := strings.Fields(line)
	if len(f) < 2 {
		return ""
	}
	return f[0] + " " + f[1]
}

// checkAgentPin warns when the host's modules pin an agent (a download to
// HostBinary) other than the binary bootstrap installs: the first pull then
// replaces it with the pinned one, which is fine when that is a release and
// this a build of your own, but a surprise otherwise.
func checkAgentPin(fsys fs.FS, h *HostSpec, binary string, out io.Writer) error {
	rs, err := Render(fsys, h, nil)
	if err != nil {
		return err
	}
	for _, r := range rs {
		d, ok := r.(*Download)
		if !ok || len(d.Files) != 1 || d.Files[0].Path != HostBinary {
			continue
		}
		sum, err := fileSHA256(binary)
		if err != nil {
			return err
		}
		if sum != d.SHA256 {
			fmt.Fprintf(out, "note: %s (sha256 %s) is not the agent %s pins (%s, sha256 %s); its first pull installs that one\n",
				binary, short(sum), h.Name, d.URL, short(d.SHA256))
		}
		return nil
	}
	fmt.Fprintf(out, "note: %s pins no agent (a download to %s), so nothing updates %s after bootstrap\n", h.Name, HostBinary, binaryName)
	return nil
}

func fileSHA256(p string) (string, error) {
	f, err := os.Open(p)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// binaryArch is what `uname -m` says on the hosts the binary runs on. A
// dynamically linked binary (a plain go build with cgo) is refused: it needs
// the operator's libc, which the host may not have.
func binaryArch(p string) (string, error) {
	f, err := elf.Open(p)
	if err != nil {
		return "", fmt.Errorf("%s: %w", p, err)
	}
	defer f.Close()
	for _, prog := range f.Progs {
		if prog.Type == elf.PT_INTERP {
			return "", fmt.Errorf("%s is linked dynamically; build a static one with CGO_ENABLED=0 go build", p)
		}
	}
	switch f.Machine {
	case elf.EM_X86_64:
		return "x86_64", nil
	case elf.EM_AARCH64:
		return "aarch64", nil
	}
	return "", fmt.Errorf("%s: unsupported architecture %s", p, f.Machine)
}

type tarFile struct {
	name    string
	mode    int64
	content []byte
}

func writeTar(w io.Writer, files []tarFile) error {
	tw := tar.NewWriter(w)
	for _, f := range files {
		if err := tw.WriteHeader(&tar.Header{Name: f.name, Mode: f.mode, Size: int64(len(f.content)), ModTime: time.Unix(0, 0), Typeflag: tar.TypeReg}); err != nil {
			return err
		}
		if _, err := tw.Write(f.content); err != nil {
			return err
		}
	}
	return tw.Close()
}

func shellQuote(s string) string { return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'" }

// OperatorAllowedSigners is an allowed_signers line for the operator's own
// git signing key (gpg.format ssh, user.signingkey, user.email), read in dir
// so a repo's own config counts.
//
// The key becomes the host's trust root, so it is read only from a file in
// the operator's ~/.ssh, symlinks resolved: a relative path, or one into a
// clone, would let a file a branch's author committed decide whose commits
// the host deploys. git itself would not notice such a file, since it only
// picks the private key by it; bootstrap reads the public key and trusts it.
// A key written in the config (key::) is refused too, so the rule has no
// exceptions; --allowed-signers is the explicit way to trust anything else.
func OperatorAllowedSigners(ctx context.Context, run Runner, dir string) ([]byte, error) {
	get := func(key string) (string, error) {
		b, err := run(ctx, "git", "-C", dir, "config", "--get", key)
		if err != nil {
			return "", fmt.Errorf("git config %s: %w", key, err)
		}
		return strings.TrimSpace(string(b)), nil
	}
	if format, _ := get("gpg.format"); format != "ssh" {
		return nil, fmt.Errorf("your commits are not signed with an SSH key (gpg.format is %q, not ssh); pass --allowed-signers", format)
	}
	signingKey, err := get("user.signingkey")
	if err != nil {
		return nil, err
	}
	email, err := get("user.email")
	if err != nil {
		return nil, err
	}
	p, err := sshDirFile(signingKey)
	if err != nil {
		return nil, err
	}
	b, err := os.ReadFile(p)
	if err == nil && !isPublicKey(string(b)) {
		// user.signingkey may name the private key; git reads its .pub.
		if p, err = sshDirFile(signingKey + ".pub"); err != nil {
			return nil, err
		}
		b, err = os.ReadFile(p)
	}
	if err != nil {
		return nil, fmt.Errorf("user.signingkey: %w", err)
	}
	pub, _, _ := strings.Cut(strings.TrimSpace(string(b)), "\n")
	if !isPublicKey(pub) {
		return nil, fmt.Errorf("user.signingkey %s is not an SSH public key", signingKey)
	}
	return fmt.Appendf(nil, "%s namespaces=\"git\" %s\n", email, pub), nil
}

// sshDirFile resolves user.signingkey to a file that, symlinks resolved, is
// in the operator's ~/.ssh (itself resolved, so a ~/.ssh kept in a dotfiles
// repo works).
func sshDirFile(signingKey string) (string, error) {
	refuse := func(why string) (string, error) {
		return "", fmt.Errorf("user.signingkey %s %s; the host trusts only a key file in ~/.ssh, so pass --allowed-signers to trust anything else", signingKey, why)
	}
	if strings.HasPrefix(signingKey, "key::") {
		return refuse("is a key written in git config")
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	p := signingKey
	if rest, ok := strings.CutPrefix(p, "~/"); ok {
		p = filepath.Join(home, rest)
	}
	if !filepath.IsAbs(p) {
		return refuse("is a relative path")
	}
	sshDir, err := filepath.EvalSymlinks(filepath.Join(home, ".ssh"))
	if err != nil {
		return "", err
	}
	real, err := filepath.EvalSymlinks(p)
	if err != nil {
		return "", fmt.Errorf("user.signingkey: %w", err)
	}
	if !strings.HasPrefix(real, sshDir+string(filepath.Separator)) {
		if real != p {
			return refuse("resolves to " + real + ", outside ~/.ssh")
		}
		return refuse("is outside ~/.ssh")
	}
	return real, nil
}

func isPublicKey(s string) bool {
	return strings.HasPrefix(s, "ssh-") || strings.HasPrefix(s, "ecdsa-") || strings.HasPrefix(s, "sk-")
}

// HostSetup is what `infrafier bootstrap-host` runs with, as root on the
// host, from the files Bootstrap uploaded to Input.
type HostSetup struct {
	Input   string
	Host    string
	Ref     string
	RepoURL string
	// DryRun makes the first pull print its plan without applying it.
	DryRun bool
	System System
	// Pull is Pull, replaced in tests.
	Pull func(context.Context, PullConfig) error
	Out  io.Writer
}

// BootstrapHost installs what Bootstrap uploaded and runs the first pull. It
// leaves owners as they are (empty), which for what it creates as root is
// root; the infra-agent module then keeps the directories as declared.
func BootstrapHost(ctx context.Context, s HostSetup) error {
	out := s.Out
	if out == nil {
		out = io.Discard
	}
	sys := s.System
	read := func(name string) ([]byte, error) { return os.ReadFile(filepath.Join(s.Input, name)) }
	bin, err := read(binaryName)
	if err != nil {
		return err
	}
	signers, err := read("allowed_signers")
	if err != nil {
		return err
	}
	key, err := read("deploy_key")
	if err != nil {
		return err
	}
	keyPub, err := read("deploy_key.pub")
	if err != nil {
		return err
	}

	if err := sys.WriteFile(HostBinary, bin, 0o755, "", ""); err != nil {
		return err
	}
	if err := sys.Mkdir(HostConfigDir, 0o755, "", ""); err != nil {
		return err
	}
	old, err := sys.Lstat(hostAllowedSigners)
	if err != nil {
		return err
	}
	if old.Exists && !bytes.Equal(old.Content, signers) {
		fmt.Fprintf(out, "replacing %s, which trusted:\n%s", hostAllowedSigners, old.Content)
	}
	fmt.Fprintf(out, "%s trusts:\n%s", hostAllowedSigners, signers)
	for _, f := range []struct {
		path    string
		content []byte
		mode    os.FileMode
	}{
		{hostAllowedSigners, signers, 0o644},
		{hostKnownHosts, []byte(githubKnownHosts), 0o644},
		{hostDeployKey, key, 0o600},
		{hostDeployKeyPub, keyPub, 0o644}, // for bootstrap's cleanup, read without sudo
	} {
		if err := sys.WriteFile(f.path, f.content, f.mode, "", ""); err != nil {
			return err
		}
	}

	// The recipient itself is printed by bootstrap, on the operator's
	// side, when the recipients file does not list it yet; here too would
	// be twice ~2000 characters.
	if err := ensureHostIdentity(sys, s.Host, out); err != nil {
		return err
	}
	fmt.Fprintf(out, "this host's age recipient is in %s\n", hostAgeRecipient)

	if _, err := sys.Run(ctx, "git", "--version"); err != nil {
		if exitedNonZero(err) {
			return err
		}
		fmt.Fprintln(out, "installing git")
		sys.Run(ctx, "env", "DEBIAN_FRONTEND=noninteractive", "apt-get", "update", "-q") // the install may work from the index it has
		if _, err := sys.Run(ctx, "env", "DEBIAN_FRONTEND=noninteractive", "apt-get", "install", "-y", "--no-install-recommends", "git"); err != nil {
			return err
		}
	}
	if err := sys.Mkdir(HostStateDir, 0o700, "", ""); err != nil {
		return err
	}
	st, err := sys.Lstat(HostRepo + "/.git")
	if err != nil {
		return err
	}
	if st.Exists {
		// A bootstrap again: keep the clone (and the state next to it, so
		// the rollback guard still holds), but use this key and URL.
		if _, err := sys.Run(ctx, "git", "-C", HostRepo, "remote", "set-url", "origin", s.RepoURL); err != nil {
			return err
		}
		if _, err := sys.Run(ctx, "git", "-C", HostRepo, "config", "core.sshCommand", hostSSHCommand); err != nil {
			return err
		}
	} else if _, err := sys.Run(ctx, "git", "clone", "--quiet", "--no-checkout", "--config", "core.sshCommand="+hostSSHCommand, s.RepoURL, HostRepo); err != nil {
		return err
	}

	cfg := DefaultPullConfig()
	cfg.Ref, cfg.Host, cfg.System, cfg.Out, cfg.DryRun = s.Ref, s.Host, sys, out, s.DryRun
	return s.Pull(ctx, cfg)
}

// ensureHostIdentity creates the host's age identity, which decrypts its
// secrets file, unless it has one: replacing it would lock the host out of a
// file encrypted to the old one. It is made here, on the host, so the private
// key never leaves it. The recipient goes next to it, readable without sudo,
// so the operator can read it back. An existing one is checked as pull checks
// it (hostIdentities); one others could read is made private again, with a
// warning that it may be known and should be replaced.
func ensureHostIdentity(sys System, host string, out io.Writer) error {
	st, err := sys.Lstat(HostAgeIdentity)
	if err != nil {
		return err
	}
	if !st.Exists {
		identity, rec, err := GenerateIdentity(agentName + " secrets of " + host + " (" + agentCommand + " bootstrap)")
		if err != nil {
			return err
		}
		if err := sys.WriteFile(HostAgeIdentity, identity, 0o600, "", ""); err != nil {
			return err
		}
		return sys.WriteFile(hostAgeRecipient, []byte(rec+"\n"), 0o644, "", "")
	}
	// Checked before the chmod below, so a file it refuses (another user's,
	// a symlink) is left as it was.
	if err := checkHostIdentity(HostAgeIdentity, st); err != nil {
		return err
	}
	if st.Mode.Perm()&0o077 != 0 {
		if err := sys.SetAttrs(HostAgeIdentity, 0o600, "", ""); err != nil {
			return err
		}
		fmt.Fprintf(out, "WARNING: %s was mode %04o, so others could read it; it is 0600 now, but the key may be known, and it decrypts %s in every commit of git history. Replace it (remove it, bootstrap %s again, put its new recipient in %s, "+agentCommand+" secrets rekey %s) and change every value in it at its source\n",
			HostAgeIdentity, st.Mode.Perm(), SecretsFile(host), host, RecipientsFile(host), host)
	}
	ids, err := hostIdentities(sys, HostAgeIdentity)
	if err != nil {
		return err
	}
	recs := identityRecipients(ids)
	if len(recs) != 1 {
		return fmt.Errorf("%s holds %d identities, want 1", HostAgeIdentity, len(recs))
	}
	return sys.WriteFile(hostAgeRecipient, []byte(recs[0]+"\n"), 0o644, "", "")
}

// noteRecipient tells the operator when the host's age recipient is not yet
// in its recipients file (in the operator's clone), so its secrets cannot be
// encrypted to it, or when that file can't be read. Either way it prints the
// recipient, which fixing the file takes.
func noteRecipient(out io.Writer, dir, host, recipient string) {
	b, err := os.ReadFile(filepath.Join(dir, RecipientsFile(host)))
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		fmt.Fprintf(out, "warning: %v\nthis host's age recipient, for %s:\n%s\n", err, RecipientsFile(host), recipient)
		return
	}
	if err == nil {
		entries, perr := parseRecipients(b)
		if perr != nil {
			fmt.Fprintf(out, "warning: %s (in %s): %v; fix it, list this host's age recipient in it, run "+agentCommand+" secrets rekey %s and merge; if this bootstrap's first pull failed, run bootstrap again after that:\n%s\n",
				RecipientsFile(host), dir, perr, host, recipient)
			return
		}
		if listsRecipient(entries, recipient) {
			return
		}
	}
	// A host whose first pull failed on its secrets has no pull timer yet,
	// so it would never fetch the fix by itself.
	fmt.Fprintf(out, "note: %s (in %s) does not list %s's age recipient yet. Before a module uses {{secret}}, add this line to it, run "+agentCommand+" secrets rekey %s and merge; if this bootstrap's first pull failed, run bootstrap again after that:\n%s\n",
		RecipientsFile(host), dir, host, host, recipient)
}

// pruneDeployKeys removes the host's older deploy keys from GitHub, keeping
// the one the host has installed.
func pruneDeployKeys(ctx context.Context, run Runner, out io.Writer, repo, target, title, keyID string) error {
	// Only now: the host may have used an older key until it got this one.
	// Only one operator bootstraps, so the host has our key installed; it is
	// read back rather than assumed, so a host step that did not install it
	// never costs the host the key it fetches with.
	b, err := run(ctx, "ssh", target, "cat "+hostDeployKeyPub)
	if err != nil {
		return fmt.Errorf("read the host's deploy key to remove older ones: %w", err)
	}
	installed := keyBody(string(b))
	b, err = run(ctx, "gh", "api", "--paginate", "repos/"+repo+"/keys", "--jq", `.[] | "\(.id) \(.key) \(.title)"`)
	if err != nil {
		return fmt.Errorf("list the deploy keys of %s to remove older ones: %w", repo, err)
	}
	type ghKey struct{ id, key string }
	var mine []ghKey
	kept := ""
	for _, line := range strings.Split(strings.TrimSpace(string(b)), "\n") {
		f := strings.SplitN(line, " ", 4) // id, key type, key, title
		if len(f) != 4 || f[3] != title {
			continue
		}
		k := ghKey{f[0], f[1] + " " + f[2]}
		if k.key == installed {
			kept = k.id
		}
		mine = append(mine, k)
	}
	if kept == "" {
		return fmt.Errorf("the deploy key installed on %s is not among %s's keys titled %q; not removing any", target, repo, title)
	}
	if kept != keyID {
		fmt.Fprintf(out, "note: %s has deploy key %s installed, not the new %s; keeping that one\n", target, kept, keyID)
	}
	for _, k := range mine {
		id := k.id
		if id == kept {
			continue
		}
		if _, err := run(ctx, "gh", "api", "-X", "DELETE", "repos/"+repo+"/keys/"+id); err != nil {
			return fmt.Errorf("remove the older deploy key %s: %w", id, err)
		}
		fmt.Fprintf(out, "removed the older deploy key %s\n", id)
	}
	return nil
}

// sshFailed tells whether err is ssh's own failure (exit 255: unreachable,
// refused, authentication), not the remote command's.
func sshFailed(err error) bool {
	code, ok := exitCode(err)
	return ok && code == 255
}
