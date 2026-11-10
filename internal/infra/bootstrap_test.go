package infra

import (
	"archive/tar"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"testing/fstest"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestBootstrapHostInstallsClonesAndPulls(t *testing.T) {
	sys, run := newTestSystem(t)
	input := t.TempDir()
	for name, content := range map[string]string{"infrafier": "binary", "allowed_signers": "me namespaces=\"git\" ssh-ed25519 AAA\n", "deploy_key": "private", "deploy_key.pub": "ssh-ed25519 KEY h\n"} {
		require.NoError(t, os.WriteFile(filepath.Join(input, name), []byte(content), 0o600))
	}
	var pulled PullConfig
	s := HostSetup{Input: input, Host: "h", Ref: "infra/h", RepoURL: "git@github.com:o/infra.git", System: sys,
		Pull: func(_ context.Context, cfg PullConfig) error { pulled = cfg; return nil }}

	require.NoError(t, BootstrapHost(context.Background(), s))
	assert.Equal(t, "binary", readRoot(t, sys, HostBinary))
	assert.Equal(t, githubKnownHosts, readRoot(t, sys, hostKnownHosts))
	for p, mode := range map[string]os.FileMode{HostBinary: 0o755, hostAllowedSigners: 0o644, hostDeployKey: 0o600, hostDeployKeyPub: 0o644, HostStateDir: 0o700} {
		fi, err := os.Stat(filepath.Join(sys.Root, p))
		require.NoError(t, err)
		assert.Equal(t, mode, fi.Mode().Perm(), p)
	}
	assert.Equal(t, []string{
		"git --version",
		"git clone --quiet --no-checkout --config core.sshCommand=" + hostSSHCommand + " git@github.com:o/infra.git " + HostRepo,
	}, run.calls)
	assert.Equal(t, "infra/h", pulled.Ref)
	assert.Equal(t, "h", pulled.Host)
	assert.Equal(t, HostRepo, pulled.Repo)
	assert.Equal(t, hostAllowedSigners, pulled.AllowedSigners)
	assert.False(t, pulled.DryRun)
	assert.Contains(t, hostSSHCommand, "StrictHostKeyChecking=yes")

	// Again, with a clone in place and other signers: the clone is kept and
	// pointed at the new key, and the replaced trust root is shown.
	require.NoError(t, os.MkdirAll(filepath.Join(sys.Root, HostRepo, ".git"), 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(input, "allowed_signers"), []byte("new namespaces=\"git\" ssh-ed25519 BBB\n"), 0o600))
	run.calls = nil
	var out strings.Builder
	s.Out = &out
	require.NoError(t, BootstrapHost(context.Background(), s))
	assert.Equal(t, []string{
		"git --version",
		"git -C " + HostRepo + " remote set-url origin git@github.com:o/infra.git",
		"git -C " + HostRepo + " config core.sshCommand " + hostSSHCommand,
	}, run.calls)
	assert.Contains(t, out.String(), "replacing "+hostAllowedSigners+", which trusted:\nme namespaces")
}

func TestBootstrapHostInstallsGitWhenMissing(t *testing.T) {
	sys, run := newTestSystem(t)
	run.broken["git --version"] = true
	input := t.TempDir()
	for _, name := range []string{"infrafier", "allowed_signers", "deploy_key", "deploy_key.pub"} {
		require.NoError(t, os.WriteFile(filepath.Join(input, name), []byte("x"), 0o600))
	}
	err := BootstrapHost(context.Background(), HostSetup{Input: input, Host: "h", Ref: "main", RepoURL: "u", System: sys,
		Pull: func(context.Context, PullConfig) error { return nil }})
	require.NoError(t, err)
	assert.Contains(t, run.calls, "env DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends git")
}

// fakeLocal plays the operator's machine: gh and ssh are faked, ssh-keygen
// runs for real so the key files exist.
type fakeLocal struct {
	calls []string
	// keys is what listing the deploy keys prints, given the new key ("type
	// key") that was uploaded; installed what the host has, the new key when
	// empty.
	keys      func(newKey string) string
	installed string
	uid       string
	upload    map[string]tarEntry
	script    string
	fail      map[string]error
	hostArch  string
	// hostname is what the host calls itself, "h.example" when empty;
	// noise is what its shell rc prints before any answer.
	hostname    string
	noise       string
	interactErr error
	// recipient is what the host's age-recipient holds.
	recipient string
}

type tarEntry struct {
	mode    int64
	content string
}

func (f *fakeLocal) local() Local {
	return Local{
		Run: func(ctx context.Context, argv ...string) ([]byte, error) {
			cmd := strings.Join(argv, " ")
			f.calls = append(f.calls, cmd)
			for prefix, err := range f.fail {
				if strings.HasPrefix(cmd, prefix) {
					return nil, err
				}
			}
			switch {
			case argv[0] == "ssh-keygen":
				return ExecRunner(ctx, argv...)
			case cmd == "ssh h.example uname -m && hostname":
				hostname := f.hostname
				if hostname == "" {
					hostname = "h.example"
				}
				return []byte(f.noise + f.hostArch + "\n" + hostname + "\n"), nil
			case cmd == "ssh h.example cat "+hostAgeRecipient:
				return []byte(f.recipient + "\n"), nil
			case strings.HasPrefix(cmd, "gh api -X POST"):
				return []byte("9\n"), nil
			case cmd == "ssh h.example cat "+hostDeployKeyPub:
				if f.installed != "" {
					return []byte(f.installed + " other\n"), nil
				}
				return []byte(f.upload["deploy_key.pub"].content), nil
			case strings.HasPrefix(cmd, "gh api --paginate"):
				if f.keys == nil {
					return []byte("9 " + keyBody(f.upload["deploy_key.pub"].content) + " infrafier pull (h)\n"), nil
				}
				return []byte(f.keys(keyBody(f.upload["deploy_key.pub"].content))), nil
			}
			return nil, nil
		},
		Upload: func(_ context.Context, stdin io.Reader, argv ...string) ([]byte, error) {
			f.calls = append(f.calls, "upload "+strings.Join(argv[:2], " "))
			f.upload = map[string]tarEntry{}
			tr := tar.NewReader(stdin)
			for {
				h, err := tr.Next()
				if errors.Is(err, io.EOF) {
					break
				}
				if err != nil {
					return nil, err
				}
				b, err := io.ReadAll(tr)
				if err != nil {
					return nil, err
				}
				f.upload[h.Name] = tarEntry{h.Mode, string(b)}
			}
			return []byte(f.noise + "infrafier-bootstrap " + f.uid + " /tmp/tmp.abc\n"), nil
		},
		Interactive: func(_ context.Context, argv ...string) error {
			f.calls = append(f.calls, "interactive "+strings.Join(argv[:3], " "))
			f.script = argv[3]
			return f.interactErr
		},
	}
}

// staticBinary builds a static agent stand-in for the host's arch.
func staticBinary(t *testing.T) string {
	t.Helper()
	if _, err := exec.LookPath("go"); err != nil {
		t.Skip("go not installed")
	}
	if _, err := exec.LookPath("ssh-keygen"); err != nil {
		t.Skip("ssh-keygen not installed")
	}
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "main.go"), []byte("package main\nfunc main() {}\n"), 0o644))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "go.mod"), []byte("module stub\ngo 1.21\n"), 0o644))
	bin := filepath.Join(dir, "infrafier")
	cmd := exec.Command("go", "build", "-o", bin, ".")
	cmd.Dir = dir
	cmd.Env = append(os.Environ(), "CGO_ENABLED=0", "GOOS=linux", "GOARCH=amd64", "GOFLAGS=")
	out, err := cmd.CombinedOutput()
	require.NoError(t, err, string(out))
	return bin
}

func bootstrapInfraDir(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	require.NoError(t, os.MkdirAll(filepath.Join(dir, "hosts"), 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "hosts/h.jsonnet"), []byte(`{ ref: 'infra/h', modules: [] }`), 0o644))
	return dir
}

func TestBootstrapSSHTarget(t *testing.T) {
	assert.Equal(t, "h", sshTarget("", &HostSpec{Name: "h"}))
	assert.Equal(t, "192.0.2.1", sshTarget("", &HostSpec{Name: "h", Address: "192.0.2.1"}))
	assert.Equal(t, "h.example", sshTarget("h.example", &HostSpec{Name: "h", Address: "192.0.2.1"}), "--ssh wins")
}

func TestBootstrapUploadsRunsAndKeepsOneDeployKey(t *testing.T) {
	bin := staticBinary(t)
	f := &fakeLocal{uid: "1000", hostArch: "x86_64", keys: func(newKey string) string {
		return "5 ssh-ed25519 OLD infrafier pull (h)\n7 ssh-ed25519 OTHER infrafier pull (other)\n9 " + newKey + " infrafier pull (h)\n"
	}}
	var out strings.Builder
	err := Bootstrap(context.Background(), BootstrapConfig{
		Dir: bootstrapInfraDir(t), Host: "h", Target: "h.example", GitHubRepo: "o/infra", RepoURL: "git@github.com:o/infra.git",
		AllowedSigners: []byte("me namespaces=\"git\" ssh-ed25519 AAA\n"), Binary: bin,
		Local: f.local(), Out: &out,
	})
	require.NoError(t, err)

	assert.Contains(t, out.String(), "note: h pins no agent (a download to /usr/local/bin/infrafier), so nothing updates infrafier after bootstrap")
	assert.Equal(t, "gh api repos/o/infra/git/ref/heads/infra/h --jq .object.sha", f.calls[0])
	assert.Contains(t, f.calls, "upload ssh h.example")
	assert.Contains(t, f.calls, "interactive ssh -t h.example")
	assert.Contains(t, f.calls, "gh api -X DELETE repos/o/infra/keys/5")
	assert.NotContains(t, f.calls, "gh api -X DELETE repos/o/infra/keys/7", "another host's key")
	assert.NotContains(t, f.calls, "gh api -X DELETE repos/o/infra/keys/9", "the new key")
	var added string
	for _, c := range f.calls {
		if strings.HasPrefix(c, "gh api -X POST") {
			added = c
		}
	}
	assert.Contains(t, added, "-f title=infrafier pull (h) -f key=ssh-ed25519 ")
	assert.Contains(t, added, "-F read_only=true")

	assert.Equal(t, int64(0o755), f.upload["infrafier"].mode)
	assert.Equal(t, "me namespaces=\"git\" ssh-ed25519 AAA\n", f.upload["allowed_signers"].content)
	assert.Equal(t, int64(0o600), f.upload["deploy_key"].mode)
	assert.Contains(t, f.upload["deploy_key"].content, "PRIVATE KEY")
	assert.Equal(t, int64(0o644), f.upload["deploy_key.pub"].mode)
	assert.Equal(t, "sudo '/tmp/tmp.abc/infrafier' bootstrap-host --input '/tmp/tmp.abc' --host 'h' --ref 'infra/h' --repo-url 'git@github.com:o/infra.git'; rc=$?; rm -rf '/tmp/tmp.abc'; exit $rc", f.script)
}

// The key kept is the one the host has installed, read back rather than
// assumed, even when it is not the one this bootstrap added.
func TestBootstrapKeepsTheKeyTheHostHasInstalled(t *testing.T) {
	bin := staticBinary(t)
	f := &fakeLocal{uid: "1000", hostArch: "x86_64", installed: "ssh-ed25519 THEIRS", keys: func(newKey string) string {
		return "9 " + newKey + " infrafier pull (h)\n11 ssh-ed25519 THEIRS infrafier pull (h)\n"
	}}
	var out strings.Builder
	err := Bootstrap(context.Background(), BootstrapConfig{Dir: bootstrapInfraDir(t), Host: "h", Target: "h.example", GitHubRepo: "o/infra",
		RepoURL: "u", Binary: bin, Local: f.local(), Out: &out})
	require.NoError(t, err)
	assert.Contains(t, f.calls, "gh api -X DELETE repos/o/infra/keys/9")
	assert.NotContains(t, f.calls, "gh api -X DELETE repos/o/infra/keys/11")
	assert.Contains(t, out.String(), "has deploy key 11 installed, not the new 9; keeping that one")

	// A key GitHub doesn't list: remove nothing rather than guess.
	f = &fakeLocal{uid: "1000", hostArch: "x86_64", installed: "ssh-ed25519 UNKNOWN"}
	err = Bootstrap(context.Background(), BootstrapConfig{Dir: bootstrapInfraDir(t), Host: "h", Target: "h.example", GitHubRepo: "o/infra",
		RepoURL: "u", Binary: bin, Local: f.local()})
	require.ErrorContains(t, err, "not removing any")
	for _, c := range f.calls {
		assert.False(t, strings.HasPrefix(c, "gh api -X DELETE"), c)
	}
}

func TestBootstrapDryRunOnlyPlansTheFirstPull(t *testing.T) {
	bin := staticBinary(t)
	f := &fakeLocal{uid: "1000", hostArch: "x86_64"}
	var out strings.Builder
	err := Bootstrap(context.Background(), BootstrapConfig{Dir: bootstrapInfraDir(t), Host: "h", Target: "h.example", GitHubRepo: "o/infra",
		RepoURL: "u", Binary: bin, DryRun: true, Local: f.local(), Out: &out})
	require.NoError(t, err)
	assert.Contains(t, f.script, " --repo-url 'u' --dry-run; rc=$?")
	assert.Contains(t, out.String(), "nothing was applied and no timer runs")
	assert.NotContains(t, out.String(), "is bootstrapped")

	sys, _ := newTestSystem(t)
	input := t.TempDir()
	for name, content := range map[string]string{"infrafier": "binary", "allowed_signers": "me namespaces=\"git\" ssh-ed25519 AAA\n", "deploy_key": "private", "deploy_key.pub": "ssh-ed25519 KEY h\n"} {
		require.NoError(t, os.WriteFile(filepath.Join(input, name), []byte(content), 0o600))
	}
	var pulled PullConfig
	require.NoError(t, BootstrapHost(context.Background(), HostSetup{Input: input, Host: "h", Ref: "infra/h", RepoURL: "u", DryRun: true, System: sys,
		Pull: func(_ context.Context, cfg PullConfig) error { pulled = cfg; return nil }}))
	assert.True(t, pulled.DryRun)
}

func TestBootstrapAsRootRunsWithoutSudo(t *testing.T) {
	bin := staticBinary(t)
	f := &fakeLocal{uid: "0", hostArch: "x86_64"}
	err := Bootstrap(context.Background(), BootstrapConfig{Dir: bootstrapInfraDir(t), Host: "h", Target: "h.example", GitHubRepo: "o/infra",
		RepoURL: "u", Binary: bin, Local: f.local()})
	require.NoError(t, err)
	assert.True(t, strings.HasPrefix(f.script, "'/tmp/tmp.abc/infrafier' bootstrap-host"), f.script)
}

func TestBootstrapRefusesBeforeTouchingAnything(t *testing.T) {
	bin := staticBinary(t)
	cases := map[string]struct {
		f    *fakeLocal
		bin  string
		want string
	}{
		"missing ref": {f: &fakeLocal{hostArch: "x86_64", fail: map[string]error{"gh api repos/o/infra/git/ref/": fmt.Errorf("HTTP 404")}},
			want: "h follows infra/h, which o/infra does not have (create it, e.g. git push origin main:infra/h)"},
		"other arch":     {f: &fakeLocal{hostArch: "aarch64"}, want: "h.example is aarch64, but " + bin + " is built for x86_64"},
		"not a binary":   {f: &fakeLocal{hostArch: "x86_64"}, bin: "/etc/hostname", want: "/etc/hostname"},
		"dynamic binary": {f: &fakeLocal{hostArch: "x86_64"}, bin: dynamicBinary(t), want: "linked dynamically"},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			b := bin
			if tc.bin != "" {
				b = tc.bin
			}
			err := Bootstrap(context.Background(), BootstrapConfig{Dir: bootstrapInfraDir(t), Host: "h", Target: "h.example", GitHubRepo: "o/infra",
				RepoURL: "u", Binary: b, Local: tc.f.local()})
			require.ErrorContains(t, err, tc.want)
			for _, c := range tc.f.calls {
				assert.False(t, strings.HasPrefix(c, "gh api -X") || strings.HasPrefix(c, "upload"), "changed something: %s", c)
			}
		})
	}
}

// dynamicBinary is any dynamically linked ELF on this machine.
func dynamicBinary(t *testing.T) string {
	for _, p := range []string{"/bin/sh", "/usr/bin/env"} {
		if _, err := binaryArch(p); err != nil && strings.Contains(err.Error(), "linked dynamically") {
			return p
		}
	}
	t.Skip("no dynamically linked binary found")
	return ""
}

func TestOperatorAllowedSigners(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	sshDir := filepath.Join(home, ".ssh")
	require.NoError(t, os.MkdirAll(sshDir, 0o700))
	priv := filepath.Join(sshDir, "signing")
	require.NoError(t, os.WriteFile(priv, []byte("-----BEGIN OPENSSH PRIVATE KEY-----\n"), 0o600))
	require.NoError(t, os.WriteFile(priv+".pub", []byte("ssh-ed25519 AAAA me@host\n"), 0o644))
	// A clone with a key a branch's author committed.
	clone := filepath.Join(home, "git", "infra")
	require.NoError(t, os.MkdirAll(filepath.Join(clone, "keys"), 0o755))
	planted := filepath.Join(clone, "keys", "signing.pub")
	require.NoError(t, os.WriteFile(planted, []byte("ssh-ed25519 ATTACKER x\n"), 0o644))

	config := map[string]string{"gpg.format": "ssh", "user.email": "me@example.com"}
	run := func(_ context.Context, argv ...string) ([]byte, error) {
		v, ok := config[argv[len(argv)-1]]
		if !ok {
			return nil, exitErr(1)
		}
		return []byte(v + "\n"), nil
	}
	signers := func(key string) (string, error) {
		config["user.signingkey"] = key
		b, err := OperatorAllowedSigners(context.Background(), run, clone)
		return string(b), err
	}
	want := "me@example.com namespaces=\"git\" ssh-ed25519 AAAA me@host\n"

	for _, key := range []string{priv + ".pub", priv, "~/.ssh/signing.pub"} {
		got, err := signers(key)
		require.NoError(t, err, key)
		assert.Equal(t, want, got, key)
	}

	link := filepath.Join(sshDir, "linked.pub")
	require.NoError(t, os.Symlink(planted, link))
	for key, why := range map[string]string{
		"keys/signing.pub":                     "is a relative path",
		planted:                                "is outside ~/.ssh",
		link:                                   "resolves to " + planted + ", outside ~/.ssh",
		"key::ssh-ed25519 BBBB":                "is a key written in git config",
		"~/git/infra/keys/../keys/signing.pub": "outside ~/.ssh",
	} {
		_, err := signers(key)
		require.ErrorContains(t, err, why, key)
		require.ErrorContains(t, err, "pass --allowed-signers", key)
	}

	// A private key in ~/.ssh whose .pub is a link out of it.
	require.NoError(t, os.WriteFile(filepath.Join(sshDir, "other"), []byte("-----BEGIN OPENSSH PRIVATE KEY-----\n"), 0o600))
	require.NoError(t, os.Symlink(planted, filepath.Join(sshDir, "other.pub")))
	_, err := signers(filepath.Join(sshDir, "other"))
	require.ErrorContains(t, err, "outside ~/.ssh")

	// ~/.ssh kept in a dotfiles repo, as a symlink: still the operator's.
	home2 := t.TempDir()
	t.Setenv("HOME", home2)
	require.NoError(t, os.Symlink(sshDir, filepath.Join(home2, ".ssh")))
	got, err := signers("~/.ssh/signing.pub")
	require.NoError(t, err)
	assert.Equal(t, want, got)

	config["gpg.format"] = "openpgp"
	_, err = signers(priv)
	require.ErrorContains(t, err, "pass --allowed-signers")
}

func TestBootstrapRefusesAHostWhoseHostnameDiffers(t *testing.T) {
	bin := staticBinary(t)
	f := &fakeLocal{uid: "1000", hostArch: "x86_64", hostname: "debian"}
	err := Bootstrap(context.Background(), BootstrapConfig{Dir: bootstrapInfraDir(t), Host: "h", Target: "h.example", GitHubRepo: "o/infra",
		RepoURL: "u", Binary: bin, Local: f.local()})
	require.ErrorContains(t, err, "calls itself debian, but you are bootstrapping it as h")
	for _, c := range f.calls {
		assert.False(t, strings.HasPrefix(c, "gh api -X POST"), "no deploy key added: %s", c)
	}
}

func TestBootstrapIgnoresWhatTheShellRcPrints(t *testing.T) {
	bin := staticBinary(t)
	f := &fakeLocal{uid: "1000", hostArch: "x86_64", noise: "Welcome to h!\ninfrafier-bootstrap is not this\n"}
	err := Bootstrap(context.Background(), BootstrapConfig{Dir: bootstrapInfraDir(t), Host: "h", Target: "h.example", GitHubRepo: "o/infra",
		RepoURL: "u", Binary: bin, Local: f.local()})
	require.NoError(t, err)
	assert.True(t, strings.HasPrefix(f.script, "sudo '/tmp/tmp.abc/infrafier' bootstrap-host"), f.script)
}

func TestBootstrapRemovesTheUploadWhenTheHostStepNeverRan(t *testing.T) {
	bin := staticBinary(t)
	f := &fakeLocal{uid: "1000", hostArch: "x86_64", interactErr: errors.New("connection reset")}
	err := Bootstrap(context.Background(), BootstrapConfig{Dir: bootstrapInfraDir(t), Host: "h", Target: "h.example", GitHubRepo: "o/infra",
		RepoURL: "u", Binary: bin, Local: f.local()})
	require.ErrorContains(t, err, "connection reset")
	assert.Contains(t, f.calls, "ssh h.example rm -rf '/tmp/tmp.abc'")

	f = &fakeLocal{uid: "1000", hostArch: "x86_64", interactErr: errors.New("connection reset"),
		fail: map[string]error{"ssh h.example rm": errors.New("unreachable")}}
	err = Bootstrap(context.Background(), BootstrapConfig{Dir: bootstrapInfraDir(t), Host: "h", Target: "h.example", GitHubRepo: "o/infra",
		RepoURL: "u", Binary: bin, Local: f.local()})
	require.ErrorContains(t, err, "/tmp/tmp.abc on h.example may still hold the deploy key")
}

func TestParseUploadAnswer(t *testing.T) {
	uid, dir, ok := parseUploadAnswer([]byte("motd\ninfrafier-bootstrap 1000 /home/a b/.infrafier-bootstrap.x\n"))
	assert.True(t, ok)
	assert.Equal(t, "1000", uid)
	assert.Equal(t, "/home/a b/.infrafier-bootstrap.x", dir)
	for _, b := range []string{"", "/tmp/x\n1000\n", "infrafier-bootstrap 1000\n", "infrafier-bootstrap  /tmp/x\n"} {
		_, _, ok := parseUploadAnswer([]byte(b))
		assert.False(t, ok, "%q", b)
	}
}

// A first pull that fails (here: secrets not encrypted to the identity the
// host just made) still says what to do, but removes no deploy key: the
// host step may have failed between writing the new key and its .pub.
func TestBootstrapAfterAFailedFirstPullNotesTheRecipientButKeepsTheKeys(t *testing.T) {
	bin := staticBinary(t)
	f := &fakeLocal{uid: "1000", hostArch: "x86_64", interactErr: errors.New("exit status 1"), recipient: "age1pq1hostkey",
		keys: func(newKey string) string {
			return "5 ssh-ed25519 OLD infrafier pull (h)\n9 " + newKey + " infrafier pull (h)\n"
		}}
	var out strings.Builder
	err := Bootstrap(context.Background(), BootstrapConfig{Dir: bootstrapInfraDir(t), Host: "h", Target: "h.example", GitHubRepo: "o/infra",
		RepoURL: "u", Binary: bin, Local: f.local(), Out: &out})
	require.ErrorContains(t, err, "on h.example: exit status 1")
	assert.Contains(t, err.Error(), "the next bootstrap removes the older ones")
	for _, c := range f.calls {
		assert.False(t, strings.HasPrefix(c, "gh api -X DELETE"), c)
	}
	assert.Contains(t, out.String(), "does not list h's age recipient yet")
	assert.Contains(t, out.String(), "run bootstrap again after that")
	assert.Contains(t, out.String(), "\nage1pq1hostkey\n")
}

// ssh's own failure (exit 255): no second connection for the recipient.
func TestBootstrapDoesNotConnectAgainWhenSSHFailed(t *testing.T) {
	bin := staticBinary(t)
	f := &fakeLocal{uid: "1000", hostArch: "x86_64", interactErr: exitErr(255)}
	err := Bootstrap(context.Background(), BootstrapConfig{Dir: bootstrapInfraDir(t), Host: "h", Target: "h.example", GitHubRepo: "o/infra",
		RepoURL: "u", Binary: bin, Local: f.local()})
	require.Error(t, err)
	assert.NotContains(t, f.calls, "ssh h.example cat "+hostAgeRecipient)
}

// Bootstrap says when the binary it installs is not the agent the host pins,
// which its first pull then installs.
func TestCheckAgentPin(t *testing.T) {
	bin := filepath.Join(t.TempDir(), "agent")
	require.NoError(t, os.WriteFile(bin, []byte("agent"), 0o755))
	module := func(pin string) fstest.MapFS {
		return fstest.MapFS{"modules/m/module.jsonnet": {Data: []byte(`{ resources: [{ download: {
  url: 'https://example.com/agent', sha256: '` + pin + `', path: '` + HostBinary + `' } }] }`)}}
	}
	h := &HostSpec{Name: "h", Modules: []string{"m"}, Vars: map[string]any{}}
	var out strings.Builder
	require.NoError(t, checkAgentPin(module(sum([]byte("agent"))), h, bin, &out))
	assert.Empty(t, out.String())
	require.NoError(t, checkAgentPin(module(sum([]byte("release"))), h, bin, &out))
	assert.Contains(t, out.String(), "is not the agent h pins (https://example.com/agent, sha256 "+sum([]byte("release"))[:12]+"); its first pull installs that one")
}
