package infra

import (
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/signal"
	"os/user"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"testing/fstest"
	"time"

	"filippo.io/age"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const secretModule = `{ resources: [
  { file: { path: '/etc/traefik/cf-dns-token', template: 'token', secret: true } },
  { file: { path: '/etc/plain', content: 'plain\n' } },
] }`

func TestRenderSecretFileGetsValuesAndGoldenGetsPlaceholders(t *testing.T) {
	fsys := testFS(secretModule, map[string]string{"modules/m/token": "CF_DNS_API_TOKEN={{secret \"cf_dns_token\"}}\n"})
	h, err := LoadHost(fsys, "h")
	require.NoError(t, err)

	// Without secrets (diff, CI): placeholders in the golden file.
	rs, err := Render(fsys, h, nil)
	require.NoError(t, err)
	tree := GoldenTree(rs, "")
	assert.Equal(t, "CF_DNS_API_TOKEN=<secret:cf_dns_token>\n", string(tree["etc/traefik/cf-dns-token"]))

	// On the host: the values, and no golden render. A golden tree built
	// from it anyway has a fixed marker, never a digest of the value.
	rs, err = Render(fsys, h, Secrets{"cf_dns_token": "s3cr3t"})
	require.NoError(t, err)
	f := rs[0].(*File)
	assert.Equal(t, "CF_DNS_API_TOKEN=s3cr3t\n", string(f.Content))
	assert.False(t, f.Placeholders)
	assert.True(t, f.UsesSecrets)
	assert.Equal(t, os.FileMode(0o600), f.Mode)
	hostTree := GoldenTree(rs, "")
	assert.NotContains(t, string(hostTree["etc/traefik/cf-dns-token"]), "sha256")
	for p, b := range hostTree {
		assert.NotContains(t, string(b), "s3cr3t", p)
	}
}

// A template that works with the values but not with a placeholder does
// not fail the host: no placeholder render there.
func TestRenderOnTheHostNeedsNoPlaceholderRender(t *testing.T) {
	fsys := testFS(`{ resources: [{ file: { path: '/etc/x', template: 'x', secret: true } }] }`, map[string]string{"modules/m/x": `{{slice (secret "pw") 0 16}}`})
	h, err := LoadHost(fsys, "h")
	require.NoError(t, err)
	rs, err := Render(fsys, h, Secrets{"pw": "0123456789abcdefXYZ"})
	require.NoError(t, err)
	assert.Equal(t, "0123456789abcdef", string(rs[0].(*File).Content))
}

// CI renders without secrets, but still refuses a name no secrets file can
// hold, and one computed from another secret.
func TestRenderWithoutSecretsChecksNames(t *testing.T) {
	for tmpl, want := range map[string]string{
		`{{secret "db password"}}`: "a secret name has",
		`{{secret (secret "pw")}}`: "a secret name has",
	} {
		fsys := testFS(`{ resources: [{ file: { path: '/etc/x', template: 'x', secret: true } }] }`, map[string]string{"modules/m/x": tmpl})
		h, err := LoadHost(fsys, "h")
		require.NoError(t, err)
		_, err = Render(fsys, h, nil)
		assert.ErrorContains(t, err, want, tmpl)
	}
}

func TestRenderSecretsOnlyInSecretFiles(t *testing.T) {
	cases := map[string]struct {
		module string
		extra  map[string]string
		want   string
	}{
		"file without secret: true": {
			module: `{ resources: [{ file: { path: '/etc/x', template: 'x' } }] }`,
			extra:  map[string]string{"modules/m/x": `{{secret "pw"}}`},
			want:   "a file without secret: true",
		},
		"world-readable": {
			module: `{ resources: [{ file: { path: '/etc/x', template: 'x', secret: true, mode: '0644' } }] }`,
			extra:  map[string]string{"modules/m/x": `{{secret "pw"}}`},
			want:   "lets every user read",
		},
		"the map itself": {
			module: `{ resources: [{ file: { path: '/etc/x', template: 'x' } }] }`,
			extra:  map[string]string{"modules/m/x": `{{.secrets}}`},
			want:   "secrets",
		},
		"missing secret": {
			module: `{ resources: [{ file: { path: '/etc/x', template: 'x', secret: true } }] }`,
			extra:  map[string]string{"modules/m/x": `{{secret "nope"}}`},
			want:   `no secret "nope"`,
		},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			fsys := testFS(tc.module, tc.extra)
			h, err := LoadHost(fsys, "h")
			require.NoError(t, err)
			_, err = Render(fsys, h, Secrets{"pw": "hunter2"})
			require.Error(t, err)
			assert.Contains(t, err.Error(), tc.want)
			assert.NotContains(t, err.Error(), "hunter2")
		})
	}
	// Nothing a template can reach holds them, in any kind of file.
	for _, tmpl := range []string{`{{printf "%v" .}}`, `{{printf "%#v" .}}`, `{{printf "%+v" .Host}}`, `{{.}}`} {
		for _, secret := range []string{"false", "true"} {
			fsys := testFS(fmt.Sprintf(`{ resources: [{ file: { path: '/etc/x', template: 'x', secret: %s } }, { file: { path: '/etc/y', content: %q } }] }`, secret, tmpl),
				map[string]string{"modules/m/x": tmpl})
			h, err := LoadHost(fsys, "h")
			require.NoError(t, err)
			rs, err := Render(fsys, h, Secrets{"pw": "hunter2"})
			require.NoError(t, err)
			for _, r := range rs {
				assert.NotContains(t, string(r.(*File).Content), "hunter2", tmpl)
			}
		}
	}
	// Nor does what a module.jsonnet gets: its host argument, all of it.
	fsys0 := testFS(`function(host) { resources: [{ command: { name: 'x', check: ['true'], run: [std.toString(host)] } }] }`, nil)
	h0, err := LoadHost(fsys0, "h")
	require.NoError(t, err)
	rs0, err := Render(fsys0, h0, Secrets{"pw": "hunter2"})
	require.NoError(t, err)
	assert.Contains(t, rs0[0].(*Command).Run[0], `"ref": "main"`)
	assert.NotContains(t, rs0[0].(*Command).Run[0], "hunter2")

	// A group-readable secret file is fine: a service may need it.
	fsys := testFS(`{ resources: [{ file: { path: '/etc/x', template: 'x', secret: true, mode: '0640', group: 'traefik' } }] }`, map[string]string{"modules/m/x": `{{secret "pw"}}`})
	h, err := LoadHost(fsys, "h")
	require.NoError(t, err)
	_, err = Render(fsys, h, Secrets{"pw": "hunter2"})
	require.NoError(t, err)
}

func TestParseSecretsNeverQuotesTheInput(t *testing.T) {
	s, err := ParseSecrets([]byte("# c\na: \"1\"\nb.c-d_e: two\n"))
	require.NoError(t, err)
	assert.Equal(t, Secrets{"a": "1", "b.c-d_e": "two"}, s)

	s, err = ParseSecrets(nil)
	require.NoError(t, err)
	assert.Empty(t, s)

	s, err = ParseSecrets([]byte("# only a comment\n"))
	require.NoError(t, err)
	assert.Empty(t, s)
	s, err = ParseSecrets([]byte("pem: |\n  line1\n  line2\nmode: \"0755\"\n"))
	require.NoError(t, err)
	assert.Equal(t, Secrets{"pem": "line1\nline2\n", "mode": "0755"}, s)

	for _, in := range []string{"pw: [hunter2\n", "pw: 12345\n", "pw: true\n", "pw: {x: hunter2}\n", "pw: a\npw: hunter2\n",
		"\"bad hunter2\": x\n", "- hunter2\n", "a: &x hunter2\nb: *x\n", "pw: !!binary aHVudGVyMg==\n", "hunter2\n",
		"a: \"x\"\n---\nhunter2: \"y\"\n", "!hunter2 pw: \"x\"\n", "!<tag:hunter2> pw: \"x\"\n", "pw: !hunter2 \"x\"\n"} {
		_, err := ParseSecrets([]byte(in))
		require.Error(t, err, in)
		assert.NotContains(t, err.Error(), "hunter2", in)
		assert.NotContains(t, err.Error(), "12345", in)
	}
}

// writeIdentity writes a fresh identity to p and returns its recipient.
func writeIdentity(t *testing.T, p string) string {
	t.Helper()
	id, rec, err := GenerateIdentity("test")
	require.NoError(t, err)
	require.NoError(t, os.MkdirAll(filepath.Dir(p), 0o700))
	require.NoError(t, os.WriteFile(p, id, 0o600))
	return rec
}

func encryptTo(t *testing.T, plain string, recipients ...string) []byte {
	t.Helper()
	entries, err := parseRecipients([]byte(strings.Join(recipients, "\n")))
	require.NoError(t, err)
	b, err := EncryptSecrets([]byte(plain), recipientsOf(entries))
	require.NoError(t, err)
	return b
}

func TestLoadHostSecrets(t *testing.T) {
	sys, _ := newTestSystem(t)
	idPath := HostAgeIdentity
	rec := writeIdentity(t, filepath.Join(sys.Root, idPath))
	other := writeIdentity(t, filepath.Join(t.TempDir(), "other"))

	fsys := testFS(`{ resources: [] }`, nil)
	s, err := LoadHostSecrets(fsys, "h", sys, idPath)
	require.NoError(t, err, "no secrets file, no secrets")
	assert.Empty(t, s)

	fsys[SecretsFile("h")] = mapFile(encryptTo(t, "pw: hunter2\n", rec, other))
	s, err = LoadHostSecrets(fsys, "h", sys, idPath)
	require.NoError(t, err)
	assert.Equal(t, Secrets{"pw": "hunter2"}, s)

	fsys[SecretsFile("h")] = mapFile(encryptTo(t, "pw: hunter2\n", other))
	_, err = LoadHostSecrets(fsys, "h", sys, idPath)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not encrypted to this host's age identity; add its recipient ("+rec+")")

	fsys[SecretsFile("h")] = mapFile(encryptTo(t, "pw: [hunter2\n", rec))
	_, err = LoadHostSecrets(fsys, "h", sys, idPath)
	require.Error(t, err)
	assert.NotContains(t, err.Error(), "hunter2")

	require.NoError(t, os.Chmod(filepath.Join(sys.Root, idPath), 0o644))
	_, err = LoadHostSecrets(fsys, "h", sys, idPath)
	assert.ErrorContains(t, err, "readable by its owner only")

	require.NoError(t, os.Remove(filepath.Join(sys.Root, idPath)))
	_, err = LoadHostSecrets(fsys, "h", sys, idPath)
	assert.ErrorContains(t, err, "no age identity")

	// A symlink is not followed, e.g. to a key another user controls.
	require.NoError(t, os.Symlink("/elsewhere", filepath.Join(sys.Root, idPath)))
	_, err = LoadHostSecrets(fsys, "h", sys, idPath)
	assert.ErrorContains(t, err, "not a regular file")
}

func TestEnsureHostIdentityKeepsAnExistingOne(t *testing.T) {
	sys, _ := newTestSystem(t)
	require.NoError(t, ensureHostIdentity(sys, "h", io.Discard))
	rec := strings.TrimSpace(readRoot(t, sys, hostAgeRecipient))
	assert.True(t, strings.HasPrefix(rec, "age1pq1"), "post-quantum hybrid")
	fi, err := os.Stat(filepath.Join(sys.Root, HostAgeIdentity))
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0o600), fi.Mode().Perm())

	// A bootstrap again keeps it (and tightens a loosened mode).
	require.NoError(t, os.Chmod(filepath.Join(sys.Root, HostAgeIdentity), 0o644))
	require.NoError(t, os.Remove(filepath.Join(sys.Root, hostAgeRecipient)))
	var warn strings.Builder
	err = ensureHostIdentity(sys, "h", &warn)
	assert.Contains(t, warn.String(), "WARNING: "+HostAgeIdentity+" was mode 0644")
	assert.Contains(t, warn.String(), "infrafier secrets rekey h) and change every value in it at its source\n")
	require.NoError(t, err)
	assert.Equal(t, rec+"\n", readRoot(t, sys, hostAgeRecipient), "the same identity, its recipient written again")
	fi, err = os.Stat(filepath.Join(sys.Root, HostAgeIdentity))
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0o600), fi.Mode().Perm())
}

type secretsFixture struct {
	repo  SecretsRepo
	me    string // the operator's recipient
	hostP string // the host's identity
	host  string // its recipient
}

func newSecretsFixture(t *testing.T) *secretsFixture {
	t.Helper()
	dir := t.TempDir()
	require.NoError(t, os.MkdirAll(filepath.Join(dir, "hosts"), 0o755))
	require.NoError(t, os.MkdirAll(filepath.Join(dir, "secrets"), 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "hosts/h.jsonnet"), []byte(`{ ref: 'main', modules: [] }`), 0o644))
	f := &secretsFixture{repo: SecretsRepo{Dir: dir, Identity: filepath.Join(t.TempDir(), "me")}, hostP: filepath.Join(t.TempDir(), "host")}
	f.me = writeIdentity(t, f.repo.Identity)
	f.host = writeIdentity(t, f.hostP)
	f.recipients(t, "# the operator\n"+f.me+"\n# h\n"+f.host+"\n")
	return f
}

func (f *secretsFixture) recipients(t *testing.T, content string) {
	t.Helper()
	require.NoError(t, os.WriteFile(filepath.Join(f.repo.Dir, RecipientsFile("h")), []byte(content), 0o644))
}

func (f *secretsFixture) hostReads(t *testing.T) (Secrets, error) {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(f.repo.Dir, SecretsFile("h")))
	require.NoError(t, err)
	ids, err := ReadIdentities(f.hostP)
	require.NoError(t, err)
	s, err := DecryptSecrets(b, ids)
	return s, err
}

func TestEditSecretsCreatesEditsAndRemovesThePlaintext(t *testing.T) {
	f := newSecretsFixture(t)
	if _, err := plaintextDir(); err != nil {
		t.Skip(err)
	}
	var tmp string
	editor := func(content string) func(string) error {
		return func(p string) error {
			tmp = p
			fi, err := os.Stat(filepath.Dir(p))
			require.NoError(t, err)
			assert.Equal(t, os.FileMode(0o700), fi.Mode().Perm())
			assert.True(t, isTmpfs(filepath.Dir(p)), "the plaintext is on a tmpfs")
			old, err := os.ReadFile(p)
			require.NoError(t, err)
			return os.WriteFile(p, append(old, content...), 0o600)
		}
	}
	never := func(string) bool { t.Fatal("asked"); return false }

	var out strings.Builder
	require.NoError(t, f.repo.EditSecrets("h", editor("cf_dns_token: \"tok-7f3a9c1e5b2d\"\n"), never, &out))
	assert.Contains(t, out.String(), "encrypted to:\n  "+shortRecipient(f.me)+" (the operator) [you]\n  "+shortRecipient(f.host)+" (h)\n")
	s, err := f.hostReads(t)
	require.NoError(t, err)
	assert.Equal(t, Secrets{"cf_dns_token": "tok-7f3a9c1e5b2d"}, s)
	assert.NoDirExists(t, filepath.Dir(tmp), "the plaintext is removed")
	b, err := os.ReadFile(filepath.Join(f.repo.Dir, SecretsFile("h")))
	require.NoError(t, err)
	assert.NotContains(t, string(b), "tok-7f3a9c1e5b2d")

	// Unchanged: the file is left as it was (no churn in git).
	out.Reset()
	require.NoError(t, f.repo.EditSecrets("h", func(string) error { return nil }, never, &out))
	assert.Contains(t, out.String(), "no changes")
	b2, _ := os.ReadFile(filepath.Join(f.repo.Dir, SecretsFile("h")))
	assert.Equal(t, b, b2)

	// Invalid, then given up: nothing written.
	asked := 0
	err = f.repo.EditSecrets("h", editor("pw: 123\n"), func(string) bool { asked++; return false }, &out)
	assert.ErrorContains(t, err, "nothing saved")
	assert.Equal(t, 1, asked)
	b2, _ = os.ReadFile(filepath.Join(f.repo.Dir, SecretsFile("h")))
	assert.Equal(t, b, b2)
	assert.NoDirExists(t, filepath.Dir(tmp))

	// A new host's file is not created by just looking at it.
	require.NoError(t, os.WriteFile(filepath.Join(f.repo.Dir, "hosts/new.jsonnet"), []byte(`{ ref: 'main', modules: [] }`), 0o644))
	require.NoError(t, os.WriteFile(filepath.Join(f.repo.Dir, RecipientsFile("new")), []byte(f.me+"\n"), 0o644))
	out.Reset()
	require.NoError(t, f.repo.EditSecrets("new", func(string) error { return nil }, never, &out))
	assert.Contains(t, out.String(), "not created")
	assert.NoFileExists(t, filepath.Join(f.repo.Dir, SecretsFile("new")))

	// A failing editor saves nothing.
	err = f.repo.EditSecrets("h", func(string) error { return errors.New("exit 1") }, never, &out)
	assert.ErrorContains(t, err, "nothing saved")
}

func TestSecretsRefuseWhatTheOperatorCouldNotDecrypt(t *testing.T) {
	f := newSecretsFixture(t)
	f.recipients(t, f.host+"\n")
	_, err := encryptIn(f.repo, "h", []byte("pw: x\n"))
	assert.ErrorContains(t, err, "does not list your age identity")
	err = f.repo.EditSecrets("h", func(string) error { t.Fatal("editor ran"); return nil }, nil, &strings.Builder{})
	assert.ErrorContains(t, err, "does not list your age identity")

	_, err = encryptIn(f.repo, "nope", []byte("pw: x\n"))
	assert.Error(t, err, "a host without hosts/<host>.jsonnet")
}

func TestRekeyAddsAReinstalledHost(t *testing.T) {
	f := newSecretsFixture(t)
	_, err := encryptIn(f.repo, "h", []byte("pw: x\n"))
	require.NoError(t, err)

	// The host is reinstalled: a new identity, which the file isn't for.
	f.host = writeIdentity(t, f.hostP+"2")
	f.hostP += "2"
	_, err = f.hostReads(t)
	var noMatch *age.NoIdentityMatchError
	require.ErrorAs(t, err, &noMatch)

	f.recipients(t, f.me+"\n"+f.host+"\n")
	lines, err := f.repo.Rekey("h")
	require.NoError(t, err)
	assert.Equal(t, []string{shortRecipient(f.me) + " [you]", shortRecipient(f.host)}, lines)
	s, err := f.hostReads(t)
	require.NoError(t, err)
	assert.Equal(t, Secrets{"pw": "x"}, s)
}

func TestSecretsRefuseMixingClassicAndPostQuantumRecipients(t *testing.T) {
	f := newSecretsFixture(t)
	classic, err := age.GenerateX25519Identity()
	require.NoError(t, err)
	f.recipients(t, f.me+"\n"+f.host+"\n"+classic.Recipient().String()+"\n")
	_, err = encryptIn(f.repo, "h", []byte("pw: x\n"))
	assert.Error(t, err)
}

func TestKeygenNeverOverwrites(t *testing.T) {
	p := filepath.Join(t.TempDir(), "sub", "id")
	rec, err := Keygen(p, "me")
	require.NoError(t, err)
	ids, err := ReadIdentities(p)
	require.NoError(t, err)
	assert.Equal(t, []string{rec}, identityRecipients(ids))
	_, err = Keygen(p, "me")
	assert.ErrorIs(t, err, os.ErrExist)
	ids2, err := ReadIdentities(p)
	require.NoError(t, err)
	assert.Equal(t, identityRecipients(ids), identityRecipients(ids2))
}

func TestPullDecryptsTheHostsSecrets(t *testing.T) {
	f := newGitFixture(t)
	f.cfg.AgeIdentity = HostAgeIdentity
	rec := writeIdentity(t, filepath.Join(f.root.Root, HostAgeIdentity))
	u, err := user.Current()
	require.NoError(t, err)
	g, err := user.LookupGroupId(u.Gid)
	require.NoError(t, err)
	f.write("modules/m/module.jsonnet", fmt.Sprintf(`{ resources: [{ file: { path: '/etc/token', template: 'token', secret: true, owner: %q, group: %q } }] }`, u.Username, g.Name))
	f.write("modules/m/token", "{{secret \"pw\"}}\n")
	f.write(SecretsFile("h"), string(encryptTo(t, "pw: hunter2\n", rec)))
	f.commit("hello\n", f.goodKey)
	f.push("main", false)
	f.clone()

	var out strings.Builder
	f.cfg.Out = &out
	require.NoError(t, Pull(t.Context(), f.cfg))
	b, err := os.ReadFile(filepath.Join(f.root.Root, "etc/token"))
	require.NoError(t, err)
	assert.Equal(t, "hunter2\n", string(b))
	assert.NotContains(t, out.String(), "hunter2", "the plan hides it")
}

func mapFile(b []byte) *fstest.MapFile { return &fstest.MapFile{Data: b} }

func TestBootstrapHostCreatesTheAgeIdentityBeforeThePull(t *testing.T) {
	sys, _ := newTestSystem(t)
	input := t.TempDir()
	for _, name := range []string{"infrafier", "allowed_signers", "deploy_key", "deploy_key.pub"} {
		require.NoError(t, os.WriteFile(filepath.Join(input, name), []byte("x"), 0o600))
	}
	var out strings.Builder
	var pulled PullConfig
	s := HostSetup{Input: input, Host: "h", Ref: "main", RepoURL: "u", System: sys, Out: &out,
		Pull: func(_ context.Context, cfg PullConfig) error {
			pulled = cfg
			_, err := os.Stat(filepath.Join(sys.Root, HostAgeIdentity))
			return err
		}}
	require.NoError(t, BootstrapHost(context.Background(), s))
	assert.Equal(t, HostAgeIdentity, pulled.AgeIdentity)
	rec := strings.TrimSpace(readRoot(t, sys, hostAgeRecipient))
	assert.Contains(t, out.String(), "this host's age recipient is in "+hostAgeRecipient+"\n")
	assert.NotContains(t, out.String(), rec, "bootstrap prints it, once")

	require.NoError(t, BootstrapHost(context.Background(), s))
	assert.Equal(t, rec, strings.TrimSpace(readRoot(t, sys, hostAgeRecipient)), "kept on a bootstrap again")
}

func TestNoteRecipient(t *testing.T) {
	dir := t.TempDir()
	var out strings.Builder
	noteRecipient(&out, dir, "h", "age1pq1xyz")
	assert.Contains(t, out.String(), "note: secrets/h.recipients (in "+dir+") does not list h's age recipient yet")
	assert.Contains(t, out.String(), "\nage1pq1xyz\n")

	require.NoError(t, os.MkdirAll(filepath.Join(dir, "secrets"), 0o755))
	_, rec, err := GenerateIdentity("h")
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(filepath.Join(dir, RecipientsFile("h")), []byte("# h\n"+rec+"\n"), 0o644))
	out.Reset()
	noteRecipient(&out, dir, "h", rec)
	assert.Empty(t, out.String())
}

// A secrets file the host cannot decrypt fails only a render that needs it,
// so the pull loop itself keeps being applied.
func TestPullAppliesWhatNeedsNoSecretWhenTheyCannotBeDecrypted(t *testing.T) {
	f := newGitFixture(t)
	f.cfg.AgeIdentity = HostAgeIdentity // never made: the host has none
	other := writeIdentity(t, filepath.Join(t.TempDir(), "other"))
	f.write(SecretsFile("h"), string(encryptTo(t, "pw: hunter2\n", other)))
	f.commit("hello\n", f.goodKey)
	f.push("main", false)
	f.clone()
	require.NoError(t, Pull(t.Context(), f.cfg))
	assert.Equal(t, "hello\n", f.motd())
}

func TestLazySecretsLoadsOnceAndOnlyWhenAsked(t *testing.T) {
	loads := 0
	l := &LazySecrets{Load: func() (Secrets, error) { loads++; return Secrets{"a": "1"}, nil }}
	fsys := testFS(`{ resources: [{ file: { path: '/etc/x', content: 'x' } }] }`, nil)
	h, err := LoadHost(fsys, "h")
	require.NoError(t, err)
	_, err = Render(fsys, h, l)
	require.NoError(t, err)
	assert.Equal(t, 0, loads)
	v, err := l.Secret("a")
	require.NoError(t, err)
	assert.Equal(t, "1", v)
	_, err = l.Secret("b")
	assert.ErrorContains(t, err, `no secret "b"`)
	assert.Equal(t, 1, loads)

	failing := &LazySecrets{Load: func() (Secrets, error) { return nil, errors.New("not encrypted to this host") }}
	_, err = failing.Secret("a")
	assert.ErrorContains(t, err, "not encrypted to this host")
}

func TestHostIdentityMustBelongToThePullUser(t *testing.T) {
	sys, _ := newTestSystem(t)
	writeIdentity(t, filepath.Join(sys.Root, HostAgeIdentity))
	_, err := hostIdentities(sys, HostAgeIdentity)
	require.NoError(t, err)
	if os.Geteuid() == 0 {
		require.NoError(t, os.Chown(filepath.Join(sys.Root, HostAgeIdentity), 65534, 65534))
		_, err = hostIdentities(sys, HostAgeIdentity)
		assert.ErrorContains(t, err, "not to the user pull runs as")
	}
}

// An error of the render with real values may quote one; what is reported
// never does.
func TestRenderErrorsNeverQuoteASecretValue(t *testing.T) {
	cases := map[string]string{
		`{{secret (secret "pw")}}`:                                      "by a name it computes",
		`{{/* "hunter2" */}}{{secret (secret "pw")}}`:                   "by a name it computes",
		`{{if eq .Vars.size "hunter2"}}{{end}}{{secret (secret "pw")}}`: "by a name it computes",
		`{{range secret "pw"}}{{.}}{{end}}`:                             "range can't iterate over <secret:pw>",
		`{{if eq (secret "pw") "hunter2"}}{{.Vars.nope}}{{end}}`:        "fails with this host's secret values but not with placeholders",
		`{{secret "nope"}}`:                                             `no secret "nope"`,
	}
	for tmpl, want := range cases {
		fsys := testFS(`{ resources: [{ file: { path: '/etc/x', template: 'x', secret: true } }] }`, map[string]string{"modules/m/x": tmpl})
		h, err := LoadHost(fsys, "h")
		require.NoError(t, err)
		_, err = Render(fsys, h, Secrets{"pw": "hunter2"})
		require.Error(t, err, tmpl)
		assert.Contains(t, err.Error(), want, tmpl)
		assert.NotContains(t, err.Error(), "hunter2", tmpl)
	}
	// What failed to load is said as it is: it holds no value.
	fsys := testFS(`{ resources: [{ file: { path: '/etc/x', template: 'x', secret: true } }] }`, map[string]string{"modules/m/x": `{{secret "pw"}}`})
	h, err := LoadHost(fsys, "h")
	require.NoError(t, err)
	_, err = Render(fsys, h, &LazySecrets{Load: func() (Secrets, error) { return nil, errors.New("not encrypted to this host") }})
	assert.ErrorContains(t, err, "not encrypted to this host")
}

// A file written by hand (age -R) that does not parse can still be opened
// to fix it; rekey refuses it and says so.
func TestEditOpensAFileThatDoesNotParse(t *testing.T) {
	if _, err := plaintextDir(); err != nil {
		t.Skip(err)
	}
	f := newSecretsFixture(t)
	require.NoError(t, os.WriteFile(filepath.Join(f.repo.Dir, SecretsFile("h")), encryptTo(t, "port: 5432\n", f.me, f.host), 0o644))
	_, err := f.repo.Rekey("h")
	assert.ErrorContains(t, err, "fix it with infrafier secrets edit h")

	var seen string
	fix := func(p string) error {
		b, _ := os.ReadFile(p)
		seen = string(b)
		return os.WriteFile(p, []byte("port: \"5432\"\n"), 0o600)
	}
	require.NoError(t, f.repo.EditSecrets("h", fix, func(string) bool { t.Fatal("asked"); return false }, io.Discard))
	assert.Equal(t, "port: 5432\n", seen)
	s, err := f.hostReads(t)
	require.NoError(t, err)
	assert.Equal(t, Secrets{"port": "5432"}, s)
}

func TestNoteRecipientReportsABrokenRecipientsFile(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.MkdirAll(filepath.Join(dir, "secrets"), 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(dir, RecipientsFile("h")), []byte("not a recipient\n"), 0o644))
	var out strings.Builder
	noteRecipient(&out, dir, "h", "age1pq1xyz")
	assert.Contains(t, out.String(), "warning: secrets/h.recipients")
	assert.Contains(t, out.String(), "\nage1pq1xyz\n", "the recipient, which fixing the file takes")
	assert.NotContains(t, out.String(), "does not list")

	// A file with only a comment is broken too ("no recipients found").
	require.NoError(t, os.WriteFile(filepath.Join(dir, RecipientsFile("h")), []byte("# h\n"), 0o644))
	out.Reset()
	noteRecipient(&out, dir, "h", "age1pq1xyz")
	assert.Contains(t, out.String(), "no recipients found")
	assert.Contains(t, out.String(), "\nage1pq1xyz\n")
}

func TestLoadHostSecretsRefusesASymlinkAndNeverQuotesTheFile(t *testing.T) {
	sys, _ := newTestSystem(t)
	writeIdentity(t, filepath.Join(sys.Root, HostAgeIdentity))
	dir := t.TempDir()
	require.NoError(t, os.MkdirAll(filepath.Join(dir, "secrets"), 0o755))
	shadow := filepath.Join(t.TempDir(), "shadow")
	require.NoError(t, os.WriteFile(shadow, []byte("root:hunter2:19000:0:99999:7:::\n"), 0o600))

	require.NoError(t, os.Symlink(shadow, filepath.Join(dir, SecretsFile("h"))))
	_, err := LoadHostSecrets(os.DirFS(dir), "h", sys, HostAgeIdentity)
	assert.ErrorContains(t, err, "not a regular file")

	// A regular file that is no age file: age's error would quote it.
	require.NoError(t, os.Remove(filepath.Join(dir, SecretsFile("h"))))
	for _, content := range []string{"root:hunter2:19000:0:99999:7:::\n", "age-encryption.org/v1\n-> hunter2 x\n"} {
		require.NoError(t, os.WriteFile(filepath.Join(dir, SecretsFile("h")), []byte(content), 0o644))
		_, err = LoadHostSecrets(os.DirFS(dir), "h", sys, HostAgeIdentity)
		require.Error(t, err)
		assert.NotContains(t, err.Error(), "hunter2")
	}
}

// Mixed classic and post-quantum recipients are refused before the editor
// opens, not after the operator typed the secrets.
func TestEditRefusesMixedRecipientsBeforeEditing(t *testing.T) {
	f := newSecretsFixture(t)
	classic, err := age.GenerateX25519Identity()
	require.NoError(t, err)
	f.recipients(t, f.me+"\n"+f.host+"\n"+classic.Recipient().String()+"\n")
	err = f.repo.EditSecrets("h", func(string) error { t.Fatal("editor ran"); return nil }, nil, io.Discard)
	assert.ErrorContains(t, err, "all recipients must be post-quantum")
}

// A save that fails keeps what was typed for another try.
func TestEditKeepsTheEditsWhenTheSaveFails(t *testing.T) {
	if _, err := plaintextDir(); err != nil {
		t.Skip(err)
	}
	if os.Geteuid() == 0 {
		t.Skip("root writes to a read-only dir")
	}
	f := newSecretsFixture(t)
	secretsDir := filepath.Join(f.repo.Dir, "secrets")
	edits := 0
	edit := func(p string) error {
		edits++
		if edits == 1 {
			require.NoError(t, os.Chmod(secretsDir, 0o500))
			return os.WriteFile(p, []byte("pw: \"typed\"\n"), 0o600)
		}
		b, err := os.ReadFile(p)
		require.NoError(t, err)
		assert.Equal(t, "pw: \"typed\"\n", string(b), "the edits are still there")
		return nil
	}
	var out strings.Builder
	again := func(string) bool { require.NoError(t, os.Chmod(secretsDir, 0o755)); return true }
	require.NoError(t, f.repo.EditSecrets("h", edit, again, &out))
	assert.Contains(t, out.String(), "not saved:")
	assert.Equal(t, 2, edits)
	s, err := f.hostReads(t)
	require.NoError(t, err)
	assert.Equal(t, Secrets{"pw": "typed"}, s)
}

func encryptIn(r SecretsRepo, host string, plain []byte) ([]string, error) {
	s, err := r.open(host)
	if err != nil {
		return nil, err
	}
	return r.write(s, plain)
}

// The host's writer once refused a clone reached through a symlink, which
// is common for an operator's clone.
func TestSecretsSaveIntoACloneReachedThroughASymlink(t *testing.T) {
	f := newSecretsFixture(t)
	link := filepath.Join(t.TempDir(), "link")
	require.NoError(t, os.Symlink(f.repo.Dir, link))
	r := SecretsRepo{Dir: link, Identity: f.repo.Identity}
	_, err := encryptIn(r, "h", []byte("pw: x\n"))
	require.NoError(t, err)
	_, err = r.Rekey("h")
	require.NoError(t, err)
	s, err := f.hostReads(t)
	require.NoError(t, err)
	assert.Equal(t, Secrets{"pw": "x"}, s)
	entries, err := os.ReadDir(filepath.Join(f.repo.Dir, "secrets"))
	require.NoError(t, err)
	for _, e := range entries {
		assert.False(t, strings.HasPrefix(e.Name(), ".infrafier-"), "temp file left: %s", e.Name())
	}
}

func TestEditRefusesAReadOnlyCloneBeforeEditing(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root writes to a read-only dir")
	}
	f := newSecretsFixture(t)
	require.NoError(t, os.Chmod(filepath.Join(f.repo.Dir, "secrets"), 0o500))
	t.Cleanup(func() { os.Chmod(filepath.Join(f.repo.Dir, "secrets"), 0o755) })
	err := f.repo.EditSecrets("h", func(string) error { t.Fatal("editor ran"); return nil }, nil, io.Discard)
	assert.ErrorContains(t, err, "permission denied")
}

// An empty render in CI once gave a nil Content, which the golden tree took
// for a render with values.
func TestGoldenOfAnEmptyPlaceholderRender(t *testing.T) {
	fsys := testFS(`{ resources: [{ file: { path: '/etc/x', template: 'x', secret: true } }] }`, map[string]string{"modules/m/x": `{{if eq (secret "on") "yes"}}on{{end}}`})
	h, err := LoadHost(fsys, "h")
	require.NoError(t, err)
	rs, err := Render(fsys, h, nil)
	require.NoError(t, err)
	assert.Equal(t, "", string(GoldenTree(rs, "")["etc/x"]))
}

// A recipient is compared as age writes it. age refuses an uppercase one
// outright, so that never reaches the comparison (where it would be "not
// listed").
func TestRecipientsAreComparedAsAgeWritesThem(t *testing.T) {
	f := newSecretsFixture(t)
	lines, err := encryptIn(f.repo, "h", []byte("pw: x\n"))
	require.NoError(t, err)
	assert.Contains(t, lines[0], "[you]")

	f.recipients(t, strings.ToUpper(f.me)+"\n"+f.host+"\n")
	_, err = encryptIn(f.repo, "h", []byte("pw: x\n"))
	assert.ErrorContains(t, err, "unknown recipient type")
}

func TestLoadHostSecretsRefusesASymlinkedSecretsDir(t *testing.T) {
	sys, _ := newTestSystem(t)
	rec := writeIdentity(t, filepath.Join(sys.Root, HostAgeIdentity))
	elsewhere := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(elsewhere, "h.age"), encryptTo(t, "pw: x\n", rec), 0o644))
	dir := t.TempDir()
	require.NoError(t, os.Symlink(elsewhere, filepath.Join(dir, "secrets")))
	_, err := LoadHostSecrets(os.DirFS(dir), "h", sys, HostAgeIdentity)
	assert.ErrorContains(t, err, "secrets is not a directory")
}

// A PR that changes only the secrets file once showed no change in diff,
// and none of the restarts it causes.
func TestGoldenDiffListsTheActionsOfAChangedSecretsFile(t *testing.T) {
	fsys := testFS(`{ resources: [
  { file: { path: '/etc/traefik/cf-dns-token', template: 'token', secret: true, onChange: [{ restart: 'traefik' }] } },
  { file: { path: '/etc/plain', content: 'plain\n', onChange: [{ restart: 'other' }] } },
] }`, map[string]string{"modules/m/token": `{{secret "tok"}}`, SecretsFile("h"): "ciphertext one"})
	h, err := LoadHost(fsys, "h")
	require.NoError(t, err)
	rs, err := Render(fsys, h, nil)
	require.NoError(t, err)
	line, err := SecretsLine(fsys, "h")
	require.NoError(t, err)
	assert.True(t, strings.HasPrefix(line, "secrets secrets/h.age sha256:"), line)
	dir := t.TempDir()
	require.NoError(t, WriteGolden(dir, rs, line))

	diffs, actions, err := GoldenDiff(dir, rs, line)
	require.NoError(t, err)
	assert.Empty(t, diffs)
	assert.Empty(t, actions)

	fsys[SecretsFile("h")] = mapFile([]byte("ciphertext two"))
	line2, err := SecretsLine(fsys, "h")
	require.NoError(t, err)
	diffs, actions, err = GoldenDiff(dir, rs, line2)
	require.NoError(t, err)
	require.Len(t, diffs, 1, "only _resources.txt")
	assert.Contains(t, diffs[0], "+"+line2)
	assert.Equal(t, []Action{{Verb: "restart", Unit: "traefik.service"}}, actions, "the file that reads secrets, not the plain one")
}

func TestParseSecretsAsksToQuoteANumericName(t *testing.T) {
	_, err := ParseSecrets([]byte("2024: \"x\"\n"))
	assert.ErrorContains(t, err, "line 1: quote this secret name (unquoted, YAML reads it as a number)")
	_, err = ParseSecrets([]byte("!hunter2 pw: \"x\"\n"))
	assert.EqualError(t, err, "line 1: a secret name takes no YAML tag")
	s, err := ParseSecrets([]byte("\"2024\": \"x\"\n"))
	require.NoError(t, err)
	assert.Equal(t, Secrets{"2024": "x"}, s)
}

// CI's infrafier diff refuses a symlinked secrets file or dir as the hosts do,
// rather than digesting its target and leaving every pull to fail.
func TestSecretsLineRefusesASymlink(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.MkdirAll(filepath.Join(dir, "secrets"), 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(dir, SecretsFile("a")), []byte("ciphertext"), 0o644))
	line, err := SecretsLine(os.DirFS(dir), "a")
	require.NoError(t, err)
	assert.NotEmpty(t, line)
	line, err = SecretsLine(os.DirFS(dir), "none")
	require.NoError(t, err)
	assert.Empty(t, line)

	require.NoError(t, os.Symlink("a.age", filepath.Join(dir, SecretsFile("b"))))
	_, err = SecretsLine(os.DirFS(dir), "b")
	assert.ErrorContains(t, err, "secrets/b.age is not a regular file")

	other := t.TempDir()
	require.NoError(t, os.Symlink(filepath.Join(dir, "secrets"), filepath.Join(other, "secrets")))
	_, err = SecretsLine(os.DirFS(other), "a")
	assert.ErrorContains(t, err, "secrets is not a directory")
}

// parseRecipients reads a recipients file as age itself does, errors and all.
func TestParseRecipientsAgreesWithAge(t *testing.T) {
	_, pq, err := GenerateIdentity("x")
	require.NoError(t, err)
	classic, err := age.GenerateX25519Identity()
	require.NoError(t, err)
	x := classic.Recipient().String()
	for _, in := range []string{
		pq + "\n", "# c\n" + pq + "\r\n\n" + x + "\n", "", "# only\n", "\n\n",
		pq + "\nnot one\n", " " + pq + "\n", "  \n", strings.ToUpper(x) + "\n",
		"age1pq1broken\n", "AGE-SECRET-KEY-1XYZ\n", "\xff\n",
	} {
		want, werr := age.ParseRecipients(strings.NewReader(in))
		got, gerr := parseRecipients([]byte(in))
		if werr != nil {
			assert.EqualError(t, gerr, werr.Error(), "%q", in)
			continue
		}
		require.NoError(t, gerr, "%q", in)
		assert.Equal(t, want, recipientsOf(got), "%q", in)
	}
}

// A signal during a write in the clone waits until the temp file is gone,
// then is raised again, for its default action or another handler.
func TestHoldSignalsRaisesAgainAfterTheWrite(t *testing.T) {
	later := make(chan os.Signal, 2)
	defer signal.Stop(later)
	done := false
	err := holdSignals(func() error {
		require.NoError(t, syscall.Kill(os.Getpid(), syscall.SIGHUP))
		time.Sleep(50 * time.Millisecond) // delivered, and held: still here
		// Registered only now, so it can only get the signal raised again.
		signal.Notify(later, syscall.SIGHUP)
		done = true
		return nil
	})
	require.NoError(t, err)
	assert.True(t, done)
	select {
	case sig := <-later:
		assert.Equal(t, syscall.SIGHUP, sig)
	case <-time.After(2 * time.Second):
		t.Fatal("the held signal was not raised again")
	}
}

// otherOwner reports every file as another user's and records chmods.
type otherOwner struct {
	System
	chmods int
}

func (o *otherOwner) Lstat(p string) (FileState, error) {
	st, err := o.System.Lstat(p)
	st.UID, st.Owner = uint32(os.Geteuid())+1, "someone"
	return st, err
}

func (o *otherOwner) SetAttrs(p string, mode fs.FileMode, owner, group string) error {
	o.chmods++
	return o.System.SetAttrs(p, mode, owner, group)
}

// A host identity bootstrap refuses (another user's) is left as it was,
// not made 0600 first.
func TestEnsureHostIdentityChecksTheOwnerBeforeTheChmod(t *testing.T) {
	sys, _ := newTestSystem(t)
	require.NoError(t, ensureHostIdentity(sys, "h", io.Discard))
	require.NoError(t, os.Chmod(filepath.Join(sys.Root, HostAgeIdentity), 0o644))
	o := &otherOwner{System: sys}
	err := ensureHostIdentity(o, "h", io.Discard)
	assert.ErrorContains(t, err, "belongs to someone, not to the user pull runs as")
	assert.Zero(t, o.chmods)
	fi, err := os.Stat(filepath.Join(sys.Root, HostAgeIdentity))
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0o644), fi.Mode().Perm())
}
