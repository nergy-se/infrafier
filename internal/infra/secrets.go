package infra

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/signal"
	"path"
	"path/filepath"
	"regexp"
	"runtime"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"unicode/utf8"

	"filippo.io/age"
	"go.yaml.in/yaml/v3"
)

// Host secrets are age-encrypted files in the desired-state repo, one per host:
//
//	secrets/<host>.age         a YAML map of secret names to values, encrypted
//	secrets/<host>.recipients  who it is encrypted to: the host and the operators
//
// The recipients file is in age's recipients file format, so `age -R` can
// read and write the secrets file too, without infrafier. It holds native age
// recipients only (age1pq1…, the post-quantum ones bootstrap and keygen make;
// age refuses to mix them with classic age1… ones): ssh keys and plugin
// recipients (age1yubikey1…), which age -R takes, are refused, since
// infrafier reads the file without age's plugins. Each host decrypts its own
// file at pull with the identity bootstrap created on it (HostAgeIdentity),
// which never leaves the host; operators edit it with `infrafier secrets
// edit` and their own identity. Plaintext never reaches git, and a host can
// read no other host's secrets.
//
// A template reads a value with {{secret "name"}}, and only the template of a
// file with secret: true may: the module file may not (a value in a command's
// arguments is in the process list of every user on the host), and neither
// may an ordinary file (its content is in plans and golden files). Such a
// file's golden file is the template rendered with placeholders instead of
// values, so review and CI, which can decrypt nothing, see everything else.
//
// So a template only outputs a secret as it is, {{secret "pw"}}, maybe
// piped through quoting or escaping. It never compares, slices, measures or
// branches on one: {{if eq (secret "mode") "tls"}} compares the placeholder
// in CI and the value on the host, so the golden file shows a branch the
// host never takes, and {{slice (secret "pw") 0 16}} fails in CI on a
// placeholder shorter than 16 characters. A choice like that belongs in
// vars, which CI sees; infrafier cannot refuse it, since to the template a
// secret is just a string.
//
// Removing a recipient (a departed operator, a host key that may be known)
// and running rekey only changes who can decrypt from then on: git history
// keeps every earlier secrets file, which the removed key still decrypts. So
// the values in it have to be changed too, at their source (a new token, a
// new password), and then edited in.
//
// edit keeps its plaintext copy on a tmpfs only. A tmpfs can be paged out to
// swap; whether swap (and the disk) is encrypted is the operator's machine to
// decide, and infrafier does not try to tell.

const (
	HostAgeIdentity  = HostConfigDir + "/age-identity"
	hostAgeRecipient = HostConfigDir + "/age-recipient"
)

// SecretSource gives Render the values for {{secret}}. Render with a nil
// SecretSource puts placeholders where values would go, which is how diff and
// CI render.
type SecretSource interface {
	Secret(name string) (string, error)
}

// Secrets are a host's decrypted secrets. A nil Secrets is a host with none,
// not placeholders: only a nil SecretSource gives those.
type Secrets map[string]string

func (s Secrets) Secret(name string) (string, error) {
	v, ok := s[name]
	if !ok {
		return "", &missingSecretError{name}
	}
	return v, nil
}

// missingSecretError names the secret asked for, which may be a value when
// the template computed the name; see safeSecretError.
type missingSecretError struct{ name string }

func (e *missingSecretError) Error() string {
	return fmt.Sprintf("no secret %q in this host's secrets file (%s secrets edit adds it)", e.name, agentCommand)
}

// LazySecrets loads the secrets on the first {{secret}}, so a secrets file the
// host cannot decrypt (its recipient not added yet) matters only to a host
// whose templates read one. For such a host the whole render fails and
// nothing is applied: applying the modules that rendered would let one
// module's purge remove the files of one that did not. A host whose timer
// runs retries and fetches the fix; a new host, whose timer only its first
// pull installs, has to be bootstrapped again.
type LazySecrets struct {
	Load func() (Secrets, error)

	once    sync.Once
	secrets Secrets
	err     error
}

func (l *LazySecrets) Secret(name string) (string, error) {
	l.once.Do(func() { l.secrets, l.err = l.Load() })
	if l.err != nil {
		return "", l.err
	}
	return l.secrets.Secret(name)
}

func SecretsFile(host string) string    { return "secrets/" + host + ".age" }
func RecipientsFile(host string) string { return "secrets/" + host + ".recipients" }

var secretNameRe = regexp.MustCompile(`^[A-Za-z0-9_][A-Za-z0-9_.-]*$`)

func secretPlaceholderValue(name string) string { return "<secret:" + name + ">" }

// maxSecretsSize bounds what is decrypted and parsed; a secrets file is a
// handful of tokens and passwords.
const maxSecretsSize = 1 << 20

// yamlTypeNames are the types yaml gives an unquoted scalar by itself.
var yamlTypeNames = map[string]string{
	"!!int": "a number", "!!float": "a number", "!!bool": "a bool",
	"!!null": "null", "!!timestamp": "a date",
}

// ParseSecrets parses decrypted secrets: a flat map of names to strings. Its
// errors give line numbers, never the input, not even a name (a token pasted
// where a name goes), since they end up in the pull's journal; yaml's own
// errors may quote it.
func ParseSecrets(plain []byte) (Secrets, error) {
	dec := yaml.NewDecoder(bytes.NewReader(plain))
	var doc yaml.Node
	err := dec.Decode(&doc)
	out := Secrets{}
	if errors.Is(err, io.EOF) { // empty, or only comments
		return out, nil
	}
	if err != nil {
		return nil, errors.New("not valid YAML")
	}
	// A second document (after ---) would be encrypted but never read.
	var next yaml.Node
	if err := dec.Decode(&next); !errors.Is(err, io.EOF) {
		return nil, errors.New("more than one YAML document; put every secret in one map")
	}
	if doc.Kind != yaml.DocumentNode || len(doc.Content) != 1 || doc.Content[0].Kind != yaml.MappingNode {
		return nil, errors.New("not a map of secret names to values")
	}
	m := doc.Content[0]
	for i := 0; i+1 < len(m.Content); i += 2 {
		k, v := m.Content[i], m.Content[i+1]
		if k.Kind != yaml.ScalarNode || !secretNameRe.MatchString(k.Value) {
			return nil, fmt.Errorf("line %d: a secret name has letters, digits, _, . and - only", k.Line)
		}
		// 2024 or true is a fine name, but YAML reads it as a number or
		// a bool unless quoted. Only a built-in type is named: any other
		// tag (!hunter2 pw) is input, maybe a token pasted there.
		if k.Tag != "!!str" {
			if t, ok := yamlTypeNames[k.Tag]; ok {
				return nil, fmt.Errorf("line %d: quote this secret name (unquoted, YAML reads it as %s)", k.Line, t)
			}
			return nil, fmt.Errorf("line %d: a secret name takes no YAML tag", k.Line)
		}
		// Only a string, so 0755 or yes is never read as something else;
		// no alias either, which could make one value stand for another.
		if v.Kind != yaml.ScalarNode || v.Tag != "!!str" {
			return nil, fmt.Errorf("line %d: a value must be a string (quote it)", v.Line)
		}
		if _, dup := out[k.Value]; dup {
			return nil, fmt.Errorf("line %d: a name given twice", k.Line)
		}
		out[k.Value] = v.Value
	}
	return out, nil
}

// ReadIdentities reads the operator's age identity file; see parseIdentities.
func ReadIdentities(p string) ([]age.Identity, error) {
	f, err := os.Open(p)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil {
		return nil, err
	}
	b, err := io.ReadAll(io.LimitReader(f, maxSecretsSize))
	if err != nil {
		return nil, err
	}
	return parseIdentities(p, fi.Mode(), b)
}

// parseIdentities parses an age identity file, refusing one that others than
// its owner can read or write, as ssh does with a private key. Its errors
// never quote the file.
func parseIdentities(p string, mode fs.FileMode, b []byte) ([]age.Identity, error) {
	if !mode.IsRegular() {
		return nil, fmt.Errorf("%s is not a regular file", p)
	}
	if mode.Perm()&0o077 != 0 {
		return nil, fmt.Errorf("%s is mode %04o; an age identity must be readable by its owner only (chmod 600)", p, mode.Perm())
	}
	ids, err := age.ParseIdentities(bytes.NewReader(b))
	if err != nil {
		return nil, fmt.Errorf("%s: %w", p, err)
	}
	return ids, nil
}

// hostIdentities reads the host's identity through sys, which refuses a
// symlink. It must belong to the user pull runs as (root): another owner
// could swap it for a key of their own.
func hostIdentities(sys System, p string) ([]age.Identity, error) {
	st, err := sys.Lstat(p)
	if err != nil {
		return nil, err
	}
	if err := checkHostIdentity(p, st); err != nil {
		return nil, err
	}
	return parseIdentities(p, st.Mode, st.Content)
}

// checkHostIdentity tells whether st, the host identity at p, is one pull
// may use: a regular file (no symlink to a key elsewhere) of its own user.
func checkHostIdentity(p string, st FileState) error {
	switch {
	case !st.Exists:
		return fs.ErrNotExist
	case !st.IsRegular:
		return fmt.Errorf("%s is not a regular file", p)
	case st.UID != uint32(os.Geteuid()):
		return fmt.Errorf("%s belongs to %s, not to the user pull runs as", p, st.Owner)
	}
	return nil
}

// identityRecipients are the public halves of ids, as recipients-file lines.
func identityRecipients(ids []age.Identity) []string {
	var out []string
	for _, id := range ids {
		switch id := id.(type) {
		case *age.X25519Identity:
			out = append(out, id.Recipient().String())
		case *age.HybridIdentity:
			out = append(out, id.Recipient().String())
		}
	}
	return out
}

// GenerateIdentity makes a new age identity, post-quantum hybrid (ML-KEM-768 +
// X25519): the secrets files live in git for ever, so they should outlast a
// future quantum computer too. It returns the identity file's content and its
// recipient.
func GenerateIdentity(comment string) (identity []byte, recipient string, err error) {
	id, err := age.GenerateHybridIdentity()
	if err != nil {
		return nil, "", err
	}
	recipient = id.Recipient().String()
	return fmt.Appendf(nil, "# %s\n# public key: %s\n%s\n", comment, recipient, id), recipient, nil
}

// decryptPlain decrypts a secrets file with ids, without checking what it
// holds: edit must open a file written by hand (age -R) that does not parse,
// or the tool to fix it could not.
func decryptPlain(ciphertext []byte, ids []age.Identity) ([]byte, error) {
	r, err := age.Decrypt(bytes.NewReader(ciphertext), ids...)
	if err != nil {
		return nil, err
	}
	plain, err := io.ReadAll(io.LimitReader(r, maxSecretsSize+1))
	if err != nil {
		return nil, err
	}
	if len(plain) > maxSecretsSize {
		return nil, fmt.Errorf("larger than %d bytes", maxSecretsSize)
	}
	return plain, nil
}

// secretsParseError marks a ParseSecrets error, which quotes nothing, apart
// from age's, which may.
type secretsParseError struct{ err error }

func (e *secretsParseError) Error() string { return e.err.Error() }
func (e *secretsParseError) Unwrap() error { return e.err }

// DecryptSecrets decrypts a secrets file with ids and parses it.
func DecryptSecrets(ciphertext []byte, ids []age.Identity) (Secrets, error) {
	plain, err := decryptPlain(ciphertext, ids)
	if err != nil {
		return nil, err
	}
	s, err := ParseSecrets(plain)
	if err != nil {
		return nil, &secretsParseError{err}
	}
	return s, nil
}

// readSecretsFile reads the host's secrets file from fsys, nil when it has
// none. Not through a symlink, neither secrets/ nor the file: what a host
// reads is a file of the commit, never one elsewhere on the host. CI's infra
// diff reads it here too, so a symlink fails there, not on every pull.
func readSecretsFile(fsys fs.FS, host string) ([]byte, error) {
	name := SecretsFile(host)
	dir, err := fs.Lstat(fsys, path.Dir(name))
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if !dir.IsDir() {
		return nil, fmt.Errorf("%s is not a directory", path.Dir(name))
	}
	fi, err := fs.Lstat(fsys, name)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if !fi.Mode().IsRegular() {
		return nil, fmt.Errorf("%s is not a regular file", name)
	}
	b, err := fs.ReadFile(fsys, name)
	if err != nil {
		return nil, err
	}
	if b == nil {
		b = []byte{} // empty, but there: not the same as none
	}
	return b, nil
}

// LoadHostSecrets decrypts secrets/<host>.age in fsys with the identity at
// identityPath on sys. A host without a secrets file has no secrets, which is
// not an error until a template asks for one.
func LoadHostSecrets(fsys fs.FS, host string, sys System, identityPath string) (Secrets, error) {
	name := SecretsFile(host)
	ciphertext, err := readSecretsFile(fsys, host)
	if err != nil {
		return nil, err
	}
	if ciphertext == nil {
		return Secrets{}, nil
	}
	if identityPath == "" {
		return nil, fmt.Errorf("%s exists, but no age identity is configured to decrypt it", name)
	}
	ids, err := hostIdentities(sys, identityPath)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, fmt.Errorf("%s exists, but this host has no age identity %s; run %s bootstrap %s again", name, identityPath, agentCommand, host)
	}
	if err != nil {
		return nil, err
	}
	s, err := DecryptSecrets(ciphertext, ids)
	var noMatch *age.NoIdentityMatchError
	if errors.As(err, &noMatch) {
		return nil, fmt.Errorf("%s is not encrypted to this host's age identity; add its recipient (%s) to %s, then "+agentCommand+" secrets rekey %s",
			name, strings.Join(identityRecipients(ids), ", "), RecipientsFile(host), host)
	}
	if err != nil {
		// ParseSecrets' errors quote nothing; age's may quote the file.
		var perr *secretsParseError
		if errors.As(err, &perr) {
			return nil, fmt.Errorf("%s: %w", name, err)
		}
		return nil, fmt.Errorf("%s: cannot decrypt it: not an age file, or damaged (age's error not shown: it may quote the file)", name)
	}
	return s, nil
}

// recipientEntry is one recipient of a recipients file.
type recipientEntry struct {
	rec age.Recipient
	// key is the recipient as age writes it (lowercase bech32), to match
	// against an identity's.
	key string
	// comment is the comment line right above it, for the operator to see.
	comment string
}

// parseRecipients parses an age recipients file, the one parser behind both
// whom a file is encrypted to and what the operator is shown of it. It reads
// a file as age.ParseRecipients does, with its errors, in one pass that also
// keeps each recipient's comment. Whether the recipients can be used
// together (age refuses to mix post-quantum and classic ones) only
// encrypting tells; see open.
func parseRecipients(b []byte) ([]recipientEntry, error) {
	if !utf8.Valid(b) {
		return nil, errors.New("recipients file is not valid UTF-8")
	}
	var out []recipientEntry
	comment := ""
	for i, l := range strings.Split(string(b), "\n") {
		l = strings.TrimSuffix(l, "\r")
		switch {
		case l == "":
			comment = ""
		case strings.HasPrefix(l, "#"):
			comment = strings.TrimSpace(strings.TrimLeft(l, "#"))
		default:
			e, err := parseRecipient(l)
			if err != nil {
				return nil, fmt.Errorf("error at line %d: %v", i+1, err)
			}
			e.comment = comment
			out = append(out, e)
			comment = ""
		}
	}
	if len(out) == 0 {
		return nil, errors.New("no recipients found")
	}
	return out, nil
}

// parseRecipient parses one line as age does (age has no parser for one
// that is exported).
func parseRecipient(l string) (recipientEntry, error) {
	switch {
	case strings.HasPrefix(l, "age1pq1"):
		r, err := age.ParseHybridRecipient(l)
		if err != nil {
			return recipientEntry{}, err
		}
		return recipientEntry{rec: r, key: r.String()}, nil
	case strings.HasPrefix(l, "age1"):
		r, err := age.ParseX25519Recipient(l)
		if err != nil {
			return recipientEntry{}, err
		}
		return recipientEntry{rec: r, key: r.String()}, nil
	}
	// Maybe an identity pasted in the wrong file: not quoted.
	return recipientEntry{}, errors.New("unknown recipient type")
}

func recipientsOf(entries []recipientEntry) []age.Recipient {
	out := make([]age.Recipient, len(entries))
	for i, e := range entries {
		out[i] = e.rec
	}
	return out
}

// listsRecipient tells whether entries hold recipient (as age writes it).
func listsRecipient(entries []recipientEntry, recipient string) bool {
	return slices.ContainsFunc(entries, func(e recipientEntry) bool { return e.key == recipient })
}

// EncryptSecrets encrypts plain (already checked with ParseSecrets) to recs.
func EncryptSecrets(plain []byte, recs []age.Recipient) ([]byte, error) {
	var out bytes.Buffer
	w, err := age.Encrypt(&out, recs...)
	if err != nil {
		return nil, err
	}
	if _, err := w.Write(plain); err != nil {
		return nil, err
	}
	if err := w.Close(); err != nil {
		return nil, err
	}
	return out.Bytes(), nil
}

// SecretsRepo is the operator's side of the secrets: a clone of the
// desired-state repo and the operator's age identity.
type SecretsRepo struct {
	Dir      string
	Identity string
}

// secretsSession is what an operator command reads once: the identity and
// the recipients file, so the list shown after encrypting is the one that was
// used, even when the file changes meanwhile (a checkout elsewhere).
type secretsSession struct {
	host       string
	ids        []age.Identity
	recipients []recipientEntry
}

// open checks the host, reads the operator's identity and the host's
// recipients file, and checks that the operator is among the recipients: a
// file the operator cannot decrypt could never be edited again.
func (r SecretsRepo) open(host string) (*secretsSession, error) {
	fsys, closeRepo, err := OpenRepo(r.Dir)
	if err != nil {
		return nil, err
	}
	defer closeRepo()
	if _, err := LoadHost(fsys, host); err != nil {
		return nil, err
	}
	ids, err := ReadIdentities(r.Identity)
	if err != nil {
		return nil, err
	}
	p := filepath.Join(r.Dir, RecipientsFile(host))
	b, err := os.ReadFile(p)
	if err != nil {
		return nil, err
	}
	entries, err := parseRecipients(b)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", p, err)
	}
	mine := identityRecipients(ids)
	if !slices.ContainsFunc(mine, func(m string) bool { return listsRecipient(entries, m) }) {
		return nil, fmt.Errorf("%s does not list your age identity (%s); you could not decrypt what it encrypts", p, strings.Join(mine, ", "))
	}
	// Everything a save needs is tried now, not after the operator typed
	// the secrets: age checks that the recipients can be used together
	// (classic and post-quantum cannot) only when it encrypts, and the
	// clone may not be writable.
	if _, err := EncryptSecrets(nil, recipientsOf(entries)); err != nil {
		return nil, fmt.Errorf("%s: %w (all recipients must be post-quantum, age1pq1…, as %s secrets keygen and bootstrap make them)", p, err, agentCommand)
	}
	if err := checkWritable(filepath.Dir(filepath.Join(r.Dir, SecretsFile(host)))); err != nil {
		return nil, err
	}
	return &secretsSession{host: host, ids: ids, recipients: entries}, nil
}

// cleanupSignals are the signals that would end the command before its
// deferred cleanup: SIGQUIT (Ctrl-\\) dumps goroutines and exits, SIGPIPE
// ends it on a write to a closed stdout (edit | head).
var cleanupSignals = []os.Signal{os.Interrupt, syscall.SIGTERM, syscall.SIGHUP, syscall.SIGQUIT, syscall.SIGPIPE}

// holdSignals runs f with cleanupSignals held, so none ends the process
// between creating a temp file in the clone's secrets/ and removing or
// renaming it, which would leave secrets/.infrafier-<hex> for a git add.
// A signal that came is raised again after f, for its default action or
// another handler (EditSecrets').
func holdSignals(f func() error) error {
	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, cleanupSignals...)
	err := f()
	signal.Stop(sigs)
	select {
	case sig := <-sigs:
		if n, ok := sig.(syscall.Signal); ok {
			syscall.Kill(os.Getpid(), n)
		}
	default:
	}
	return err
}

// checkWritable tells whether writeOperatorFile could write in dir, by
// creating its temp file there and removing it. dir is secrets/, which
// exists: the recipients file open read is in it.
func checkWritable(dir string) error {
	return holdSignals(func() error {
		f, err := operatorTemp(dir)
		if err != nil {
			return err
		}
		f.Close()
		return os.Remove(f.Name())
	})
}

func operatorTemp(dir string) (*os.File, error) { return os.CreateTemp(dir, "."+agentName+"-") }

// writeOperatorFile replaces p atomically (temp file, fsync, rename) with
// plain os calls. Not writeAtomic: that is the host's writer, made for root,
// which refuses a path that leaves a directory through a symlink, and an
// operator's clone is often reached through one (~/git → /data/git).
func writeOperatorFile(p string, b []byte) error {
	return holdSignals(func() error { return writeOperatorFileNow(p, b) })
}

func writeOperatorFileNow(p string, b []byte) error {
	f, err := operatorTemp(filepath.Dir(p))
	if err != nil {
		return err
	}
	tmp := f.Name()
	defer os.Remove(tmp) // fails harmlessly after the rename
	_, err = f.Write(b)
	if err == nil {
		err = f.Chmod(0o644)
	}
	if err == nil {
		err = f.Sync()
	}
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		return err
	}
	return os.Rename(tmp, p)
}

// decrypt returns the host's decrypted secrets file, nil when there is none.
func (r SecretsRepo) decrypt(s *secretsSession) ([]byte, error) {
	ciphertext, err := os.ReadFile(filepath.Join(r.Dir, SecretsFile(s.host)))
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	plain, err := decryptPlain(ciphertext, s.ids)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", SecretsFile(s.host), err)
	}
	return plain, nil
}

// write checks plain and writes it as the host's secrets file, and returns
// whom it was encrypted to, for the operator to see.
func (r SecretsRepo) write(s *secretsSession, plain []byte) ([]string, error) {
	if len(plain) > maxSecretsSize {
		return nil, fmt.Errorf("larger than %d bytes", maxSecretsSize)
	}
	if _, err := ParseSecrets(plain); err != nil {
		return nil, &secretsParseError{err}
	}
	ciphertext, err := EncryptSecrets(plain, recipientsOf(s.recipients))
	if err != nil {
		return nil, err
	}
	if err := writeOperatorFile(filepath.Join(r.Dir, SecretsFile(s.host)), ciphertext); err != nil {
		return nil, err
	}
	return describeRecipients(s.recipients, identityRecipients(s.ids)), nil
}

// describeRecipients is one line per recipient for the operator to check:
// a post-quantum recipient is ~2000 characters, so it is shortened, with the
// comment line above it in the file. A recipients file changed in a PR could
// add someone else's key, and this is where the operator sees whom they
// encrypted to; compare the host's with its /etc/infrafier/age-recipient.
func describeRecipients(entries []recipientEntry, mine []string) []string {
	var out []string
	for _, e := range entries {
		d := shortRecipient(e.key)
		if e.comment != "" {
			d += " (" + e.comment + ")"
		}
		if slices.Contains(mine, e.key) {
			d += " [you]"
		}
		out = append(out, d)
	}
	return out
}

// shortRecipient keeps the type prefix and the last characters, which
// include the bech32 checksum.
func shortRecipient(r string) string {
	if len(r) <= 40 {
		return r
	}
	return r[:16] + "…" + r[len(r)-12:]
}

const newSecretsTemplate = `# Secrets of %s: name: value, values quoted. Read in a template of a file
# with secret: true as {{secret "name"}}. Saved encrypted to the recipients in
# %s; this plaintext copy is removed when the editor exits.
`

// EditSecrets lets the operator edit host's secrets in a private temp file
// on a tmpfs and writes them back encrypted. edit runs the editor on the
// file; ask reads the answer to "edit again?" when what was saved is not
// valid.
func (r SecretsRepo) EditSecrets(host string, edit func(path string) error, ask func(prompt string) bool, out io.Writer) error {
	// Fail before anyone types a secret into a file that cannot be saved.
	sess, err := r.open(host)
	if err != nil {
		return err
	}
	plain, err := r.decrypt(sess)
	if err != nil {
		return err
	}
	existed := plain != nil
	if !existed {
		plain = fmt.Appendf(nil, newSecretsTemplate, host, RecipientsFile(host))
	}
	base, err := plaintextDir()
	if err != nil {
		return err
	}
	tmp, err := os.MkdirTemp(base, agentName+"-secrets-")
	if err != nil {
		return err
	}
	// A signal would kill the process before the deferred RemoveAll, and
	// leave the plaintext behind. Ctrl-C while the editor runs is the
	// editor's (vim leaves insert mode with it); otherwise, and for any
	// other signal, remove the plaintext and exit. The handler is stopped
	// only after the RemoveAll below (defers run last first).
	// writing is held while the secrets file is written, so this handler
	// does not end the process between the temp file and its rename (see
	// holdSignals, which only keeps the default action from doing so).
	var editing, saved atomic.Bool
	var writing sync.Mutex
	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, cleanupSignals...)
	stop := make(chan struct{})
	defer func() { signal.Stop(sigs); close(stop) }()
	go func() {
		for {
			select {
			case <-stop:
				return
			case sig := <-sigs:
				if sig == os.Interrupt && editing.Load() {
					continue
				}
				writing.Lock()
				if saved.Load() {
					// Saved while the signal waited: the command
					// ends now anyway, and did what was asked.
					writing.Unlock()
					return
				}
				os.RemoveAll(tmp)
				fmt.Fprintf(out, "\n%v: plaintext copy removed\n", sig)
				code := 130
				if n, ok := sig.(syscall.Signal); ok {
					code = 128 + int(n)
				}
				os.Exit(code)
			}
		}
	}()
	// The dir is 0700 and removed with everything in it, the editor's swap
	// and backup files included.
	defer os.RemoveAll(tmp)

	p := filepath.Join(tmp, host+".yaml")
	if err := os.WriteFile(p, plain, 0o600); err != nil {
		return err
	}
	for {
		editing.Store(true)
		err := edit(p)
		editing.Store(false)
		if err != nil {
			return fmt.Errorf("editor: %w (nothing saved)", err)
		}
		edited, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		// Unchanged, the template of a new host's file included: just
		// looking must not create an (empty) secrets file.
		if bytes.Equal(edited, plain) {
			if existed {
				fmt.Fprintf(out, "no changes; %s left as it was\n", SecretsFile(host))
			} else {
				fmt.Fprintf(out, "no changes; %s not created\n", SecretsFile(host))
			}
			return nil
		}
		writing.Lock()
		lines, err := r.write(sess, edited)
		if err == nil {
			saved.Store(true)
		}
		writing.Unlock()
		if err == nil {
			fmt.Fprintf(out, "wrote %s, encrypted to:\n  %s\n%s\n", SecretsFile(host), strings.Join(lines, "\n  "), SecretsNextStep(host))
			return nil
		}
		var perr *secretsParseError
		if errors.As(err, &perr) {
			// Here the operator sees the plaintext anyway, so yaml's
			// own message, which may quote it, is shown.
			var v any
			if yerr := yaml.Unmarshal(edited, &v); yerr != nil {
				err = yerr
			}
		} else {
			// What was typed is only in the plaintext copy: keep it
			// for another try (fix the cause in another terminal).
			err = fmt.Errorf("not saved: %w", err)
		}
		fmt.Fprintf(out, "%s: %v\n", SecretsFile(host), err)
		if !ask("edit again? (no discards the changes)") {
			return errors.New("discarded; nothing saved")
		}
	}
}

// plaintextDir is where edit puts its plaintext copy: a tmpfs, so it never
// reaches a disk (removing a file there does not erase its blocks, nor a
// snapshot). XDG_RUNTIME_DIR is the user's own; /dev/shm is shared, but the
// copy's dir is 0700. Anything else is refused rather than used silently.
func plaintextDir() (string, error) {
	if runtime.GOOS != "linux" {
		return "", fmt.Errorf("secrets edit runs on Linux only: it can tell a tmpfs (where the plaintext copy goes) from a disk there, not on %s", runtime.GOOS)
	}
	for _, d := range []string{os.Getenv("XDG_RUNTIME_DIR"), "/dev/shm"} {
		if d != "" && isTmpfs(d) {
			return d, nil
		}
	}
	return "", errors.New("found no tmpfs for the plaintext copy (XDG_RUNTIME_DIR, /dev/shm); set XDG_RUNTIME_DIR to a directory on a tmpfs")
}

func isTmpfs(dir string) bool {
	var st syscall.Statfs_t
	if err := syscall.Statfs(dir, &st); err != nil {
		return false
	}
	const tmpfsMagic, ramfsMagic = 0x01021994, 0x858458f6
	t := uint32(st.Type)
	return t == tmpfsMagic || t == ramfsMagic
}

// Rekey encrypts host's secrets again, to the recipients its recipients file
// lists now: after adding a host's new identity or removing an operator. It
// does not take the values away from a removed recipient (see the package
// doc): that takes new values.
func (r SecretsRepo) Rekey(host string) ([]string, error) {
	s, err := r.open(host)
	if err != nil {
		return nil, err
	}
	plain, err := r.decrypt(s)
	if err != nil {
		return nil, err
	}
	if plain == nil {
		return nil, fmt.Errorf("%s has no %s; %s secrets edit %s creates it", host, SecretsFile(host), agentCommand, host)
	}
	lines, err := r.write(s, plain)
	var perr *secretsParseError
	if errors.As(err, &perr) {
		return nil, fmt.Errorf("%s: %w; fix it with %s secrets edit %s", SecretsFile(host), err, agentCommand, host)
	}
	return lines, err
}

// SecretsNextStep is what follows a new secrets file: its digest is in
// rendered/<host>/_resources.txt, so CI's infrafier diff fails until it is
// rendered again.
func SecretsNextStep(host string) string {
	return fmt.Sprintf("next: %s diff --update, then commit %s and rendered/%s", agentCommand, SecretsFile(host), host)
}

// DefaultOperatorIdentity is where the operator's age identity for the host
// secrets is: $OperatorIdentityEnv, else <user config dir>/<agentName>/
// age-identity, apart from the API token's config. Empty when there is no
// user config dir.
func DefaultOperatorIdentity() string {
	if p := os.Getenv(OperatorIdentityEnv); p != "" {
		return p
	}
	dir, err := os.UserConfigDir()
	if err != nil {
		return ""
	}
	return filepath.Join(dir, agentName, "age-identity")
}

// Keygen writes a new operator identity to p, never over an existing one.
func Keygen(p, comment string) (string, error) {
	identity, recipient, err := GenerateIdentity(comment)
	if err != nil {
		return "", err
	}
	if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
		return "", err
	}
	f, err := os.OpenFile(p, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return "", err
	}
	_, err = f.Write(identity)
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		os.Remove(p)
		return "", err
	}
	return recipient, nil
}
