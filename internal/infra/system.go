package infra

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net"
	"net/http"
	neturl "net/url"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"time"
)

// System is everything planning and applying touch on a host. Packages and
// units are queried and changed through Run (dpkg-query, apt-get, systemctl),
// so a test only fakes the command runner.
type System interface {
	Lstat(path string) (FileState, error)
	ReadDir(path string) ([]string, error)
	// WriteFile replaces path atomically (temp file in the same directory,
	// then rename), creating missing parent directories.
	WriteFile(path string, content []byte, mode fs.FileMode, owner, group string) error
	SetAttrs(path string, mode fs.FileMode, owner, group string) error
	Mkdir(path string, mode fs.FileMode, owner, group string) error
	RemoveAll(path string) error
	// Symlink creates path as a symbolic link to target.
	Symlink(target, path string) error
	// Rename moves oldpath to newpath, replacing it, within one directory.
	Rename(oldpath, newpath string) error
	// LstatSum is Lstat without Content: for a regular file it streams the
	// file through sha256 into SHA256 instead, so a large binary is never
	// held in memory.
	LstatSum(path string) (FileState, error)
	// LstatMeta is Lstat without Content: only the metadata, Stamp included.
	LstatMeta(path string) (FileState, error)
	// WriteFileFrom is WriteFile with the content read from r. When r fails,
	// its error is returned and path is left as it was.
	WriteFileFrom(path string, r io.Reader, mode fs.FileMode, owner, group string) error
	// Open opens a regular file for reading, never through a symlink.
	Open(path string) (io.ReadCloser, error)
	// Fetch GETs an https URL with header and secret added to the request. A
	// status other than 200 is an error. The secret headers are dropped on a
	// redirect to another host, and never appear in an error.
	Fetch(ctx context.Context, url string, header, secret http.Header) (io.ReadCloser, error)
	// Run runs argv and returns its standard output; stderr only goes into
	// the error, so a warning never ends up in a state that is parsed (e.g.
	// `systemctl is-active`). A non-zero exit is an error that wraps one with
	// an ExitCode() method, like *exec.ExitError.
	Run(ctx context.Context, argv ...string) ([]byte, error)
}

// FileState is what Lstat found. Content is only read for regular files,
// Link only for symlinks.
type FileState struct {
	Exists    bool
	IsDir     bool
	IsRegular bool
	IsSymlink bool
	Link      string
	Mode      fs.FileMode // permission bits only
	Owner     string
	Group     string
	UID, GID  uint32 // what Owner and Group were resolved from
	Content   []byte
	SHA256    string // hex, from LstatSum only
	// Stamp identifies this version of a regular file without reading it.
	Stamp Stamp
}

// Stamp is what changes whenever a file's content may have: its inode, size,
// mtime and ctime. The kernel sets ctime on every write, chmod and chown, and
// userspace cannot set it back, so a matching Stamp means an unchanged file
// even when its mtime was restored. Git and rsync rely on the same.
type Stamp struct {
	Dev   uint64 `json:"dev"`
	Ino   uint64 `json:"ino"`
	Size  int64  `json:"size"`
	Mtime int64  `json:"mtime"` // ns
	Ctime int64  `json:"ctime"` // ns
}

// Runner runs a command; OS uses exec by default.
type Runner func(ctx context.Context, argv ...string) ([]byte, error)

// OS is the real System. Root prefixes every path, which lets tests (and a
// future container e2e) apply into a directory.
//
// Files are reached without following a symlink out of a directory that a
// user other than root can change (see openDir), since the agent runs as root
// and modules write into directories services own (/etc/postgresql/…/main,
// Grafana's dashboards): otherwise such a user could swap a file for a link
// to /etc/shadow between plan and apply, and have it chmodded or shown in a
// diff.
type OS struct {
	Root   string
	Runner Runner
	// HTTP fetches downloads; nil is a client with connect and header
	// timeouts (the body is bounded by the ctx of the run).
	HTTP *http.Client
}

// waitDelay bounds how long a command's output is waited for after it exited
// (or was cancelled). Without it a command that leaves a child holding stdout
// (a daemon started with &) blocks the run for as long as the child lives.
var waitDelay = 10 * time.Second

// setupCmd makes cmd stop with SIGTERM when ctx is done, so a timeout does
// not SIGKILL dpkg halfway, and bounds the wait for its output.
func setupCmd(cmd *exec.Cmd) {
	cmd.Cancel = func() error { return cmd.Process.Signal(syscall.SIGTERM) }
	cmd.WaitDelay = waitDelay
}

// runCmd runs cmd. A command that exited 0 but left its output open past
// waitDelay succeeded; only the rest of its output is lost.
func runCmd(cmd *exec.Cmd) error {
	setupCmd(cmd)
	err := cmd.Run()
	if errors.Is(err, exec.ErrWaitDelay) {
		return nil
	}
	return err
}

func ExecRunner(ctx context.Context, argv ...string) ([]byte, error) {
	cmd := exec.CommandContext(ctx, argv[0], argv[1:]...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	if err := runCmd(cmd); err != nil {
		msg := bytes.TrimSpace(stderr.Bytes())
		if len(msg) == 0 {
			msg = bytes.TrimSpace(stdout.Bytes())
		}
		return stdout.Bytes(), fmt.Errorf("%s: %w: %s", argv[0], err, msg)
	}
	return stdout.Bytes(), nil
}

func (o *OS) path(p string) string { return filepath.Join(o.Root, p) }

func (o *OS) Run(ctx context.Context, argv ...string) ([]byte, error) {
	if o.Runner == nil {
		return ExecRunner(ctx, argv...)
	}
	return o.Runner(ctx, argv...)
}

// rootOnly tells whether only root can change what is in the directory.
func rootOnly(fi fs.FileInfo) bool {
	st, ok := fi.Sys().(*syscall.Stat_t)
	return ok && st.Uid == 0 && fi.Mode().Perm()&0o022 == 0
}

// openDir opens the directory p (under o.Root), creating missing ones (0755)
// when create is set. The directories from / down that only root can change
// are opened by path, so the host's own symlinks there (/lib → usr/lib) are
// followed. From the first one anybody else can change, each step is taken
// inside the directory before it (os.Root), so a symlink placed there cannot
// lead out of it. A symlink root placed in a root-only directory is trusted
// as a whole, even if its target runs through a directory a user can change.
func (o *OS) openDir(p string, create bool) (*os.Root, error) {
	full, err := filepath.Abs(o.path(p))
	if err != nil {
		return nil, err
	}
	var rest []string
	for _, c := range strings.Split(full, "/") {
		if c != "" {
			rest = append(rest, c)
		}
	}
	trusted := "/"
	for len(rest) > 0 {
		next := filepath.Join(trusted, rest[0])
		fi, err := os.Stat(next)
		if err != nil || !fi.IsDir() || !rootOnly(fi) {
			break // missing ones are created below, the same way
		}
		trusted, rest = next, rest[1:]
	}
	r, err := os.OpenRoot(trusted)
	if err != nil {
		return nil, err
	}
	for _, c := range rest {
		if create {
			if err := r.Mkdir(c, 0o755); err != nil && !errors.Is(err, fs.ErrExist) {
				r.Close()
				return nil, err
			}
		}
		next, err := r.OpenRoot(c)
		r.Close()
		if err != nil {
			return nil, fmt.Errorf("open %s: %w", full, err)
		}
		r = next
	}
	return r, nil
}

// inDir runs fn with the directory holding p and p's name in it.
func (o *OS) inDir(p string, create bool, fn func(r *os.Root, name string) error) error {
	r, err := o.openDir(filepath.Dir(p), create)
	if err != nil {
		return err
	}
	defer r.Close()
	return fn(r, filepath.Base(p))
}

// openNoFollow opens name in r, refusing a symlink, and checks that what it
// opened is what Lstat saw: a link swapped in between would otherwise be
// followed to a sibling.
func openNoFollow(r *os.Root, name string, flag int) (*os.File, fs.FileInfo, error) {
	lfi, err := r.Lstat(name)
	if err != nil {
		return nil, nil, err
	}
	if lfi.Mode()&fs.ModeSymlink != 0 {
		return nil, nil, fmt.Errorf("%s: is a symlink", name)
	}
	f, err := r.OpenFile(name, flag|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, nil, err
	}
	fi, err := f.Stat()
	if err == nil && !os.SameFile(lfi, fi) {
		err = fmt.Errorf("%s: changed while it was opened", name)
	}
	if err != nil {
		f.Close()
		return nil, nil, err
	}
	return f, fi, nil
}

type readMode int

const (
	readContent readMode = iota
	readSum
	readMeta
)

func (o *OS) Lstat(p string) (FileState, error) { return o.lstat(p, readContent) }

func (o *OS) LstatSum(p string) (FileState, error) { return o.lstat(p, readSum) }

func (o *OS) LstatMeta(p string) (FileState, error) { return o.lstat(p, readMeta) }

func (o *OS) lstat(p string, read readMode) (FileState, error) {
	var st FileState
	err := o.inDir(p, false, func(r *os.Root, name string) error {
		fi, err := r.Lstat(name)
		if err != nil {
			return err
		}
		if fi.Mode().IsRegular() && read != readMeta {
			// What is read and reported is the opened file itself, as it
			// was before the read: a write while it is hashed changes the
			// ctime after the Stamp, so the next run hashes it again.
			f, ofi, err := openNoFollow(r, name, os.O_RDONLY)
			if err != nil {
				return err
			}
			defer f.Close()
			if read == readSum {
				h := sha256.New()
				if _, err := io.Copy(h, f); err != nil {
					return err
				}
				st.SHA256 = hex.EncodeToString(h.Sum(nil))
			} else if st.Content, err = io.ReadAll(f); err != nil {
				return err
			}
			fi = ofi
		}
		st.Exists, st.IsDir, st.IsRegular = true, fi.IsDir(), fi.Mode().IsRegular()
		st.IsSymlink, st.Mode = fi.Mode()&fs.ModeSymlink != 0, fi.Mode().Perm()
		if sys, ok := fi.Sys().(*syscall.Stat_t); ok {
			st.UID, st.GID = sys.Uid, sys.Gid
			st.Owner = userName(sys.Uid)
			st.Group = groupName(sys.Gid)
			if st.IsRegular {
				st.Stamp = Stamp{Dev: uint64(sys.Dev), Ino: sys.Ino, Size: sys.Size,
					Mtime: sys.Mtim.Nano(), Ctime: sys.Ctim.Nano()}
			}
		}
		if st.IsSymlink {
			st.Link, err = r.Readlink(name)
		}
		return err
	})
	if errors.Is(err, fs.ErrNotExist) {
		return FileState{}, nil
	}
	if err != nil {
		return FileState{}, err
	}
	return st, nil
}

func (o *OS) ReadDir(p string) ([]string, error) {
	r, err := o.openDir(p, false)
	if err != nil {
		return nil, err
	}
	defer r.Close()
	f, err := r.Open(".")
	if err != nil {
		return nil, err
	}
	defer f.Close()
	entries, err := f.ReadDir(-1)
	if err != nil {
		return nil, err
	}
	names := make([]string, len(entries))
	for i, e := range entries {
		names[i] = e.Name()
	}
	slices.Sort(names)
	return names, nil
}

func (o *OS) WriteFile(p string, content []byte, mode fs.FileMode, owner, group string) error {
	return o.WriteFileFrom(p, bytes.NewReader(content), mode, owner, group)
}

func (o *OS) WriteFileFrom(p string, src io.Reader, mode fs.FileMode, owner, group string) error {
	return o.inDir(p, true, func(r *os.Root, name string) error {
		var rnd [8]byte
		rand.Read(rnd[:])
		tmp := "." + agentName + "-" + hex.EncodeToString(rnd[:])
		f, err := r.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
		if err != nil {
			return err
		}
		defer r.Remove(tmp) // fails harmlessly after the rename
		_, err = io.Copy(f, src)
		if err == nil {
			err = setAttrs(f, mode, owner, group)
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
		return r.Rename(tmp, name)
	})
}

func (o *OS) SetAttrs(p string, mode fs.FileMode, owner, group string) error {
	return o.inDir(p, false, func(r *os.Root, name string) error {
		f, _, err := openNoFollow(r, name, os.O_RDONLY)
		if err != nil {
			return err
		}
		defer f.Close()
		return setAttrs(f, mode, owner, group)
	})
}

func (o *OS) Mkdir(p string, mode fs.FileMode, owner, group string) error {
	// Missing parents get the usual 0755, not the leaf's (perhaps 0750)
	// mode, so its owner can still reach it.
	return o.inDir(p, true, func(r *os.Root, name string) error {
		if err := r.Mkdir(name, mode); err != nil && !errors.Is(err, fs.ErrExist) {
			return err
		}
		f, fi, err := openNoFollow(r, name, os.O_RDONLY)
		if err != nil {
			return err
		}
		defer f.Close()
		if !fi.IsDir() {
			return fmt.Errorf("%s: exists and is not a directory", p)
		}
		return setAttrs(f, mode, owner, group)
	})
}

func (o *OS) RemoveAll(p string) error {
	err := o.inDir(p, false, func(r *os.Root, name string) error { return r.RemoveAll(name) })
	if errors.Is(err, fs.ErrNotExist) {
		return nil // as os.RemoveAll: the parent is already gone
	}
	return err
}

// rootFile closes the directory it was opened in along with the file.
type rootFile struct {
	*os.File
	dir *os.Root
}

func (f rootFile) Close() error { return errors.Join(f.File.Close(), f.dir.Close()) }

func (o *OS) Open(p string) (io.ReadCloser, error) {
	r, err := o.openDir(filepath.Dir(p), false)
	if err != nil {
		return nil, err
	}
	f, fi, err := openNoFollow(r, filepath.Base(p), os.O_RDONLY)
	if err == nil && !fi.Mode().IsRegular() {
		f.Close()
		err = fmt.Errorf("%s: not a regular file", p)
	}
	if err != nil {
		r.Close()
		return nil, err
	}
	return rootFile{File: f, dir: r}, nil
}

var defaultHTTP = &http.Client{
	Transport: &http.Transport{
		Proxy:                 http.ProxyFromEnvironment,
		DialContext:           (&net.Dialer{Timeout: 30 * time.Second}).DialContext,
		TLSHandshakeTimeout:   30 * time.Second,
		ResponseHeaderTimeout: time.Minute,
	},
	CheckRedirect: httpsRedirectsOnly,
}

// httpsRedirectsOnly is http.Client's default redirect policy (at most 10)
// that also refuses to follow one to anything but https.
func httpsRedirectsOnly(req *http.Request, via []*http.Request) error {
	if req.URL.Scheme != "https" {
		return fmt.Errorf("redirected to %s: only https URLs are fetched", redactURL(req.URL))
	}
	if len(via) >= 10 {
		return errors.New("stopped after 10 redirects")
	}
	return nil
}

func (o *OS) Fetch(ctx context.Context, url string, header, secret http.Header) (io.ReadCloser, error) {
	if !strings.HasPrefix(url, "https://") {
		return nil, fmt.Errorf("%s: only https URLs are fetched", url)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	for k, vs := range header {
		req.Header[k] = vs
	}
	for k, vs := range secret {
		req.Header[k] = vs
	}
	req.Header.Set("User-Agent", agentName)
	c := o.HTTP
	if c == nil {
		c = defaultHTTP
	}
	if len(secret) > 0 {
		c = dropSecretsOffHost(c, secret)
	}
	resp, err := c.Do(req)
	if err != nil {
		// A *url.Error names the request that failed, which after a
		// redirect is a signed URL.
		var ue *neturl.Error
		if errors.As(err, &ue) {
			if u, perr := neturl.Parse(ue.URL); perr == nil {
				ue.URL = redactURL(u)
			}
		}
		return nil, err
	}
	// Also for a client with its own redirect policy (tests).
	if resp.Request.URL.Scheme != "https" {
		resp.Body.Close()
		return nil, fmt.Errorf("GET %s: redirected to %s: only https URLs are fetched", url, redactURL(resp.Request.URL))
	}
	if resp.StatusCode != http.StatusOK {
		resp.Body.Close()
		return nil, fmt.Errorf("GET %s: %s", url, resp.Status)
	}
	return resp.Body, nil
}

// dropSecretsOffHost is c with a redirect policy that also removes the
// secret headers from a redirect that leaves the first request's host, or
// follows one that did. net/http does that only for Authorization, Cookie
// and WWW-Authenticate, and only between domains, so a custom header (an
// X-Api-Key) would reach a signed download URL on a CDN, and its logs.
func dropSecretsOffHost(c *http.Client, secret http.Header) *http.Client {
	cc := *c
	next := c.CheckRedirect
	cc.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		if next != nil {
			if err := next(req, via); err != nil {
				return err
			}
		} else if len(via) >= 10 {
			return errors.New("stopped after 10 redirects")
		}
		// Not append(via[1:], req): that could write into net/http's
		// own slice of requests.
		left := !sameHost(req.URL, via[0].URL)
		for _, r := range via[1:] {
			left = left || !sameHost(r.URL, via[0].URL)
		}
		if left {
			for k := range secret {
				req.Header.Del(k)
			}
		}
		return nil
	}
	return &cc
}

// sameHost compares hosts as a server sees them: the name in any case, and
// the port with the scheme's default filled in, so https://API.example.com:443
// and https://api.example.com are the same host.
func sameHost(a, b *neturl.URL) bool {
	return strings.EqualFold(a.Hostname(), b.Hostname()) && effectivePort(a) == effectivePort(b)
}

func effectivePort(u *neturl.URL) string {
	if p := u.Port(); p != "" {
		return p
	}
	switch strings.ToLower(u.Scheme) {
	case "https":
		return "443"
	case "http":
		return "80"
	}
	return ""
}

// redactURL is u without its userinfo, query and fragment, for errors: a
// redirect's query is often a signature (a signed download URL), a
// credential for as long as it is valid.
func redactURL(u *neturl.URL) string {
	r := *u
	r.User, r.RawQuery, r.ForceQuery, r.Fragment, r.RawFragment = nil, "", false, "", ""
	return r.String()
}

func (o *OS) Rename(oldpath, newpath string) error {
	if filepath.Dir(oldpath) != filepath.Dir(newpath) {
		return fmt.Errorf("rename %s to %s: not in one directory", oldpath, newpath)
	}
	return o.inDir(newpath, false, func(r *os.Root, name string) error { return r.Rename(filepath.Base(oldpath), name) })
}

func (o *OS) Symlink(target, p string) error {
	return o.inDir(p, true, func(r *os.Root, name string) error { return r.Symlink(target, name) })
}

// setAttrs sets the mode and owner of the open file f, never of whatever its
// path names by now.
func setAttrs(f *os.File, mode fs.FileMode, owner, group string) error {
	if err := f.Chmod(mode); err != nil {
		return err
	}
	if owner == "" && group == "" {
		return nil
	}
	uid, gid := -1, -1
	if owner != "" {
		var err error
		if uid, err = lookupID(owner, func(n string) (string, error) {
			u, err := user.Lookup(n)
			if err != nil {
				return "", err
			}
			return u.Uid, nil
		}); err != nil {
			return err
		}
	}
	if group != "" {
		var err error
		if gid, err = lookupID(group, func(n string) (string, error) {
			g, err := user.LookupGroup(n)
			if err != nil {
				return "", err
			}
			return g.Gid, nil
		}); err != nil {
			return err
		}
	}
	return f.Chown(uid, gid)
}

// lookupID resolves a user or group name to its id. A number that names no
// one is taken as the id itself: Lstat reports an owner without a passwd
// entry that way (userName), and restore must be able to put it back.
func lookupID(name string, lookup func(string) (string, error)) (int, error) {
	id, err := lookup(name)
	if err != nil {
		if n, perr := strconv.Atoi(name); perr == nil && n >= 0 {
			return n, nil
		}
		return -1, err
	}
	return strconv.Atoi(id)
}

func userName(uid uint32) string {
	id := strconv.FormatUint(uint64(uid), 10)
	if u, err := user.LookupId(id); err == nil {
		return u.Username
	}
	return id
}

func groupName(gid uint32) string {
	id := strconv.FormatUint(uint64(gid), 10)
	if g, err := user.LookupGroupId(id); err == nil {
		return g.Name
	}
	return id
}

// exitedNonZero tells a command that ran and failed (e.g. `systemctl
// is-active` on a stopped unit) from one that could not run at all. It
// matches *exec.ExitError and the fakes in tests.
func exitedNonZero(err error) bool {
	code, ok := exitCode(err)
	return ok && code > 0
}

// exitCode is the exit code of the command err comes from, if it ran.
func exitCode(err error) (int, bool) {
	var ee interface{ ExitCode() int }
	if !errors.As(err, &ee) {
		return 0, false
	}
	return ee.ExitCode(), true
}
