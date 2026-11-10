package infra

import (
	"archive/tar"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"hash"
	"io"
	"path"
	"strings"
	"time"
)

// The download cache. Planning fills it (MakePlan otherwise only reads):
// whether an installed file is current can only be told from the sha256 of
// the archive member, which needs the archive once.
//
//	blobs/<sha256>          a file to install, named by its own sha256
//	archives/<sha256>.json  archive sha256 → {member: sha256 of its blob}
//	installed.json          installed path → its sha256 and Stamp (installedIndex)
//
// Both are named by content, so a stale or half-written entry can only be
// missing, never wrong: a blob is checked against its name again while it is
// installed. Apply removes the entries the plan's downloads no longer use,
// so old versions don't pile up, and the blobs whose files are all installed:
// otherwise every pinned file is on disk twice, ~700 MB with
// monitoring and Traefik. A manifest stays while its download is pinned, so a
// plan still tells an installed member is current without the archive. The
// price: a file changed after it was installed (by hand, or by a package
// shipping the same path) has no blob to be put back from, and its download
// is fetched again (Prometheus: ~120 MB).
const downloadCache = HostStateDir + "/downloads"

// Limits on what a download may be. Prometheus, the biggest one planned, is
// ~120 MB as a tarball with ~300 MB of binaries in it.
var (
	maxDownloadBytes int64 = 2 << 30
	maxMemberBytes   int64 = 1 << 30
	// downloadTimeout bounds one fetch, so a stalled mirror fails the run
	// rather than holding the pull lock for the unit's whole hour.
	downloadTimeout = 15 * time.Minute
	// racyWindow: a file whose ctime is less than this before it was hashed
	// is not put in installed.json (downloadCacheUse.stat). A second is far
	// more than a kernel tick (1-4 ms), the window that matters.
	racyWindow = time.Second
	now        = time.Now
)

type archiveManifest struct {
	Members map[string]string `json:"members"`
}

func blobPath(sum string) string     { return downloadCache + "/blobs/" + sum }
func manifestPath(sum string) string { return downloadCache + "/archives/" + sum + ".json" }

// installedIndex is downloads/installed.json: the sha256 of each installed
// download file with the Stamp it had when it was hashed or installed. A
// plan hashes a file only when its Stamp changed, so a pull does not read
// every binary on the host (~700 MB with monitoring and Traefik) to find
// that nothing changed.
type installedIndex map[string]installedEntry

type installedEntry struct {
	Stamp  Stamp  `json:"stamp"`
	SHA256 string `json:"sha256"`
}

const indexPath = downloadCache + "/installed.json"

// downloadCacheUse is what the plan's downloads know of and need from the
// cache: Apply prunes the blobs and manifests they don't name, and the blobs
// whose files are installed, and saves the index for the files they install.
type downloadCacheUse struct {
	blobs     map[string][]string // blob sha256 → the files installed from it
	manifests map[string]bool
	present   map[string]bool // blobs/ as read once per plan; nil until then
	index     installedIndex  // nil until read
	paths     map[string]bool // the files the plan's downloads install
	dirty     bool
}

func newDownloadCacheUse() *downloadCacheUse {
	return &downloadCacheUse{blobs: map[string][]string{}, manifests: map[string]bool{}, paths: map[string]bool{}}
}

// add marks the cache entries d uses: its manifest and the blobs of the
// members it installs now, not those an earlier commit extracted, with the
// files each is installed to. Two downloads may share a blob.
func (u *downloadCacheUse) add(d *Download, memberSums map[string]string) {
	if d.Files[0].Member == "" {
		u.blobs[d.SHA256] = append(u.blobs[d.SHA256], d.Files[0].Path)
		return
	}
	u.manifests[d.SHA256] = true
	for _, f := range d.Files {
		s := memberSums[f.Member]
		u.blobs[s] = append(u.blobs[s], f.Path)
	}
}

// blobNeeded tells whether a blob the plan uses must stay in the cache: some
// file installed from it may not hold it. Without hashing, a file holds it
// when this run's index entry for it names the blob and its Stamp has not
// changed since. Anything less certain (an entry left out as racy, a file
// gone, an error) keeps the blob; the next run prunes it once it can tell.
func (u *downloadCacheUse) blobNeeded(sys System, sum string) bool {
	for _, p := range u.blobs[sum] {
		e, ok := u.index[p]
		if !ok || e.SHA256 != sum {
			return true
		}
		st, err := sys.LstatMeta(p)
		if err != nil || !st.IsRegular || st.Stamp != e.Stamp {
			return true
		}
	}
	return false
}

func (u *downloadCacheUse) loadIndex(sys System) error {
	if u.index != nil {
		return nil
	}
	u.index = installedIndex{}
	st, err := sys.Lstat(indexPath)
	if err != nil || !st.Exists {
		return err
	}
	if !st.IsRegular {
		// saveIndex could not replace a directory, and each run would hash
		// every file again without saying why.
		return fmt.Errorf("%s exists and is not a regular file", indexPath)
	}
	// "null" decodes without an error into a nil map, which stat could not
	// write to.
	if json.Unmarshal(st.Content, &u.index) != nil || u.index == nil {
		u.index, u.dirty = installedIndex{}, true // rebuilt by hashing
	}
	return nil
}

// stat is LstatSum, with the sha256 taken from the index when the file's
// Stamp has not changed since it was recorded.
func (u *downloadCacheUse) stat(sys System, p string) (FileState, error) {
	u.paths[p] = true
	if err := u.loadIndex(sys); err != nil {
		return FileState{}, err
	}
	st, err := sys.LstatMeta(p)
	if err != nil || !st.IsRegular {
		return st, err
	}
	if e, ok := u.index[p]; ok && e.Stamp == st.Stamp && e.SHA256 != "" {
		st.SHA256 = e.SHA256
		return st, nil
	}
	hashed := now() // before the stat: a write after it is what is caught
	if st, err = sys.LstatSum(p); err != nil || !st.IsRegular {
		return st, err
	}
	// A write within one tick of the file's last change keeps its ctime
	// (ext4 takes it from the coarse kernel clock), so the Stamp cannot tell
	// whether the file changed while it was hashed. Such a file is not
	// recorded and is hashed again next run, as git does with "racy" index
	// entries.
	if hashed.Sub(time.Unix(0, st.Stamp.Ctime)) < racyWindow {
		u.forget(p)
		return st, nil
	}
	u.index[p], u.dirty = installedEntry{Stamp: st.Stamp, SHA256: st.SHA256}, true
	return st, nil
}

// forget drops p from the index, so the next run hashes it.
func (u *downloadCacheUse) forget(p string) {
	if _, ok := u.index[p]; ok {
		delete(u.index, p)
		u.dirty = true
	}
}

// record notes that p now holds content with sha256 sum, written or
// chmodded by this run (which changed its ctime). Unlike stat, it records a
// fresh ctime: the content is what this run wrote, not what a hash read.
func (u *downloadCacheUse) record(sys System, p, sum string) error {
	st, err := sys.LstatMeta(p)
	if err != nil {
		return err
	}
	if u.index == nil {
		u.index = installedIndex{}
	}
	u.index[p], u.dirty = installedEntry{Stamp: st.Stamp, SHA256: sum}, true
	return nil
}

// saveIndex writes the index, without the files no download installs any
// more.
func (u *downloadCacheUse) saveIndex(sys System) error {
	for p := range u.index {
		if !u.paths[p] {
			delete(u.index, p)
			u.dirty = true
		}
	}
	if !u.dirty {
		return nil
	}
	if len(u.index) == 0 {
		u.dirty = false
		return sys.RemoveAll(indexPath)
	}
	if err := ensureCacheDirs(sys); err != nil {
		return err
	}
	b, err := json.Marshal(u.index)
	if err != nil {
		return err
	}
	if err := sys.WriteFile(indexPath, b, 0o600, "", ""); err != nil {
		return err
	}
	u.dirty = false
	return nil
}

// hasBlob tells whether the blob is cached, reading blobs/ once per plan:
// Lstat would read all of the blob.
func (u *downloadCacheUse) hasBlob(sys System, sum string) (bool, error) {
	if u.present == nil {
		u.present = map[string]bool{}
		dir := downloadCache + "/blobs"
		st, err := sys.Lstat(dir)
		if err != nil {
			return false, err
		}
		if st.Exists {
			names, err := sys.ReadDir(dir)
			if err != nil {
				return false, err
			}
			for _, n := range names {
				u.present[n] = true
			}
		}
	}
	return u.present[sum], nil
}

// fetched adds the blobs a fetch of d just wrote, those of the members in
// extracted, to the listing of blobs/, so a later download that needs one of
// them does not fetch again.
func (u *downloadCacheUse) fetched(sums map[string]string, extracted map[string]bool) {
	if u.present == nil {
		return // not read yet: the listing will include them
	}
	for m := range extracted {
		u.present[sums[m]] = true
	}
}

func planDownload(ctx context.Context, sys System, d *Download, use *downloadCacheUse) ([]*Change, error) {
	sums, err := memberSums(sys, d)
	if err != nil {
		return nil, err
	}
	type target struct {
		f   DownloadFile
		st  FileState
		sum string
	}
	var targets []target
	// need is the members to extract when the download is fetched: those
	// whose blob is missing for a file to install, or that no earlier fetch
	// extracted. The others' files are current, and their blobs would only
	// be pruned again: one drifted promtool would otherwise put all
	// of Prometheus back into blobs/, ~300 MB.
	need := map[string]bool{}
	for _, f := range d.Files {
		st, err := use.stat(sys, f.Path)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", f.Path, err)
		}
		if st.IsDir {
			return nil, fmt.Errorf("%s: is a directory", f.Path)
		}
		if st.Exists && !st.IsRegular && !st.IsSymlink {
			return nil, fmt.Errorf("%s: exists and is neither a regular file nor a symlink", f.Path)
		}
		sum := sums[f.Member]
		if sum == "" {
			need[f.Member] = true // a member no earlier fetch extracted
		} else if st.SHA256 != sum {
			// To be installed: the blob has to be there.
			if ok, err := use.hasBlob(sys, sum); err != nil {
				return nil, err
			} else if !ok {
				need[f.Member] = true
			}
		}
		targets = append(targets, target{f: f, st: st, sum: sum})
	}
	if len(need) > 0 {
		if sums, err = fetchDownload(ctx, sys, d, need); err != nil {
			return nil, err
		}
		use.fetched(sums, need)
		for i := range targets {
			targets[i].sum = sums[targets[i].f.Member]
		}
	}
	use.add(d, sums)

	var changes []*Change
	for _, t := range targets {
		f, st, sum := t.f, t.st, t.sum
		name := path.Base(d.URL)
		if f.Member != "" {
			name += ":" + f.Member
		}
		c := &Change{Key: d.Key() + ":" + f.Path, actions: d.OnChange}
		switch {
		case !st.Exists:
			c.Summary = fmt.Sprintf("install %s from %s (sha256 %s)", f.Path, name, short(sum))
		case st.IsSymlink:
			c.Summary = fmt.Sprintf("replace %s (a symlink to %s) with %s (sha256 %s)", f.Path, st.Link, name, short(sum))
		case st.SHA256 != sum:
			c.Summary = fmt.Sprintf("install %s from %s (sha256 %s → %s)%s", f.Path, name, short(st.SHA256), short(sum), attrsChanged(st, d.Mode, d.Owner, d.Group))
		default:
			attrs := attrsChanged(st, d.Mode, d.Owner, d.Group)
			if attrs == "" {
				continue
			}
			c.Summary = "update " + f.Path + attrs
			c.do = func(ctx context.Context, sys System) error {
				if err := sys.SetAttrs(f.Path, d.Mode, d.Owner, d.Group); err != nil {
					return err
				}
				// Not recorded as planned: an earlier change in this run (a
				// package shipping the path) may have rewritten it, and
				// its new Stamp would vouch for the pin. Hashed again
				// instead, and left out of the index like any file hashed
				// right after a change (stat), so the next run hashes it.
				st, err := sys.LstatSum(f.Path)
				if err != nil {
					return err
				}
				if st.SHA256 != sum {
					return fmt.Errorf("%s changed during the run: sha256 %s, want %s", f.Path, short(st.SHA256), short(sum))
				}
				use.forget(f.Path)
				return nil
			}
			changes = append(changes, c)
			continue
		}
		c.do = func(ctx context.Context, sys System) error {
			if err := installBlob(ctx, sys, sum, f.Path, d); err != nil {
				return err
			}
			return use.record(sys, f.Path, sum)
		}
		changes = append(changes, c)
	}
	return changes, nil
}

// memberSums is the sha256 of each file a download installs, as far as the
// cache knows them; nil when it doesn't know the archive at all.
func memberSums(sys System, d *Download) (map[string]string, error) {
	if d.Files[0].Member == "" {
		return map[string]string{"": d.SHA256}, nil
	}
	st, err := sys.Lstat(manifestPath(d.SHA256))
	if err != nil || !st.Exists {
		return nil, err
	}
	var m archiveManifest
	if !st.IsRegular || json.Unmarshal(st.Content, &m) != nil || m.Members == nil {
		return nil, nil // fetched again and rewritten
	}
	return m.Members, nil
}

// installBlob copies the blob named sum to p, checking it against its name
// on the way: a blob that no longer matches (a bad disk) is removed, so the
// next run fetches it again, and p is left as it was.
func installBlob(ctx context.Context, sys System, sum, p string, d *Download) error {
	src, err := sys.Open(blobPath(sum))
	if err != nil {
		return err
	}
	defer src.Close()
	limit := maxMemberBytes
	if d.Files[0].Member == "" {
		limit = maxDownloadBytes // the download itself, fetched under that limit
	}
	r := newVerifyingReader(src, sum, limit)
	if len(d.PreInstallCheck) == 0 && !d.KeepPrevious {
		err = sys.WriteFileFrom(p, r, d.Mode, d.Owner, d.Group)
	} else {
		err = installStaged(ctx, sys, r, p, d)
	}
	// A blob that no longer matches its name, or grew past the limit, would
	// fail the same way every run: removed, so the next run fetches it.
	var mismatch *checksumError
	var tooBig *sizeError
	if errors.As(err, &mismatch) || errors.As(err, &tooBig) {
		return errors.Join(err, sys.RemoveAll(blobPath(sum)))
	}
	return err
}

// stagedPath is where installStaged writes the new file: in p's directory,
// so the rename into place is atomic, and hidden. Only one pull runs at a
// time, so the name is fixed and a crash's leftover is overwritten.
func stagedPath(p string) string {
	return path.Dir(p) + "/." + path.Base(p) + "." + agentName + "-new"
}

// installStaged installs the new file in steps the plain WriteFileFrom does
// in one: it writes it to stagedPath, runs the pre-install check on it, keeps
// the old file as <p>.prev, and only then renames the new one over p. The
// rename leaves a running binary its inode, so the agent replacing itself
// carries on with the old code until the run ends; the next run is the new
// one's. A failure anywhere before the rename leaves p as it was.
func installStaged(ctx context.Context, sys System, r io.Reader, p string, d *Download) error {
	tmp := stagedPath(p)
	if err := sys.WriteFileFrom(tmp, r, d.Mode, d.Owner, d.Group); err != nil {
		return err
	}
	installed := false
	defer func() {
		if !installed {
			sys.RemoveAll(tmp)
		}
	}()
	if len(d.PreInstallCheck) > 0 {
		argv := make([]string, len(d.PreInstallCheck))
		for i, a := range d.PreInstallCheck {
			argv[i] = strings.ReplaceAll(a, PreInstallFile, tmp)
		}
		if _, err := sys.Run(ctx, argv...); err != nil {
			return fmt.Errorf("not installed, the pre-install check of the new file failed (%s): %w", strings.Join(d.PreInstallCheck, " "), err)
		}
	}
	if d.KeepPrevious && !d.leavePrevious {
		if err := keepPrevious(sys, p); err != nil {
			return fmt.Errorf("keep %s: %w", previousPath(p), err)
		}
	}
	if err := sys.Rename(tmp, p); err != nil {
		return err
	}
	installed = true
	return nil
}

// keepPrevious copies p, when it is a regular file, to <p>.prev, with p's own
// mode and owner: the new file's could let more users read the old content.
// A copy, not a rename, so p is never missing: the pull unit runs it, and a
// crash between two renames would leave the host without its agent.
func keepPrevious(sys System, p string) error {
	st, err := sys.LstatMeta(p)
	if err != nil || !st.IsRegular {
		return err
	}
	src, err := sys.Open(p)
	if err != nil {
		return err
	}
	defer src.Close()
	return sys.WriteFileFrom(previousPath(p), src, st.Mode, st.Owner, st.Group)
}

// fetchDownload fetches d, checks it against its pin and puts the members in
// want (the download itself, "", when it is not an archive) into the cache.
// It returns the sha256 of each file to install: of the others, as an earlier
// fetch recorded them in the manifest.
func fetchDownload(ctx context.Context, sys System, d *Download, want map[string]bool) (map[string]string, error) {
	if err := ensureCacheDirs(sys); err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(ctx, downloadTimeout)
	defer cancel()
	body, err := sys.Fetch(ctx, d.URL)
	if err != nil {
		return nil, err
	}
	defer body.Close()
	if d.Files[0].Member == "" {
		if err := sys.WriteFileFrom(blobPath(d.SHA256), newVerifyingReader(body, d.SHA256, maxDownloadBytes), 0o600, "", ""); err != nil {
			return nil, fmt.Errorf("fetch %s: %w", d.URL, err)
		}
		return map[string]string{"": d.SHA256}, nil
	}

	// The archive is checked as a whole before anything in it is used, so
	// it goes to disk first; it is removed once its members are out.
	tmp := downloadCache + "/archives/" + d.SHA256 + ".download"
	defer sys.RemoveAll(tmp)
	if err := sys.WriteFileFrom(tmp, newVerifyingReader(body, d.SHA256, maxDownloadBytes), 0o600, "", ""); err != nil {
		return nil, fmt.Errorf("fetch %s: %w", d.URL, err)
	}
	// One pass: each member is written to a temporary name in blobs/ while
	// it is hashed, then renamed to its sha256. eachMember bounds its size.
	// A temporary file a crash leaves behind is named by no download, so
	// the next prune removes it.
	sums := map[string]string{}
	i := 0
	if err := eachMember(sys, tmp, want, func(name string, r io.Reader) error {
		i++
		part := fmt.Sprintf("%s/blobs/.extract-%s-%d", downloadCache, d.SHA256, i)
		h := sha256.New()
		if err := sys.WriteFileFrom(part, io.TeeReader(r, h), 0o600, "", ""); err != nil {
			return err
		}
		sum := hex.EncodeToString(h.Sum(nil))
		if err := sys.Rename(part, blobPath(sum)); err != nil {
			sys.RemoveAll(part)
			return err
		}
		sums[name] = sum
		return nil
	}); err != nil {
		return nil, fmt.Errorf("%s: %w", d.URL, err)
	}
	for member := range want {
		if sums[member] == "" {
			return nil, fmt.Errorf("%s: archive has no regular file %s", d.URL, member)
		}
	}
	// Keep what earlier commits extracted from the same archive.
	if old, err := memberSums(sys, d); err == nil {
		for m, s := range old {
			if _, ok := sums[m]; !ok {
				sums[m] = s
			}
		}
	}
	b, err := json.Marshal(archiveManifest{Members: sums})
	if err != nil {
		return nil, err
	}
	return sums, sys.WriteFile(manifestPath(d.SHA256), b, 0o600, "", "")
}

func ensureCacheDirs(sys System) error {
	for _, dir := range []string{downloadCache, downloadCache + "/blobs", downloadCache + "/archives"} {
		if err := sys.Mkdir(dir, 0o700, "", ""); err != nil {
			return err
		}
	}
	return nil
}

// eachMember calls fn for each regular file of the .tar.gz at p whose clean
// name is in want. Names are only compared, never used as paths, so a member
// like ../../etc/passwd can't write anywhere.
func eachMember(sys System, p string, want map[string]bool, fn func(name string, r io.Reader) error) error {
	f, err := sys.Open(p)
	if err != nil {
		return err
	}
	defer f.Close()
	gz, err := gzip.NewReader(f)
	if err != nil {
		return fmt.Errorf("not a .tar.gz: %w", err)
	}
	defer gz.Close()
	tr := tar.NewReader(gz)
	seen := map[string]bool{}
	for {
		hdr, err := tr.Next()
		if errors.Is(err, io.EOF) {
			return nil
		}
		if err != nil {
			return fmt.Errorf("read archive: %w", err)
		}
		name := path.Clean(strings.TrimPrefix(hdr.Name, "./"))
		if !want[name] || hdr.Typeflag != tar.TypeReg {
			continue
		}
		if seen[name] {
			return fmt.Errorf("archive has %s twice", name)
		}
		seen[name] = true
		if hdr.Size > maxMemberBytes {
			return fmt.Errorf("%s is %d bytes, more than %d", name, hdr.Size, maxMemberBytes)
		}
		if err := fn(name, tr); err != nil {
			return fmt.Errorf("%s: %w", name, err)
		}
	}
}

type checksumError struct{ want, got string }

func (e *checksumError) Error() string {
	return fmt.Sprintf("sha256 mismatch: want %s, got %s", e.want, e.got)
}

type sizeError struct{ limit int64 }

func (e *sizeError) Error() string { return fmt.Sprintf("more than %d bytes", e.limit) }

// verifyingReader passes r through and, instead of a clean EOF, fails when
// what it read does not hash to want or is longer than limit. WriteFileFrom
// then never renames the file into place.
type verifyingReader struct {
	r     io.Reader
	h     hash.Hash
	want  string
	left  int64
	limit int64
}

func newVerifyingReader(r io.Reader, want string, limit int64) *verifyingReader {
	return &verifyingReader{r: r, h: sha256.New(), want: want, left: limit + 1, limit: limit}
}

func (v *verifyingReader) Read(p []byte) (int, error) {
	if int64(len(p)) > v.left {
		p = p[:v.left]
	}
	n, err := v.r.Read(p)
	v.h.Write(p[:n])
	v.left -= int64(n)
	if v.left <= 0 {
		return n, &sizeError{limit: v.limit}
	}
	if errors.Is(err, io.EOF) {
		if got := hex.EncodeToString(v.h.Sum(nil)); got != v.want {
			return n, &checksumError{want: v.want, got: got}
		}
	}
	return n, err
}

// pruneDownloads removes the cache entries use does not name, and the blobs
// it names whose files are all installed. It runs only after an apply
// without errors, so a failed run keeps what its retry needs.
func pruneDownloads(sys System, use *downloadCacheUse) error {
	var errs []error
	prune := func(dir string, keep func(name string) bool) {
		st, err := sys.Lstat(dir)
		if err != nil || !st.Exists {
			errs = append(errs, err)
			return
		}
		names, err := sys.ReadDir(dir)
		if err != nil {
			errs = append(errs, err)
			return
		}
		for _, n := range names {
			if !keep(n) {
				errs = append(errs, sys.RemoveAll(dir+"/"+n))
			}
		}
	}
	prune(downloadCache+"/blobs", func(n string) bool {
		_, ok := use.blobs[n]
		return ok && use.blobNeeded(sys, n)
	})
	prune(downloadCache+"/archives", func(n string) bool {
		sum, ok := strings.CutSuffix(n, ".json")
		return ok && use.manifests[sum]
	})
	return errors.Join(errs...)
}

func planUser(ctx context.Context, sys System, u *User) ([]*Change, error) {
	found, err := getent(ctx, sys, "passwd", u.Name)
	if err != nil {
		return nil, err
	}
	if !found {
		return []*Change{{Key: u.Key(), Summary: "create system user " + u.Name, do: func(ctx context.Context, sys System) error {
			// A package installed earlier in this run may have created
			// the user (as Debian packages do for their service
			// account): useradd would exit 9 and stop the run.
			if found, err := getent(ctx, sys, "passwd", u.Name); err != nil {
				return err
			} else if found {
				return addMissingGroups(ctx, sys, u)
			}
			// Checked here, not in the plan: a package installed earlier
			// in this run may create the groups.
			if err := groupsExist(ctx, sys, u); err != nil {
				return err
			}
			// --user-group refuses a group of that name that is left
			// over (a removed package): join it instead.
			own, err := getent(ctx, sys, "group", u.Name)
			if err != nil {
				return err
			}
			args := []string{"useradd", "--system", "--home-dir", u.Home, "--no-create-home", "--shell", "/usr/sbin/nologin"}
			if own {
				args = append(args, "--gid", u.Name)
			} else {
				args = append(args, "--user-group")
			}
			if len(u.Groups) > 0 {
				args = append(args, "--groups", strings.Join(u.Groups, ","))
			}
			_, err = sys.Run(ctx, append(args, u.Name)...)
			return err
		}}}, nil
	}
	missing, err := missingGroups(ctx, sys, u)
	if err != nil || len(missing) == 0 {
		return nil, err
	}
	return []*Change{{Key: u.Key(), Summary: "add user " + u.Name + " to " + strings.Join(missing, ", "), do: func(ctx context.Context, sys System) error {
		return addMissingGroups(ctx, sys, u)
	}}}, nil
}

// missingGroups is u.Groups less those the user is in.
func missingGroups(ctx context.Context, sys System, u *User) ([]string, error) {
	if len(u.Groups) == 0 {
		return nil, nil
	}
	out, err := sys.Run(ctx, "id", "-nG", u.Name)
	if err != nil {
		return nil, fmt.Errorf("id: %w", err)
	}
	has := map[string]bool{}
	for _, g := range strings.Fields(string(out)) {
		has[g] = true
	}
	var missing []string
	for _, g := range u.Groups {
		if !has[g] {
			missing = append(missing, g)
		}
	}
	return missing, nil
}

// addMissingGroups adds the user to the groups it is not in, as they are
// at apply time.
func addMissingGroups(ctx context.Context, sys System, u *User) error {
	missing, err := missingGroups(ctx, sys, u)
	if err != nil || len(missing) == 0 {
		return err
	}
	if err := groupsExist(ctx, sys, u); err != nil {
		return err
	}
	_, err = sys.Run(ctx, "usermod", "--append", "--groups", strings.Join(missing, ","), u.Name)
	return err
}

// getent tells whether the passwd or group database has name; exit 2 is
// "not found", anything else that fails is an error.
func getent(ctx context.Context, sys System, db, name string) (bool, error) {
	_, err := sys.Run(ctx, "getent", db, name)
	if err == nil {
		return true, nil
	}
	if code, ran := exitCode(err); ran && code == 2 {
		return false, nil
	}
	return false, fmt.Errorf("getent %s: %w", db, err)
}

func groupsExist(ctx context.Context, sys System, u *User) error {
	for _, g := range u.Groups {
		ok, err := getent(ctx, sys, "group", g)
		if err != nil {
			return err
		}
		if !ok {
			return fmt.Errorf("user %s: group %s does not exist; list the package that creates it before the user, or create it", u.Name, g)
		}
	}
	return nil
}
