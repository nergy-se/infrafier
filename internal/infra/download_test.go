package infra

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"testing/fstest"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func sum(b []byte) string {
	s := sha256.Sum256(b)
	return hex.EncodeToString(s[:])
}

type member struct {
	name string
	body string
	typ  byte
}

func tarGz(t *testing.T, entries ...member) []byte {
	t.Helper()
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	for _, e := range entries {
		typ := e.typ
		if typ == 0 {
			typ = tar.TypeReg
		}
		hdr := &tar.Header{Name: e.name, Mode: 0o755, Typeflag: typ}
		if typ == tar.TypeReg {
			hdr.Size = int64(len(e.body))
		} else {
			hdr.Linkname = e.body
		}
		require.NoError(t, tw.WriteHeader(hdr))
		if typ == tar.TypeReg {
			_, err := tw.Write([]byte(e.body))
			require.NoError(t, err)
		}
	}
	require.NoError(t, tw.Close())
	require.NoError(t, gz.Close())
	return buf.Bytes()
}

// files serves path → content and counts the requests.
type files struct {
	content  map[string][]byte
	requests atomic.Int32
}

func serve(t *testing.T, sys *OS) (*files, string) {
	t.Helper()
	f := &files{content: map[string][]byte{}}
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.requests.Add(1)
		b, ok := f.content[r.URL.Path]
		if !ok {
			http.NotFound(w, r)
			return
		}
		w.Write(b)
	}))
	t.Cleanup(srv.Close)
	sys.HTTP = srv.Client()
	return f, srv.URL
}

func cacheEntries(t *testing.T, sys *OS, dir string) []string {
	t.Helper()
	entries, err := os.ReadDir(filepath.Join(sys.Root, downloadCache, dir))
	require.NoError(t, err)
	var names []string
	for _, e := range entries {
		names = append(names, e.Name())
	}
	return names
}

func promDownload(url, sha string) *Download {
	return &Download{URL: url, SHA256: sha, Mode: 0o755,
		Files: []DownloadFile{
			{Member: "prom-1/prometheus", Path: "/usr/local/bin/prometheus"},
			{Member: "prom-1/promtool", Path: "/usr/local/bin/promtool"},
		},
		OnChange: []Action{{Verb: "restart", Unit: "prometheus.service"}},
	}
}

func TestDownloadInstallsArchiveMembers(t *testing.T) {
	sys, run := newTestSystem(t)
	srv, base := serve(t, sys)
	archive := tarGz(t,
		member{name: "prom-1/", typ: tar.TypeDir},
		member{name: "prom-1/prometheus", body: "prometheus v1"},
		member{name: "./prom-1/promtool", body: "promtool v1"},
		member{name: "prom-1/LICENSE", body: "license"},
	)
	srv.content["/prom-1.tar.gz"] = archive
	d := promDownload(base+"/prom-1.tar.gz", sum(archive))

	p, still, err := planAndApply(t, sys, []Resource{d}, nil)
	require.NoError(t, err)
	assert.Empty(t, still)
	assert.Contains(t, p.String(), "install /usr/local/bin/prometheus from prom-1.tar.gz:prom-1/prometheus (sha256 "+sum([]byte("prometheus v1"))[:12]+")")
	assert.Equal(t, "prometheus v1", readRoot(t, sys, "/usr/local/bin/prometheus"))
	assert.Equal(t, "promtool v1", readRoot(t, sys, "/usr/local/bin/promtool"))
	fi, err := os.Stat(filepath.Join(sys.Root, "/usr/local/bin/prometheus"))
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0o755), fi.Mode().Perm())
	assert.Equal(t, []string{"systemctl restart prometheus.service"}, run.changing())
	// Neither the archive nor, once installed, its members are kept:
	// only the manifest, which tells the next plan what to expect.
	assert.Empty(t, cacheEntries(t, sys, "blobs"))
	assert.Equal(t, []string{sum(archive) + ".json"}, cacheEntries(t, sys, "archives"))
	fi, err = os.Stat(filepath.Join(sys.Root, downloadCache))
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0o700), fi.Mode().Perm())

	// Installed: the next plan only hashes, and fetches nothing.
	p, err = MakePlan(context.Background(), sys, []Resource{d})
	require.NoError(t, err)
	assert.True(t, p.Empty(), p.String())
	assert.Equal(t, int32(1), srv.requests.Load())

	// A file changed by hand has no blob left to be put back from: the
	// archive is fetched again, the file reinstalled, and the blob pruned.
	require.NoError(t, os.WriteFile(filepath.Join(sys.Root, "/usr/local/bin/promtool"), []byte("edited"), 0o755))
	// Only the drifted member is extracted: prometheus is current.
	_, err = MakePlan(context.Background(), sys, []Resource{d})
	require.NoError(t, err)
	assert.Equal(t, []string{sum([]byte("promtool v1"))}, cacheEntries(t, sys, "blobs"))
	p, _, err = planAndApply(t, sys, []Resource{d}, nil)
	require.NoError(t, err)
	require.Len(t, p.Changes, 1, p.String())
	assert.Contains(t, p.Changes[0].Summary, "install /usr/local/bin/promtool")
	assert.Equal(t, "promtool v1", readRoot(t, sys, "/usr/local/bin/promtool"))
	assert.Equal(t, "prometheus v1", readRoot(t, sys, "/usr/local/bin/prometheus"))
	assert.Equal(t, int32(2), srv.requests.Load(), "the apply installs from the blob the MakePlan extracted")
	assert.Empty(t, cacheEntries(t, sys, "blobs"))
}

// A new pin installs only the members that changed, restarts once, and the
// clean apply prunes the old version from the cache.
func TestDownloadUpgradePrunesTheOldVersion(t *testing.T) {
	sys, run := newTestSystem(t)
	srv, base := serve(t, sys)
	v1 := tarGz(t, member{name: "prom-1/prometheus", body: "prometheus v1"}, member{name: "prom-1/promtool", body: "promtool"})
	v2 := tarGz(t, member{name: "prom-1/prometheus", body: "prometheus v2"}, member{name: "prom-1/promtool", body: "promtool"})
	srv.content["/v1.tar.gz"], srv.content["/v2.tar.gz"] = v1, v2
	_, _, err := planAndApply(t, sys, []Resource{promDownload(base+"/v1.tar.gz", sum(v1))}, nil)
	require.NoError(t, err)
	run.calls = nil

	p, _, err := planAndApply(t, sys, []Resource{promDownload(base+"/v2.tar.gz", sum(v2))}, nil)
	require.NoError(t, err)
	require.Len(t, p.Changes, 1, p.String())
	assert.Contains(t, p.Changes[0].Summary, "install /usr/local/bin/prometheus")
	assert.Equal(t, []string{"systemctl restart prometheus.service"}, run.changing())
	assert.Equal(t, "prometheus v2", readRoot(t, sys, "/usr/local/bin/prometheus"))
	assert.Empty(t, cacheEntries(t, sys, "blobs"))
	assert.Equal(t, []string{sum(v2) + ".json"}, cacheEntries(t, sys, "archives"))
}

func TestDownloadPlainFile(t *testing.T) {
	sys, _ := newTestSystem(t)
	srv, base := serve(t, sys)
	bin := []byte("#!/bin/sh\necho hi\n")
	srv.content["/tool"] = bin
	d := &Download{URL: base + "/tool", SHA256: sum(bin), Mode: 0o755, Files: []DownloadFile{{Path: "/usr/local/bin/tool"}}}
	_, _, err := planAndApply(t, sys, []Resource{d}, nil)
	require.NoError(t, err)
	assert.Equal(t, string(bin), readRoot(t, sys, "/usr/local/bin/tool"))
	assert.Empty(t, cacheEntries(t, sys, "blobs"), "installed: not kept")
	assert.Empty(t, cacheEntries(t, sys, "archives"))
}

// What does not match its pin is never installed or cached.
func TestDownloadRejectsAMismatch(t *testing.T) {
	sys, _ := newTestSystem(t)
	srv, base := serve(t, sys)
	archive := tarGz(t, member{name: "prom-1/prometheus", body: "x"}, member{name: "prom-1/promtool", body: "y"})
	srv.content["/a.tar.gz"] = append(archive, 0) // tampered
	_, err := MakePlan(context.Background(), sys, []Resource{promDownload(base+"/a.tar.gz", sum(archive))})
	assert.ErrorContains(t, err, "sha256 mismatch")
	assert.NoFileExists(t, filepath.Join(sys.Root, "/usr/local/bin/prometheus"))
	assert.Empty(t, cacheEntries(t, sys, "blobs"))
	assert.Empty(t, cacheEntries(t, sys, "archives"))

	_, err = MakePlan(context.Background(), sys, []Resource{promDownload(base+"/missing.tar.gz", sum(archive))})
	assert.ErrorContains(t, err, "404")
}

func TestDownloadMissingMember(t *testing.T) {
	sys, _ := newTestSystem(t)
	srv, base := serve(t, sys)
	// promtool is only a symlink here, which is not installed.
	archive := tarGz(t, member{name: "prom-1/prometheus", body: "x"}, member{name: "prom-1/promtool", body: "/etc/shadow", typ: tar.TypeSymlink})
	srv.content["/a.tar.gz"] = archive
	_, err := MakePlan(context.Background(), sys, []Resource{promDownload(base+"/a.tar.gz", sum(archive))})
	assert.ErrorContains(t, err, "archive has no regular file prom-1/promtool")
}

// A cached blob that no longer matches its name is not installed, and is
// removed so that the next run fetches it again.
func TestDownloadCorruptBlobIsFetchedAgain(t *testing.T) {
	sys, _ := newTestSystem(t)
	srv, base := serve(t, sys)
	archive := tarGz(t, member{name: "prom-1/prometheus", body: "prometheus"}, member{name: "prom-1/promtool", body: "promtool"})
	srv.content["/a.tar.gz"] = archive
	d := promDownload(base+"/a.tar.gz", sum(archive))
	_, _, err := planAndApply(t, sys, []Resource{d}, nil)
	require.NoError(t, err)
	require.NoError(t, os.Remove(filepath.Join(sys.Root, "/usr/local/bin/prometheus")))
	blob := filepath.Join(sys.Root, blobPath(sum([]byte("prometheus"))))
	require.NoError(t, os.WriteFile(blob, []byte("bit rot"), 0o600))

	_, _, err = planAndApply(t, sys, []Resource{d}, nil)
	assert.ErrorContains(t, err, "sha256 mismatch")
	assert.NoFileExists(t, filepath.Join(sys.Root, "/usr/local/bin/prometheus"))
	assert.NoFileExists(t, blob)

	_, _, err = planAndApply(t, sys, []Resource{d}, nil)
	require.NoError(t, err)
	assert.Equal(t, "prometheus", readRoot(t, sys, "/usr/local/bin/prometheus"))
	assert.Equal(t, int32(2), srv.requests.Load())
}

func TestFetchOnlyHTTPS(t *testing.T) {
	sys, _ := newTestSystem(t)
	_, err := sys.Fetch(context.Background(), "http://example.com/x")
	assert.ErrorContains(t, err, "only https")
}

func TestRenderDownloadAndUser(t *testing.T) {
	pin := sum([]byte("x"))
	fsys := fstest.MapFS{
		"modules/m/module.jsonnet": {Data: []byte(`function(host) local v = host.vars.v; { resources: [
  { user: { name: 'prometheus', home: '/var/lib/prometheus', groups: ['disk', 'adm', 'disk'] } },
  { download: {
    url: 'https://example.com/prometheus-%s.tar.gz' % v,
    sha256: '` + pin + `',
    extract: {
      ['prometheus-%s/promtool' % v]: '/usr/local/bin/promtool',
      ['prometheus-%s/prometheus' % v]: '/usr/local/bin/prometheus',
    },
    onChange: [{ restart: 'prometheus' }],
  } },
] }`)},
	}
	rs, err := Render(fsys, &HostSpec{Name: "h", Modules: []string{"m"}, Vars: map[string]any{"v": "3.5.0"}}, nil)
	require.NoError(t, err)
	require.Len(t, rs, 2)
	assert.Equal(t, &User{Name: "prometheus", Home: "/var/lib/prometheus", Groups: []string{"adm", "disk"}}, rs[0])
	assert.Equal(t, "download https://example.com/prometheus-3.5.0.tar.gz sha256:"+pin+" 0755 root:root\n"+
		"  prometheus-3.5.0/prometheus → /usr/local/bin/prometheus\n"+
		"  prometheus-3.5.0/promtool → /usr/local/bin/promtool\n"+
		"  on change: restart prometheus.service", describe(rs[1]))

	agent := fstest.MapFS{"modules/m/module.jsonnet": {Data: []byte(`{ resources: [{ download: {
    url: 'https://example.com/agent', sha256: '` + pin + `', path: '/usr/local/bin/agent',
    preInstallCheck: ['{file}', 'check-plan'], keepPrevious: true,
  } }] }`)}}
	rs, err = Render(agent, &HostSpec{Name: "h", Modules: []string{"m"}}, nil)
	require.NoError(t, err)
	assert.Equal(t, "download https://example.com/agent sha256:"+pin+" 0755 root:root\n"+
		"  → /usr/local/bin/agent\n"+
		"  keep previous: /usr/local/bin/agent.prev\n"+
		"  pre-install check: {file} check-plan", describe(rs[0]))

	dl := "download: { url: 'https://e.com/x', sha256: '" + pin + "'"
	for name, tc := range map[string]struct{ resources, err string }{
		"http":          {"{ download: { url: 'http://e.com/x', sha256: '" + pin + "', path: '/x' } }", "url must be https"},
		"short sha":     {"{ download: { url: 'https://e.com/x', sha256: 'abc', path: '/x' } }", "sha256 must be 64"},
		"path and tar":  {"{ " + dl + ", path: '/x', extract: { a: '/y' } } }", "exactly one of path, extract"},
		"neither":       {"{ " + dl + " } }", "exactly one of path, extract"},
		"member escape": {"{ " + dl + ", extract: { '../a': '/y' } } }", "clean relative path"},
		"relative path": {"{ " + dl + ", path: 'x' } }", "must be absolute"},
		"user name":     {"{ user: { name: 'Root' } }", "name must be lowercase"},
		"user group":    {"{ user: { name: 'a', groups: ['b c'] } }", "group \"b c\""},
		"unit file":     {"{ " + dl + ", path: '/etc/systemd/system/x.service' } }", "write unit files with a file resource"},
		"clash":         {"{ " + dl + ", path: '/x' } }, { file: { path: '/x', content: 'x' } }", "same path /x"},
		"owner first":   {"{ " + dl + ", path: '/x', owner: 'p' } }, { user: { name: 'p' } }", "download:https://e.com/x is owned by p, but user p is declared after it"},
		"group first":   {"{ dir: { path: '/d', group: 'p' } }, { user: { name: 'p' } }", "dir:/d is owned by p, but user p"},
		"check of tar":  {"{ " + dl + ", extract: { a: '/y' }, preInstallCheck: ['{file}'] } }", "preInstallCheck needs path"},
		"check no file": {"{ " + dl + ", path: '/x', preInstallCheck: ['/x', 'version'] } }", "must name the new file as {file}"},
		"prev clash":    {"{ " + dl + ", path: '/x', keepPrevious: true } }, { file: { path: '/x.prev', content: 'x' } }", "same path /x.prev"},
		"staged clash":  {"{ " + dl + ", path: '/d/x', preInstallCheck: ['{file}'] } }, { file: { path: '/d/.x.infrafier-new', content: 'x' } }", "same path /d/.x.infrafier-new"},
	} {
		t.Run(name, func(t *testing.T) {
			fsys := fstest.MapFS{"modules/m/module.jsonnet": {Data: []byte("{ resources: [" + tc.resources + "] }")}}
			_, err := Render(fsys, &HostSpec{Name: "h", Modules: []string{"m"}, Vars: map[string]any{}}, nil)
			assert.ErrorContains(t, err, tc.err)
		})
	}
}

// infrafier diff lists a download's restarts when its pin changes, although
// its files have no golden file.
func TestGoldenDiffListsDownloadActions(t *testing.T) {
	dir := t.TempDir()
	d := promDownload("https://e.com/v1.tar.gz", sum([]byte("1")))
	require.NoError(t, WriteGolden(dir, []Resource{d}, ""))
	_, acts, err := GoldenDiff(dir, []Resource{d}, "")
	require.NoError(t, err)
	assert.Empty(t, acts)

	d2 := promDownload("https://e.com/v2.tar.gz", sum([]byte("2")))
	diffs, acts, err := GoldenDiff(dir, []Resource{d2}, "")
	require.NoError(t, err)
	assert.Len(t, diffs, 1)
	assert.Equal(t, []Action{{Verb: "restart", Unit: "prometheus.service"}}, acts)
}

// withGetent answers getent from the given databases ("passwd x", "group
// y"): exit 2 for a name not in them, as getent does.
func withGetent(sys *OS, run *fakeRunner, known ...string) {
	sys.Runner = func(ctx context.Context, argv ...string) ([]byte, error) {
		if len(argv) == 3 && argv[0] == "getent" {
			run.calls = append(run.calls, strings.Join(argv, " "))
			if slices.Contains(known, argv[1]+" "+argv[2]) {
				return nil, nil
			}
			return nil, exitErr(2)
		}
		return run.run(ctx, argv...)
	}
}

// Its actions are listed only for what changes a file on the host: a new
// mirror, a dropped file or an action alone restarts nothing there.
func TestGoldenDiffDownloadActionsOnlyForInstalls(t *testing.T) {
	restart := []Action{{Verb: "restart", Unit: "prometheus.service"}}
	for name, tc := range map[string]struct {
		change func(d *Download)
		want   []Action
	}{
		"mirror":        {func(d *Download) { d.URL = "https://mirror.e.com/v1.tar.gz" }, nil},
		"action added":  {func(d *Download) { d.OnChange = append(d.OnChange, Action{Verb: "restart", Unit: "other.service"}) }, nil},
		"file dropped":  {func(d *Download) { d.Files = d.Files[:1] }, nil},
		"keep previous": {func(d *Download) { d.KeepPrevious = true }, nil},
		"check added":   {func(d *Download) { d.PreInstallCheck = []string{PreInstallFile, "version"} }, nil},
		"pin, kept":     {func(d *Download) { d.KeepPrevious, d.SHA256 = true, sum([]byte("2")) }, restart},
		"file moved":    {func(d *Download) { d.Files[1].Path = "/usr/bin/promtool" }, restart},
		"mode":          {func(d *Download) { d.Mode = 0o750 }, restart},
		"owner":         {func(d *Download) { d.Owner = "prometheus" }, restart},
		"member":        {func(d *Download) { d.Files[1].Member = "prom-2/promtool" }, restart},
		"new resource": {func(d *Download) {
			d.Files = append(d.Files, DownloadFile{Member: "prom-1/x", Path: "/usr/local/bin/x"})
		}, restart},
	} {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			d := promDownload("https://e.com/v1.tar.gz", sum([]byte("1")))
			d.Owner, d.Group = "root", "root"
			require.NoError(t, WriteGolden(dir, []Resource{d, &Package{Name: "x"}}, ""))
			tc.change(d)
			_, acts, err := GoldenDiff(dir, []Resource{d, &Package{Name: "x"}}, "")
			require.NoError(t, err)
			if tc.want == nil {
				assert.Empty(t, acts)
			} else {
				assert.Equal(t, tc.want, acts)
			}
		})
	}
}

func TestUser(t *testing.T) {
	u := &User{Name: "prometheus", Home: "/var/lib/prometheus", Groups: []string{"adm", "disk"}}
	changing := func(run *fakeRunner) []string {
		var out []string
		for _, c := range run.calls {
			if !strings.HasPrefix(c, "getent ") {
				out = append(out, c)
			}
		}
		return out
	}

	t.Run("missing", func(t *testing.T) {
		sys, run := newTestSystem(t)
		withGetent(sys, run, "group adm", "group disk")
		p, _, err := planAndApply(t, sys, []Resource{u}, nil)
		require.NoError(t, err)
		assert.Equal(t, "create system user prometheus\n", p.String())
		assert.Equal(t, []string{"useradd --system --home-dir /var/lib/prometheus --no-create-home --shell /usr/sbin/nologin --user-group --groups adm,disk prometheus"}, changing(run))
	})

	t.Run("its group is left over", func(t *testing.T) {
		sys, run := newTestSystem(t)
		withGetent(sys, run, "group adm", "group disk", "group prometheus")
		_, _, err := planAndApply(t, sys, []Resource{u}, nil)
		require.NoError(t, err)
		assert.Equal(t, []string{"useradd --system --home-dir /var/lib/prometheus --no-create-home --shell /usr/sbin/nologin --gid prometheus --groups adm,disk prometheus"}, changing(run))
	})

	t.Run("a group does not exist", func(t *testing.T) {
		sys, run := newTestSystem(t)
		withGetent(sys, run, "group disk")
		_, _, err := planAndApply(t, sys, []Resource{u}, nil)
		assert.ErrorContains(t, err, "group adm does not exist")
		assert.Empty(t, changing(run))
	})

	t.Run("lacks a group", func(t *testing.T) {
		sys, run := newTestSystem(t)
		withGetent(sys, run, "passwd prometheus", "group adm", "group disk")
		run.out["id -nG prometheus"] = "prometheus disk\n"
		p, _, err := planAndApply(t, sys, []Resource{u}, nil)
		require.NoError(t, err)
		assert.Equal(t, "add user prometheus to adm\n", p.String())
		assert.Contains(t, run.calls, "usermod --append --groups adm prometheus")
	})

	t.Run("as declared", func(t *testing.T) {
		sys, run := newTestSystem(t)
		withGetent(sys, run, "passwd prometheus")
		run.out["id -nG prometheus"] = "prometheus adm disk other\n"
		p, err := MakePlan(context.Background(), sys, []Resource{u})
		require.NoError(t, err)
		assert.True(t, p.Empty())
	})

	t.Run("getent fails", func(t *testing.T) {
		sys, run := newTestSystem(t)
		run.fail["getent passwd prometheus"] = true // exit 1: not "not found"
		_, err := MakePlan(context.Background(), sys, []Resource{u})
		assert.ErrorContains(t, err, "getent passwd")
	})
}

// countingSys counts the files hashed.
type countingSys struct {
	*OS
	hashed []string
}

func (c *countingSys) LstatSum(p string) (FileState, error) {
	c.hashed = append(c.hashed, p)
	return c.OS.LstatSum(p)
}

// An unchanged installed file is not hashed again; one whose stamp changed
// is, even with its size and mtime put back.
func TestDownloadHashesOnlyChangedFiles(t *testing.T) {
	inner, _ := newTestSystem(t)
	srv, base := serve(t, inner)
	archive := tarGz(t, member{name: "prom-1/prometheus", body: "prometheus"}, member{name: "prom-1/promtool", body: "promtool"})
	srv.content["/a.tar.gz"] = archive
	d := promDownload(base+"/a.tar.gz", sum(archive))
	sys := &countingSys{OS: inner}
	_, _, err := planAndApply(t, sys, []Resource{d}, nil)
	require.NoError(t, err)

	sys.hashed = nil
	_, _, err = planAndApply(t, sys, []Resource{d}, nil)
	require.NoError(t, err)
	assert.Empty(t, sys.hashed, "installed by the last run: recorded, not hashed")

	bin := filepath.Join(inner.Root, "/usr/local/bin/promtool")
	fi, err := os.Stat(bin)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(bin, []byte("PROMTOOL"), 0o755)) // same size
	require.NoError(t, os.Chtimes(bin, fi.ModTime(), fi.ModTime()))
	p, err := MakePlan(context.Background(), sys, []Resource{d})
	require.NoError(t, err)
	assert.Equal(t, []string{"/usr/local/bin/promtool"}, sys.hashed)
	require.Len(t, p.Changes, 1)
	assert.Contains(t, p.Changes[0].Summary, "install /usr/local/bin/promtool")
}

// A file whose ctime is too close to when it was hashed may have been
// written during the hash without its Stamp changing, so it is not
// recorded: the next run hashes it again.
func TestDownloadDoesNotRecordARacyHash(t *testing.T) {
	inner, _ := newTestSystem(t)
	srv, base := serve(t, inner)
	bin := []byte("tool")
	srv.content["/tool"] = bin
	d := &Download{URL: base + "/tool", SHA256: sum(bin), Mode: 0o755, Files: []DownloadFile{{Path: "/usr/local/bin/tool"}}}
	_, _, err := planAndApply(t, inner, []Resource{d}, nil)
	require.NoError(t, err)
	p := filepath.Join(inner.Root, "/usr/local/bin/tool")
	require.NoError(t, os.WriteFile(p, bin, 0o755)) // ctime: now

	sys := &countingSys{OS: inner}
	for range 2 {
		_, err = MakePlan(context.Background(), sys, []Resource{d})
		require.NoError(t, err)
	}
	assert.Equal(t, []string{"/usr/local/bin/tool", "/usr/local/bin/tool"}, sys.hashed)

	setNow(t, time.Now().Add(time.Hour))
	sys.hashed = nil
	for range 2 {
		_, _, err = planAndApply(t, sys, []Resource{d}, nil)
		require.NoError(t, err)
	}
	assert.Equal(t, []string{"/usr/local/bin/tool"}, sys.hashed, "old enough: recorded once")
}

// An installed.json that is not a regular file is an error, not an index
// that silently never saves.
func TestDownloadIndexNotARegularFile(t *testing.T) {
	sys, _ := newTestSystem(t)
	require.NoError(t, os.MkdirAll(filepath.Join(sys.Root, indexPath), 0o755))
	d := &Download{URL: "https://e.com/tool", SHA256: sum([]byte("x")), Mode: 0o755, Files: []DownloadFile{{Path: "/usr/local/bin/tool"}}}
	_, err := MakePlan(context.Background(), sys, []Resource{d})
	assert.ErrorContains(t, err, "installed.json exists and is not a regular file")
}

// An installed.json of "null" decodes to a nil map: rebuilt like a
// malformed one, not a panic.
func TestDownloadIndexNull(t *testing.T) {
	sys, _ := newTestSystem(t)
	srv, base := serve(t, sys)
	bin := []byte("tool")
	srv.content["/tool"] = bin
	d := &Download{URL: base + "/tool", SHA256: sum(bin), Mode: 0o755, Files: []DownloadFile{{Path: "/usr/local/bin/tool"}}}
	_, _, err := planAndApply(t, sys, []Resource{d}, nil)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(filepath.Join(sys.Root, indexPath), []byte("null"), 0o600))
	setNow(t, time.Now().Add(time.Hour)) // not racy: the hash goes into the index
	p, _, err := planAndApply(t, sys, []Resource{d}, nil)
	require.NoError(t, err)
	assert.True(t, p.Empty())
}

// A mode-only update checks the content again: something earlier in the run
// may have rewritten the file, and recording the planned sum with its new
// Stamp would vouch for the wrong binary on every later pull.
func TestDownloadAttrsUpdateHashesAgain(t *testing.T) {
	inner, _ := newTestSystem(t)
	srv, base := serve(t, inner)
	bin := []byte("tool")
	srv.content["/tool"] = bin
	d := &Download{URL: base + "/tool", SHA256: sum(bin), Mode: 0o755, Files: []DownloadFile{{Path: "/usr/local/bin/tool"}}}
	_, _, err := planAndApply(t, inner, []Resource{d}, nil)
	require.NoError(t, err)

	d.Mode = 0o750
	p, err := MakePlan(context.Background(), inner, []Resource{d})
	require.NoError(t, err)
	require.Len(t, p.Changes, 1)
	require.NoError(t, os.WriteFile(filepath.Join(inner.Root, "/usr/local/bin/tool"), []byte("TOOL"), 0o755))
	_, err = p.Apply(context.Background(), inner, nil)
	assert.ErrorContains(t, err, "/usr/local/bin/tool changed during the run")

	sys := &countingSys{OS: inner}
	p, err = MakePlan(context.Background(), sys, []Resource{d})
	require.NoError(t, err)
	assert.Equal(t, []string{"/usr/local/bin/tool"}, sys.hashed, "not in the index")
	require.Len(t, p.Changes, 1)
	assert.Contains(t, p.Changes[0].Summary, "install /usr/local/bin/tool")
}

// A blob one fetch just wrote counts as cached for the rest of the plan:
// two archives that ship the same file need only one of them fetched.
func TestDownloadSharedBlobIsFetchedOnce(t *testing.T) {
	sys, _ := newTestSystem(t)
	srv, base := serve(t, sys)
	a := tarGz(t, member{name: "a/tool", body: "tool"})
	b := tarGz(t, member{name: "b/tool", body: "tool"})
	srv.content["/a.tar.gz"], srv.content["/b.tar.gz"] = a, b
	rs := []Resource{
		&Download{URL: base + "/a.tar.gz", SHA256: sum(a), Mode: 0o755, Files: []DownloadFile{{Member: "a/tool", Path: "/opt/a/tool"}}},
		&Download{URL: base + "/b.tar.gz", SHA256: sum(b), Mode: 0o755, Files: []DownloadFile{{Member: "b/tool", Path: "/opt/b/tool"}}},
	}
	_, _, err := planAndApply(t, sys, rs, nil)
	require.NoError(t, err)
	require.Equal(t, int32(2), srv.requests.Load())
	require.Empty(t, cacheEntries(t, sys, "blobs"), "both installed: pruned")

	for _, p := range []string{"/opt/a/tool", "/opt/b/tool"} {
		require.NoError(t, os.Remove(filepath.Join(sys.Root, p)))
	}
	_, _, err = planAndApply(t, sys, rs, nil)
	require.NoError(t, err)
	assert.Equal(t, int32(3), srv.requests.Load(), "only a.tar.gz fetched again")
	assert.Equal(t, "tool", readRoot(t, sys, "/opt/b/tool"))
}

// A cached blob over its limit fails every install the same way: removed,
// so the next run fetches it again.
func TestDownloadOversizedBlobIsFetchedAgain(t *testing.T) {
	sys, _ := newTestSystem(t)
	srv, base := serve(t, sys)
	bin := []byte("tool")
	srv.content["/tool"] = bin
	d := &Download{URL: base + "/tool", SHA256: sum(bin), Mode: 0o755, Files: []DownloadFile{{Path: "/usr/local/bin/tool"}}}
	_, _, err := planAndApply(t, sys, []Resource{d}, nil)
	require.NoError(t, err)
	old := maxDownloadBytes
	maxDownloadBytes = int64(len(bin))
	t.Cleanup(func() { maxDownloadBytes = old })
	require.NoError(t, os.WriteFile(filepath.Join(sys.Root, blobPath(sum(bin))), []byte("tool and more"), 0o600))
	require.NoError(t, os.Remove(filepath.Join(sys.Root, "/usr/local/bin/tool")))

	_, _, err = planAndApply(t, sys, []Resource{d}, nil)
	assert.ErrorContains(t, err, "more than 4 bytes")
	_, _, err = planAndApply(t, sys, []Resource{d}, nil)
	require.NoError(t, err)
	assert.Equal(t, "tool", readRoot(t, sys, "/usr/local/bin/tool"))
}

// A package installed earlier in the run may create the user: then only its
// groups are added, no useradd that would fail.
func TestUserCreatedEarlierInTheRun(t *testing.T) {
	u := &User{Name: "prometheus", Home: "/var/lib/prometheus", Groups: []string{"adm"}}
	sys, run := newTestSystem(t)
	exists := false
	sys.Runner = func(ctx context.Context, argv ...string) ([]byte, error) {
		if len(argv) == 3 && argv[0] == "getent" {
			if argv[1] == "group" || exists {
				return nil, nil
			}
			return nil, exitErr(2)
		}
		return run.run(ctx, argv...)
	}
	p, err := MakePlan(context.Background(), sys, []Resource{u})
	require.NoError(t, err)
	assert.Equal(t, "create system user prometheus\n", p.String())
	exists = true // the package's postinst ran
	run.out["id -nG prometheus"] = "prometheus\n"
	_, err = p.Apply(context.Background(), sys, nil)
	require.NoError(t, err)
	assert.Equal(t, []string{"id -nG prometheus", "usermod --append --groups adm prometheus"}, run.calls)
}

// A download's file no resource declares any more is removed by the purge
// of its directory, so infrafier diff lists that directory's actions.
func TestGoldenDiffListsPurgeOfARemovedDownload(t *testing.T) {
	dir := t.TempDir()
	purge := &Dir{Path: "/opt/prom", Mode: 0o755, Purge: true, OnChange: []Action{{Verb: "restart", Unit: "purged.service"}}}
	d := &Download{URL: "https://e.com/v1.tar.gz", SHA256: sum([]byte("1")), Mode: 0o755,
		Files: []DownloadFile{{Member: "a", Path: "/opt/prom/a"}, {Member: "b", Path: "/opt/prom/b"}}}
	require.NoError(t, WriteGolden(dir, []Resource{purge, d}, ""))

	_, acts, err := GoldenDiff(dir, []Resource{purge, d}, "")
	require.NoError(t, err)
	assert.Empty(t, acts)
	d.Files = d.Files[:1]
	_, acts, err = GoldenDiff(dir, []Resource{purge, d}, "")
	require.NoError(t, err)
	assert.Equal(t, []Action{{Verb: "restart", Unit: "purged.service"}}, acts)
	_, acts, err = GoldenDiff(dir, []Resource{purge}, "")
	require.NoError(t, err)
	assert.Equal(t, []Action{{Verb: "restart", Unit: "purged.service"}}, acts)

	// Dropping keepPrevious purges the .prev, and that is listed too.
	d.KeepPrevious = true
	require.NoError(t, WriteGolden(dir, []Resource{purge, d}, ""))
	d.KeepPrevious = false
	_, acts, err = GoldenDiff(dir, []Resource{purge, d}, "")
	require.NoError(t, err)
	assert.Equal(t, []Action{{Verb: "restart", Unit: "purged.service"}}, acts)
}

func setNow(t *testing.T, at time.Time) {
	old := now
	now = func() time.Time { return at }
	t.Cleanup(func() { now = old })
}

// Dropping a member from extract frees its blob.
func TestDownloadPrunesADroppedMember(t *testing.T) {
	sys, _ := newTestSystem(t)
	srv, base := serve(t, sys)
	archive := tarGz(t, member{name: "prom-1/prometheus", body: "prometheus"}, member{name: "prom-1/promtool", body: "promtool"})
	srv.content["/a.tar.gz"] = archive
	d := promDownload(base+"/a.tar.gz", sum(archive))
	_, _, err := planAndApply(t, sys, []Resource{d}, nil)
	require.NoError(t, err)
	// Keep a blob for each: the installed files are removed by hand.
	for _, p := range []string{"/usr/local/bin/prometheus", "/usr/local/bin/promtool"} {
		require.NoError(t, os.Remove(filepath.Join(sys.Root, p)))
	}
	_, err = MakePlan(context.Background(), sys, []Resource{d}) // fetches; applies nothing
	require.NoError(t, err)
	require.Len(t, cacheEntries(t, sys, "blobs"), 2)
	d.Files = d.Files[:1]
	_, _, err = planAndApply(t, sys, []Resource{d}, nil)
	require.NoError(t, err)
	assert.Empty(t, cacheEntries(t, sys, "blobs"), "promtool no longer pinned, prometheus installed")
	assert.Equal(t, []string{sum(archive) + ".json"}, cacheEntries(t, sys, "archives"))
}

// A blob stays while a file installed from it cannot be told to hold it
// without hashing: here /opt/b/tool, rewritten just now with the same
// content, so its hash is racy and not recorded. The next run records it and
// prunes the blob, which a.tar.gz and b.tar.gz share.
func TestDownloadBlobStaysUntilEveryFileIsKnownToHoldIt(t *testing.T) {
	sys, _ := newTestSystem(t)
	srv, base := serve(t, sys)
	a := tarGz(t, member{name: "a/tool", body: "tool"})
	b := tarGz(t, member{name: "b/tool", body: "tool"})
	srv.content["/a.tar.gz"], srv.content["/b.tar.gz"] = a, b
	rs := []Resource{
		&Download{URL: base + "/a.tar.gz", SHA256: sum(a), Mode: 0o755, Files: []DownloadFile{{Member: "a/tool", Path: "/opt/a/tool"}}},
		&Download{URL: base + "/b.tar.gz", SHA256: sum(b), Mode: 0o755, Files: []DownloadFile{{Member: "b/tool", Path: "/opt/b/tool"}}},
	}
	_, _, err := planAndApply(t, sys, rs, nil)
	require.NoError(t, err)
	require.NoError(t, os.Remove(filepath.Join(sys.Root, "/opt/a/tool")))
	require.NoError(t, os.WriteFile(filepath.Join(sys.Root, "/opt/b/tool"), []byte("tool"), 0o755)) // ctime: now

	p, _, err := planAndApply(t, sys, rs, nil)
	require.NoError(t, err)
	require.Len(t, p.Changes, 1, p.String())
	assert.Equal(t, []string{sum([]byte("tool"))}, cacheEntries(t, sys, "blobs"), "kept: /opt/b/tool not known to hold it")
	require.Equal(t, int32(3), srv.requests.Load())

	// While it is kept, a changed file is put back from it, without a fetch.
	require.NoError(t, os.WriteFile(filepath.Join(sys.Root, "/opt/a/tool"), []byte("edited"), 0o755))
	p, _, err = planAndApply(t, sys, rs, nil)
	require.NoError(t, err)
	require.Len(t, p.Changes, 1, p.String())
	assert.Equal(t, "tool", readRoot(t, sys, "/opt/a/tool"))
	assert.Equal(t, int32(3), srv.requests.Load())

	setNow(t, time.Now().Add(time.Hour))
	p, _, err = planAndApply(t, sys, rs, nil)
	require.NoError(t, err)
	assert.True(t, p.Empty(), p.String())
	assert.Empty(t, cacheEntries(t, sys, "blobs"))
	assert.Equal(t, int32(3), srv.requests.Load())
}

// A plain download is installed under the download limit, not the member one.
func TestDownloadPlainFileOverTheMemberLimit(t *testing.T) {
	old := maxMemberBytes
	maxMemberBytes = 4
	t.Cleanup(func() { maxMemberBytes = old })
	sys, _ := newTestSystem(t)
	srv, base := serve(t, sys)
	bin := []byte("longer than four bytes")
	srv.content["/tool"] = bin
	d := &Download{URL: base + "/tool", SHA256: sum(bin), Mode: 0o755, Files: []DownloadFile{{Path: "/usr/local/bin/tool"}}}
	_, _, err := planAndApply(t, sys, []Resource{d}, nil)
	require.NoError(t, err)
	assert.Equal(t, string(bin), readRoot(t, sys, "/usr/local/bin/tool"))
}

func TestFetchRefusesARedirectToHTTP(t *testing.T) {
	sys, _ := newTestSystem(t)
	plain := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.Write([]byte("x")) }))
	t.Cleanup(plain.Close)
	tls := httptest.NewTLSServer(http.RedirectHandler(plain.URL+"/x", http.StatusFound))
	t.Cleanup(tls.Close)

	sys.HTTP = tls.Client() // the default policy follows it; Fetch still refuses
	_, err := sys.Fetch(context.Background(), tls.URL)
	assert.ErrorContains(t, err, "redirected to "+plain.URL+"/x: only https")

	c := tls.Client()
	c.CheckRedirect = httpsRedirectsOnly
	sys.HTTP = c
	_, err = sys.Fetch(context.Background(), tls.URL)
	assert.ErrorContains(t, err, "only https")
}

// A new binary a check rejects cannot be put back: the restart stays owed
// and the unit is not started on it, as after a purge.
func TestDownloadFailedCheckOwesTheRestart(t *testing.T) {
	sys, run := newTestSystem(t)
	srv, base := serve(t, sys)
	archive := tarGz(t, member{name: "prom-1/prometheus", body: "new"}, member{name: "prom-1/promtool", body: "new"})
	srv.content["/a.tar.gz"] = archive
	d := promDownload(base+"/a.tar.gz", sum(archive))
	d.OnChange[0].Checks = [][]string{{"promtool", "check", "config", "/etc/prometheus/prometheus.yml"}}
	run.fail["promtool check config /etc/prometheus/prometheus.yml"] = true
	run.fail["systemctl is-active prometheus.service"] = true
	run.out["systemctl is-active prometheus.service"] = "inactive\n"

	_, still, err := planAndApply(t, sys, []Resource{d, &Unit{Name: "prometheus.service", Active: true}}, nil)
	assert.ErrorContains(t, err, "check failed")
	assert.Equal(t, []Action{{Verb: "restart", Unit: "prometheus.service", Checks: d.OnChange[0].Checks}}, still)
	assert.NotContains(t, run.calls, "systemctl start prometheus.service")
	assert.Equal(t, "new", readRoot(t, sys, "/usr/local/bin/prometheus"))
}

// The agent's own download: the new binary is checked at a temporary
// name before it replaces the old one, which is kept as .prev.
func TestDownloadPreInstallCheckAndKeepPrevious(t *testing.T) {
	sys, run := newTestSystem(t)
	srv, base := serve(t, sys)
	staged := "/usr/local/bin/.agent." + agentName + "-new"
	check := staged + " version"
	var checked []string // the staged file's content at each check
	sys.Runner = func(ctx context.Context, argv ...string) ([]byte, error) {
		if strings.Join(argv, " ") == check {
			checked = append(checked, readRoot(t, sys, staged))
		}
		return run.run(ctx, argv...)
	}
	agent := func(v string) []Resource {
		bin := []byte("agent " + v)
		srv.content["/agent-"+v] = bin
		return []Resource{
			// A purge of the directory leaves .prev: it is declared.
			&Dir{Path: "/usr/local/bin", Mode: 0o755, Purge: true},
			&Download{URL: base + "/agent-" + v, SHA256: sum(bin), Mode: 0o755,
				Files:           []DownloadFile{{Path: "/usr/local/bin/agent"}},
				PreInstallCheck: []string{PreInstallFile, "version"}, KeepPrevious: true},
		}
	}
	prev := filepath.Join(sys.Root, "/usr/local/bin/agent.prev")

	_, _, err := planAndApply(t, sys, agent("v1"), nil)
	require.NoError(t, err)
	assert.Equal(t, "agent v1", readRoot(t, sys, "/usr/local/bin/agent"))
	assert.Equal(t, []string{"agent v1"}, checked)
	assert.NoFileExists(t, prev, "nothing to keep on the first install")

	// v2 fails its check: v1 stays, and nothing is left behind.
	run.fail[check] = true
	_, _, err = planAndApply(t, sys, agent("v2"), nil)
	assert.ErrorContains(t, err, "not installed, the pre-install check of the new file failed ({file} version)")
	assert.Equal(t, "agent v1", readRoot(t, sys, "/usr/local/bin/agent"))
	assert.NoFileExists(t, filepath.Join(sys.Root, staged))
	assert.NoFileExists(t, prev)

	delete(run.fail, check)
	// .prev keeps the old file's own mode, not the new one's.
	require.NoError(t, os.Chmod(filepath.Join(sys.Root, "/usr/local/bin/agent"), 0o700))
	_, _, err = planAndApply(t, sys, agent("v2"), nil)
	require.NoError(t, err)
	assert.Equal(t, "agent v2", readRoot(t, sys, "/usr/local/bin/agent"))
	assert.Equal(t, "agent v1", readRoot(t, sys, "/usr/local/bin/agent.prev"))
	fi, err := os.Stat(prev)
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0o700), fi.Mode().Perm())
	assert.NoFileExists(t, filepath.Join(sys.Root, staged))

	// Installed: the next plan neither checks nor purges anything.
	checked = nil
	p, err := MakePlan(context.Background(), sys, agent("v2"))
	require.NoError(t, err)
	assert.True(t, p.Empty(), p.String())
	assert.Empty(t, checked)

	// A fallback run is .prev (v1) running: installing v3 leaves .prev as
	// it is, rather than keeping v2, the agent that just failed.
	rs := agent("v3")
	rs[1].(*Download).leavePrevious = true
	_, _, err = planAndApply(t, sys, rs, nil)
	require.NoError(t, err)
	assert.Equal(t, "agent v3", readRoot(t, sys, "/usr/local/bin/agent"))
	assert.Equal(t, "agent v1", readRoot(t, sys, "/usr/local/bin/agent.prev"))
}

// A plan check writes nothing, so a download the pull did not cache fails
// it rather than being fetched.
func TestReadOnlySystemRefusesAFetch(t *testing.T) {
	sys, _ := newTestSystem(t)
	srv, base := serve(t, sys)
	bin := []byte("tool")
	srv.content["/tool"] = bin
	d := &Download{URL: base + "/tool", SHA256: sum(bin), Mode: 0o755, Files: []DownloadFile{{Path: "/usr/local/bin/tool"}}}
	_, err := MakePlan(context.Background(), readOnlySystem{sys}, []Resource{d})
	assert.ErrorContains(t, err, "refused, a plan check writes nothing")
	assert.Zero(t, srv.requests.Load())

	// Cached by a pull's plan: the check plans it without a fetch.
	_, err = MakePlan(context.Background(), sys, []Resource{d})
	require.NoError(t, err)
	p, err := MakePlan(context.Background(), readOnlySystem{sys}, []Resource{d})
	require.NoError(t, err)
	assert.Contains(t, p.String(), "install /usr/local/bin/tool")
	assert.Equal(t, int32(1), srv.requests.Load())
}
