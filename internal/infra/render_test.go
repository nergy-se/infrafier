package infra

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"testing/fstest"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// testFS is a repo with host h, which has module m; module is m's
// module.jsonnet.
func testFS(module string, extra map[string]string) fstest.MapFS {
	fsys := fstest.MapFS{
		"hosts/h.jsonnet":          {Data: []byte(`{ ref: 'main', modules: ['m'], vars: { size: '2G' } }`)},
		"modules/m/module.jsonnet": {Data: []byte(module)},
	}
	for k, v := range extra {
		fsys[k] = &fstest.MapFile{Data: []byte(v)}
	}
	return fsys
}

func renderTest(t *testing.T, fsys fstest.MapFS) ([]Resource, error) {
	t.Helper()
	h, err := LoadHost(fsys, "h")
	require.NoError(t, err)
	return Render(fsys, h, nil)
}

func TestRenderModule(t *testing.T) {
	fsys := testFS(`function(host) { resources: [
  { package: 'nginx' },
  { dir: { path: '/etc/nginx/sites-enabled', purge: true } },
  { file: {
    path: '/etc/nginx/sites-enabled/site',
    template: 'site.conf',
    mode: '0640',
    group: 'www-data',
    onChange: [{ reload: 'nginx.service', check: ['nginx', '-t'] }],
  } },
] + (if host.ref == 'main' then [{ file: { path: '/etc/standby', content: 'yes\n' } }] else []) + [
  { file: { path: '/var/lib/grafana/d.json', source: 'd.json' } },
  { unit: { name: 'nginx.service', enabled: true, active: true } },
] }`, map[string]string{
		"modules/m/site.conf": "host {{.Host.Name}} size {{.Vars.size}}\n",
		"modules/m/d.json":    `{"title": "{{ not a template }}"}`,
	})
	rs, err := renderTest(t, fsys)
	require.NoError(t, err)
	assert.Equal(t, []Resource{
		&Package{Name: "nginx"},
		&Dir{Path: "/etc/nginx/sites-enabled", Mode: 0o755, Owner: "root", Group: "root", Purge: true},
		&File{Path: "/etc/nginx/sites-enabled/site", Content: []byte("host h size 2G\n"), Mode: 0o640, Owner: "root", Group: "www-data",
			OnChange: []Action{{Verb: "reload", Unit: "nginx.service", Checks: [][]string{{"nginx", "-t"}}}}},
		&File{Path: "/etc/standby", Content: []byte("yes\n"), Mode: 0o644, Owner: "root", Group: "root"},
		&File{Path: "/var/lib/grafana/d.json", Content: []byte(`{"title": "{{ not a template }}"}`), Mode: 0o644, Owner: "root", Group: "root"},
		&Unit{Name: "nginx.service", Enabled: true, Active: true},
	}, rs)
}

func TestRenderErrors(t *testing.T) {
	cases := map[string]struct {
		module string
		extra  map[string]string
		want   string
	}{
		"missing var": {
			module: `{ resources: [{ file: { path: '/etc/x', template: 'x' } }] }`,
			extra:  map[string]string{"modules/m/x": "{{.Vars.nope}}"},
			want:   `map has no entry for key "nope"`,
		},
		"unknown field": {
			module: `{ resources: [{ file: { path: '/etc/x', content: 'x', mod: '0644' } }] }`,
			want:   "field mod not found",
		},
		"two kinds": {
			module: `{ resources: [{ package: 'x', unit: { name: 'x' } }] }`,
			want:   "exactly one of file, dir, package, unit, command",
		},
		"two contents": {
			module: `{ resources: [{ file: { path: '/etc/x', content: 'x', source: 'y' } }] }`,
			want:   "exactly one of template, source, content",
		},
		"relative path": {
			module: `{ resources: [{ file: { path: 'etc/x', content: 'x' } }] }`,
			want:   "must be absolute and clean",
		},
		"bad mode": {
			module: `{ resources: [{ file: { path: '/etc/x', content: 'x', mode: '644x' } }] }`,
			want:   "want octal permission bits",
		},
		"bad action": {
			module: `{ resources: [{ file: { path: '/etc/x', content: 'x', onChange: [{ restart: 'a', reload: 'b' }] } }] }`,
			want:   "exactly one of restart, reload, try-restart",
		},
		"duplicate": {
			module: `{ resources: [{ file: { path: '/etc/x', content: 'x' } }, { file: { path: '/etc/x', content: 'y' } }] }`,
			want:   "file:/etc/x is declared by both module m and module m",
		},
		"file and dir on one path": {
			module: `{ resources: [{ dir: { path: '/etc/x' } }, { file: { path: '/etc/x', content: 'x' } }] }`,
			want:   "file:/etc/x in module m has the same path /etc/x as dir:/etc/x in module m",
		},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			_, err := renderTest(t, testFS(tc.module, tc.extra))
			require.ErrorContains(t, err, tc.want)
		})
	}
}

func TestGoldenDiffListsChangedFilesAndActions(t *testing.T) {
	dir := t.TempDir()
	rs := []Resource{
		&File{Path: "/etc/a", Content: []byte("a\n"), Mode: 0o644, OnChange: []Action{{Verb: "reload", Unit: "a.service"}}},
		&File{Path: "/etc/s", Content: []byte("hunter2\n"), Mode: 0o600, Secret: true},
	}
	require.NoError(t, WriteGolden(dir, rs, ""))
	b, err := os.ReadFile(dir + "/etc/s")
	require.NoError(t, err)
	assert.Equal(t, string(secretPlaceholder([]byte("hunter2\n"))), string(b))
	assert.NotContains(t, string(b), "hunter2")

	diffs, actions, err := GoldenDiff(dir, rs, "")
	require.NoError(t, err)
	assert.Empty(t, diffs)
	assert.Empty(t, actions)

	// A changed secret still shows as changed, with the actions it triggers.
	rotated := []Resource{rs[0], &File{Path: "/etc/s", Content: []byte("hunter3\n"), Mode: 0o600, Secret: true, OnChange: []Action{{Verb: "restart", Unit: "s.service"}}}}
	diffs, actions, err = GoldenDiff(dir, rotated, "")
	require.NoError(t, err)
	assert.Contains(t, strings.Join(diffs, ""), "+++ b/etc/s")
	assert.NotContains(t, strings.Join(diffs, ""), "hunter")
	assert.Equal(t, []Action{{Verb: "restart", Unit: "s.service"}}, actions)

	rs[0].(*File).Content = []byte("b\n")
	diffs, actions, err = GoldenDiff(dir, rs, "")
	require.NoError(t, err)
	require.Len(t, diffs, 1)
	assert.Contains(t, diffs[0], "-a\n+b\n")
	assert.Equal(t, []Action{{Verb: "reload", Unit: "a.service"}}, actions)

	// A file no longer rendered shows as removed.
	diffs, _, err = GoldenDiff(dir, rs[1:], "")
	require.NoError(t, err)
	assert.Len(t, diffs, 2) // etc/a and _resources.txt
}

func TestGoldenDiffListsActionsOfModeOnlyChanges(t *testing.T) {
	dir := t.TempDir()
	rs := []Resource{&File{Path: "/etc/a", Content: []byte("a\n"), Mode: 0o644, OnChange: []Action{{Verb: "reload", Unit: "a.service"}}}}
	require.NoError(t, WriteGolden(dir, rs, ""))

	rs[0].(*File).Mode = 0o640
	diffs, actions, err := GoldenDiff(dir, rs, "")
	require.NoError(t, err)
	require.Len(t, diffs, 1) // only _resources.txt
	assert.Equal(t, []Action{{Verb: "reload", Unit: "a.service"}}, actions)
}

func TestUnitNamesWithoutATypeAreServices(t *testing.T) {
	rs, err := renderTest(t, testFS(`{ resources: [
  { file: { path: '/etc/x', content: 'x', onChange: [{ restart: 'nginx' }] } },
  { unit: { name: 'nginx', active: true } },
  { unit: { name: 'x.timer', active: true } },
] }`, nil))
	require.NoError(t, err)
	assert.Equal(t, "nginx.service", rs[0].(*File).OnChange[0].Unit)
	assert.Equal(t, "nginx.service", rs[1].(*Unit).Name)
	assert.Equal(t, "x.timer", rs[2].(*Unit).Name)
}

func TestSecretFilesDefaultToOwnerOnly(t *testing.T) {
	rs, err := renderTest(t, testFS(`{ resources: [{ file: { path: '/etc/s', content: 'x', secret: true } }, { file: { path: '/etc/p', content: 'x' } }] }`, nil))
	require.NoError(t, err)
	assert.Equal(t, fs.FileMode(0o600), rs[0].(*File).Mode)
	assert.Equal(t, fs.FileMode(0o644), rs[1].(*File).Mode)
}

func TestUnitNamesWithDotsStillGetAType(t *testing.T) {
	assert.Equal(t, "php8.2-fpm.service", unitName("php8.2-fpm"))
	assert.Equal(t, "php8.2-fpm.service", unitName("php8.2-fpm.service"))
	assert.Equal(t, "x.timer", unitName("x.timer"))
}

func TestGoldenDiffListsThePurgeActionsOfARemovedFile(t *testing.T) {
	dir := t.TempDir()
	reload := []Action{{Verb: "reload", Unit: "nginx.service"}}
	rs := []Resource{
		&Dir{Path: "/etc/nginx/sites-enabled", Mode: 0o755, Purge: true, OnChange: reload},
		&File{Path: "/etc/nginx/sites-enabled/old", Content: []byte("x\n"), Mode: 0o644},
	}
	require.NoError(t, WriteGolden(dir, rs, ""))
	_, actions, err := GoldenDiff(dir, rs[:1], "")
	require.NoError(t, err)
	assert.Equal(t, reload, actions)
}

func TestStaleGoldenListsRenderedTreesWithoutAHost(t *testing.T) {
	dir := t.TempDir()
	for _, h := range []string{"host-a", "host-c"} {
		require.NoError(t, os.MkdirAll(filepath.Join(dir, h), 0o755))
	}
	stale, err := StaleGolden(dir, []string{"host-a", "host-b"})
	require.NoError(t, err)
	assert.Equal(t, []string{"host-c"}, stale)
}

func TestStaleGoldenIgnoresPlainFiles(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.MkdirAll(filepath.Join(dir, "host-a"), 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "README.md"), []byte("x"), 0o644))
	require.NoError(t, os.WriteFile(filepath.Join(dir, ".gitkeep"), nil, 0o644))
	stale, err := StaleGolden(dir, []string{"host-a"})
	require.NoError(t, err)
	assert.Empty(t, stale)
}

func TestRenderJsonnetHostBaseAndLibrary(t *testing.T) {
	fsys := fstest.MapFS{
		"hosts/base.libsonnet": {Data: []byte(`{ vars: { size: '2G' } }`)},
		"hosts/h.jsonnet":      {Data: []byte(`(import 'base.libsonnet') + { ref: 'main', modules: ['m'] }`)},
		"lib/infra.libsonnet": {Data: []byte(`{
  reloadChecked(unit, check):: { reload: unit, check: check },
}`)},
		"modules/m/module.jsonnet": {Data: []byte(`
local infra = import 'lib/infra.libsonnet';
function(host) {
  resources: [
    { package: 'nginx' },
    { file: { path: '/etc/nginx/site', template: 'site.conf', onChange: [infra.reloadChecked('nginx', ['nginx', '-t'])] } },
  ] + (if host.ref == 'main' then [{ file: { path: '/etc/standby', content: 'yes\n' } }] else []) + [
    { unit: { name: 'nginx', enabled: true, active: true } },
  ],
}`)},
		"modules/m/site.conf": {Data: []byte("host {{.Host.Name}} size {{.Vars.size}}\n")},
	}
	hosts, err := Hosts(fsys)
	require.NoError(t, err)
	assert.Equal(t, []string{"h"}, hosts)
	h, err := LoadHost(fsys, "h")
	require.NoError(t, err)
	file, err := HostFile(fsys, "h")
	require.NoError(t, err)
	assert.Equal(t, "hosts/h.jsonnet", file)
	got, err := Render(fsys, h, nil)
	require.NoError(t, err)
	assert.Equal(t, []Resource{
		&Package{Name: "nginx"},
		&File{Path: "/etc/nginx/site", Content: []byte("host h size 2G\n"), Mode: 0o644, Owner: "root", Group: "root",
			OnChange: []Action{{Verb: "reload", Unit: "nginx.service", Checks: [][]string{{"nginx", "-t"}}}}},
		&File{Path: "/etc/standby", Content: []byte("yes\n"), Mode: 0o644, Owner: "root", Group: "root"},
		&Unit{Name: "nginx.service", Enabled: true, Active: true},
	}, got)
}

// A host's address reaches its own modules (host.address, .Host.Address), and
// another host's file reads it by importing that host.
func TestHostAddress(t *testing.T) {
	fsys := fstest.MapFS{
		"hosts/a.jsonnet": {Data: []byte(`{ ref: 'main', address: '192.0.2.1', modules: ['m'], vars: { peer: (import 'b.jsonnet').address } }`)},
		"hosts/b.jsonnet": {Data: []byte(`{ ref: 'main', address: '2001:db8::2' }`)},
		"modules/m/module.jsonnet": {Data: []byte(`function(host) { resources: [
  { file: { path: '/etc/self', content: host.address } },
  { file: { path: '/etc/peer', template: 'peer' } },
] }`)},
		"modules/m/peer": {Data: []byte("{{.Host.Address}} {{.Vars.peer}}")},
	}
	h, err := LoadHost(fsys, "a")
	require.NoError(t, err)
	assert.Equal(t, "192.0.2.1", h.Address)
	rs, err := Render(fsys, h, nil)
	require.NoError(t, err)
	require.Len(t, rs, 2)
	assert.Equal(t, "192.0.2.1", string(rs[0].(*File).Content))
	assert.Equal(t, "192.0.2.1 2001:db8::2", string(rs[1].(*File).Content))
}

func TestRenderJsonnetModuleWithoutHostArgument(t *testing.T) {
	rs, err := renderTest(t, testFS(`{ resources: [{ package: 'x' }] }`, nil))
	require.NoError(t, err)
	assert.Equal(t, []Resource{&Package{Name: "x"}}, rs)
}

func TestRenderJsonnetErrors(t *testing.T) {
	cases := map[string]struct {
		module string
		extra  map[string]string
		want   string
	}{
		"unknown field": {
			module: `{ resources: [{ file: { path: '/etc/x', content: 'x', mod: '0644' } }] }`,
			want:   "field mod not found",
		},
		"field in another case": {
			module: `{ resources: [{ file: { Path: '/etc/x', content: 'x' } }] }`,
			want:   "field Path not found",
		},
		"unknown top-level field": {
			module: `{ resource: [] }`,
			want:   "field resource not found",
		},
		"wrong type": {
			module: `{ resources: [{ unit: { name: ['x'] } }] }`,
			want:   "cannot unmarshal",
		},
		"validation still applies": {
			module: `{ resources: [{ file: { path: 'etc/x', content: 'x' } }] }`,
			want:   "must be absolute and clean",
		},
		"import outside the repository": {
			module: `import '../../../etc/passwd'`,
			want:   "outside the repository",
		},
		"importstr outside the repository": {
			module: `{ resources: [{ file: { path: '/etc/x', content: importstr '../../../../etc/hostname' } }] }`,
			want:   "outside the repository",
		},
		"absolute import": {
			module: `import '/etc/passwd'`,
			want:   "relative to the importing file or the repository root",
		},
		"missing import": {
			module: `import 'nope.libsonnet'`,
			want:   "not found in the repository",
		},
		"no secret native function": {
			module: `{ resources: [{ file: { path: '/etc/x', content: std.native('secret')('pw') } }] }`,
			want:   "Unexpected type null, expected function",
		},
		"no external variables": {
			module: `{ resources: [{ file: { path: '/etc/x', content: std.extVar('secret') } }] }`,
			want:   "Undefined external variable: secret",
		},
		"secret only in a secret file's template": {
			module: `{ resources: [{ file: { path: '/etc/x', template: 'x' } }] }`,
			extra:  map[string]string{"modules/m/x": `{{secret "pw"}}`},
			want:   "secret is only allowed in the template of a file with secret: true",
		},
		"number for a string field": {
			module: `{ resources: [{ file: { path: '/etc/x', content: 'x', mode: std.parseOctal('644') } }] }`,
			// Only the part every Go version prints: 1.27 names the outer struct and the index
			// (moduleSpec.resources.0.file.mode), 1.26 the inner one (fileSpec.resources.file.mode).
			want: "file.mode of type string",
		},
		"misspelled nested field names its path": {
			module: `{ resources: [{ file: { path: '/etc/x', content: 'x', onChange: [{ Restart: 'x' }] } }] }`,
			want:   "resources[0].file.onChange[0]: field Restart not found",
		},
		"unknown host argument": {
			module: `function(hst) { resources: [] }`,
			want:   "function has no parameter host",
		},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			_, err := renderTest(t, testFS(tc.module, tc.extra))
			require.ErrorContains(t, err, tc.want)
		})
	}
}

func TestSecretPlaceholderInJsonnetModuleSecretFile(t *testing.T) {
	rs, err := renderTest(t, testFS(`{ resources: [{ file: { path: '/etc/s', template: 's', secret: true } }] }`,
		map[string]string{"modules/m/s": `pw={{secret "pw"}}`}))
	require.NoError(t, err)
	f := rs[0].(*File)
	assert.True(t, f.UsesSecrets)
	assert.True(t, f.Placeholders)
}

func TestJsonnetHostErrors(t *testing.T) {
	cases := map[string]struct {
		files map[string]string
		want  string
	}{
		"unknown field": {
			files: map[string]string{"hosts/h.jsonnet": `{ ref: 'main', module: ['m'] }`},
			want:  "field module not found",
		},
		"no ref": {
			files: map[string]string{"hosts/h.jsonnet": `{ modules: [] }`},
			want:  "hosts/h.jsonnet: ref is required",
		},
		"address not an IP": {
			files: map[string]string{"hosts/h.jsonnet": `{ ref: 'main', address: 'h.lan' }`},
			want:  `hosts/h.jsonnet: address "h.lan" is not an IP address`,
		},
		"a YAML host next to it": {
			files: map[string]string{"hosts/h.jsonnet": `{ ref: 'main' }`, "hosts/h.yaml": "ref: main\n"},
			want:  "hosts/h.yaml is not read, host and module files are jsonnet: write it as hosts/h.jsonnet",
		},
		"only a YAML host": {
			files: map[string]string{"hosts/h.yaml": "ref: main\n"},
			want:  "hosts/h.yaml is not read, host and module files are jsonnet: write it as hosts/h.jsonnet",
		},
		"missing": {
			files: map[string]string{"hosts/x.jsonnet": `{ ref: 'main' }`},
			want:  "hosts/h.jsonnet",
		},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			fsys := fstest.MapFS{}
			for k, v := range tc.files {
				fsys[k] = &fstest.MapFile{Data: []byte(v)}
			}
			_, err := LoadHost(fsys, "h")
			require.ErrorContains(t, err, tc.want)
		})
	}
}

func TestHostsListsJsonnetHostsAndRefusesYAML(t *testing.T) {
	fsys := fstest.MapFS{
		"hosts/b.jsonnet":      {Data: []byte(`{ ref: 'main' }`)},
		"hosts/a.jsonnet":      {Data: []byte(`{ ref: 'main' }`)},
		"hosts/base.libsonnet": {Data: []byte(`{}`)},
	}
	hosts, err := Hosts(fsys)
	require.NoError(t, err)
	assert.Equal(t, []string{"a", "b"}, hosts)

	// Skipping it would drop the host from diff, whose --update would then
	// delete its rendered/ tree.
	fsys["hosts/c.yaml"] = &fstest.MapFile{Data: []byte("ref: main\n")}
	_, err = Hosts(fsys)
	require.EqualError(t, err, "hosts/c.yaml is not read, host and module files are jsonnet: write it as hosts/c.jsonnet")
}

func TestModuleYAMLIsRefused(t *testing.T) {
	onlyYAML := testFS("", map[string]string{"modules/m/module.yaml": "resources: []\n"})
	delete(onlyYAML, "modules/m/module.jsonnet")
	for name, fsys := range map[string]fstest.MapFS{
		"next to module.jsonnet": testFS(`{ resources: [] }`, map[string]string{"modules/m/module.yaml": "resources: []\n"}),
		"instead of it":          onlyYAML,
	} {
		t.Run(name, func(t *testing.T) {
			_, err := renderTest(t, fsys)
			require.EqualError(t, err, "module m: modules/m/module.yaml is not read, host and module files are jsonnet: write it as modules/m/module.jsonnet")
		})
	}
}

// writeRepo writes files into a new directory, a symlink for a value that
// starts with "-> ".
func writeRepo(t *testing.T, files map[string]string) string {
	t.Helper()
	dir := t.TempDir()
	for name, v := range files {
		p := filepath.Join(dir, name)
		require.NoError(t, os.MkdirAll(filepath.Dir(p), 0o755))
		if target, ok := strings.CutPrefix(v, "-> "); ok {
			require.NoError(t, os.Symlink(target, p))
			continue
		}
		require.NoError(t, os.WriteFile(p, []byte(v), 0o644))
	}
	return dir
}

func TestOpenRepoRefusesSymlinksOutOfTheCheckout(t *testing.T) {
	outside := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(outside, "key"), []byte("AGE-SECRET-KEY-1\n"), 0o644))
	host := map[string]string{"hosts/h.jsonnet": `{ ref: 'main', modules: ['m'] }`}
	cases := map[string]map[string]string{
		"importstr of a symlinked file": {
			"lib/k":                    "-> " + filepath.Join(outside, "key"),
			"modules/m/module.jsonnet": `{ resources: [{ file: { path: '/etc/x', content: importstr 'lib/k' } }] }`,
		},
		"importstr through a symlinked directory": {
			"lib":                      "-> " + outside,
			"modules/m/module.jsonnet": `{ resources: [{ file: { path: '/etc/x', content: importstr 'lib/key' } }] }`,
		},
		"source through a symlinked file": {
			"modules/m/k":              "-> " + filepath.Join(outside, "key"),
			"modules/m/module.jsonnet": `{ resources: [{ file: { path: '/etc/x', source: 'k' } }] }`,
		},
		"template through a symlinked directory": {
			"modules/m/d":              "-> " + outside,
			"modules/m/module.jsonnet": `{ resources: [{ file: { path: '/etc/x', template: 'd/key' } }] }`,
		},
	}
	for name, files := range cases {
		t.Run(name, func(t *testing.T) {
			for k, v := range host {
				files[k] = v
			}
			fsys, closeRepo, err := OpenRepo(writeRepo(t, files))
			require.NoError(t, err)
			defer closeRepo()
			h, err := LoadHost(fsys, "h")
			require.NoError(t, err)
			_, err = Render(fsys, h, nil)
			require.ErrorContains(t, err, "escapes")
			assert.NotContains(t, err.Error(), "AGE-SECRET-KEY")
		})
	}
}

func TestOpenRepoFollowsSymlinksInsideTheCheckout(t *testing.T) {
	fsys, closeRepo, err := OpenRepo(writeRepo(t, map[string]string{
		"hosts/h.jsonnet":          `{ ref: 'main', modules: ['m'] }`,
		"lib/real.libsonnet":       `{ pkg: 'x' }`,
		"lib/infra.libsonnet":      "-> real.libsonnet",
		"modules/m/module.jsonnet": `{ resources: [{ package: (import 'lib/infra.libsonnet').pkg }] }`,
	}))
	require.NoError(t, err)
	defer closeRepo()
	h, err := LoadHost(fsys, "h")
	require.NoError(t, err)
	rs, err := Render(fsys, h, nil)
	require.NoError(t, err)
	assert.Equal(t, []Resource{&Package{Name: "x"}}, rs)
}

// permFS refuses to read one file.
type permFS struct {
	fstest.MapFS
	denied string
}

func (f permFS) Open(name string) (fs.File, error) {
	if name == f.denied {
		return nil, &fs.PathError{Op: "open", Path: name, Err: fs.ErrPermission}
	}
	return f.MapFS.Open(name)
}

func (f permFS) ReadFile(name string) ([]byte, error) {
	if name == f.denied {
		return nil, &fs.PathError{Op: "open", Path: name, Err: fs.ErrPermission}
	}
	return f.MapFS.ReadFile(name)
}

func TestJsonnetErrorsKeepTheImportErrorAndNameTheFile(t *testing.T) {
	fsys := permFS{MapFS: fstest.MapFS{
		"hosts/h.jsonnet":      {Data: []byte(`(import 'base.libsonnet') + { ref: 'main' }`)},
		"hosts/base.libsonnet": {Data: []byte(`{}`)},
	}, denied: "hosts/base.libsonnet"}
	_, err := LoadHost(fsys, "h")
	require.Error(t, err)
	assert.True(t, errors.Is(err, fs.ErrPermission), err)
	assert.Equal(t, 1, strings.Count(err.Error(), "hosts/h.jsonnet"), err)
	assert.Contains(t, err.Error(), "hosts/h.jsonnet:1:2", err)

	// A top-level argument error has no position; the file is prefixed.
	_, err = renderTest(t, testFS(`function(hst) {}`, nil))
	require.Error(t, err)
	assert.Equal(t, 1, strings.Count(err.Error(), "modules/m/module.jsonnet"), err)
	assert.Contains(t, err.Error(), "modules/m/module.jsonnet: RUNTIME ERROR: function has no parameter host", err)
}

func TestJsonnetStringsArriveExactly(t *testing.T) {
	rs, err := renderTest(t, testFS(`{ resources: [
  { file: { path: '/etc/a', content: 'x \u2028 y' } },
  { file: { path: '/etc/b', content: 'x\ufffey' } },
] }`, nil))
	require.NoError(t, err)
	assert.Equal(t, "x \u2028 y", string(rs[0].(*File).Content))
	assert.Equal(t, "x\ufffey", string(rs[1].(*File).Content))
}

// Vars render as written: a whole number as an int (a float64 1000000 would
// print as 1e+06), and gt still compares.
func TestJsonnetHostVarsRenderAsBefore(t *testing.T) {
	rs, err := renderTest(t, fstest.MapFS{
		"hosts/h.jsonnet":          {Data: []byte(`{ ref: 'main', modules: ['m'], vars: { n: 9100, big: 1000000, f: 1.5, b: true, l: [7], m: { k: 'v' } } }`)},
		"modules/m/module.jsonnet": {Data: []byte(`{ resources: [{ file: { path: '/etc/x', template: 'x' } }] }`)},
		"modules/m/x":              {Data: []byte("{{.Vars.n}} {{.Vars.big}} {{.Vars.f}} {{.Vars.b}} {{index .Vars.l 0}} {{.Vars.m.k}} {{if gt .Vars.n 3}}gt{{end}}\n")},
	})
	require.NoError(t, err)
	assert.Equal(t, "9100 1000000 1.5 true 7 v gt\n", string(rs[0].(*File).Content))
}
