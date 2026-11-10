package infra

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"maps"
	"os"
	"path"
	"reflect"
	"slices"
	"strings"

	"github.com/google/go-jsonnet"
)

// Jsonnet builds the structure of a host or module file: what it evaluates
// to is decoded strictly (decodeJSONStrict) into HostSpec or moduleSpec and
// validated. The contents of files stay text/template. A YAML host or module
// file is not read; one in the repo is an error (specFile), not skipped.
//
// Evaluation is pure, so render stays deterministic for CI and diff:
//   - imports, importstr and importbin resolve only inside fsys (the fetched
//     commit), relative to the importing file and then to the repo root, so
//     modules/m/module.jsonnet can import 'lib/infra.libsonnet';
//   - there are no external variables and no native functions, so nothing
//     outside the repo reaches it, and no secret can: plans and module output
//     never contain one (see secrets.go). A file with secret: true reads its
//     secrets in its template, as before;
//   - a module gets its host as the top-level argument host, when it is a
//     function(host): {name, ref, address, modules, vars}.
//
// A shared host base is a .libsonnet file, since every hosts/*.jsonnet is a
// host.
//
// The import check here is only on the spelling of the path; a symlink in the
// checkout is stopped by the fs.FS itself, which OpenRepo gives.

// OpenRepo opens a checkout of the desired-state repo for Hosts, LoadHost and
// Render. Every path, through a symlinked file or parent directory alike,
// must resolve inside dir (os.Root), so neither an import nor a template or
// source file can read a file of the host (its age identity, /etc/shadow)
// into a plan. A relative symlink that stays inside dir works; an absolute
// one is refused even when it points inside dir, since dir is not / to
// os.Root. close releases dir.
func OpenRepo(dir string) (fsys fs.FS, close func() error, err error) {
	root, err := os.OpenRoot(dir)
	if err != nil {
		return nil, nil, err
	}
	return root.FS(), root.Close, nil
}

// loadSpec evaluates file, a host or module .jsonnet file, and decodes it into
// v. A module gets its host (not nil) as the top-level argument.
func loadSpec(fsys fs.FS, file string, host *HostSpec, v any) error {
	// An evaluation error names the file itself (evalJSONNet).
	b, err := evalJSONNet(fsys, file, host)
	if err != nil {
		return err
	}
	if err := decodeJSONStrict(b, v); err != nil {
		return fmt.Errorf("%s: %w", file, err)
	}
	return nil
}

// evalJSONNet evaluates file in fsys, with host as the top-level argument when
// it is not nil.
func evalJSONNet(fsys fs.FS, file string, host *HostSpec) ([]byte, error) {
	vm := jsonnet.MakeVM()
	im := &fsImporter{fsys: fsys, cache: map[string]jsonnet.Contents{}}
	vm.Importer(im)
	if host != nil {
		modules := host.Modules
		if modules == nil {
			modules = []string{}
		}
		b, err := json.Marshal(map[string]any{"name": host.Name, "ref": host.Ref, "address": host.Address, "modules": modules, "vars": host.Vars})
		if err != nil {
			return nil, fmt.Errorf("host %s as jsonnet: %w", host.Name, err)
		}
		vm.TLACode("host", string(b))
	}
	out, err := vm.EvaluateFile(file)
	if err != nil {
		// go-jsonnet formats its errors into text, trace included; keep
		// the importer's error underneath for errors.Is.
		// The trace usually names file with a position already; prefix
		// it only when not (a top-level argument error has no position).
		msg := strings.TrimSpace(err.Error())
		if !strings.Contains(msg, file+":") {
			msg = file + ": " + msg
		}
		return nil, &jsonnetError{msg: msg, cause: im.err}
	}
	return []byte(out), nil
}

type jsonnetError struct {
	msg   string
	cause error
}

func (e *jsonnetError) Error() string { return e.msg }
func (e *jsonnetError) Unwrap() error { return e.cause }

// fsImporter resolves jsonnet imports inside fsys and nowhere else.
type fsImporter struct {
	fsys  fs.FS
	cache map[string]jsonnet.Contents // foundAt → contents, so they never change
	err   error                       // the first error, for jsonnetError
}

func (im *fsImporter) Import(importedFrom, importedPath string) (jsonnet.Contents, string, error) {
	c, foundAt, err := im.find(importedFrom, importedPath)
	if err != nil && im.err == nil {
		im.err = err
	}
	return c, foundAt, err
}

func (im *fsImporter) find(importedFrom, importedPath string) (jsonnet.Contents, string, error) {
	if path.IsAbs(importedPath) {
		return jsonnet.Contents{}, "", fmt.Errorf("import %q: imports are relative to the importing file or the repository root", importedPath)
	}
	var candidates []string
	if importedFrom != "" {
		candidates = append(candidates, path.Join(path.Dir(importedFrom), importedPath))
	}
	candidates = append(candidates, path.Clean(importedPath))
	for _, p := range candidates {
		if !fs.ValidPath(p) {
			return jsonnet.Contents{}, "", fmt.Errorf("import %q: outside the repository", importedPath)
		}
		if c, ok := im.cache[p]; ok {
			return c, p, nil
		}
		b, err := fs.ReadFile(im.fsys, p)
		if errors.Is(err, fs.ErrNotExist) {
			continue
		}
		if err != nil {
			return jsonnet.Contents{}, "", fmt.Errorf("import %q: %w", importedPath, err)
		}
		c := jsonnet.MakeContentsRaw(b)
		im.cache[p] = c
		return c, p, nil
	}
	return jsonnet.Contents{}, "", fmt.Errorf("import %q: not found in the repository", importedPath)
}

// specFile is dir/base.jsonnet. A dir/base.yaml next to it or instead of it
// is an error: it is not read, and skipping it quietly would drop
// a module from a host, or a host from diff (whose --update would then delete
// its rendered/ tree).
func specFile(fsys fs.FS, dir, base string) (string, error) {
	p := dir + "/" + base + ".jsonnet"
	if err := noYAML(fsys, dir+"/"+base+".yaml", p); err != nil {
		return "", err
	}
	if _, err := fs.Stat(fsys, p); err != nil {
		return "", err
	}
	return p, nil
}

// noYAML refuses yamlFile, a host or module file in YAML, when it
// exists (as a file or as a symlink, dangling or not).
func noYAML(fsys fs.FS, yamlFile, jsonnetFile string) error {
	_, err := fs.Lstat(fsys, yamlFile)
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	return fmt.Errorf("%s is not read, host and module files are jsonnet: write it as %s", yamlFile, jsonnetFile)
}

// decodeJSONStrict decodes jsonnet's output into v strictly:
//   - every object key must be a json tag of v's type, spelled exactly:
//     DisallowUnknownFields alone would take "Path" for path;
//   - a number is not a string: mode: std.parseOctal('644') is 420, which
//     a lenient decoder would turn into the string "420", read as mode 0420.
//
// Numbers in HostSpec.Vars become int when whole and float64 otherwise, so
// templates render them as written (a float64 1000000 would print as
// 1e+06).
func decodeJSONStrict(b []byte, v any) error {
	var raw any
	if err := json.Unmarshal(b, &raw); err != nil {
		return err
	}
	if err := checkKeys(raw, reflect.TypeOf(v), ""); err != nil {
		return err
	}
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	dec.UseNumber()
	if err := dec.Decode(v); err != nil {
		return err
	}
	if h, ok := v.(*HostSpec); ok {
		h.Vars, _ = jsonNumbers(h.Vars).(map[string]any)
	}
	return nil
}

// checkKeys refuses an object key that is not exactly the json tag of a
// field of the struct t it decodes into. at is the path, for the error.
func checkKeys(raw any, t reflect.Type, at string) error {
	for t.Kind() == reflect.Pointer {
		t = t.Elem()
	}
	switch t.Kind() {
	case reflect.Struct:
		obj, ok := raw.(map[string]any)
		if !ok {
			return nil // a wrong type is the decoder's error
		}
		for _, k := range slices.Sorted(maps.Keys(obj)) {
			f, ok := fieldByTag(t, k)
			if !ok {
				return fmt.Errorf("%sfield %s not found in type %s", where(at), k, t)
			}
			if err := checkKeys(obj[k], f.Type, at+"."+k); err != nil {
				return err
			}
		}
	case reflect.Slice:
		arr, _ := raw.([]any)
		for i, e := range arr {
			if err := checkKeys(e, t.Elem(), fmt.Sprintf("%s[%d]", at, i)); err != nil {
				return err
			}
		}
	case reflect.Map:
		obj, _ := raw.(map[string]any)
		for k, e := range obj {
			if err := checkKeys(e, t.Elem(), at+"."+k); err != nil {
				return err
			}
		}
	}
	return nil
}

func where(at string) string {
	if at == "" {
		return ""
	}
	return strings.TrimPrefix(at, ".") + ": "
}

func fieldByTag(t reflect.Type, key string) (reflect.StructField, bool) {
	for i := range t.NumField() {
		f := t.Field(i)
		if name, _, _ := strings.Cut(f.Tag.Get("json"), ","); name == key && name != "-" {
			return f, true
		}
	}
	return reflect.StructField{}, false
}

// jsonNumbers replaces the json.Numbers in v by int or float64.
func jsonNumbers(v any) any {
	switch v := v.(type) {
	case json.Number:
		if i, err := v.Int64(); err == nil {
			return int(i)
		}
		f, _ := v.Float64()
		return f
	case map[string]any:
		for k, e := range v {
			v[k] = jsonNumbers(e)
		}
	case []any:
		for i, e := range v {
			v[i] = jsonNumbers(e)
		}
	}
	return v
}
