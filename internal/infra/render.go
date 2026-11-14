package infra

import (
	"bytes"
	"errors"
	"fmt"
	"io/fs"
	"maps"
	"net/http"
	"net/netip"
	"path"
	"regexp"
	"slices"
	"sort"
	"strconv"
	"strings"
	"text/template"
)

// The desired state is a git repository, read from the fetched commit, so a
// config change needs no new agent release:
//
//	hosts/<hostname>.jsonnet       HostSpec
//	modules/<name>/module.jsonnet  the module's resources
//	modules/<name>/<file>          templates and verbatim sources it refers to
//
// jsonnet.go describes how the .jsonnet files are evaluated. Templates
// get .Host (the HostSpec) and .Vars (its vars), and a missing key is an error
// rather than an empty string in a config file. The template of a file with
// secret: true also gets {{secret "name"}}; see secrets.go.

// HostSpec is hosts/<hostname>.jsonnet.
type HostSpec struct {
	Name string `json:"-"`
	// Ref is the branch this host follows (e.g. main for a standby,
	// infra/<host> for the active host); the pull unit is rendered with it.
	Ref string `json:"ref"`
	// Address is the host's IP on the servers' network, optional. The other
	// hosts' configs read it from its host file (a scrape target, say) and
	// bootstrap's ssh goes to it when --ssh is not given. An IP rather than a
	// name, so neither depends on DNS or /etc/hosts.
	Address string         `json:"address"`
	Modules []string       `json:"modules"`
	Vars    map[string]any `json:"vars"`
}

type moduleSpec struct {
	Resources []resourceSpec `json:"resources"`
}

type resourceSpec struct {
	File     *fileSpec     `json:"file"`
	Dir      *dirSpec      `json:"dir"`
	Package  string        `json:"package"`
	Unit     *unitSpec     `json:"unit"`
	Command  *commandSpec  `json:"command"`
	Download *downloadSpec `json:"download"`
	User     *userSpec     `json:"user"`
}

// downloadSpec has exactly one of Path (the download itself is the file)
// and Extract (archive member → path).
type downloadSpec struct {
	URL      string            `json:"url"`
	SHA256   string            `json:"sha256"`
	Path     string            `json:"path"`
	Extract  map[string]string `json:"extract"`
	Mode     string            `json:"mode"`
	Owner    string            `json:"owner"`
	Group    string            `json:"group"`
	OnChange []actionSpec      `json:"onChange"`
	// PreInstallCheck and KeepPrevious: see Download.
	PreInstallCheck []string `json:"preInstallCheck"`
	KeepPrevious    bool     `json:"keepPrevious"`
	// Headers are sent as they are, and shown in golden files.
	// SecretHeaders maps a header to the name of a host secret holding its
	// whole value (e.g. "Bearer …"); see Download.
	Headers       map[string]string `json:"headers"`
	SecretHeaders map[string]string `json:"secretHeaders"`
}

type userSpec struct {
	Name   string   `json:"name"`
	Home   string   `json:"home"`
	Groups []string `json:"groups"`
}

type fileSpec struct {
	Path string `json:"path"`
	// Exactly one of: Template (rendered), Source (copied as is, e.g. a
	// Grafana dashboard full of {{ }}) or Content (inline).
	Template string       `json:"template"`
	Source   string       `json:"source"`
	Content  *string      `json:"content"`
	Mode     string       `json:"mode"`
	Owner    string       `json:"owner"`
	Group    string       `json:"group"`
	Secret   bool         `json:"secret"`
	OnChange []actionSpec `json:"onChange"`
}

type actionSpec struct {
	Restart    string   `json:"restart"`
	Reload     string   `json:"reload"`
	TryRestart string   `json:"try-restart"`
	Check      []string `json:"check"`
}

type dirSpec struct {
	Path     string       `json:"path"`
	Mode     string       `json:"mode"`
	Owner    string       `json:"owner"`
	Group    string       `json:"group"`
	Purge    bool         `json:"purge"`
	OnChange []actionSpec `json:"onChange"`
}

type unitSpec struct {
	Name    string `json:"name"`
	Enabled bool   `json:"enabled"`
	Active  bool   `json:"active"`
}

type commandSpec struct {
	Name   string   `json:"name"`
	Check  []string `json:"check"`
	Run    []string `json:"run"`
	Secret bool     `json:"secret"`
}

// templateData is all a template can reach, {{printf "%v" .}} included: the
// secrets are never in it, only in the secret function given to the templates
// that may read them.
type templateData struct {
	Host *HostSpec
	Vars map[string]any
}

// Hosts lists the host names in hosts/, from hosts/<name>.jsonnet. A
// hosts/*.yaml is an error, not skipped (see specFile).
func Hosts(fsys fs.FS) ([]string, error) {
	yamls, err := fs.Glob(fsys, "hosts/*.yaml")
	if err != nil {
		return nil, err
	}
	if len(yamls) > 0 {
		y := yamls[0]
		return nil, noYAML(fsys, y, strings.TrimSuffix(y, ".yaml")+".jsonnet")
	}
	matches, err := fs.Glob(fsys, "hosts/*.jsonnet")
	if err != nil {
		return nil, err
	}
	var names []string
	for _, m := range matches {
		names = append(names, strings.TrimSuffix(path.Base(m), ".jsonnet"))
	}
	sort.Strings(names)
	return names, nil
}

// HostFile is the host's file in fsys, hosts/<name>.jsonnet. It is not in
// HostSpec, which templates see.
func HostFile(fsys fs.FS, name string) (string, error) {
	return specFile(fsys, "hosts", name)
}

func LoadHost(fsys fs.FS, name string) (*HostSpec, error) {
	h, _, err := LoadHostFile(fsys, name)
	return h, err
}

// LoadHostFile is LoadHost, which also returns the file it read, for
// messages.
func LoadHostFile(fsys fs.FS, name string) (*HostSpec, string, error) {
	file, err := HostFile(fsys, name)
	if err != nil {
		return nil, "", err
	}
	h := &HostSpec{}
	if err := loadSpec(fsys, file, nil, h); err != nil {
		return nil, "", err
	}
	h.Name = name
	if h.Ref == "" {
		return nil, "", fmt.Errorf("%s: ref is required", file)
	}
	if h.Address != "" {
		if _, err := netip.ParseAddr(h.Address); err != nil {
			return nil, "", fmt.Errorf("%s: address %q is not an IP address", file, h.Address)
		}
	}
	if h.Vars == nil {
		h.Vars = map[string]any{}
	}
	return h, file, nil
}

// Render turns a host's modules into resources. It is pure: it reads only
// fsys and secrets. With nil secrets, {{secret}} renders a placeholder, so
// diff and CI render every host without being able to decrypt anything.
func Render(fsys fs.FS, h *HostSpec, secrets SecretSource) ([]Resource, error) {
	data := templateData{Host: h, Vars: h.Vars}
	var out []Resource
	owner := map[string]string{} // resource key → module, for duplicates
	// A File and a Dir on one path have different keys, so they are caught
	// by path: the second one would fail every plan once the first exists.
	byPath := map[string]string{} // path → "<key> in module <m>"
	for _, m := range h.Modules {
		rs, err := renderModule(fsys, m, data, secrets)
		if err != nil {
			return nil, fmt.Errorf("module %s: %w", m, err)
		}
		for _, r := range rs {
			if prev, ok := owner[r.Key()]; ok {
				return nil, fmt.Errorf("%s is declared by both module %s and module %s", r.Key(), prev, m)
			}
			owner[r.Key()] = m
			paths, _ := pathsAndActions(r)
			// Reserved, not declared: a purge still removes the file a
			// crash left at a staged path.
			if d, ok := r.(*Download); ok && (len(d.PreInstallCheck) > 0 || d.KeepPrevious) {
				for _, f := range d.Files {
					paths = append(paths, stagedPath(f.Path))
				}
			}
			for _, p := range paths {
				if prev, ok := byPath[p]; ok {
					return nil, fmt.Errorf("%s in module %s has the same path %s as %s", r.Key(), m, p, prev)
				}
				byPath[p] = r.Key() + " in module " + m
			}
			out = append(out, r)
		}
	}
	if err := checkUsersFirst(out); err != nil {
		return nil, err
	}
	return out, nil
}

// checkUsersFirst refuses a resource owned by a user (or its group, which
// useradd --user-group creates) that is declared after it. Apply goes in
// order and stops at the first failure, so the chown would fail before the
// user exists, and every pull after it the same way.
func checkUsersFirst(rs []Resource) error {
	users := map[string]int{}
	for i, r := range rs {
		if u, ok := r.(*User); ok {
			users[u.Name] = i
		}
	}
	for i, r := range rs {
		var owner, group string
		switch r := r.(type) {
		case *File:
			owner, group = r.Owner, r.Group
		case *Dir:
			owner, group = r.Owner, r.Group
		case *Download:
			owner, group = r.Owner, r.Group
		default:
			continue
		}
		for _, name := range []string{owner, group} {
			if j, ok := users[name]; ok && j > i {
				return fmt.Errorf("%s is owned by %s, but user %s is declared after it; declare the user first", r.Key(), name, name)
			}
		}
	}
	return nil
}

func renderModule(fsys fs.FS, name string, data templateData, secrets SecretSource) ([]Resource, error) {
	dir := "modules/" + name
	file, err := specFile(fsys, dir, "module")
	if err != nil {
		return nil, err
	}
	var spec moduleSpec
	if err := loadSpec(fsys, file, data.Host, &spec); err != nil {
		return nil, err
	}
	var out []Resource
	for i, rs := range spec.Resources {
		r, err := rs.resource(fsys, dir, data, secrets)
		if err != nil {
			return nil, fmt.Errorf("resource %d: %w", i+1, err)
		}
		out = append(out, r)
	}
	return out, nil
}

func (rs resourceSpec) resource(fsys fs.FS, dir string, data templateData, secrets SecretSource) (Resource, error) {
	n := 0
	for _, set := range []bool{rs.File != nil, rs.Dir != nil, rs.Package != "", rs.Unit != nil, rs.Command != nil, rs.Download != nil, rs.User != nil} {
		if set {
			n++
		}
	}
	if n != 1 {
		return nil, fmt.Errorf("must be exactly one of file, dir, package, unit, command, download, user")
	}
	switch {
	case rs.Download != nil:
		return rs.Download.resource(secrets)
	case rs.User != nil:
		return rs.User.resource()
	case rs.File != nil:
		return rs.File.resource(fsys, dir, data, secrets)
	case rs.Dir != nil:
		d := rs.Dir
		if err := checkPath(d.Path); err != nil {
			return nil, err
		}
		mode, err := parseMode(d.Mode, 0o755)
		if err != nil {
			return nil, err
		}
		out := &Dir{Path: d.Path, Mode: mode, Owner: orRoot(d.Owner), Group: orRoot(d.Group), Purge: d.Purge}
		if len(d.OnChange) > 0 && !d.Purge {
			return nil, fmt.Errorf("dir %s: onChange only runs after a purge, so it needs purge: true", d.Path)
		}
		if out.OnChange, err = actions(d.OnChange); err != nil {
			return nil, fmt.Errorf("dir %s: %w", d.Path, err)
		}
		return out, nil
	case rs.Package != "":
		return &Package{Name: rs.Package}, nil
	case rs.Unit != nil:
		if rs.Unit.Name == "" {
			return nil, fmt.Errorf("unit without name")
		}
		return &Unit{Name: unitName(rs.Unit.Name), Enabled: rs.Unit.Enabled, Active: rs.Unit.Active}, nil
	default:
		c := rs.Command
		if c.Name == "" || len(c.Check) == 0 || len(c.Run) == 0 {
			return nil, fmt.Errorf("command needs name, check and run")
		}
		return &Command{Name: c.Name, Check: c.Check, Run: c.Run, Secret: c.Secret}, nil
	}
}

func (f *fileSpec) resource(fsys fs.FS, dir string, data templateData, secrets SecretSource) (Resource, error) {
	if err := checkPath(f.Path); err != nil {
		return nil, err
	}
	var content []byte
	var usesSecrets, placeholders bool
	var err error
	switch {
	case f.Template != "" && f.Source == "" && f.Content == nil:
		var raw []byte
		raw, err = fs.ReadFile(fsys, path.Join(dir, f.Template))
		if err != nil {
			break
		}
		if !f.Secret {
			content, err = execTemplate(f.Template, raw, data, noSecrets(f.Template, "a file without secret: true is shown in plans and golden files"))
			break
		}
		// Without secrets (diff, CI) this render has the placeholders the
		// golden file shows. On a host it has the values, and no golden
		// file is rendered: it would only cost a render that can fail
		// where the real one works ({{slice (secret "pw") 0 16}}).
		var used []string
		var srcErr error
		content, err = execTemplate(f.Template, raw, data, secretFuncs(secrets, &used, &srcErr))
		if err != nil && secrets != nil {
			err = safeSecretError(f.Template, raw, data, srcErr)
		}
		if err != nil || len(used) == 0 {
			break
		}
		usesSecrets, placeholders = true, secrets == nil
	case f.Source != "" && f.Template == "" && f.Content == nil:
		content, err = fs.ReadFile(fsys, path.Join(dir, f.Source))
	case f.Content != nil && f.Template == "" && f.Source == "":
		content = []byte(*f.Content)
	default:
		return nil, fmt.Errorf("file %s: needs exactly one of template, source, content", f.Path)
	}
	if err != nil {
		return nil, fmt.Errorf("file %s: %w", f.Path, err)
	}
	defaultMode := fs.FileMode(0o644)
	if f.Secret {
		defaultMode = 0o600 // hidden from review, so also from other users
	}
	mode, err := parseMode(f.Mode, defaultMode)
	if err != nil {
		return nil, fmt.Errorf("file %s: %w", f.Path, err)
	}
	if usesSecrets && mode&0o007 != 0 {
		return nil, fmt.Errorf("file %s: mode %04o lets every user read the secrets in it; give others no access (0600, or 0640 with a group for a service that needs them)", f.Path, mode)
	}
	out := &File{Path: f.Path, Content: content, UsesSecrets: usesSecrets, Placeholders: placeholders, Mode: mode, Owner: orRoot(f.Owner), Group: orRoot(f.Group), Secret: f.Secret}
	if out.OnChange, err = actions(f.OnChange); err != nil {
		return nil, fmt.Errorf("file %s: %w", f.Path, err)
	}
	return out, nil
}

var sha256Re = regexp.MustCompile(`^[0-9a-f]{64}$`)

func (d *downloadSpec) resource(secrets SecretSource) (Resource, error) {
	if !strings.HasPrefix(d.URL, "https://") {
		return nil, fmt.Errorf("download %q: url must be https", d.URL)
	}
	if !sha256Re.MatchString(d.SHA256) {
		return nil, fmt.Errorf("download %s: sha256 must be 64 lowercase hex digits, the one upstream publishes for the file at url", d.URL)
	}
	out := &Download{URL: d.URL, SHA256: d.SHA256, Owner: orRoot(d.Owner), Group: orRoot(d.Group)}
	switch {
	case d.Path != "" && d.Extract == nil:
		out.Files = []DownloadFile{{Path: d.Path}}
	case d.Path == "" && len(d.Extract) > 0:
		for _, member := range slices.Sorted(maps.Keys(d.Extract)) {
			if member == "" || path.IsAbs(member) || path.Clean(member) != member || member == ".." || strings.HasPrefix(member, "../") {
				return nil, fmt.Errorf("download %s: archive member %q must be a clean relative path", d.URL, member)
			}
			out.Files = append(out.Files, DownloadFile{Member: member, Path: d.Extract[member]})
		}
	default:
		return nil, fmt.Errorf("download %s: needs exactly one of path, extract", d.URL)
	}
	for _, f := range out.Files {
		if err := checkPath(f.Path); err != nil {
			return nil, fmt.Errorf("download %s: %w", d.URL, err)
		}
		// A unit file written by a download would need a daemon-reload,
		// which only file resources trigger; unit files belong in those.
		if isUnitFile(f.Path) {
			return nil, fmt.Errorf("download %s: %s is a systemd unit path; write unit files with a file resource", d.URL, f.Path)
		}
	}
	if d.PreInstallCheck != nil {
		if d.Path == "" {
			return nil, fmt.Errorf("download %s: preInstallCheck needs path: it checks the one file a download without extract installs", d.URL)
		}
		if !slices.ContainsFunc(d.PreInstallCheck, func(a string) bool { return strings.Contains(a, PreInstallFile) }) {
			return nil, fmt.Errorf("download %s: preInstallCheck must name the new file as %s, e.g. [%q, \"version\"]; otherwise it checks something else", d.URL, PreInstallFile, PreInstallFile)
		}
		out.PreInstallCheck = d.PreInstallCheck
	}
	out.KeepPrevious = d.KeepPrevious
	if err := d.headers(out, secrets); err != nil {
		return nil, fmt.Errorf("download %s: %w", d.URL, err)
	}
	var err error
	if out.Mode, err = parseMode(d.Mode, 0o755); err != nil {
		return nil, fmt.Errorf("download %s: %w", d.URL, err)
	}
	if out.OnChange, err = actions(d.OnChange); err != nil {
		return nil, fmt.Errorf("download %s: %w", d.URL, err)
	}
	return out, nil
}

// headerNameRe is an HTTP field name (RFC 9110 5.1, a token).
var headerNameRe = regexp.MustCompile("^[A-Za-z0-9!#$%&'*+.^_`|~-]+$")

// refusedHeaders cannot be set by a download, with why. All of them pass
// render and would only fail on the host, at the fetch.
var refusedHeaders = map[string]string{
	"Host":              "it is set by " + agentName + " from the URL",
	"User-Agent":        "it is set by " + agentName,
	"Connection":        "it is set by net/http",
	"Content-Length":    "it is set by net/http",
	"Transfer-Encoding": "it is set by net/http",
	"Te":                "it is set by net/http",
	"Expect":            "a GET has no body to continue",
	// net/http only decompresses a response itself when it asked for
	// gzip; with the header set the pin is checked against the
	// compressed bytes and fails.
	"Accept-Encoding": "net/http would then hand on a compressed body, which fails the pin",
	// Fetch takes only a 200 with the whole file.
	"Range":               "Fetch takes only a 200 with the whole file",
	"If-Range":            "Fetch takes only a 200 with the whole file",
	"If-Match":            "Fetch takes only a 200 with the whole file",
	"If-None-Match":       "Fetch takes only a 200 with the whole file",
	"If-Modified-Since":   "Fetch takes only a 200 with the whole file",
	"If-Unmodified-Since": "Fetch takes only a 200 with the whole file",
	// For an https URL net/http sends request headers to the origin
	// inside the proxy's tunnel, so the proxy never sees it and the
	// origin gets the proxy's credential. A proxy's credential goes in
	// HTTPS_PROXY's userinfo.
	"Proxy-Authorization": "it would reach the server, not the proxy; set the proxy's credential in HTTPS_PROXY",
}

// credentialHeaders carry credentials, so they may only be secretHeaders:
// as headers they would be in golden files and in git.
var credentialHeaders = map[string]bool{"Authorization": true, "Cookie": true}

// headers checks d's headers and secretHeaders and puts them in out, with
// each secret's value read from secrets, or its placeholder when secrets is
// nil (diff, CI, bootstrap), in which case out refuses to fetch. An error
// names the header and the secret, never a value.
func (d *downloadSpec) headers(out *Download, secrets SecretSource) error {
	seen := map[string]bool{}
	name := func(field, h string) (string, error) {
		if !headerNameRe.MatchString(h) {
			return "", fmt.Errorf("%s: %q is not a header name", field, h)
		}
		c := http.CanonicalHeaderKey(h)
		if why, ok := refusedHeaders[c]; ok {
			return "", fmt.Errorf("%s: %s cannot be set by a download: %s", field, c, why)
		}
		if seen[c] {
			return "", fmt.Errorf("%s: %s is given twice (header names are case-insensitive, and one may be in headers and secretHeaders)", field, c)
		}
		seen[c] = true
		return c, nil
	}
	for _, h := range slices.Sorted(maps.Keys(d.Headers)) {
		c, err := name("headers", h)
		if err != nil {
			return err
		}
		if credentialHeaders[c] {
			return fmt.Errorf("headers: %s carries a credential; put it in secretHeaders, as the name of a host secret", c)
		}
		if !validHeaderValue(d.Headers[h]) {
			return fmt.Errorf("headers: %s: the value has a control character (a line break?)", c)
		}
		if out.Headers == nil {
			out.Headers = map[string]string{}
		}
		out.Headers[c] = d.Headers[h]
	}
	for _, h := range slices.Sorted(maps.Keys(d.SecretHeaders)) {
		c, err := name("secretHeaders", h)
		if err != nil {
			return err
		}
		secret := d.SecretHeaders[h]
		if !secretNameRe.MatchString(secret) {
			return fmt.Errorf("secretHeaders: %s: %w", c, errBadSecretName)
		}
		v := secretPlaceholderValue(secret)
		if secrets == nil {
			out.placeholders = true
		} else {
			// The name is the module's own string, never a value, so
			// the error may show it.
			if v, err = secrets.Secret(secret); err != nil {
				return fmt.Errorf("secretHeaders: %s: %w", c, err)
			}
			if !validHeaderValue(v) {
				return fmt.Errorf("secretHeaders: %s: secret %q is not a valid header value: it is empty or has a control character such as a line break (value not shown)", c, secret)
			}
		}
		if out.SecretHeaders == nil {
			out.SecretHeaders, out.secretValues = map[string]string{}, http.Header{}
		}
		out.SecretHeaders[c] = secret
		out.secretValues.Set(c, v)
	}
	return nil
}

// validHeaderValue: no control characters but tab (RFC 9110 5.5), not
// empty, and no leading or trailing whitespace, which a server would strip.
func validHeaderValue(v string) bool {
	if v == "" || strings.TrimSpace(v) != v {
		return false
	}
	for _, r := range v {
		if (r < 0x20 && r != '\t') || r == 0x7f {
			return false
		}
	}
	return true
}

// systemNameRe is what useradd and groupadd take on Debian, without the
// trailing $ of machine accounts.
var systemNameRe = regexp.MustCompile(`^[a-z_][a-z0-9_-]{0,31}$`)

func (u *userSpec) resource() (Resource, error) {
	if !systemNameRe.MatchString(u.Name) {
		return nil, fmt.Errorf("user %q: name must be lowercase letters, digits, _ and -, at most 32", u.Name)
	}
	out := &User{Name: u.Name, Home: u.Home}
	if out.Home == "" {
		out.Home = "/nonexistent"
	} else if err := checkPath(out.Home); err != nil {
		return nil, fmt.Errorf("user %s: home: %w", u.Name, err)
	}
	for _, g := range u.Groups {
		if !systemNameRe.MatchString(g) {
			return nil, fmt.Errorf("user %s: group %q must be lowercase letters, digits, _ and -, at most 32", u.Name, g)
		}
		if !slices.Contains(out.Groups, g) {
			out.Groups = append(out.Groups, g)
		}
	}
	slices.Sort(out.Groups)
	return out, nil
}

func actions(specs []actionSpec) ([]Action, error) {
	var out []Action
	for _, a := range specs {
		act, err := a.action()
		if err != nil {
			return nil, err
		}
		out = append(out, act)
	}
	return out, nil
}

func (a actionSpec) action() (Action, error) {
	var acts []Action
	if a.Restart != "" {
		acts = append(acts, Action{Verb: "restart", Unit: unitName(a.Restart)})
	}
	if a.Reload != "" {
		acts = append(acts, Action{Verb: "reload", Unit: unitName(a.Reload)})
	}
	if a.TryRestart != "" {
		acts = append(acts, Action{Verb: "try-restart", Unit: unitName(a.TryRestart)})
	}
	if len(acts) != 1 {
		return Action{}, fmt.Errorf("onChange entry needs exactly one of restart, reload, try-restart")
	}
	if len(a.Check) > 0 {
		acts[0].Checks = [][]string{a.Check}
	}
	return acts[0], acts[0].validate()
}

// unitName adds .service to a unit name without a type, as systemctl does,
// so "nginx" and "nginx.service" are one unit when actions are merged and a
// fresh start is matched with the restart it replaces.
func unitName(name string) string {
	if name == "" {
		return name
	}
	if i := strings.LastIndex(name, "."); i >= 0 && unitTypes[name[i+1:]] {
		return name
	}
	return name + ".service"
}

var unitTypes = map[string]bool{"service": true, "socket": true, "device": true, "mount": true, "automount": true, "swap": true, "target": true, "path": true, "timer": true, "slice": true, "scope": true}

// noSecrets is the secret function where secrets may not go; why says what
// would show them.
func noSecrets(where, why string) template.FuncMap {
	return template.FuncMap{"secret": func(string) (string, error) {
		return "", fmt.Errorf("secret is only allowed in the template of a file with secret: true, not in %s: %s", where, why)
	}}
}

// secretFuncs reads values from secrets, or gives placeholders when secrets
// is nil, which is why a template may only output a secret, never compare or
// slice it (see the package doc of secrets.go). It appends the names it was asked for to used, and keeps the first
// error of the SecretSource in srcErr, for safeSecretError; both may be nil.
func secretFuncs(secrets SecretSource, used *[]string, srcErr *error) template.FuncMap {
	return template.FuncMap{"secret": func(name string) (string, error) {
		if used != nil {
			*used = append(*used, name)
		}
		// In both modes, so CI catches a name no secrets file can hold
		// (a space, or one computed from another secret's placeholder).
		if !secretNameRe.MatchString(name) {
			return "", errBadSecretName
		}
		if secrets == nil {
			return secretPlaceholderValue(name), nil
		}
		v, err := secrets.Secret(name)
		if err != nil && srcErr != nil && *srcErr == nil {
			*srcErr = err
		}
		return v, err
	}}
}

var errBadSecretName = errors.New("a secret name has letters, digits, _, . and - only")

// safeSecretError replaces the error of a render with this host's secret
// values, which may quote one ({{range secret "pw"}}, {{secret (secret
// "pw")}}) and would reach the pull's journal, by one that cannot:
//   - the secrets could not be loaded: that error (it holds no value);
//   - a name not in the secrets file: the name, when the render with
//     placeholders asks for it too, so it comes from the template or its
//     vars and is no value (a quoted string elsewhere in the template proves
//     nothing: it may be a comment);
//   - otherwise the error of the render with placeholders, or, when that
//     works, only that the values make it fail.
func safeSecretError(name string, raw []byte, data templateData, srcErr error) error {
	var asked []string
	_, perr := execTemplate(name, raw, data, secretFuncs(nil, &asked, nil))
	var missing *missingSecretError
	switch {
	case errors.As(srcErr, &missing) && slices.Contains(asked, missing.name):
		return missing
	case errors.As(srcErr, &missing):
		return fmt.Errorf("%s asks for a secret by a name it computes, which is not in this host's secrets file (name not shown: it may be a value)", name)
	case srcErr != nil:
		return srcErr
	case perr != nil:
		return perr
	}
	return fmt.Errorf("%s fails with this host's secret values but not with placeholders (error not shown: it may quote a value)", name)
}

func execTemplate(name string, raw []byte, data templateData, funcs template.FuncMap) ([]byte, error) {
	t, err := template.New(name).Option("missingkey=error").Funcs(funcs).Parse(string(raw))
	if err != nil {
		return nil, err
	}
	var b bytes.Buffer
	if err := t.Execute(&b, data); err != nil {
		return nil, err
	}
	return b.Bytes(), nil
}

func checkPath(p string) error {
	if p == "" || !path.IsAbs(p) || path.Clean(p) != p || p == "/" {
		return fmt.Errorf("path %q must be absolute and clean", p)
	}
	return nil
}

func parseMode(s string, def fs.FileMode) (fs.FileMode, error) {
	if s == "" {
		return def, nil
	}
	m, err := strconv.ParseUint(s, 8, 32)
	if err != nil || m > 0o777 {
		return 0, fmt.Errorf("mode %q: want octal permission bits like \"0644\"", s)
	}
	return fs.FileMode(m), nil
}

func orRoot(s string) string {
	if s == "" {
		return "root"
	}
	return s
}
