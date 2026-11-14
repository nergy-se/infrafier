package infra

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const token = "Bearer github_pat_s3cr3t"

func headerModule(download string) string {
	return `{ resources: [ { download: ` + download + ` } ] }`
}

const assetDownload = `{
  url: 'https://api.github.com/repos/o/dist/releases/assets/123',
  sha256: '` + "0000000000000000000000000000000000000000000000000000000000000000" + `',
  path: '/usr/local/bin/apiserver',
  headers: { accept: 'application/octet-stream' },
  secretHeaders: { Authorization: 'dist-token' },
}`

// A release asset of a private repository: the token comes from the host's
// secrets on the host, a placeholder in CI, and golden files show the
// header and the secret's name, never the value, the same either way.
func TestDownloadSecretHeaderRender(t *testing.T) {
	fsys := testFS(headerModule(assetDownload), nil)
	h, err := LoadHost(fsys, "h")
	require.NoError(t, err)

	ci, err := Render(fsys, h, nil)
	require.NoError(t, err)
	d := ci[0].(*Download)
	assert.True(t, d.placeholders)
	assert.Equal(t, map[string]string{"Accept": "application/octet-stream"}, d.Headers)
	assert.Equal(t, map[string]string{"Authorization": "dist-token"}, d.SecretHeaders)

	host, err := Render(fsys, h, Secrets{"dist-token": token})
	require.NoError(t, err)
	d = host[0].(*Download)
	assert.False(t, d.placeholders)
	assert.Equal(t, token, d.secretValues.Get("Authorization"))

	desc := describe(d)
	assert.Contains(t, desc, "\n  header Accept: \"application/octet-stream\"")
	assert.Contains(t, desc, "\n  header Authorization: secret \"dist-token\"")
	assert.NotContains(t, desc, "s3cr3t")
	assert.Equal(t, describe(ci[0]), desc, "golden files must not depend on the values")
	// Header lines are no file lines for golden.go.
	assert.Equal(t, []string{"/usr/local/bin/apiserver"}, downloadPaths(desc))
	assert.Len(t, downloadInstalls(desc), 1)

	for p, b := range GoldenTree(host, "") {
		assert.NotContains(t, string(b), "s3cr3t", p)
	}
}

// A header value with a "→" must not read as a file line in a golden
// diff, or changing only that header would run the download's onChange.
func TestDownloadHeaderWithArrowIsNoFileLine(t *testing.T) {
	d := &Download{URL: "https://example.com/a", SHA256: strings.Repeat("0", 64), Mode: 0o755, Owner: "root", Group: "root",
		Files:   []DownloadFile{{Path: "/usr/local/bin/a"}},
		Headers: map[string]string{"X-Note": "build → /tmp/tool"}}
	desc := describe(d)
	assert.Contains(t, desc, `header X-Note: "build \u2192 /tmp/tool"`)
	assert.Equal(t, []string{"/usr/local/bin/a"}, downloadPaths(desc))
	assert.Len(t, downloadInstalls(desc), 1)
}

func TestDownloadHeaderErrors(t *testing.T) {
	for name, tc := range map[string]struct {
		download string
		secrets  Secrets
		want     string
	}{
		"credential in plain headers": {
			download: `headers: { Authorization: 'Bearer x' }`,
			want:     "Authorization carries a credential; put it in secretHeaders",
		},
		"not a header name": {
			download: `headers: { 'Bad Name': 'x' }`,
			want:     `"Bad Name" is not a header name`,
		},
		"set by infrafier": {
			download: `headers: { host: 'example.com' }`,
			want:     "Host is set by infrafier",
		},
		"twice across the two": {
			download: `headers: { 'x-api-key': 'a' }, secretHeaders: { 'X-Api-Key': 'k' }`,
			want:     "X-Api-Key is given twice",
		},
		"line break in a value": {
			download: `headers: { Accept: 'a\r\nX-Evil: 1' }`,
			want:     "Accept: the value has a control character",
		},
		"bad secret name": {
			download: `secretHeaders: { Authorization: 'a token' }`,
			want:     "a secret name has letters",
		},
		"missing secret": {
			download: `secretHeaders: { Authorization: 'dist-token' }`,
			secrets:  Secrets{"other": "x"},
			want:     `no secret "dist-token"`,
		},
		"secret with a line break": {
			download: `secretHeaders: { Authorization: 'dist-token' }`,
			secrets:  Secrets{"dist-token": "Bearer s3cr3t\n"},
			want:     `secret "dist-token" is not a valid header value`,
		},
	} {
		t.Run(name, func(t *testing.T) {
			d := `{ url: 'https://example.com/a', sha256: '` + strings.Repeat("0", 64) + `', path: '/usr/local/bin/a', ` + tc.download + ` }`
			fsys := testFS(headerModule(d), nil)
			h, err := LoadHost(fsys, "h")
			require.NoError(t, err)
			var src SecretSource
			if tc.secrets != nil {
				src = tc.secrets
			}
			_, err = Render(fsys, h, src)
			assert.ErrorContains(t, err, tc.want)
			if err != nil {
				assert.NotContains(t, err.Error(), "s3cr3t", "an error never shows a value")
			}
		})
	}
}

type seen struct {
	mu      sync.Mutex
	headers []http.Header
}

func (s *seen) add(h http.Header) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.headers = append(s.headers, h.Clone())
}

// GitHub's asset API answers with a redirect to a signed URL on another
// host. The secret headers stop at the first host, also a custom one that
// net/http itself would forward; plain headers go on. A redirect on the
// same host keeps them.
func TestFetchDropsSecretHeadersOnARedirectToAnotherHost(t *testing.T) {
	sys, _ := newTestSystem(t)
	bin := []byte("apiserver build")

	var cdn seen
	signed := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cdn.add(r.Header)
		w.Write(bin)
	}))
	t.Cleanup(signed.Close)
	var api seen
	apiSrv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		api.add(r.Header)
		if r.URL.Path == "/assets/123" {
			http.Redirect(w, r, "/assets/123/download", http.StatusFound) // same host
			return
		}
		http.Redirect(w, r, signed.URL+"/signed?sig=x", http.StatusFound)
	}))
	t.Cleanup(apiSrv.Close)
	sys.HTTP = apiSrv.Client() // httptest servers share one certificate

	d := &Download{URL: apiSrv.URL + "/assets/123", SHA256: sum(bin), Mode: 0o755,
		Files:         []DownloadFile{{Path: "/usr/local/bin/apiserver"}},
		Headers:       map[string]string{"Accept": "application/octet-stream"},
		SecretHeaders: map[string]string{"Authorization": "dist-token", "X-Api-Key": "key"},
		secretValues:  http.Header{"Authorization": {token}, "X-Api-Key": {"s3cr3t-key"}},
	}
	p, still, err := planAndApply(t, sys, []Resource{d}, nil)
	require.NoError(t, err)
	assert.Empty(t, still)
	assert.Equal(t, string(bin), readRoot(t, sys, "/usr/local/bin/apiserver"))
	assert.NotContains(t, p.String(), "s3cr3t")

	require.Len(t, api.headers, 2)
	for _, h := range api.headers {
		assert.Equal(t, token, h.Get("Authorization"))
		assert.Equal(t, "s3cr3t-key", h.Get("X-Api-Key"))
		assert.Equal(t, "application/octet-stream", h.Get("Accept"))
		assert.Equal(t, agentName, h.Get("User-Agent"))
	}
	require.Len(t, cdn.headers, 1)
	assert.Empty(t, cdn.headers[0].Get("Authorization"))
	assert.Empty(t, cdn.headers[0].Get("X-Api-Key"))
	assert.Equal(t, "application/octet-stream", cdn.headers[0].Get("Accept"))
}

// A failed fetch names the URL and the status, never a header's value.
func TestFetchErrorShowsNoSecret(t *testing.T) {
	sys, _ := newTestSystem(t)
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "Bad credentials", http.StatusUnauthorized)
	}))
	t.Cleanup(srv.Close)
	sys.HTTP = srv.Client()
	_, err := sys.Fetch(context.Background(), srv.URL+"/a", nil, http.Header{"Authorization": {token}})
	assert.ErrorContains(t, err, "401 Unauthorized")
	assert.NotContains(t, err.Error(), "s3cr3t")
}

// Rendered without secrets, a download has placeholders for them, which are
// never sent.
func TestDownloadWithPlaceholdersDoesNotFetch(t *testing.T) {
	sys, _ := newTestSystem(t)
	srv, base := serve(t, sys)
	bin := []byte("x")
	srv.content["/a"] = bin
	d := &Download{URL: base + "/a", SHA256: sum(bin), Mode: 0o755,
		Files:         []DownloadFile{{Path: "/usr/local/bin/a"}},
		SecretHeaders: map[string]string{"Authorization": "dist-token"},
		secretValues:  http.Header{"Authorization": {secretPlaceholderValue("dist-token")}},
		placeholders:  true,
	}
	_, err := MakePlan(context.Background(), sys, []Resource{d})
	assert.ErrorContains(t, err, "rendered without this host's secrets")
	assert.Zero(t, srv.requests.Load())
}
