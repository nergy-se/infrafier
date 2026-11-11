package infra

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestHostDiffRunsTheHostsDryRun(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.MkdirAll(filepath.Join(dir, "hosts"), 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "hosts/h.jsonnet"), []byte(`{ ref: 'infra/h', address: '192.0.2.1', modules: [] }`), 0o644))

	var calls [][]string
	local := Local{Interactive: func(_ context.Context, argv ...string) error {
		calls = append(calls, argv)
		return nil
	}}
	var out strings.Builder
	require.NoError(t, HostDiff(context.Background(), HostDiffConfig{Dir: dir, Host: "h", Local: local, Out: &out}))
	require.Len(t, calls, 1)
	assert.Equal(t, []string{"ssh", "-t", "192.0.2.1"}, calls[0][:3], "the host file's address, with a terminal for sudo")
	assert.Equal(t, `if [ "$(id -u)" = 0 ]; then s=; else s=sudo; fi; exec $s '/usr/local/bin/infrafier' pull --dry-run --ref 'infra/h' --host 'h'`, calls[0][3])
	assert.Contains(t, out.String(), "planning h at infra/h on h (ssh 192.0.2.1)")

	// Another branch and destination; a failure on the host is the command's.
	calls = nil
	failed := errors.New("exit status 1")
	local.Interactive = func(_ context.Context, argv ...string) error { calls = append(calls, argv); return failed }
	err := HostDiff(context.Background(), HostDiffConfig{Dir: dir, Host: "h", Target: "root@h.example", Ref: "pr/it's", Local: local})
	require.ErrorIs(t, err, failed)
	assert.Equal(t, "root@h.example", calls[0][2])
	assert.Contains(t, calls[0][3], `--ref 'pr/it'\''s'`)

	// An unknown host never connects.
	calls = nil
	require.Error(t, HostDiff(context.Background(), HostDiffConfig{Dir: dir, Host: "nope", Local: local}))
	assert.Empty(t, calls)
}
