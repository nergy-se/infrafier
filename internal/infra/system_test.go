package infra

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// A command that exits but leaves a child holding stdout (a daemon started
// with &) must not block the run for as long as the child lives.
func TestExecRunnerDoesNotWaitForABackgroundChild(t *testing.T) {
	old := waitDelay
	waitDelay = 100 * time.Millisecond
	t.Cleanup(func() { waitDelay = old })

	start := time.Now()
	_, err := ExecRunner(context.Background(), "sh", "-c", "sleep 5 &")
	require.NoError(t, err)
	assert.Less(t, time.Since(start), 3*time.Second)
}

// outside is a file next to the System's root, which a symlink placed inside
// the root (a directory root does not own) must never reach.
func symlinkSetup(t *testing.T) (sys *OS, outside string) {
	t.Helper()
	dir := t.TempDir()
	root := filepath.Join(dir, "root")
	require.NoError(t, os.MkdirAll(filepath.Join(root, "etc"), 0o755))
	outside = filepath.Join(dir, "shadow")
	require.NoError(t, os.WriteFile(outside, []byte("secret\n"), 0o600))
	return &OS{Root: root}, outside
}

func TestSetAttrsRefusesASymlink(t *testing.T) {
	sys, outside := symlinkSetup(t)
	require.NoError(t, os.Symlink(outside, filepath.Join(sys.Root, "etc/conf")))

	require.Error(t, sys.SetAttrs("/etc/conf", 0o644, "", ""))
	fi, err := os.Stat(outside)
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0o600), fi.Mode().Perm())
}

func TestSymlinkedDirectoryIsNotFollowedOutOfTheRoot(t *testing.T) {
	sys, outside := symlinkSetup(t)
	// /etc/app swapped for a link to the directory holding the secret.
	require.NoError(t, os.Symlink(filepath.Dir(outside), filepath.Join(sys.Root, "etc/app")))

	_, err := sys.Lstat("/etc/app/shadow")
	require.Error(t, err, "read through the link")
	require.Error(t, sys.WriteFile("/etc/app/shadow", []byte("x\n"), 0o644, "", ""))
	require.Error(t, sys.SetAttrs("/etc/app/shadow", 0o644, "", ""))
	require.Error(t, sys.Mkdir("/etc/app/sub", 0o755, "", ""))
	require.Error(t, sys.RemoveAll("/etc/app/shadow"))

	b, err := os.ReadFile(outside)
	require.NoError(t, err)
	assert.Equal(t, "secret\n", string(b))
	fi, err := os.Stat(outside)
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0o600), fi.Mode().Perm())
	assert.NoDirExists(t, filepath.Join(filepath.Dir(outside), "sub"))
}

// The host's own symlinks in directories only root can change, such as
// /lib → usr/lib on a merged-/usr system, are still followed.
func TestSymlinkInARootOnlyDirectoryIsFollowed(t *testing.T) {
	fi, err := os.Lstat("/lib")
	if err != nil || fi.Mode()&os.ModeSymlink == 0 {
		t.Skip("/lib is not a symlink here")
	}
	if _, err := os.Stat("/usr/lib/os-release"); err != nil {
		t.Skip("no /usr/lib/os-release")
	}
	st, err := (&OS{}).Lstat("/lib/os-release")
	require.NoError(t, err)
	assert.True(t, st.Exists)
}
