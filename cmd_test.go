package main

import (
	"bufio"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/nergy-se/infrafier/internal/infra"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/urfave/cli/v2"
)

func TestPullExit(t *testing.T) {
	var out strings.Builder
	assert.NoError(t, pullExit(&out, fmt.Errorf("%w (/var/lib/infrafier/lock)", infra.ErrPullRunning)))
	assert.Equal(t, "skipped: another infrafier pull is running (/var/lib/infrafier/lock)\n", out.String())

	out.Reset()
	other := errors.New("fetch failed")
	assert.ErrorIs(t, pullExit(&out, other), other)
	assert.Empty(t, out.String())
	assert.NoError(t, pullExit(&out, nil))

	// The pull unit runs the previous agent on this exit code only.
	var coder cli.ExitCoder
	require.ErrorAs(t, pullExit(&out, fmt.Errorf("%w: module m: unknown field", infra.ErrCannotPlan)), &coder)
	assert.Equal(t, infra.CannotPlanExitCode, coder.ExitCode())
	assert.Empty(t, out.String())
}

func TestAskAsksAgainOnAnUnknownAnswer(t *testing.T) {
	for in, want := range map[string]bool{
		"\n":          true,
		"y\n":         true,
		"j\n":         true,
		"ye\nn\n":     false,
		"y es\nyes\n": true,
		"nej\n":       false,
		"":            false, // no terminal: no, never a loop
		"maybe":       false,
	} {
		var out strings.Builder
		assert.Equal(t, want, ask(bufio.NewReader(strings.NewReader(in)), &out, "edit again?", true), "%q", in)
		assert.Contains(t, out.String(), "edit again? [Y/n] ")
	}
	var out strings.Builder
	assert.False(t, ask(bufio.NewReader(strings.NewReader("\n")), &out, "Apply?", false))
	assert.Contains(t, out.String(), "[y/N]")
}

func TestIsVimVersion(t *testing.T) {
	assert.True(t, isVimVersion([]byte("VIM - Vi IMproved 9.2 (2026 Feb 14)\nIncluded patches: 1-100\n")))
	assert.True(t, isVimVersion([]byte("NVIM v0.11.0\nBuild type: Release\n")))
	assert.False(t, isVimVersion([]byte("BusyBox v1.36.1 multi-call binary.\n")))
	assert.False(t, isVimVersion(nil))
}

// The editor is found as sh runs it, so ~ and $HOME in EDITOR still find
// the vim that needs its swap and undo files turned off.
func TestEditorWordsExpandAsShDoes(t *testing.T) {
	home := t.TempDir()
	bin := filepath.Join(home, "my bin")
	require.NoError(t, os.MkdirAll(bin, 0o755))
	ed := filepath.Join(bin, "ed1")
	require.NoError(t, os.WriteFile(ed, []byte("#!/bin/sh\n"), 0o755))
	t.Setenv("HOME", home)
	assert.Equal(t, []string{ed}, editorWords(`~/"my bin"/ed1`))
	assert.Equal(t, []string{ed, "--wait", "a b"}, editorWords(`"$HOME/my bin/ed1" --wait 'a b'`))
	assert.Equal(t, []string{ed}, editorWords(`'`+ed+`'`))
	assert.Nil(t, editorWords("no-such-editor-here"))
	assert.Nil(t, editorWords("TERM=xterm "+ed))
}

func TestEditorCommandRefusesAllButTerminalVim(t *testing.T) {
	bin := t.TempDir()
	for _, n := range []string{"gvim", "vim", "nano"} {
		script := "#!/bin/sh\n"
		if n == "vim" {
			script += "echo 'VIM - Vi IMproved 9.1'\n"
		}
		require.NoError(t, os.WriteFile(filepath.Join(bin, n), []byte(script), 0o755))
	}
	t.Setenv("PATH", bin+":"+os.Getenv("PATH"))
	t.Setenv("VISUAL", "")
	for editor, want := range map[string]string{
		"gvim":           "a GUI vim is not supported",
		"gvim -f":        "a GUI vim is not supported",
		"vim -g":         "a GUI vim is not supported",
		"nano":           "secrets edit runs vim or nvim only",
		"TERM=xterm vim": "cannot find the program it runs",
		"no-such-editor": "cannot find the program it runs",
	} {
		t.Setenv("EDITOR", editor)
		_, err := editorCommand()
		assert.ErrorContains(t, err, want, editor)
	}
	t.Setenv("EDITOR", "vim")
	_, err := editorCommand()
	assert.NoError(t, err)
}

func TestGitHubRemote(t *testing.T) {
	for in, want := range map[string][2]string{
		"git@github.com:o/infra.git":       {"git@github.com:o/infra.git", "o/infra"},
		"git@github.com:o/infra":           {"git@github.com:o/infra.git", "o/infra"},
		"https://github.com/o/infra.git":   {"git@github.com:o/infra.git", "o/infra"},
		"https://github.com/o/infra":       {"git@github.com:o/infra.git", "o/infra"},
		"ssh://git@github.com/o/infra.git": {"git@github.com:o/infra.git", "o/infra"},
	} {
		u, r, err := infra.GitHubRemote(in)
		require.NoError(t, err, in)
		assert.Equal(t, want, [2]string{u, r}, in)
	}
	for _, in := range []string{"git@gitlab.com:o/infra.git", "https://github.com/o", "/srv/infra.git", "https://github.com/o/i/x"} {
		_, _, err := infra.GitHubRemote(in)
		assert.Error(t, err, in)
	}
}
