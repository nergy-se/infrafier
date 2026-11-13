# infrafier

infrafier keeps a few Linux servers in the state described by a git repository. It is pull-based: every host runs `infrafier pull` from a systemd timer. Each run fetches the host's branch, checks that its head is a signed fast-forward of the last commit it applied, renders the host's modules from that commit, and applies the difference to the live system. A file edited by hand is put back on the next run.

```
host spec + modules ──render──▶ resources ──plan (reads the host)──▶ changes ──apply──▶ host
   pure, golden files in git                  read only                  writes, then restarts
```

It is meant for a handful of hosts run by a small team that wants every change reviewed as a diff of the real config files, and wants the hosts to trust signatures, not a CI server or GitHub. It is one static binary with no agent server, no database and no inbound port.

It runs on Debian and Ubuntu with systemd (packages go through `apt-get`), and needs `git` on the hosts. `bootstrap` sets hosts up from GitHub repositories (deploy keys, `gh`). The pull itself only needs read access over ssh.

## The desired-state repo

```
hosts/<hostname>.jsonnet        the ref it follows, its address, modules and vars
modules/<name>/module.jsonnet   the module's resources
modules/<name>/<file>           templates and verbatim sources it refers to
rendered/<hostname>/            golden files: what each host gets, checked in CI
secrets/<hostname>.age          the host's secrets, age-encrypted (see "Secrets")
secrets/<hostname>.recipients   who that file is encrypted to
```

A host file:

```jsonnet
{
  ref: 'main',                   // the branch this host applies
  address: '192.0.2.10',         // optional: other hosts' configs and bootstrap's ssh use it
  modules: ['base', 'nginx'],    // applied in this order
  vars: { site: 'example.com' }, // for templates (.Vars) and modules (host.vars)
}
```

A typical rollout: a standby host follows `main` and gets every change first, and the active host follows `infra/<host>`, promoted with `git push origin main:infra/<host>` once the standby has been healthy. `infrafier_ref_lag_seconds` shows how long a merged change has waited.

### Workflow

1. Edit a module or a host, then run `infrafier diff` in the repo. It prints the change as unified diffs of the rendered files, plus the restarts and reloads it would trigger.
2. Run `infrafier diff --update` and commit `rendered/` with the change. Run `infrafier diff` in CI: it fails while `rendered/` is stale, or still holds a host that has no host file (`--update` removes it), so a PR always shows the real files.
3. From your machine, `infrafier diff --host <host>` shows what the host's next pull will change: over your ssh and sudo, the host's own agent fetches and verifies its ref and prints the plan against the live system (diffs of the files, then the actions), without applying anything or writing its state or metrics. Add `--ref <branch>` to plan a PR's branch before merging it. On the host itself this is `infrafier pull --ref <ref> --dry-run`.

### Modules

Modules and hosts are [jsonnet](https://jsonnet.org), which builds their structure. The contents of files stay Go `text/template`. A module is an object, or a `function(host)` that gets its host as `{name, ref, address, modules, vars}`, and evaluates to `{resources: [...]}`. Resources are applied in order. A file can import any `.libsonnet` in the repo (relative to the importing file, then to the repo root), which is where helpers for your own modules go.

```jsonnet
function(host) {
  resources: [
    { package: 'nginx' },                      // the first install of a run runs apt-get update first
    { dir: {
      path: '/etc/nginx/sites-enabled',
      purge: true,                             // remove what no resource declares (never through a symlink)
      onChange: [{ reload: 'nginx', check: ['nginx', '-t'] }],  // when the purge removed something
    } },
    { file: {
      path: '/etc/nginx/sites-enabled/site',
      template: 'site.conf',                   // or source: (copied as is) or content: (inline)
      mode: '0644',                            // a string; default 0644 for files, 0755 for dirs
      owner: 'root', group: 'root',            // a name or a numeric id; default root:root
      onChange: [{ reload: 'nginx', check: ['nginx', '-t'] }],  // or restart:, try-restart:
    } },
    { unit: { name: 'nginx', enabled: true, active: true } },  // false leaves it as it is
    { user: { name: 'prometheus', home: '/var/lib/prometheus', groups: ['adm'] } },
    { download: {                              // from https, checked against the sha256 upstream publishes
      url: 'https://github.com/prometheus/prometheus/releases/download/v3.15.1/prometheus-3.15.1.linux-amd64.tar.gz',
      sha256: '6a726885328ad9efebbf36e876ce2fb6225468a71fd1e7ce3ba666d5f4d97a84',
      extract: {                               // archive member → path; or path: for a download that is the file
        'prometheus-3.15.1.linux-amd64/prometheus': '/usr/local/bin/prometheus',
        'prometheus-3.15.1.linux-amd64/promtool': '/usr/local/bin/promtool',
      },
      onChange: [{ restart: 'prometheus' }],   // when an installed file changes
    } },
    { command: {                               // the escape hatch; keep these few
      name: 'replication-role',
      check: ['psql', '-tAc', '…'],             // must not change anything: every plan runs it
      run: ['psql', '-c', '…'],                 // runs only when check exits non-zero
    } },
  ],
}
```

| Resource | Fields |
|---|---|
| `file` | `path`, one of `template`/`source`/`content`, `mode`, `owner`, `group`, `secret`, `onChange` |
| `dir` | `path`, `mode`, `owner`, `group`, `purge`, `onChange` |
| `package` | the Debian package name; a virtual one (`mail-transport-agent`) is an error, name its provider |
| `unit` | `name`, `enabled`, `active`; names without a type get `.service`, as systemctl does |
| `user` | `name`, `home` (not created; `/nonexistent` by default), `groups` (must exist); a system user with its own group and no login shell |
| `download` | `url`, `sha256`, one of `path`/`extract`, `mode` (default 0755), `owner`, `group`, `onChange`, `preInstallCheck`, `keepPrevious`, `headers`, `secretHeaders` (see "Downloads that need a credential") |
| `command` | `name`, `check`, `run`, `secret` |
| action | one of `restart`/`reload`/`try-restart` (a unit), `check` (a command) |

What a file evaluates to is decoded strictly: an unknown or misspelled field (`Path` for `path`) and a number where a string belongs are errors that name the place, e.g. `resources[0].file.onChange[0]: field Restart not found`. Evaluation sees only the fetched commit: no environment, no external variables, and no secrets, which only a file's template reads (and a download's `secretHeaders` names). Two resources on one path are an error, and so is a resource owned by a `user` declared after it.

Templates get `.Host` (`.Host.Name`, `.Host.Ref`, `.Host.Address`) and `.Vars`. A missing key is an error, never an empty string in a config file.

### Changes and actions

Actions run once per unit, after all changes, and a restart wins over a reload. Every action's `check` runs before any unit is touched. When a check fails, the files that triggered the action are put back to what they were right before this run wrote them, and the action is skipped, so the next run tries again. A unit sharing one of those files is skipped too, so no unit runs a mix of old and new files that no check approved. A reload of a stopped unit is skipped: it reads its files when it starts. A unit with `enabled` or `active` is enabled and started only after all files are written, `daemon-reload` has run and the checks have passed, so a module may list a unit before its unit file.

An action that could not run (the restart failed, a purge can't be undone, systemd could not be asked) is kept in `/var/lib/infrafier/state.json` and run on the next pull, which would otherwise see no change and never restart the unit. Writing a unit file under `/etc/systemd/system` runs `daemon-reload` first. A unit file is always a `file`, never a download.

Downloads are cached by content in `/var/lib/infrafier/downloads`, so a pull fetches only when a pin changes, and hashes only the installed files whose inode, size or times changed. A file that is installed is not kept in the cache as well.

**Symlinks:** the agent runs as root, so in a directory that a service user can change (`/var/lib/grafana`, `/etc/postgresql/…/main`) it never follows a symlink out of that directory, for reads, writes, mode and owner changes or purges. A link swapped in there makes the run fail instead. Symlinks in directories only root can change, like `/lib → usr/lib`, are followed as usual.

## Trust

A commit on a host's ref is root on that host, so `pull` applies only commits that `git verify-commit` accepts:
- GPG signatures are checked against the keyring in `/etc/infrafier/gnupg`.
- SSH signatures are checked against `/etc/infrafier/allowed_signers`.

Both live on the host, outside the repo, so a commit can't add its own key. They hold only operator keys, **never GitHub's web-flow key**. A head is accepted when:
- an operator signed it, or
- it's a merge commit whose tree is exactly the tree of its second parent (the PR head), an operator signed that PR head, and the PR head contains the merge's first parent. That is what GitHub's **Create a merge commit** button makes from an up-to-date PR. The last rule stops a hand-made merge of `main` with an old signed commit from rolling a host back.

So GitHub can only put trees on a ref that an operator signed: merge rights or a stolen GitHub session can't deploy. The host's deploy key is read-only and reads only the desired-state repo.

A head that isn't a descendant of the last commit written to the host is refused, unless `--allow-rewind` is given: re-pushing an old signed commit can't roll a host back to a config with a known hole.

None of this depends on the code or the repo being secret: a host trusts only the keys in its own files.

### Merging with a signed PR head

Use GitHub's **Create a merge commit** button and disable squash and rebase merging, which make commits that no longer have the PR head as a parent. Before pressing merge:

1. **The PR's last commit is signed by you.** If it holds someone else's commits, approve them with an empty signed commit on top: `git commit --allow-empty -S -m "Approve" && git push`.
2. **The PR is up to date with `main`.** If not, rebase it and sign the rebased commits (`git rebase --gpg-sign origin/main`), rather than GitHub's "Update branch" button, which adds a commit signed with GitHub's key.

An out-of-date PR merged anyway has a tree nobody signed, and every host refuses it (`infrafier_last_apply_success` drops to 0). Sign `main` with an empty commit and the next pull deploys it.

## Secrets

A host's secrets are in `secrets/<host>.age`: a YAML map of names to string values, [age](https://age-encryption.org)-encrypted to the recipients in `secrets/<host>.recipients`, which are the host itself and the operators. Each host decrypts only its own file, at pull, with the age identity `bootstrap` created on it (`/etc/infrafier/age-identity`, which never leaves the host). Plaintext never reaches git, CI or the logs.

A template reads a value with `{{secret "name"}}`, and only in a file with `secret: true` (mode 0600 by default, never readable by others). Module files can't read secrets: a value there would end up in a command's arguments or in plans. In `rendered/`, such a file is rendered with placeholders (`<secret:name>`). A template only outputs a secret as it is, and never compares, slices or branches on one: CI renders the placeholder, so `{{if eq (secret "mode") "tls"}}` would take a branch there that the host never takes. Put choices like that in `vars`.

- **Your identity** (once): `infrafier secrets keygen` writes `~/.config/infrafier/age-identity` (or `--identity`, or `$INFRAFIER_AGE_IDENTITY`) and prints your recipient. Add it to each `secrets/<host>.recipients` you should be able to edit.
- **A host's recipient:** `bootstrap` creates the host's identity and prints the line to add when the recipients file doesn't list it yet. Only post-quantum `age1pq1…` recipients are taken, the kind keygen and bootstrap make.
- **Editing:** `infrafier secrets edit <host>` decrypts the file into vim or nvim on a tmpfs, with swap, undo and backup files kept off, and encrypts it again when you save. A file that isn't valid YAML of strings is not saved, and you get to edit it again. Then `infrafier diff --update` and commit both.
- **Changing who can decrypt:** edit the recipients file, then `infrafier secrets rekey <host>`. That only changes who can decrypt from then on: git history keeps every earlier file, which a removed recipient still decrypts. When a recipient is removed because its key may be known, change the values themselves too, at their source.

### Downloads that need a credential

A release asset of a private GitHub repository can't be fetched from its `releases/download/…` link with a token; the API's asset URL can. The token comes from a host secret through `secretHeaders`, which maps a header to the name of the secret holding its whole value:

```jsonnet
{ download: {
  url: 'https://api.github.com/repos/<owner>/<repo>/releases/assets/<id>',  // gh release view --json assets
  sha256: '…',
  path: '/usr/local/bin/apiserver',
  headers: { Accept: 'application/octet-stream' },   // the asset, not its JSON
  secretHeaders: { Authorization: 'dist-token' },    // the secret: "Bearer github_pat_…"
} }
```

- `headers` are sent as they are and shown in `rendered/`; `Authorization`, `Proxy-Authorization` and `Cookie` can only be `secretHeaders`. `Host`, `User-Agent` and the other headers infrafier or Go set can be neither.
- `rendered/` and plans show a secret header as its name and the secret's (`header Authorization: secret "dist-token"`), never the value, and so does every error. A download rendered without secrets (diff, CI) never fetches, so a placeholder is never sent.
- A secret header is dropped on any redirect that leaves the URL's host: GitHub answers with a redirect to a signed URL on another host, which needs none. Go's own client keeps a custom header (an `X-Api-Key`) there, and `Authorization` too when only the port differs.
- Give the token the least it needs: a fine-grained token with `Contents: read` on that one repository, one per host, so each can be revoked alone. The sha256 pin still decides what is installed: a replaced asset gets a new id, and changed content fails the pin.

`rendered/<host>/_resources.txt` ends with a sha256 of the host's secrets file, so `infrafier diff` lists the restarts of every file that reads secrets when it changes.

## Setting up a host

`infrafier bootstrap <host>` does it from your machine, in your clone of the desired-state repo, over your own ssh, and asks for sudo on the host once:

```
infrafier bootstrap --dry-run <host>   # set the host up, print the first pull's plan
infrafier bootstrap <host>             # again, applying it
```

It installs the binary as `/usr/local/bin/infrafier`, your git signing key as `/etc/infrafier/allowed_signers` (or `--allowed-signers`), a new read-only deploy key on the repo (with `gh`), the host's age identity, and the clone in `/var/lib/infrafier/repo`, then runs the first pull. The clone URL and the GitHub repo default to your clone's `origin`. It refuses a host whose ref doesn't exist yet, and one whose hostname is not `<host>`, since the timer applies `hosts/<hostname>.jsonnet`. Running it again is safe: it replaces the files, keeps the clone and the host's state, and leaves one deploy key. `--ssh` defaults to the host's `address`, else its name.

Bootstrap installs the agent once; after that the repo updates it (next section). The timer is yours to define, in a module like the one below.

## The agent updating itself

The agent is a download like any other, pinned to a release in the repo, so a new agent is a reviewed, signed pin bump:

```jsonnet
{
  resources: [
    { dir: { path: '/etc/infrafier' } },
    { dir: { path: '/var/lib/infrafier', mode: '0700' } },
    { download: {
      url: 'https://github.com/nergy-se/infrafier/releases/download/v0.1.0/infrafier-linux-amd64',
      sha256: '…',                                  // from the release's SHA256SUMS
      path: '/usr/local/bin/infrafier',
      keepPrevious: true,                           // the replaced binary stays as infrafier.prev
      preInstallCheck: ['{file}', 'check-plan'],    // the new binary must plan this commit first
    } },
    { file: { path: '/etc/systemd/system/infrafier-pull.service', template: 'infrafier-pull.service' } },
    { file: { path: '/etc/systemd/system/infrafier-pull.timer', source: 'infrafier-pull.timer',
              onChange: [{ restart: 'infrafier-pull.timer' }] } },
    { unit: { name: 'infrafier-pull.timer', enabled: true, active: true } },
  ],
}
```

- **`preInstallCheck`** runs on the new binary at a temporary name next to its path, before it replaces the old one. `check-plan` renders and plans the commit being applied, writing nothing, so a binary that can't handle this host's commit (a module field it doesn't know, a bug) is never installed. The new binary takes over from the next run; the running one keeps its inode.
- **`keepPrevious`** keeps the replaced binary as `infrafier.prev`. When a later commit can't be rendered by the new agent, `pull` exits 3 and records that commit. The service then runs the previous agent with `--fallback`, which applies exactly that commit (still verified), without fetching, and sets `infrafier_fallback 1`:

```ini
# infrafier-pull.service
[Unit]
Description=Apply this host's config from git (infrafier pull)
Wants=network-online.target
After=network-online.target

[Service]
Type=oneshot
ExecStart=/bin/sh -c '/usr/local/bin/infrafier pull --ref {{.Host.Ref}}; rc=$?; [ $rc -eq 3 ] && [ -x /usr/local/bin/infrafier.prev ] && exec /usr/local/bin/infrafier.prev pull --ref {{.Host.Ref}} --fallback; exit $rc'
TimeoutStartSec=1h
```

```ini
# infrafier-pull.timer
[Timer]
OnBootSec=2min
OnUnitInactiveSec=5min
RandomizedDelaySec=30s

[Install]
WantedBy=timers.target
```

A fetch or a signature failure gets no fallback, since the old agent would then judge a commit the new one refused. Rolling the agent back is reverting the pin. `state.json` stays readable by older agents, which also keep the fields they don't know.

Release binaries are built with `-trimpath` and `CGO_ENABLED=0` from the Go version in [the release workflow](.github/workflows/release.yml), so a CI of your own can rebuild a tag and compare its sha256 with your pin.

## Metrics

With `--textfile-dir` (default `/var/lib/node_exporter/textfile`, empty to skip), each run writes `infrafier.prom` for node_exporter's textfile collector:

| Metric | Meaning |
|---|---|
| `infrafier_last_apply_success` | 1 when the last run applied without error |
| `infrafier_last_apply_timestamp_seconds` | when the last run happened |
| `infrafier_last_success_timestamp_seconds` | when a run last succeeded |
| `infrafier_applied_commit_info{commit,ref}` | the commit last applied without error |
| `infrafier_behind_runs` | runs in a row that ended with the host not on its ref's head |
| `infrafier_pending_actions` | restarts owed by a failed run |
| `infrafier_fallback` | 1 when the last run was the previous agent's (see above) |
| `infrafier_ref_lag_seconds{ref}` | age of the oldest commit on `main` that isn't on the host's ref; 0 when they match |

Alert on `infrafier_last_apply_success == 0`, a stale `infrafier_last_success_timestamp_seconds`, a growing `infrafier_behind_runs`, and `infrafier_fallback == 1`.

## Building

```
CGO_ENABLED=0 go build -trimpath .
go test ./...    # needs git and ssh-keygen
```

## History

infrafier was written for the servers of [Nergy](https://nergy.se) and extracted from its private monorepo in November 2026, with fresh history. Its issues and pull requests start here.

## License

Apache-2.0, see [LICENSE](LICENSE). To report a security issue, see [SECURITY.md](SECURITY.md).
