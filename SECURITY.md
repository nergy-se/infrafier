# Security

infrafier runs as root and decides what runs on a host from a git commit, so
a bug in how it verifies commits, reads the repository or writes files can be
a way into every host it runs on.

## Reporting a vulnerability

Report it privately through GitHub: **Security → Report a vulnerability** on
this repository. Please don't open a public issue. You'll get an answer within
a week.

Especially welcome:
- a commit a host applies although no operator key signed it or its tree
  (`verifyHead`), or one that rolls a host back without `--allow-rewind`;
- a template, import or source file that reads a file outside the checkout,
  or a secret that reaches a plan, a golden file, a log or an error;
- a write, chmod or purge that follows a symlink out of a directory a
  non-root user can change;
- a download installed without matching its pinned sha256.

## Supported versions

Only the latest release gets fixes. Upgrading is a pin bump in your
desired-state repo; see "The agent updating itself" in the README.
