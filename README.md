# password-cleaner

Remove lines containing secrets from text. Secrets are never stored in the
clear: you keep a file of their SHA-256 hashes, and every substring of each
input line is hashed and looked up in it.

```console
$ password-cleaner add                      # prompts, without echo
$ cat shell-history | password-cleaner > cleaned
$ password-cleaner --redact app.log         # keep the lines, blank the secrets
$ password-cleaner --check config.yaml      # exit 1 if it contains a secret
```

## Install

Homebrew (macOS on Apple Silicon, Linux on x86-64 and arm64):

```sh
brew install jondoveston/tap/password-cleaner
```

Nix:

```sh
nix run github:jondoveston/password-cleaner -- --version
nix profile install github:jondoveston/password-cleaner
```

With Go (needs the Go version in `go.mod`). This installs into `$GOBIN`, or
`$(go env GOPATH)/bin` if that is unset. The version is not stamped in, so
`--version` prints `dev`:

```sh
go install github.com/jondoveston/password-cleaner@latest
```

From a checkout, into `~/.local/bin`:

```sh
task install
task uninstall   # remove it again
```

### Switching from a local install to Homebrew

```sh
task uninstall                                  # from a checkout
rm -f "$(go env GOPATH)/bin/password-cleaner"   # if you used `go install`
brew install jondoveston/tap/password-cleaner
```

## Usage

```
password-cleaner [flags] [file...]   filter files, or stdin if none (or "-")
password-cleaner add [flags]         add secrets to the hash file
password-cleaner hash [flags]        print the hash-file line for a secret
```

Run any command with `--help` for the full text.

### Filtering

By default a line containing a secret is **dropped**. Lines keep their
original endings (LF or CRLF), and there is no limit on line length.

| Flag                  | What it does                                                        |
| --------------------- | ------------------------------------------------------------------- |
| `-f, --hash-file F`   | hash file to use; repeat for several                                |
| `--on-match MODE`     | `drop` (default), `redact`, or `stderr`                             |
| `-r, --redact`        | same as `--on-match redact`                                         |
| `--replacement TEXT`  | what `--redact` writes instead of a secret (default `[REDACTED]`)   |
| `-c, --check`         | print `FILE:LINE` for each match, filter nothing                    |
| `--min-length N`      | shortest substring tried for bare hashes (default 8)                |
| `-v, --verbose`       | say which hash files were used and how many lines were removed      |

`--on-match stderr` writes the **whole line, secret included,** to standard
error. It is there for compatibility with earlier versions; the other modes
never print a secret anywhere.

`--check` never prints line content, only `<file>:<line>` (`<stdin>` for
standard input), which makes it safe in CI logs and pre-commit hooks. With no
hashes loaded it fails rather than report that everything is clean.

**Exit status:** 0 on success, 1 if `--check` found a secret, 2 on any error.

### Hash files

The hash file is chosen from, in order: `--hash-file`,
`$PASSWORD_CLEANER_HASH_FILE` (several files separated like `$PATH`), then
`password-cleaner/hashes.txt` in `$XDG_CONFIG_HOME`, or your config directory
(on macOS `~/.config` if it exists, otherwise `~/Library/Application Support`).

```
# a comment on its own line is ignored, like blank lines
8:5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8  # bank, added 2026-10-25
5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8
```

Text after a `#` on a hash line is a comment that reminds you which secret it
is. It has no effect on matching. `add` writes one on every line it creates,
made of your `--comment` (if any) and the date: `bank, added 2026-10-25`.

The number before the colon is the secret's length in bytes. With it, only
substrings of the lengths present in the file are hashed, which is dramatically
faster than trying every length (about 60 times on a typical log line). The
cost is that anyone who reads the file learns each secret's length. Lines
without a length still work, but force every substring of at least
`--min-length` bytes to be tried, so a bare hash of a secret shorter than that
is never found.

Malformed lines are skipped with a warning naming the file and line number.
The warning never repeats the line.

### Adding secrets

```sh
password-cleaner add                      # on a terminal: asked twice, no echo
pass show example.com | head -n1 | password-cleaner add --comment example.com
```

When standard input is not a terminal, each non-empty line is a secret. They
are deliberately not accepted as arguments, so they never reach your shell
history or the process list. `add` creates the file with mode 0600 (and its
directory with 0700) and skips hashes already present (upgrading bare ones, see below).

Secrets shorter than 8 characters are accepted with a warning. Shorter than 4
are refused unless you pass `--force`, because they occur in ordinary text and
would wreck the output. `password-cleaner hash` takes the same input and flags
but prints the line instead of saving it.

### Upgrading from 0.0.x

Earlier versions took the secret as an argument (`password-cleaner "secret"`)
and wrote matching lines to stderr. Now: use `add` or `hash` instead, and
`--on-match stderr` for the old behaviour. Existing hash files keep working as
they are. To get length-tagged lines and the faster matching, run `add` again
with the same secrets: a bare hash that is already in the file is rewritten
in place to include the length (keeping its comment, unless you give a new
`--comment`), and everything else in the file is left alone. Secrets that are
not in the file yet are added as usual.

## Development

Everything is driven by [go-task](https://taskfile.dev). Either use
`nix develop` or [mise](https://mise.jdx.dev) (`mise install`, see
`mise.toml`) to get Go, task and golangci-lint.

```sh
task            # build ./password-cleaner
task check      # fmt:check, vet, test and lint, as CI does
task run -- --version
task --list
```

The Go version is whatever the stable nixpkgs channel in `flake.nix` provides
(currently nixos-26.05); keep the `go` line in `go.mod` at or below it.

### Nix builds

Nix builds everything, including the release binaries. Go cross-compiles with
`CGO_ENABLED=0`, so one machine can build every target:

```sh
task nix:build     # native build, with tests
task nix:cross     # linux x86-64/arm64 and darwin arm64
task nix:release   # tarballs + SHA256SUMS + the Homebrew formula in ./result
task nix:check     # nix flake check
```

Nix only sees files tracked by git, so `git add` new files before building.
After changing `go.mod`/`go.sum`, run `task nix:vendor-hash` to refresh
`vendorHash` in `flake.nix`.

### Releasing

1. Change `VERSION` and commit.
2. `task release:tag` creates and pushes `v<VERSION>`.
3. The `release` workflow builds `.#release` with Nix, publishes the tarballs
   and `SHA256SUMS` as a GitHub release, and pushes the generated formula to
   `jondoveston/homebrew-tap` (`Formula/password-cleaner.rb`).

The workflow needs a `HOMEBREW_TAP_GITHUB_TOKEN` secret: a fine-grained token
limited to the `homebrew-tap` repository with **Contents: Read and write**.
