# password-cleaner

Filter stdin, dropping any line that contains a secret. Secrets are never
stored in the clear: you keep a file of SHA-256 hashes, and every substring of
each input line (of at least `--min-length` characters) is hashed and compared
against it.

Lines that are clean go to stdout. Lines that contain a known secret go to
stderr, so you can see what was removed.

```console
$ password-cleaner "my-secret-password" >> ~/.config/password-cleaner/hashes.txt
$ cat shell-history.txt | password-cleaner > cleaned.txt
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
password-cleaner [flags] [password]
```

| Flag                | What it does                                                  |
| ------------------- | ------------------------------------------------------------- |
| `--hash-file PATH`  | file of SHA-256 hashes, one per line (`#` starts a comment)    |
| `--min-length N`    | shortest substring to check (default 8)                       |
| `--version`         | print version, commit and build date                          |

With a `password` argument it prints that password's SHA-256 hash, ready to
append to the hash file. Without one it filters stdin.

The default hash file is `password-cleaner/hashes.txt` in your config
directory (`$XDG_CONFIG_HOME`, or `~/.config` on macOS if it exists).

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
There are no dependencies outside the standard library, so `vendorHash` in
`flake.nix` is `null`. If you add one, run `task nix:vendor-hash` to compute it
(and again whenever `go.mod`/`go.sum` change).

### Releasing

1. Change `VERSION` and commit.
2. `task release:tag` creates and pushes `v<VERSION>`.
3. The `release` workflow builds `.#release` with Nix, publishes the tarballs
   and `SHA256SUMS` as a GitHub release, and pushes the generated formula to
   `jondoveston/homebrew-tap` (`Formula/password-cleaner.rb`).

The workflow needs a `HOMEBREW_TAP_GITHUB_TOKEN` secret: a fine-grained token
limited to the `homebrew-tap` repository with **Contents: Read and write**.
