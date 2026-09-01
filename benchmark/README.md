# BugScope Benchmarks

The small programs under `Cpp/toy` are stored directly in this repository. The
large real-world reproduction projects are intentionally excluded from Git and
are reconstructed with `reproduce-manifest.json`.

## Reproduction manifest

Each manifest project has a stable destination such as `OOB/zstd`, a source,
and zero or more cases. A case records its BugScope bug type, target file,
relevant source line, and expected SHA-256.

The released bug type names are:

- `OSO`: upper-bound buffer overflow
- `NOF`: negative-offset buffer underflow
- `ASO`: allocation-size overflow
- `DBZ`: divide by zero
- `MLK`: memory leak

The current manifest uses Git sources in two forms:

- A complete checkout identified by an upstream URL and immutable commit.
- A `subdirectory` export from an immutable Git checkout. The downloader uses
  sparse checkout, exports only the requested source subtree, and records its
  origin in `.bugscope-source.json`.

The downloader also supports checksum-verified snapshot archives for future
datasets, but no current manifest entry requires a separately hosted archive.

## Usage

List all projects:

```sh
bash benchmark/setup_reproduce.sh --list
```

Download all reproduction projects:

```sh
bash benchmark/setup_reproduce.sh
```

Download one category, bug type, or project:

```sh
bash benchmark/setup_reproduce.sh --category OOB
bash benchmark/setup_reproduce.sh --bug-type ASO
bash benchmark/setup_reproduce.sh --subtype IZC
bash benchmark/setup_reproduce.sh --project OOB/zstd
```

Verify an existing local dataset without downloading:

```sh
bash benchmark/setup_reproduce.sh --verify-only
```

By default an invalid existing directory is left untouched. `--force` moves it
to a timestamped backup before installing the manifest version. `--strict`
turns any unavailable future snapshot entry into a failure.

An alternate output root can be used for testing or isolated datasets:

```sh
bash benchmark/setup_reproduce.sh \
  --destination /tmp/bugscope-reproduce \
  --project DBZ/libuv
```

## Patches

Patches required to reconstruct a benchmark working tree are stored under
`benchmark/patches`. They are applied only after checking out the exact commit
listed in the manifest. Do not edit downloaded third-party projects and commit
their source into the BugScope repository; add a patch and update the manifest
instead.

## Optional snapshot assets

If a future benchmark cannot be reconstructed from Git, publish a deterministic
`.tar.gz` or `.zip` containing the project directory, then set these fields:

```json
{
  "type": "snapshot",
  "archive_url": "https://example.org/project.tar.gz",
  "archive_sha256": "<64 lowercase hex characters>",
  "archive_root": "optional-top-level-directory"
}
```

The downloader validates the archive hash, rejects path traversal entries, and
then validates every case target hash from the manifest.
