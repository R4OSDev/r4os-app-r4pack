# R4PACK.R4X

`R4PACK.R4X` is an independent R4OS application implemented in Zig.

## Package

- Version: `0.1.5`
- Image target: `/SOFTWARE/R4CODE/R4PACK.R4X`
- Image scope: `full`
- Canonical project manifest: `module.R4MF`

The manifest is the single source of truth for the artifact, imports, image
target, and package metadata.

## Build

On Windows:

    Build.bat

On Linux:

    ./Build.sh

The build starters resolve the current local R4OS dependency checkouts through
`Settings.R4S`. The URL and hash entries in `build.zig.zon` record the
last verified standalone dependency identities; workspace builds use the
mapped local checkouts.

## Documentation

Independent code, rodata and data inputs are prepared by explicitly declared
compute workers (`runtime.workers=owned-v1`). The foreground caller joins them,
then preserves the canonical section order, aggregate size limit, first input
error and package bytes. Workers do not print or own the console. Code-only
commands stay serial; `--serial` selects the same serial preparation explicitly.
An older provider or refused worker creation falls back to serial preparation.
An unconfirmed join requests terminal process exit while retaining its buffers
and complete main frame through the actual worker stop.

`/SELFTEST` compares serial and parallel packages byte for byte, checks actual
worker CPU/role witnesses and input boundaries, and removes only its exclusively
created process-generation paths. Small inputs are a correctness pilot; parallel
preparation does not imply a speedup.
Inspection allocates the actual file size, bounded at16 MB, independently of
the unchanged64 KB CLI pack/input limit. The full self-inspection remains part
of the original selftest even when this tool's own artifact exceeds64 KB.

Detailed German technical notes from the migration are preserved in
`DOCUMENTATION.de.txt`. Source-transfer provenance is recorded in
`PROVENANCE.txt`.

## License

Original R4OS material is licensed under Apache License 2.0. See `LICENSE`
and `NOTICE`. Any repository-specific external material is documented in
`THIRD_PARTY_NOTICES.md`.
