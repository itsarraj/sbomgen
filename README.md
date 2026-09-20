# sbomgen

Generates a real CycloneDX 1.5 JSON SBOM (Software Bill of Materials)
from a `Cargo.lock`, `package-lock.json`, or `requirements.txt` — one
tool across three ecosystems instead of `cargo-cyclonedx`, `cyclonedx-npm`,
and `cyclonedx-py` separately, matching the polyglot-repo framing this
workspace's own `depaudit` already established for vulnerability
scanning.

## Usage

```bash
sbomgen Cargo.lock                       # SBOM to stdout
sbomgen package-lock.json -o sbom.json   # write to a file
sbomgen requirements.txt
```

## What's in the output

The real CycloneDX 1.5 JSON shape: `bomFormat`, `specVersion`, a random
`serialNumber` (`urn:uuid:...`), and a `components` array — one entry per
resolved package with `type: "library"`, `name`, `version`, and a `purl`
(Package URL — `pkg:cargo/serde@1.0.229`, `pkg:npm/%40babel/core@7.20.0`
for a scoped package, `pkg:pypi/django-rest-framework@3.14.0` with PyPI's
own PEP 503 name normalization applied). `purl` is what lets this SBOM be
cross-referenced against OSV, Dependency-Track, or any other
purl-consuming tool.

## Status: built and verified against this crate's own real Cargo.lock

- **16 unit tests** (`cargo test --lib`) across three modules:
  - `lockfile` (7): real `Cargo.lock` TOML parsing, `package-lock.json`'s
    modern `"packages"` map (scoped `@babel/core` included, the root
    project entry excluded), `requirements.txt` exact-pin extraction
    (a `>=` range correctly skipped), and filename-based format
    auto-detection including a clean error for an unrecognized filename.
  - `purl` (5): the exact purl shape for each ecosystem, including a
    scoped npm package's `@` percent-encoded into its namespace segment,
    and PyPI name normalization (`Django_Rest-Framework` →
    `django-rest-framework`, per PEP 503).
  - `cyclonedx` (4): the top-level document shape, that every component
    gets `type: "library"` and a `bom-ref` matching its own `purl`,
    duplicate name+version pairs deduplicated, and that the whole
    document actually serializes to valid JSON with the exact keys a
    CycloneDX consumer expects (`bomFormat`, `specVersion`, `type`,
    `purl`, `bom-ref`).
- **Live-verified against this very crate's own real `Cargo.lock`**: ran
  the compiled binary against it and got back valid JSON — confirmed by
  actually parsing the output with `python3 -m json.tool`-equivalent
  parsing, not just eyeballing it — with 74 real components, each a real
  dependency of this crate (`clap`, `serde_json`, `uuid`, `chrono`, and
  so on), each with a correctly-formed `pkg:cargo/...` purl.

**Not done / deliberately deferred**: Yarn/pnpm/Go/Ruby lockfiles (the
same four ecosystems this workspace's `depaudit` already added — wiring
the same parsing logic in here is a natural v2, not attempted here to
keep this pass's scope to the three formats above); a `license` field per
component (CycloneDX supports it, but neither `Cargo.lock` nor
`package-lock.json` nor `requirements.txt` reliably carries the
dependency's actual license string — that needs a registry API call per
package, out of scope for a fast, offline, single-file tool); and
dependency-graph edges (`dependencies` relationships between components)
— this SBOM is a flat component list, not a full dependency tree.
