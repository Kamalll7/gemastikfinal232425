# Patch references

This directory contains one patch guide per challenge and applyable unified
diffs for the key fixes. Everything here is defensive: the original challenge
source under `gemastik-xvi-final/`, `gemastik-xvii-final/`, and
`gemastik18-final/` was not modified.

## How to use a diff

Each diff uses `a/` and `b/` path prefixes, so apply it with `patch -p1` from
the challenge root. Example:

```bash
cd gemastik18-final/services/blogpost
patch -p1 --dry-run < ../../../patches/blogpost/fix-upload-and-metadata.diff
patch -p1 < ../../../patches/blogpost/fix-upload-and-metadata.diff
```

Always dry-run first. For a lab, copy the challenge directory to a scratch
location before applying anything. The diffs are reference fixes, not a
guarantee that the whole challenge still behaves identically; run the
regression checklist in the corresponding `PATCH.md`.

## Status conventions

- **VALID** findings have concrete before/after guidance; key fixes also have a
  diff that was dry-run tested against the unmodified source.
- **PARTIALLY VALID** findings are fixed only for the proven scope; the
  unproven scope is called out explicitly.
- **INVALID** findings have no patch: the claim is not supported by source.
- **UNVERIFIED** findings have hardening advice but no claim of a confirmed
  vulnerability. Reproduce first.

## Index

| Challenge | Year | Findings | Reference diff(s) |
|---|---|---:|---|
| [blogpost](blogpost/PATCH.md) | 2025 | 3 | `fix-upload-and-metadata.diff` |
| [cdn](cdn/PATCH.md) | 2025 | 2 | `fix-redirect-validation.diff` |
| [phew](phew/PATCH.md) | 2025 | 1 | guidance only |
| [sheesh](sheesh/PATCH.md) | 2025 | 1 | guidance only |
| [carbeat](carbeat/PATCH.md) | 2025 | 1 | `fix-getline-width.diff` |
| [warmup](warmup/PATCH.md) | 2025 | 1 | `fix-path-confinement.diff` |
| [anti-alchemy](anti-alchemy/PATCH.md) | 2024 | 1 | guidance only |
| [asmr](asmr/PATCH.md) | 2024 | 2 | `fix-size-tracking.diff` |
| [bit-canvas](bit-canvas/PATCH.md) | 2024 | 3 | `fix-bounds-and-scanf.diff` |
| [fjb](fjb/PATCH.md) | 2024 | 2 | `fix-bounded-name-copy.diff` |
| [gift-card](gift-card/PATCH.md) | 2024 | 1 | guidance only |
| [gift-voucher](gift-voucher/PATCH.md) | 2024 | 2 | `fix-canonical-base64.diff` |
| [gleam-drive](gleam-drive/PATCH.md) | 2024 | 3 | guidance only |
| [go-green](go-green/PATCH.md) | 2024 | 1 | `fix-negative-donation.diff` |
| [kode-viewer](kode-viewer/PATCH.md) | 2024 | 3 | `fix-ownership-and-email.diff` |
| [more-less](more-less/PATCH.md) | 2024 | 1 | `fix-safe-yaml.diff` |
| [tempest-poc](tempest-poc/PATCH.md) | 2024 | 4 | `fix-upgrade-scope.diff` |
| [ticketer](ticketer/PATCH.md) | 2024 | 1 | `fix-ticket-id-replay.diff` |
| [art](art/PATCH.md) | 2023 | 1 | `fix-template-escaping.diff` |
| [back-to-basic](back-to-basic/PATCH.md) | 2023 | 1 | guidance only |
| [burvesigner](burvesigner/PATCH.md) | 2023 | 1 | guidance only |
| [crawlback](crawlback/PATCH.md) | 2023 | 1 | guidance only |
| [gemas-fetcher](gemas-fetcher/PATCH.md) | 2023 | 1 | `fix-url-validation.diff` |
| [gemas-notes](gemas-notes/PATCH.md) | 2023 | 2 | `fix-parameterized-count.diff` |
| [hirnfick](hirnfick/PATCH.md) | 2023 | 1 | guidance only |
| [pasta](pasta/PATCH.md) | 2023 | 1 | `fix-full-range-nonce.diff` |
| [s3](s3/PATCH.md) | 2023 | 1 | `fix-download-confinement.diff` |
| [xl](xl/PATCH.md) | 2023 | 1 | `fix-buffer-type.diff` |

Per-challenge guides also contain the vulnerable and patched code patterns,
verification steps, and a regression checklist. The matching exploit is linked
from each guide and from the main playbook.
