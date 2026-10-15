# Vendored `/v1` OpenAPI document

`v1.json` is the public OpenAPI 3.1 description of the HodeiShield read-only API, byte for byte as the
service publishes it at `GET /v1/openapi.json`. The Rust client in `crates/hodeishield-api` is generated
from it; nothing in that client is written by hand from memory.

| Field | Value |
|---|---|
| `info.version` | `2026-10-19` |
| SHA-256 | `8c9a44bc696584105f10b67d490a8816dabc26b07b80ed18369e6d3e498359c4` |
| Operations | 16, all `GET` |

## Updating it

The **OpenAPI sync** workflow (`.github/workflows/openapi-sync.yml`) checks this copy every Monday, and
on demand: it compares it with the published document by content (key order and whitespace do not
count). When they differ it opens, or comments on, one issue labelled `openapi-drift`, with both
`info.version` values, whether [oasdiff](https://github.com/oasdiff/oasdiff) finds a breaking change
(and in which direction) and a summary, and the run is red. When they match again it closes the issue.
If the published document cannot be fetched or compared, an issue labelled `openapi-check-failed`
reports that instead. The workflow never changes this copy or opens a pull request: a maintainer
decides whether the API or this copy is behind. To take the published document, by hand:

1. Replace `v1.json` with the new document, unchanged.
2. Update the version and SHA-256 above and in `xtask/src/main.rs` (`EXPECTED_SHA256`).
3. `cargo xtask codegen` rewrites `crates/hodeishield-api/src/generated.rs`.
4. `cargo xtask codegen --check` (run in CI) fails when the committed client is not what the document
   generates, or when the document's hash is not the recorded one.

`/v1` only changes compatibly (see the document's "Versioning" section): new operations, new optional
parameters, new fields. The generated types ignore unknown fields, so an older CLI keeps working against
a newer `/v1`.
