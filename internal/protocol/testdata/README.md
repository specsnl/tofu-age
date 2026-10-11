# OpenTofu external encryption method schemas

`header.schema.json`, `input.schema.json` and `output.schema.json` are copied unchanged from
[opentofu/opentofu `internal/encryption/method/external/protocol`](https://github.com/opentofu/opentofu/tree/main/internal/encryption/method/external/protocol),
at the release set in `OPENTOFU_SCHEMAS_VERSION` in [`taskfiles/Taskfile.schemas.yml`](../../../taskfiles/Taskfile.schemas.yml).
They are licensed under the [Mozilla Public License 2.0](https://github.com/opentofu/opentofu/blob/main/LICENSE), like the
rest of OpenTofu.

The tests validate what `tofu-age` reads and writes against them. Never edit them by hand:

| Command               | What it does                                                                                |
|-----------------------|---------------------------------------------------------------------------------------------|
| `task schemas:update` | Download the schemas at `OPENTOFU_SCHEMAS_VERSION` into this directory                      |
| `task schemas:check`  | Fail when these files differ from that release, or the latest OpenTofu release changed them |

The `OpenTofu schemas` workflow runs the check on the first of every month. When it fails, set `OPENTOFU_SCHEMAS_VERSION` to the
release it names, run `task schemas:update`, and review the diff: a new protocol version needs changes in
`internal/protocol` too.
