# OpenTofu external encryption method schemas

`header.schema.json`, `input.schema.json` and `output.schema.json` are copied unchanged from
[opentofu/opentofu `internal/encryption/method/external/protocol`](https://github.com/opentofu/opentofu/tree/044374f75a95659e83d96613cad1fabbaba485ff/internal/encryption/method/external/protocol),
at commit `044374f75a95659e83d96613cad1fabbaba485ff`. They are licensed under the
[Mozilla Public License 2.0](https://github.com/opentofu/opentofu/blob/main/LICENSE), like the rest of OpenTofu.

The tests validate what `tofu-age` reads and writes against them. To update them, copy the files again
from a newer commit, unchanged, and update the commit above.
