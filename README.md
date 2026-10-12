# tofu-age

Encrypt OpenTofu state and plan files with [age](https://github.com/FiloSottile/age).

`tofu-age` is an
[OpenTofu external encryption method](https://opentofu.org/docs/language/state/encryption/#external-encryption-method):
a small static binary that OpenTofu runs on every state and plan write and read. It translates
between OpenTofu's protocol and `filippo.io/age`, so the backend only ever stores ciphertext.

```hcl
terraform {
  encryption {
    method "external" "age" {
      encrypt_command = ["tofu-age", "encrypt", "age-recipients.txt"]
      decrypt_command = ["tofu-age", "decrypt"]
    }

    state {
      method   = method.external.age
      enforced = true
    }

    plan {
      method   = method.external.age
      enforced = true
    }
  }
}
```

What it does, in one list:

- **No shared secret.** Each engineer and each CI runner has its own age keypair. Access is granted
  or removed by editing a recipients file of public keys, which is safe to commit.
- **A fresh envelope per write.** age generates a new file key on every write and wraps it for each
  recipient. Any single matching identity can read it.
- **The identity never touches disk.** `tofu-age decrypt` reads it from `TOFU_AGE_IDENTITY` only,
  so `op run` or a CI secret can inject it.

---

## Install

`ghcr.io/specsnl/opentofu` ships the binary. Each release publishes a static tarball per OS and
architecture, `tofu-age_<os>_<arch>.tar.gz` for `linux` and `darwin` on `amd64` and `arm64`, and a
`checksums.txt`. The archive names carry no version, so the download URL is built from the
version, the OS and the architecture alone. The darwin tarballs are for running `tofu` on a Mac.

To install it in an image, pin the version and both checksums, check the download with
`sha256sum -c`, then `install` the binary:

```dockerfile
# Latest version of Alpine image: https://hub.docker.com/_/alpine/tags
FROM alpine:3.24.2 AS tofu-age

# Latest version of tofu-age: https://github.com/specsnl/tofu-age/releases
ARG TOFU_AGE_VERSION=<version>
# Checksums can be found in the checksums.txt file attached to the release
ARG TOFU_AGE_CHECKSUM_AMD64=<sha256 of tofu-age_linux_amd64.tar.gz>
ARG TOFU_AGE_CHECKSUM_ARM64=<sha256 of tofu-age_linux_arm64.tar.gz>
ARG TARGETARCH

WORKDIR /tmp/tofu-age

RUN case "${TARGETARCH}" in \
            amd64) checksum="${TOFU_AGE_CHECKSUM_AMD64}" ;; \
            arm64) checksum="${TOFU_AGE_CHECKSUM_ARM64}" ;; \
            *) echo "Unsupported architecture: ${TARGETARCH}" >&2; exit 1 ;; \
        esac \
    && archive="tofu-age_linux_${TARGETARCH}.tar.gz" \
    && wget -q "https://github.com/specsnl/tofu-age/releases/download/v${TOFU_AGE_VERSION}/${archive}" \
    && echo "${checksum}  ${archive}" > checksum.txt \
    && sha256sum -c checksum.txt \
    && tar -xzf "${archive}" tofu-age \
    && install -m 0755 tofu-age /usr/local/bin/tofu-age

FROM alpine:3.24.2

COPY --from=tofu-age /usr/local/bin/tofu-age /usr/local/bin/tofu-age
```

The checksums are pinned in the Dockerfile rather than read from `checksums.txt` at build time, so a
replaced release asset fails the build instead of being trusted.

Building from a checkout needs nothing but Docker and [Task](https://taskfile.dev):

```sh
task build
```

---

## Getting started

Generate a keypair, keep the identity in 1Password, and add the public key to the recipients file
next to the root module:

```sh
age-keygen -o key.txt            # prints the public key (age1…)
op item create --category "Secure Note" --title "tofu-age <name>" "notesPlain=$(cat key.txt)"
rm key.txt
```

Then let `op run` inject the identity, with `TOFU_AGE_IDENTITY=op://<vault>/<item>/notesPlain` in
`.env.tofu`:

```sh
op run --env-file=.env.tofu -- tofu plan
```

Granting and revoking access, CI use, and break-glass recovery are in the
[runbook](./docs/runbook.md). The reasoning behind key management is in
[docs/design.md](./docs/design.md).

---

## Contributing

Every command runs through [Task](https://taskfile.dev), which wraps the Docker Compose services
that pin the Go, golangci-lint, hadolint, and Node versions — so a check runs the same way locally
as it does in CI. Run `task --list` for the full set.

```sh
task checkall   # tidy:check, lint, lint:docker, test, md:check — run this before opening a pull request
```

Conventions, workflow, and the house rules that reviews are held to: [AGENTS.md](./AGENTS.md).

---

## License

MIT — see [LICENSE](./LICENSE).
