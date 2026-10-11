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

Distribution is Docker only: `ghcr.io/specsnl/opentofu` ships the binary. Releases publish Linux
tarballs and a `checksums.txt`, so an image can install it the way it installs any other release
binary. There is no release yet.

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

Key management, the break-glass key, and how recipient changes take effect are in
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
