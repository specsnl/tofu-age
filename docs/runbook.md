# Operations runbook

Step-by-step procedures for granting access, revoking it, and break-glass recovery. The reasoning behind them is in [design.md](./design.md) § Key management and § Operations.

Commands assume the root module's directory, with `tofu init` already run, and these tools on the `PATH`:

- `tofu` and `tofu-age`, both in `ghcr.io/specsnl/opentofu`.
- `age` and `age-keygen`, 1.3 or later for post-quantum keys.
- `op`, the 1Password CLI, signed in.
- `jq`.

## Rewriting a state

Recipient changes take effect only when a state is written again, and **a `tofu apply` that changes nothing does not write the state.** OpenTofu skips the write when the state, its lineage and its serial are all unchanged, so after a recipients change the backend still holds the old ciphertext. Force the write instead:

```sh
op run --env-file=.env.tofu -- sh -c 'tofu state pull | jq ".serial += 1" | tofu state push -'
```

`tofu state pull` decrypts the state with your identity and prints it to the pipe. `jq` bumps the serial, so OpenTofu sees a newer snapshot and writes it. `tofu state push -` encrypts it to the recipients file on disk and stores it. The plaintext only passes through the pipe; it never touches disk.

- **You need an identity that can already read the state.** Someone who is being added can't do this themselves.
- **The recipients file on disk is the one used.** Run it from a checkout that has the change: the merged `main`, or the pull request's branch.
- **Run it once per state:** every root module that uses the recipients file, and every workspace of each (`tofu workspace select <name>`).
- **A concurrent write makes the push fail, rather than be overwritten.** `tofu state push` refuses a snapshot that is older than the backend's, or has the same serial with different contents. Run the command again. Never add `-force`.

Then check the result: `tofu plan` with the new identity reads the state and shows no changes, and with a removed identity it fails.

This was checked against OpenTofu v1.13.1 and tofu-age 0.1.0 on an S3 backend: after a key was added, a no-change `tofu apply` left the object untouched and the new key could not read it; the command above rewrote it, and the new key could.

## Generating a keypair

Generate the key, store it in 1Password, and delete the local file:

```sh
age-keygen -o key.txt            # prints the public key (age1…)
# or, for a post-quantum key:   age-keygen -pq -o key.txt   (age1pq1…)
op item create --vault <vault> --category "Secure Note" --title "tofu-age <name>" "notesPlain=$(cat key.txt)"
rm key.txt
```

`age-keygen` writes `key.txt` readable by you alone, and the identity exists on disk only between those commands. Use a personal vault for an engineer's key, a vault shared by the CI administrators for a CI key, and a restricted vault for the break-glass key. Keep an offline copy of the break-glass key as well, for example on paper in a safe: without it, a lost 1Password account can mean lost state.

To print the public key again later:

```sh
op read "op://<vault>/tofu-age <name>/notesPlain" | age-keygen -y
```

## The recipients file

`age-recipients.txt` sits next to the root module and is committed. It takes one public key per line. Blank lines and lines starting with `#` are skipped, so put a comment above each key naming whose it is and where it lives:

```text
# alice (laptop)
age1q…
# ci (github actions, specsnl)
age1x…
# break-glass (1Password vault "tofu-age break-glass", offline copy in the safe)
age1z…
# carol (ssh key, laptop)
ssh-ed25519 AAAA… carol@laptop
```

The comment is what makes removing someone later unambiguous: a bare `age1…` line can't be traced to a person.

- **Post-quantum keys can't share the file with classic or SSH keys.** age refuses to encrypt to both kinds at once, so every write fails until the file is fixed. Switching is in [design.md](./design.md) § Operations.
- **An SSH key must have no passphrase.** Its holder runs `tofu-age check age-recipients.txt` to confirm, see [Adding someone](#adding-someone).
- **The break-glass and CI keys are always listed.** Without break-glass, losing every other identity loses the state.

## Using an identity

`tofu-age decrypt` reads the identity from `TOFU_AGE_IDENTITY` only. It never reads a file.

### Locally, with 1Password

Put a reference to your item in `.env.tofu`, next to the root module:

```sh
TOFU_AGE_IDENTITY=op://<vault>/tofu-age <name>/notesPlain
```

It holds a reference, not the key, but it names your own item, so keep it out of git. Then run `tofu` under `op run`, which resolves the reference into the environment of that one command:

```sh
op run --env-file=.env.tofu -- tofu plan
op run --env-file=.env.tofu -- tofu-age check age-recipients.txt
```

A pipeline needs `sh -c`, so that every command in it gets the variable, as in [Rewriting a state](#rewriting-a-state).

An engineer using their SSH key instead skips 1Password: `TOFU_AGE_IDENTITY="$(cat ~/.ssh/id_ed25519)" tofu plan`.

### In CI, with a GitHub secret

Copy the CI key from 1Password into a repository secret, without it touching disk:

```sh
op read "op://<vault>/tofu-age ci/notesPlain" | gh secret set TOFU_AGE_IDENTITY --repo specsnl/<repo>
```

Or into an organization secret, shared with the repositories that run `tofu`:

```sh
op read "op://<vault>/tofu-age ci/notesPlain" | gh secret set TOFU_AGE_IDENTITY --org specsnl --repos <repo>,<repo>
```

Then pass it to the steps that run `tofu`:

```yaml
env:
  TOFU_AGE_IDENTITY: ${{ secrets.TOFU_AGE_IDENTITY }}
```

## Adding someone

1. **They generate a keypair,** as in [Generating a keypair](#generating-a-keypair), and send you the public key. Only the public key: it is safe to paste anywhere.
2. **Add the key to `age-recipients.txt`,** with a comment naming them, in a pull request.
3. **They run `tofu-age check age-recipients.txt`** on that branch, with their identity in `TOFU_AGE_IDENTITY`. It fails on a key that is not in the file, or an SSH key with a passphrase, which they would otherwise only find out about on their first read.
4. **Merge, then [rewrite every state](#rewriting-a-state) they need,** with your own identity. Until a state is rewritten, they can't read it: older state stays encrypted to the old list.
5. **They run `tofu plan`.** It should read the state and show no changes.

## Removing someone, or a lost laptop

1. **Delete their line from `age-recipients.txt`** in a pull request. Delete every key they hold: a classic and a post-quantum key during a switch, or an SSH key.
2. **Merge, then [rewrite every state](#rewriting-a-state)** with an identity that stays in the file. The rewritten state no longer opens with the removed key.
3. **Rotate the secrets held in state.** The removed key still opens every older version in the backend's history, such as S3 object versions, and its holder may have seen the plaintext already. Rewriting a state does not undo either. Rotate each database password, token and generated key the state holds, then apply. Deleting old object versions narrows the exposure but does not replace rotation.
4. **Revoke what is left:** their access to the vault holding their item, and the item itself once they no longer need it.

A lost laptop is the same procedure. The identity lives in 1Password rather than on disk, but a laptop with an unlocked 1Password session or an SSH key on it has to be treated as exposed. The owner then generates a new key and is added again.

For a leaked CI key, do it in one pull request: [generate a new CI key](#generating-a-keypair), replace the old line with the new one, merge, rewrite every state with a person's identity, then [update the secret](#in-ci-with-a-github-secret). CI can't read state between the rewrite and the secret update, so keep that gap short.

## Break-glass

The break-glass key is for when no other identity can read a state: every key is lost, or tofu-age itself can't run.

### With OpenTofu

If `tofu` and `tofu-age` still run, use the break-glass identity like any other. Put its reference in an env file of its own, such as `.env.break-glass`:

```sh
TOFU_AGE_IDENTITY=op://<restricted vault>/tofu-age break-glass/notesPlain
```

Then [add new keys](#adding-someone) and [rewrite every state](#rewriting-a-state) with `op run --env-file=.env.break-glass`. Once the new keys can read state, stop using the break-glass key.

### Without OpenTofu

The state object in the backend is a JSON envelope. The age ciphertext is base64 in its `encrypted_data` field. Download the object, for example with `aws s3 cp s3://<bucket>/<key> state.enc`, and decrypt it with the `age` CLI:

```sh
jq -r '.encrypted_data' state.enc | base64 -d | age -d -i <(op read "op://<restricted vault>/tofu-age break-glass/notesPlain") > plain.tfstate
```

`<(…)` hands the identity to `age` without writing it to disk; it needs `bash` or `zsh`. With the offline copy, pass its path to `-i` instead. A state written with post-quantum keys needs age 1.3 or later.

`plain.tfstate` holds every secret in the state in plaintext. Keep it on an encrypted disk, and delete it when you are done.

### Afterwards

The break-glass key may now be exposed: it was used on a machine, and perhaps its offline copy left the safe. Generate a new one, replace its line, rewrite every state, and store the new key the same way.
