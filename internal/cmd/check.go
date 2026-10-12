package cmd

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	"filippo.io/age"
	"filippo.io/age/agessh"
	"github.com/spf13/cobra"
	"golang.org/x/crypto/ssh"
)

var errNoListedIdentity = errors.New("no identity in " + envIdentity + " is in the recipients file")

func newCheckCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "check <recipients-file>",
		Short: "Check that the identity in " + envIdentity + " can decrypt for a recipients file",
		Long: `Check that the identity in ` + envIdentity + ` can decrypt for a recipients file.

Run it after adding a key to the recipients file, rather than finding out on
the first "tofu plan". It reads both exactly as encrypt and decrypt do, so it
fails on an identity that is unset, malformed or protected by a passphrase,
and on a recipients file that encrypt would refuse.

It passes when at least one identity in ` + envIdentity + ` is in the file,
and lists each one as in or not in the file. While switching to post-quantum
keys a developer holds both kinds, and only one is listed.

It never prints an identity, only public keys: an age key in full, a
post-quantum key shortened, and an SSH key by its fingerprint.

A human runs it, not OpenTofu: the result goes to stdout and errors to stderr.`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := check(cmd.OutOrStdout(), os.Getenv(envIdentity), args[0]); err != nil {
				return fmt.Errorf("check: %w", err)
			}

			return nil
		},
	}
}

func check(w io.Writer, identity, recipientsFile string) error {
	// The identity first: a passphrase-protected SSH key fails whatever the
	// file holds.
	identities, err := parseIdentities(identity)
	if err != nil {
		return err
	}

	// A probe encrypted the way encrypt does it, so a file that encrypt refuses
	// fails here too.
	probe, err := encrypt(nil, recipientsFile)
	if err != nil {
		return err
	}

	var listed, unlisted []string

	for _, id := range identities {
		key, err := publicKey(id, identity)
		if err != nil {
			return err
		}

		_, err = age.Decrypt(bytes.NewReader(probe), id)
		if _, ok := errors.AsType[*age.NoIdentityMatchError](err); ok {
			unlisted = append(unlisted, key)

			continue
		}

		if err != nil {
			return fmt.Errorf("decrypt a probe for %s: %w", key, err)
		}

		listed = append(listed, key)
	}

	if len(listed) == 0 {
		return fmt.Errorf("%w %s: %s", errNoListedIdentity, recipientsFile, strings.Join(unlisted, ", "))
	}

	for _, key := range listed {
		fmt.Fprint(w, "in ", recipientsFile, ":     ", key, "\n")
	}

	for _, key := range unlisted {
		fmt.Fprint(w, "not in ", recipientsFile, ": ", key, "\n")
	}

	return nil
}

// shortPostQuantumKey is long enough to find a post-quantum key in a recipients
// file. The whole key is about 2,000 characters.
const shortPostQuantumKey = 32

// publicKey names id by its public key. identity is the value of
// TOFU_AGE_IDENTITY that id was parsed from: agessh does not expose an SSH
// key's public half, so it is parsed again from there.
func publicKey(id age.Identity, identity string) (string, error) {
	switch id := id.(type) {
	case *age.X25519Identity:
		return id.Recipient().String(), nil
	case *age.HybridIdentity:
		return id.Recipient().String()[:shortPostQuantumKey] + "…", nil
	case *agessh.Ed25519Identity, *agessh.RSAIdentity:
		signer, err := ssh.ParsePrivateKey([]byte(identity))
		if err != nil {
			return "", fmt.Errorf("parse %s as an SSH private key: %w", envIdentity, err)
		}

		pub := signer.PublicKey()

		return pub.Type() + " " + ssh.FingerprintSHA256(pub), nil
	default:
		return "", fmt.Errorf("parse %s: unsupported identity type %T", envIdentity, id)
	}
}
