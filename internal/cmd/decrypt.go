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

	"github.com/specsnl/tofu-age/internal/protocol"
)

const envIdentity = "TOFU_AGE_IDENTITY"

var (
	errNoIdentity = errors.New(envIdentity + " is unset or empty")

	errSSHPassphrase = errors.New("it is protected by a passphrase, and tofu-age has no way to ask for one: " +
		"use an age identity, or an SSH key without a passphrase")
)

func newDecryptCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "decrypt",
		Short: "Decrypt an OpenTofu payload with the age identity in " + envIdentity,
		Long: `Decrypt an OpenTofu payload with the age identity in ` + envIdentity + `.

The identity is read from the environment only, never from a file, so that
a secrets manager or a CI secret can inject it. It holds either:

  - one or more age private keys, classic (AGE-SECRET-KEY-1...) or
    post-quantum (AGE-SECRET-KEY-PQ-1...), one per line. Blank lines and
    lines starting with "#" are ignored, so the output of age-keygen works
    as is.
  - one SSH private key (ed25519 or RSA), as ssh-keygen writes it:
    TOFU_AGE_IDENTITY="$(cat ~/.ssh/id_ed25519)". A key protected by a
    passphrase is refused: there is no terminal to ask for it on.

OpenTofu writes the ciphertext to stdin and reads the payload from stdout;
diagnostics go to stderr.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			err := protocol.Run(cmd.InOrStdin(), cmd.OutOrStdout(), func(payload []byte) ([]byte, error) {
				return decrypt(payload, os.Getenv(envIdentity))
			})
			if err != nil {
				return fmt.Errorf("decrypt: %w", err)
			}

			return nil
		},
	}
}

func decrypt(ciphertext []byte, identity string) ([]byte, error) {
	identities, err := parseIdentities(identity)
	if err != nil {
		return nil, err
	}

	r, err := age.Decrypt(bytes.NewReader(ciphertext), identities...)
	if err != nil {
		return nil, fmt.Errorf("decrypt the payload: %w", err)
	}

	// age authenticates the payload chunk by chunk, so a truncated or tampered
	// ciphertext fails here, while reading, rather than in Decrypt.
	plaintext, err := io.ReadAll(r)
	if err != nil {
		return nil, fmt.Errorf("decrypt the payload: %w", err)
	}

	return plaintext, nil
}

// parseIdentities parses the identities in the value of TOFU_AGE_IDENTITY.
// Neither age's errors nor these repeat the value: it is a private key.
func parseIdentities(identity string) ([]age.Identity, error) {
	if identity == "" {
		return nil, errNoIdentity
	}

	if strings.HasPrefix(strings.TrimSpace(identity), "-----BEGIN") {
		return parseSSHIdentity(identity)
	}

	identities, err := age.ParseIdentities(strings.NewReader(identity))
	if err != nil {
		return nil, fmt.Errorf("parse %s: %w", envIdentity, err)
	}

	return identities, nil
}

// parseSSHIdentity parses the SSH private key in the value of
// TOFU_AGE_IDENTITY. The age CLI prompts for the passphrase of a protected key;
// OpenTofu runs tofu-age with no terminal to prompt on, so it refuses one.
func parseSSHIdentity(pemBytes string) ([]age.Identity, error) {
	id, err := agessh.ParseIdentity([]byte(pemBytes))
	if missing, ok := errors.AsType[*ssh.PassphraseMissingError](err); ok {
		// Newer OpenSSH keys carry their public key in the clear, which tells
		// the developer which of their keys this is.
		if missing.PublicKey != nil {
			return nil, fmt.Errorf("parse %s: the SSH key %s: %w", envIdentity, ssh.FingerprintSHA256(missing.PublicKey), errSSHPassphrase)
		}

		return nil, fmt.Errorf("parse %s: the SSH key: %w", envIdentity, errSSHPassphrase)
	}

	if err != nil {
		return nil, fmt.Errorf("parse %s as an SSH private key: %w", envIdentity, err)
	}

	return []age.Identity{id}, nil
}
