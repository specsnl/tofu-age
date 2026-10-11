package cmd

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"strings"

	"filippo.io/age"
	"filippo.io/age/agessh"
	"github.com/spf13/cobra"

	"github.com/specsnl/tofu-age/internal/protocol"
)

var (
	errNoRecipients = errors.New("no recipients found")

	// errUnknownRecipient does not repeat the line: it may be a private key
	// pasted into the recipients file by mistake.
	errUnknownRecipient = errors.New("unknown recipient type")
)

func newEncryptCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "encrypt <recipients-file>",
		Short: "Encrypt an OpenTofu payload to the age recipients in a file",
		Long: `Encrypt an OpenTofu payload to the age recipients in a file.

The recipients file holds public keys, one per line, and is safe to commit.
Blank lines and lines starting with "#" are ignored. Any one of the matching
identities can decrypt the result.

A key is an age key, classic (age1...) or post-quantum (age1pq1...), or an
SSH key (ssh-ed25519 or ssh-rsa). age keys are recommended. age refuses to
mix post-quantum keys with any other kind, because one classic key would
leave the file open to a quantum computer.

The public half of an SSH key does not tell whether its private half has a
passphrase, so a protected key is only refused when it is used to decrypt.

OpenTofu writes the payload to stdin and reads the ciphertext from stdout;
diagnostics go to stderr.`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			err := protocol.Run(cmd.InOrStdin(), cmd.OutOrStdout(), func(payload []byte) ([]byte, error) {
				return encrypt(payload, args[0])
			})
			if err != nil {
				return fmt.Errorf("encrypt: %w", err)
			}

			return nil
		},
	}
}

func encrypt(plaintext []byte, recipientsFile string) ([]byte, error) {
	recipients, err := readRecipients(recipientsFile)
	if err != nil {
		return nil, err
	}

	var ciphertext bytes.Buffer

	w, err := age.Encrypt(&ciphertext, recipients...)
	if err != nil {
		return nil, fmt.Errorf("start the encryption: %w", err)
	}

	if _, err := w.Write(plaintext); err != nil {
		return nil, fmt.Errorf("encrypt the payload: %w", err)
	}

	// Close writes the last chunk and its authentication tag. Without it the
	// ciphertext is truncated, and fails to decrypt.
	if err := w.Close(); err != nil {
		return nil, fmt.Errorf("finish the encryption: %w", err)
	}

	return ciphertext.Bytes(), nil
}

// readRecipients parses the recipients file at path. An empty or comment-only
// file is an error.
//
// age.ParseRecipients cannot be used: it takes age keys only. This is its
// syntax, with SSH keys added the way the age CLI adds them.
func readRecipients(path string) ([]age.Recipient, error) {
	content, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read the recipients file: %w", err)
	}

	var recipients []age.Recipient

	for i, line := range strings.Split(string(content), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		r, err := parseRecipient(line)
		if err != nil {
			return nil, fmt.Errorf("parse the recipients file %s: line %d: %w", path, i+1, err)
		}

		recipients = append(recipients, r)
	}

	if len(recipients) == 0 {
		return nil, fmt.Errorf("parse the recipients file %s: %w", path, errNoRecipients)
	}

	return recipients, nil
}

func parseRecipient(s string) (age.Recipient, error) {
	switch {
	case strings.HasPrefix(s, "age1pq1"):
		return age.ParseHybridRecipient(s)
	case strings.HasPrefix(s, "age1"):
		return age.ParseX25519Recipient(s)
	case strings.HasPrefix(s, "ssh-"):
		return agessh.ParseRecipient(s)
	default:
		return nil, errUnknownRecipient
	}
}
