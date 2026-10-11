package cmd

import (
	"fmt"

	"github.com/spf13/cobra"
)

func newEncryptCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "encrypt <recipients-file>",
		Short: "Encrypt an OpenTofu payload to the age recipients in a file",
		Long: `Encrypt an OpenTofu payload to the age recipients in a file.

The recipients file holds age public keys, one per line, and is safe to
commit. OpenTofu writes the payload to stdin and reads the ciphertext from
stdout; diagnostics go to stderr.`,
		Args: cobra.ExactArgs(1),
		RunE: func(*cobra.Command, []string) error {
			return fmt.Errorf("encrypt: %w", errNotImplemented)
		},
	}
}
