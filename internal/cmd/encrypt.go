package cmd

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/specsnl/tofu-age/internal/protocol"
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
		RunE: func(cmd *cobra.Command, _ []string) error {
			err := protocol.Run(cmd.InOrStdin(), cmd.OutOrStdout(), func([]byte) ([]byte, error) {
				return nil, errNotImplemented
			})
			if err != nil {
				return fmt.Errorf("encrypt: %w", err)
			}

			return nil
		},
	}
}
