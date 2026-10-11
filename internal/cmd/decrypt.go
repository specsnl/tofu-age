package cmd

import (
	"fmt"

	"github.com/spf13/cobra"
)

func newDecryptCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "decrypt",
		Short: "Decrypt an OpenTofu payload with the age identity in TOFU_AGE_IDENTITY",
		Long: `Decrypt an OpenTofu payload with the age identity in TOFU_AGE_IDENTITY.

The identity is read from the environment only, never from a file, so that
a secrets manager or a CI secret can inject it. OpenTofu writes the
ciphertext to stdin and reads the payload from stdout; diagnostics go to
stderr.`,
		Args: cobra.NoArgs,
		RunE: func(*cobra.Command, []string) error {
			return fmt.Errorf("decrypt: %w", errNotImplemented)
		},
	}
}
