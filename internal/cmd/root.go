// Package cmd is the tofu-age command tree.
//
// stdout belongs to the OpenTofu external encryption method protocol: encrypt
// and decrypt write the header line and the response object there, and nothing
// else. Diagnostics go to stderr.
//
// # No os.Exit here
//
// Commands return errors; main prints them and turns them into the exit code.
// os.Exit skips deferred cleanup, so calling it inside a command would leave
// writers unflushed.
package cmd

import "github.com/spf13/cobra"

const flagVersion = "version"

// Execute builds the command tree and runs it against the process's arguments
// and streams.
func Execute() error {
	return NewRootCmd().Execute()
}

// NewRootCmd builds the tofu-age root command, with every subcommand attached.
//
// Exported because a test drives the tree the way main does — build it, point
// cmd.SetOut/SetErr at buffers, execute — and that is the only way to assert
// what reaches stdout.
func NewRootCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "tofu-age",
		Short: "An OpenTofu external encryption method backed by age",
		Long: `tofu-age translates between OpenTofu's external encryption method protocol
and age. OpenTofu runs it on every state and plan write and read:

  method "external" "age" {
    encrypt_command = ["tofu-age", "encrypt", "age-recipients.txt"]
    decrypt_command = ["tofu-age", "decrypt"]
  }

Use "tofu-age <command> --help" for more information about a command.`,

		// Without SilenceUsage every runtime failure appends the full usage block
		// after the message. Usage helps with a bad flag, not with a failed
		// decryption; on a runtime failure it buries the one line that matters.
		SilenceUsage: true,

		// Without SilenceErrors Cobra prints its own "Error: ..." line in addition
		// to main's. main owns the single print.
		SilenceErrors: true,

		// The root has a RunE only so that --version has somewhere to be handled.
		// Without the flag it prints the help. Args stays nil so Cobra's legacy
		// validator keeps rejecting an unknown subcommand rather than silently
		// showing help for it.
		RunE: func(cmd *cobra.Command, _ []string) error {
			if version, _ := cmd.Flags().GetBool(flagVersion); version {
				writeVersion(cmd.OutOrStdout(), true)

				return nil
			}

			return cmd.Help()
		},
	}

	// Local, not persistent: --version answers for the binary, not for a
	// subcommand.
	//
	// Reimplemented rather than enabled with cmd.Version, because Cobra's
	// built-in flag renders through its own template. Going through writeVersion
	// is what keeps --version and `version --dont-prettify` byte-identical.
	cmd.Flags().Bool(flagVersion, false, "Print the version and exit (same as: version --dont-prettify)")

	cmd.AddCommand(
		newCheckCmd(),
		newDecryptCmd(),
		newEncryptCmd(),
		newVersionCmd(),
	)

	return cmd
}
