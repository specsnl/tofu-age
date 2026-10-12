package cmd

import (
	"fmt"
	"io"

	"github.com/spf13/cobra"
)

// Version is the binary version, injected at build time:
//
//	-ldflags "-X github.com/specsnl/tofu-age/internal/cmd.Version=1.2.3"
//
// The Dockerfile and .goreleaser.yml name this variable by that exact path, so
// it has to stay in this package under this name — rename it and every build
// silently ships as "dev".
var Version = "dev"

const flagDontPrettify = "dont-prettify"

func newVersionCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "version",
		Short: "Print the tofu-age version",
		Long: `Print the tofu-age version.

The version is a result, not narration, so it goes to stdout and can be
captured:

  tofu-age version --dont-prettify   # 1.2.3

The root flag "tofu-age --version" is the same as "--dont-prettify".`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			bare, _ := cmd.Flags().GetBool(flagDontPrettify)

			writeVersion(cmd.OutOrStdout(), bare)

			return nil
		},
	}

	cmd.Flags().Bool(flagDontPrettify, false, "Print the bare version string, with nothing around it")

	return cmd
}

// writeVersion prints the version on w.
//
// bare drops the sentence around the value, for $(tofu-age version
// --dont-prettify): a shell substitution wants the version, not a phrase
// containing it.
//
// Shared with the root's --version, which is defined to mean exactly
// `version --dont-prettify` — one function so the two cannot drift.
func writeVersion(w io.Writer, bare bool) {
	if bare {
		fmt.Fprintln(w, Version)

		return
	}

	fmt.Fprintln(w, "tofu-age version", Version)
}
