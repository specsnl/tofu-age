// Command tofu-age is an OpenTofu external encryption method backed by age.
//
//	tofu-age encrypt <recipients-file>   # public keys, one per line; safe to commit
//	tofu-age decrypt                     # identity read from TOFU_AGE_IDENTITY
package main

import (
	"fmt"
	"io"
	"os"

	"github.com/specsnl/tofu-age/internal/cmd"
)

// main is the only place in tofu-age that calls os.Exit. It skips deferred
// cleanup, so called from inside a command it would leave writers unflushed.
// Commands return an error; it is printed once, here.
func main() {
	if err := cmd.Execute(); err != nil {
		report(os.Stderr, err)

		os.Exit(1)
	}
}

// report prints err on stderr. Never stdout: that stream belongs to the
// OpenTofu protocol, and anything else written there corrupts the response.
func report(w io.Writer, err error) {
	fmt.Fprintln(w, "tofu-age:", err)
}
