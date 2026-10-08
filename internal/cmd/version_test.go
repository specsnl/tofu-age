package cmd_test

import (
	"testing"

	"github.com/specsnl/tofu-age/internal/cmd"
)

// The version is the product of the command, so it belongs on stdout: a user
// running `tofu-age version --dont-prettify > v.txt` must find it in the file.
func TestVersion(t *testing.T) {
	for _, tc := range []struct {
		name string
		args []string
		want string
	}{
		{"prettified by default", []string{"version"}, "tofu-age version " + cmd.Version + "\n"},
		{"bare with --dont-prettify", []string{"version", "--dont-prettify"}, cmd.Version + "\n"},
		{"bare with the root --version", []string{"--version"}, cmd.Version + "\n"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			stdout, stderr, err := run(t, tc.args...)
			if err != nil {
				t.Fatalf("%v: %v", tc.args, err)
			}

			if stdout != tc.want {
				t.Errorf("stdout = %q, want %q", stdout, tc.want)
			}

			if stderr != "" {
				t.Errorf("version narrated on stderr: %q", stderr)
			}
		})
	}
}

// --version is defined as `version --dont-prettify`, so the test is that the two
// produce the same bytes rather than that each produces something plausible.
func TestVersion_RootFlagMatchesDontPrettify(t *testing.T) {
	viaFlag, _, err := run(t, "--version")
	if err != nil {
		t.Fatalf("--version: %v", err)
	}

	viaCmd, _, err := run(t, "version", "--dont-prettify")
	if err != nil {
		t.Fatalf("version --dont-prettify: %v", err)
	}

	if viaFlag != viaCmd {
		t.Errorf("--version = %q, version --dont-prettify = %q; they must agree", viaFlag, viaCmd)
	}
}

// Nothing injects Version under `go test`, so the fallback is what a build
// without -ldflags ships as.
func TestVersion_DefaultsToDev(t *testing.T) {
	if cmd.Version != "dev" {
		t.Errorf("Version = %q, want %q", cmd.Version, "dev")
	}
}

func TestVersion_RejectsArguments(t *testing.T) {
	if _, _, err := run(t, "version", "extra"); err == nil {
		t.Fatal("want an error for an unexpected argument, got none")
	}
}
