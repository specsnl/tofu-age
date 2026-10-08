package cmd_test

import (
	"os"
	"strings"
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

// The Dockerfile names the variable by its full path, in a string the compiler
// never checks. Renaming or moving Version would leave it injecting into
// nothing, and every build would silently ship as "dev" — so the path is
// asserted against the source rather than trusted.
func TestVersion_DockerfileInjectsThisVariable(t *testing.T) {
	const (
		module = "github.com/specsnl/tofu-age"
		want   = module + "/internal/cmd.Version"
	)

	content, err := os.ReadFile("../../Dockerfile")
	if err != nil {
		t.Fatalf("read the Dockerfile: %v", err)
	}

	// The Dockerfile builds the path from ${GO_MODULE}, so the module has to be
	// its default and the suffix has to follow the variable.
	for _, fragment := range []string{
		"ARG GO_MODULE=" + module + "\n",
		"${GO_MODULE}" + strings.TrimPrefix(want, module) + "=",
	} {
		if !strings.Contains(string(content), fragment) {
			t.Errorf("the Dockerfile lacks %q; a build from it would not inject %s and would ship as %q", fragment, want, "dev")
		}
	}
}

func TestVersion_RejectsArguments(t *testing.T) {
	if _, _, err := run(t, "version", "extra"); err == nil {
		t.Fatal("want an error for an unexpected argument, got none")
	}
}
