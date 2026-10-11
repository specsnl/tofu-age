package cmd_test

import (
	"bytes"
	"errors"
	"strings"
	"testing"

	"github.com/specsnl/tofu-age/internal/cmd"
	"github.com/specsnl/tofu-age/internal/protocol"
)

// header is the protocol's first line, which encrypt and decrypt write before
// anything can fail.
const header = `{"magic":"OpenTofu-External-Encryption-Method","version":1}` + "\n"

// run builds the tree the way main does, points both streams at buffers, and
// executes with an empty stdin. Every assertion below reads those buffers: if a
// test cannot see the output, a command wrote to os.Stdout/os.Stderr directly
// and the wiring is wrong, which is exactly what this helper is here to catch.
func run(t *testing.T, args ...string) (string, string, error) {
	t.Helper()

	return runWithInput(t, "", args...)
}

// runWithInput is run with stdin, for the commands that speak the protocol.
func runWithInput(t *testing.T, stdin string, args ...string) (string, string, error) {
	t.Helper()

	var stdout, stderr bytes.Buffer

	root := cmd.NewRootCmd()
	root.SetOut(&stdout)
	root.SetErr(&stderr)
	root.SetIn(strings.NewReader(stdin))
	root.SetArgs(args)

	err := root.Execute()

	return stdout.String(), stderr.String(), err
}

// Without the flag the root prints its help.
func TestRoot_BareInvocationPrintsHelp(t *testing.T) {
	stdout, _, err := run(t)
	if err != nil {
		t.Fatalf("bare invocation: %v", err)
	}

	if !strings.Contains(stdout, "Usage:") {
		t.Errorf("stdout = %q, want the help", stdout)
	}
}

// A RunE on the root must not turn a typo into a silent help screen.
func TestRoot_UnknownCommandStillFails(t *testing.T) {
	if _, _, err := run(t, "bogus"); err == nil {
		t.Fatal("want an error for an unknown command, got none")
	}
}

// Without SilenceUsage every runtime failure drags the usage block along;
// without SilenceErrors Cobra prints its own copy next to main's.
func TestRoot_SilencesUsageAndErrors(t *testing.T) {
	root := cmd.NewRootCmd()
	if !root.SilenceUsage || !root.SilenceErrors {
		t.Fatalf("SilenceUsage = %v, SilenceErrors = %v, want both true", root.SilenceUsage, root.SilenceErrors)
	}

	stdout, stderr, err := run(t, "decrypt")
	if err == nil {
		t.Fatal("want an error, got none")
	}

	// stdout holds the protocol header and nothing else.
	if stdout != header {
		t.Errorf("stdout = %q, want only the header; main owns the single print", stdout)
	}

	if stderr != "" {
		t.Errorf("stderr = %q, want nothing; main owns the single print", stderr)
	}
}

// Until the crypto is built, encrypt and decrypt speak the protocol and then
// fail: stdout holds the header alone, and the error says why.
func TestStubs_SpeakTheProtocolThenFail(t *testing.T) {
	for _, args := range [][]string{
		{"encrypt", "age-recipients.txt"},
		{"decrypt"},
	} {
		t.Run(args[0], func(t *testing.T) {
			stdout, stderr, err := runWithInput(t, `{"payload":"aGVsbG8="}`, args...)
			if err == nil || !strings.Contains(err.Error(), "not implemented") {
				t.Fatalf("error = %v, want it to say not implemented", err)
			}

			if !strings.HasPrefix(err.Error(), args[0]+": ") {
				t.Errorf("error = %q, want it to name the command", err)
			}

			if stdout != header {
				t.Errorf("stdout = %q, want only the header", stdout)
			}

			if stderr != "" {
				t.Errorf("stderr = %q, want nothing; main owns the single print", stderr)
			}
		})
	}
}

// A key in the input is refused by both commands, before any crypto, with the
// sentinel intact through the command's wrapping.
func TestStubs_RejectAKey(t *testing.T) {
	for _, args := range [][]string{
		{"encrypt", "age-recipients.txt"},
		{"decrypt"},
	} {
		t.Run(args[0], func(t *testing.T) {
			stdout, _, err := runWithInput(t, `{"key":"c2VjcmV0","payload":"aGVsbG8="}`, args...)
			if !errors.Is(err, protocol.ErrKeyProvided) {
				t.Fatalf("error = %v, want %v", err, protocol.ErrKeyProvided)
			}

			if stdout != header {
				t.Errorf("stdout = %q, want only the header", stdout)
			}
		})
	}
}

func TestStubs_ValidateArguments(t *testing.T) {
	for _, args := range [][]string{
		{"encrypt"},
		{"encrypt", "a.txt", "b.txt"},
		{"decrypt", "extra"},
	} {
		t.Run(strings.Join(args, " "), func(t *testing.T) {
			_, _, err := run(t, args...)
			if err == nil {
				t.Fatal("want an argument error, got none")
			}

			if strings.Contains(err.Error(), "not implemented") {
				t.Errorf("error = %v, want the arguments rejected before the command runs", err)
			}
		})
	}
}

// --version is local to the root: a subcommand has no version of its own.
func TestRoot_VersionFlagIsNotPersistent(t *testing.T) {
	_, _, err := run(t, "decrypt", "--version")
	if err == nil || !strings.Contains(err.Error(), "unknown flag") {
		t.Errorf("error = %v, want an unknown flag", err)
	}
}
