package cmd_test

import (
	"bytes"
	"encoding/json"
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

// inputFor is the input object OpenTofu writes on stdin to hand over payload.
func inputFor(t *testing.T, payload []byte) string {
	t.Helper()

	line, err := json.Marshal(map[string][]byte{"payload": payload})
	if err != nil {
		t.Fatalf("encode the input: %v", err)
	}

	return string(line) + "\n"
}

// outputOf asserts that stdout is the header followed by exactly one output
// line, and returns the payload in it.
func outputOf(t *testing.T, stdout string) []byte {
	t.Helper()

	rest, ok := strings.CutPrefix(stdout, header)
	if !ok {
		t.Fatalf("stdout = %q, want it to start with the header", stdout)
	}

	line, ok := strings.CutSuffix(rest, "\n")
	if !ok || strings.Contains(line, "\n") {
		t.Fatalf("stdout = %q, want one output line after the header", stdout)
	}

	var out struct {
		Payload []byte `json:"payload"`
	}

	dec := json.NewDecoder(strings.NewReader(line))
	dec.DisallowUnknownFields()

	if err := dec.Decode(&out); err != nil {
		t.Fatalf("decode the output %q: %v", line, err)
	}

	return out.Payload
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

// A key in the input is refused by both commands, before any crypto, with the
// sentinel intact through the command's wrapping.
func TestCommands_RejectAKey(t *testing.T) {
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

// Bad arguments are rejected before the command runs, so not even the header
// reaches stdout.
func TestCommands_ValidateArguments(t *testing.T) {
	for _, args := range [][]string{
		{"encrypt"},
		{"encrypt", "a.txt", "b.txt"},
		{"decrypt", "extra"},
	} {
		t.Run(strings.Join(args, " "), func(t *testing.T) {
			stdout, _, err := run(t, args...)
			if err == nil {
				t.Fatal("want an argument error, got none")
			}

			if stdout != "" {
				t.Errorf("stdout = %q, want nothing: the arguments are rejected before the command runs", stdout)
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
