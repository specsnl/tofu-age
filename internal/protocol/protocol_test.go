package protocol

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"strings"
	"testing"
)

const wantHeader = `{"magic":"OpenTofu-External-Encryption-Method","version":1}` + "\n"

// echo is a transform that hands the payload back unchanged.
func echo(payload []byte) ([]byte, error) {
	return payload, nil
}

func run(t *testing.T, stdin string, transform func([]byte) ([]byte, error)) (string, error) {
	t.Helper()

	var stdout bytes.Buffer

	err := Run(strings.NewReader(stdin), &stdout, transform)

	return stdout.String(), err
}

// OpenTofu reads up to the first newline and parses that as the header, so the
// header has to be the very first bytes and has to end in a newline.
func TestRun_HeaderIsTheFirstLine(t *testing.T) {
	stdout, err := run(t, `{"payload":"aGVsbG8="}`, echo)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}

	if !strings.HasPrefix(stdout, wantHeader) {
		t.Errorf("stdout = %q, want it to start with %q", stdout, wantHeader)
	}
}

func TestRun_TransformsThePayload(t *testing.T) {
	var got []byte

	stdout, err := run(t, `{"payload":"aGVsbG8="}`, func(payload []byte) ([]byte, error) {
		got = payload

		return []byte("goodbye"), nil
	})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}

	if string(got) != "hello" {
		t.Errorf("transform got %q, want %q", got, "hello")
	}

	if want := wantHeader + `{"payload":"Z29vZGJ5ZQ=="}` + "\n"; stdout != want {
		t.Errorf("stdout = %q, want %q", stdout, want)
	}
}

// Whatever happens, stdout is the header and at most one output object: JSON,
// one value per line, and nothing else for OpenTofu to trip over. On an error,
// the output object is missing and the header stands alone.
func TestRun_StdoutHoldsOnlyJSON(t *testing.T) {
	errTransform := errors.New("transform failed")

	for _, tc := range []struct {
		name      string
		stdin     string
		transform func([]byte) ([]byte, error)
		ok        bool
		wantErr   error
	}{
		{name: "success", stdin: `{"payload":"aGVsbG8="}`, ok: true},
		{name: "success with an empty payload", stdin: `{"payload":""}`, ok: true},
		{name: "success with an empty key", stdin: `{"key":"","payload":"aGVsbG8="}`, ok: true},
		{name: "success with trailing whitespace", stdin: "{\"payload\":\"aGVsbG8=\"}\n\n", ok: true},
		{name: "empty stdin", stdin: "", wantErr: io.EOF},
		{name: "not JSON", stdin: "hello"},
		{name: "not base64", stdin: `{"payload":"not base64!"}`},
		{name: "unknown field", stdin: `{"payload":"aGVsbG8=","extra":1}`},
		{name: "missing payload", stdin: `{}`, wantErr: ErrNoPayload},
		{name: "null payload", stdin: `{"payload":null}`, wantErr: ErrNoPayload},
		{name: "null input", stdin: `null`, wantErr: ErrNoPayload},
		{name: "a second object", stdin: `{"payload":"aGVsbG8="}{"payload":"aGVsbG8="}`, wantErr: ErrTrailingData},
		{name: "trailing garbage", stdin: `{"payload":"aGVsbG8="} garbage`, wantErr: ErrTrailingData},
		{name: "a key", stdin: `{"key":"c2VjcmV0","payload":"aGVsbG8="}`, wantErr: ErrKeyProvided},
		{
			name:      "the transform fails",
			stdin:     `{"payload":"aGVsbG8="}`,
			transform: func([]byte) ([]byte, error) { return nil, errTransform },
			wantErr:   errTransform,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			transform := tc.transform
			if transform == nil {
				transform = echo
			}

			stdout, err := run(t, tc.stdin, transform)

			switch {
			case !tc.ok && err == nil:
				t.Fatal("want an error, got none")
			case tc.ok && err != nil:
				t.Fatalf("Run: %v", err)
			case tc.wantErr != nil && !errors.Is(err, tc.wantErr):
				t.Fatalf("error = %v, want %v", err, tc.wantErr)
			}

			want := 1
			if tc.ok {
				want = 2
			}

			assertJSONLines(t, stdout, want)

			if !strings.HasPrefix(stdout, wantHeader) {
				t.Errorf("stdout = %q, want it to start with the header", stdout)
			}
		})
	}
}

// assertJSONLines fails unless stdout is exactly want lines, each one a JSON
// object.
func assertJSONLines(t *testing.T, stdout string, want int) {
	t.Helper()

	if !strings.HasSuffix(stdout, "\n") {
		t.Fatalf("stdout = %q, want it newline-terminated", stdout)
	}

	lines := strings.Split(strings.TrimSuffix(stdout, "\n"), "\n")
	if len(lines) != want {
		t.Fatalf("stdout = %q, want %d lines", stdout, want)
	}

	for _, line := range lines {
		var object map[string]any
		if err := json.Unmarshal([]byte(line), &object); err != nil || object == nil {
			t.Errorf("stdout line %q is not a JSON object: %v", line, err)
		}
	}
}

// A key means a key provider was configured next to the method. Refusing it
// before the transform runs keeps it from being silently ignored.
func TestRun_RejectsAKeyBeforeTransforming(t *testing.T) {
	called := false

	_, err := run(t, `{"key":"c2VjcmV0","payload":"aGVsbG8="}`, func(payload []byte) ([]byte, error) {
		called = true

		return payload, nil
	})
	if !errors.Is(err, ErrKeyProvided) {
		t.Fatalf("error = %v, want %v", err, ErrKeyProvided)
	}

	if called {
		t.Error("the transform ran on an input carrying a key")
	}

	if !strings.Contains(err.Error(), "key provider") {
		t.Errorf("error = %q, want it to point at the key provider", err)
	}
}

// A nil result must still encode as a string: null fails OpenTofu's schema.
func TestRun_NilResultIsAnEmptyPayload(t *testing.T) {
	stdout, err := run(t, `{"payload":""}`, func([]byte) ([]byte, error) { return nil, nil })
	if err != nil {
		t.Fatalf("Run: %v", err)
	}

	if want := wantHeader + `{"payload":""}` + "\n"; stdout != want {
		t.Errorf("stdout = %q, want %q", stdout, want)
	}
}

type failingWriter struct{}

func (failingWriter) Write([]byte) (int, error) {
	return 0, errors.New("broken pipe")
}

// If the header cannot be written OpenTofu is not listening, so there is no
// point reading the input or running the transform.
func TestRun_StopsWhenTheHeaderCannotBeWritten(t *testing.T) {
	called := false

	err := Run(strings.NewReader(`{"payload":""}`), failingWriter{}, func(payload []byte) ([]byte, error) {
		called = true

		return payload, nil
	})
	if err == nil || !strings.Contains(err.Error(), "broken pipe") {
		t.Fatalf("error = %v, want the write failure", err)
	}

	if called {
		t.Error("the transform ran after the header failed")
	}
}

// The writer is what keeps stdout to a header and one object, so every other
// sequence is refused, and a refused call writes nothing.
func TestWriter_RefusesAnyOtherOrder(t *testing.T) {
	for _, tc := range []struct {
		name  string
		steps []func(*writer) error
		want  string
	}{
		{
			name:  "output before the header",
			steps: []func(*writer) error{writeOutput},
			want:  "",
		},
		{
			name:  "the header twice",
			steps: []func(*writer) error{writeHeader, writeHeader},
			want:  wantHeader,
		},
		{
			name:  "the output twice",
			steps: []func(*writer) error{writeHeader, writeOutput, writeOutput},
			want:  wantHeader + `{"payload":"aGVsbG8="}` + "\n",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var stdout bytes.Buffer

			w := &writer{w: &stdout}

			var err error
			for _, step := range tc.steps {
				err = step(w)
			}

			if !errors.Is(err, errOutOfOrder) {
				t.Errorf("error = %v, want %v", err, errOutOfOrder)
			}

			if got := stdout.String(); got != tc.want {
				t.Errorf("stdout = %q, want %q", got, tc.want)
			}
		})
	}
}

func writeHeader(w *writer) error {
	return w.writeHeader()
}

func writeOutput(w *writer) error {
	return w.writeOutput([]byte("hello"))
}
