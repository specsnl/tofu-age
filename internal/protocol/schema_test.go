package protocol

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/santhosh-tekuri/jsonschema/v6"
)

// compile loads one of the schemas vendored from OpenTofu under testdata.
// Content assertions are on, so a payload that is not base64 fails too.
func compile(t *testing.T, name string) *jsonschema.Schema {
	t.Helper()

	c := jsonschema.NewCompiler()
	c.AssertContent()

	schema, err := c.Compile("testdata/" + name + ".schema.json")
	if err != nil {
		t.Fatalf("compile the %s schema: %v", name, err)
	}

	return schema
}

func validate(schema *jsonschema.Schema, document string) error {
	instance, err := jsonschema.UnmarshalJSON(strings.NewReader(document))
	if err != nil {
		return err
	}

	return schema.Validate(instance)
}

// What Run writes is what OpenTofu parses: the first line against the header
// schema, the second against the output schema.
func TestSchema_HeaderAndOutput(t *testing.T) {
	headerSchema, outputSchema := compile(t, "header"), compile(t, "output")

	for _, tc := range []struct {
		name   string
		stdin  string
		result []byte
	}{
		{"a payload", `{"payload":"aGVsbG8="}`, []byte("ciphertext")},
		{"binary", `{"payload":"aGVsbG8="}`, []byte{0x00, 0xff, '\n', '"'}},
		{"an empty result", `{"payload":""}`, []byte{}},
		{"a nil result", `{"payload":""}`, nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			stdout, err := run(t, tc.stdin, func([]byte) ([]byte, error) { return tc.result, nil })
			if err != nil {
				t.Fatalf("Run: %v", err)
			}

			headerLine, outputLine, _ := strings.Cut(strings.TrimSuffix(stdout, "\n"), "\n")

			if err := validate(headerSchema, headerLine); err != nil {
				t.Errorf("header %s: %v", headerLine, err)
			}

			if err := validate(outputSchema, outputLine); err != nil {
				t.Errorf("output %s: %v", outputLine, err)
			}
		})
	}
}

// The input type has to match what OpenTofu sends, so it marshals to a
// document the input schema accepts — with and without the optional key.
func TestSchema_InputType(t *testing.T) {
	schema := compile(t, "input")

	for _, in := range []input{
		{Payload: []byte("hello")},
		{Payload: []byte{}},
		{Key: []byte("secret"), Payload: []byte("hello")},
	} {
		document, err := json.Marshal(in)
		if err != nil {
			t.Fatalf("marshal %+v: %v", in, err)
		}

		if err := validate(schema, string(document)); err != nil {
			t.Errorf("input %s: %v", document, err)
		}
	}
}

// readInput accepts what the input schema accepts and rejects what it rejects.
// The one deliberate difference is a key: the schema allows it, and tofu-age
// refuses it because it takes no key provider.
func TestSchema_ReadInputAgreesWithTheSchema(t *testing.T) {
	schema := compile(t, "input")

	for _, tc := range []struct {
		document string
		valid    bool
		accepted bool
	}{
		{`{"payload":"aGVsbG8="}`, true, true},
		{`{"payload":""}`, true, true},
		{`{"key":"","payload":"aGVsbG8="}`, true, true},
		{`{"key":"c2VjcmV0","payload":"aGVsbG8="}`, true, false},
		{`{}`, false, false},
		{`{"key":"c2VjcmV0"}`, false, false},
		{`{"payload":null}`, false, false},
		{`{"payload":42}`, false, false},
		{`{"payload":"not base64!"}`, false, false},
		{`{"payload":"aGVsbG8=","extra":1}`, false, false},
		{`null`, false, false},
		{`[]`, false, false},
	} {
		t.Run(tc.document, func(t *testing.T) {
			if err := validate(schema, tc.document); (err == nil) != tc.valid {
				t.Errorf("schema verdict = %v (%v), want valid = %v", err == nil, err, tc.valid)
			}

			_, err := readInput(strings.NewReader(tc.document))
			if (err == nil) != tc.accepted {
				t.Errorf("readInput error = %v, want accepted = %v", err, tc.accepted)
			}

			if tc.valid && !tc.accepted && !errors.Is(err, ErrKeyProvided) {
				t.Errorf("readInput error = %v; a schema-valid input may only be refused for its key", err)
			}
		})
	}
}
