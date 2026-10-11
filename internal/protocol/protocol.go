// Package protocol speaks version 1 of OpenTofu's external encryption method
// protocol, and nothing else: no crypto happens here.
//
// OpenTofu runs the method once per state or plan write or read. The method
// writes a header line to stdout, reads one input object from stdin, and
// answers with one output object on stdout. Diagnostics go to stderr, and a
// non-zero exit fails the operation.
//
// The schemas are in OpenTofu's tree, under
// internal/encryption/method/external/protocol; testdata holds a copy that the
// tests validate against.
package protocol

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
)

const (
	magic   = "OpenTofu-External-Encryption-Method"
	version = 1
)

var (
	// ErrKeyProvided means OpenTofu passed key material in. tofu-age takes its
	// keys from age, so a key here is a key provider configured on the method
	// by mistake.
	ErrKeyProvided = errors.New(`the input carries a key: tofu-age takes no key provider, so remove "keys" from the method "external" block`)

	// ErrNoPayload means the input lacks the one field the schema requires.
	ErrNoPayload = errors.New("the input has no payload")

	// ErrTrailingData means stdin held more than the one input object.
	ErrTrailingData = errors.New("the input is followed by more data")

	// errOutOfOrder means a write would break the header-then-one-object
	// shape of stdout.
	errOutOfOrder = errors.New("out of order")
)

type header struct {
	Magic   string `json:"magic"`
	Version int    `json:"version"`
}

// []byte fields are base64-encoded and decoded by encoding/json, which is the
// encoding the protocol uses.
type input struct {
	Key     []byte `json:"key,omitempty"`
	Payload []byte `json:"payload"`
}

type output struct {
	Payload []byte `json:"payload"`
}

// Run handles one call from OpenTofu: it writes the header to stdout, reads the
// input from stdin, passes the payload through transform, and writes the
// result as the output.
//
// The header goes out before anything can fail, so on an error stdout holds the
// header and nothing else. The error is returned for the caller to print on
// stderr.
func Run(stdin io.Reader, stdout io.Writer, transform func(payload []byte) ([]byte, error)) error {
	w := &writer{w: stdout}

	if err := w.writeHeader(); err != nil {
		return err
	}

	in, err := readInput(stdin)
	if err != nil {
		return err
	}

	result, err := transform(in.Payload)
	if err != nil {
		return err
	}

	return w.writeOutput(result)
}

// readInput decodes the single input object on r, as strictly as the schema
// describes it: no unknown fields, a payload, and nothing after the object.
func readInput(r io.Reader) (input, error) {
	dec := json.NewDecoder(r)
	dec.DisallowUnknownFields()

	var in input
	if err := dec.Decode(&in); err != nil {
		return input{}, fmt.Errorf("read the input: %w", err)
	}

	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return input{}, fmt.Errorf("read the input: %w", ErrTrailingData)
	}

	// A missing or null payload decodes to nil; an empty string decodes to an
	// empty, non-nil slice and is a valid payload.
	if in.Payload == nil {
		return input{}, fmt.Errorf("read the input: %w", ErrNoPayload)
	}

	if len(in.Key) > 0 {
		return input{}, fmt.Errorf("read the input: %w", ErrKeyProvided)
	}

	return in, nil
}

// writer is the only thing that writes to stdout. It emits the header line,
// then exactly one output object, and refuses any other sequence.
type writer struct {
	w             io.Writer
	headerWritten bool
	outputWritten bool
}

func (w *writer) writeHeader() error {
	if w.headerWritten {
		return fmt.Errorf("write the header: %w: it is already written", errOutOfOrder)
	}

	w.headerWritten = true

	return w.writeLine("write the header", header{Magic: magic, Version: version})
}

func (w *writer) writeOutput(payload []byte) error {
	switch {
	case !w.headerWritten:
		return fmt.Errorf("write the output: %w: the header must come first", errOutOfOrder)
	case w.outputWritten:
		return fmt.Errorf("write the output: %w: it is already written", errOutOfOrder)
	}

	w.outputWritten = true

	// A nil slice would encode as null, which the schema rejects.
	if payload == nil {
		payload = []byte{}
	}

	return w.writeLine("write the output", output{Payload: payload})
}

// writeLine encodes v and writes it, newline-terminated, in a single Write, so
// a failed encode leaves nothing half-written on stdout.
func (w *writer) writeLine(what string, v any) error {
	line, err := json.Marshal(v)
	if err != nil {
		return fmt.Errorf("%s: %w", what, err)
	}

	if _, err := w.w.Write(append(line, '\n')); err != nil {
		return fmt.Errorf("%s: %w", what, err)
	}

	return nil
}
