package main

import (
	"bytes"
	"errors"
	"testing"
)

func TestReport(t *testing.T) {
	var stderr bytes.Buffer

	report(&stderr, errors.New("it broke"))

	if got, want := stderr.String(), "tofu-age: it broke\n"; got != want {
		t.Errorf("stderr = %q, want %q", got, want)
	}
}
