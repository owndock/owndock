package main

import (
	"strings"
	"testing"
)

func TestSelectPreviousUsesSemanticOrder(t *testing.T) {
	previous, err := selectPrevious(
		"v2.0.0",
		strings.NewReader("v1.2.0\nv1.10.0\nnot-a-release\nv1.3.0\n"),
		false,
	)
	if err != nil {
		t.Fatal(err)
	}
	if previous != "v1.10.0" {
		t.Fatalf("previous = %q", previous)
	}
}

func TestSelectPreviousHandlesPrereleasePrecedence(t *testing.T) {
	previous, err := selectPrevious(
		"v1.0.0",
		strings.NewReader("v1.0.0-beta.2\nv0.9.9\nv1.0.0-beta.11\n"),
		false,
	)
	if err != nil {
		t.Fatal(err)
	}
	if previous != "v1.0.0-beta.11" {
		t.Fatalf("previous = %q", previous)
	}
}

func TestSelectPreviousRequiresMonotonicRelease(t *testing.T) {
	for _, published := range []string{"v2.0.0\n", "v1.0.0+published\n"} {
		if _, err := selectPrevious("v1.0.0", strings.NewReader(published), true); err == nil {
			t.Fatalf("published tags %q accepted a non-monotonic release", published)
		}
	}
}

func TestSelectPreviousValidatesInputAndBounds(t *testing.T) {
	if _, err := selectPrevious("1.0.0", strings.NewReader("v0.9.0\n"), false); err == nil {
		t.Fatal("accepted a tag without the v prefix")
	}
	tooMany := strings.Repeat("invalid\n", 1001)
	if _, err := selectPrevious("v1.0.0", strings.NewReader(tooMany), false); err == nil {
		t.Fatal("accepted more than 1000 release records")
	}
	previous, err := selectPrevious("v1.0.0", strings.NewReader("invalid\n"), false)
	if err != nil || previous != "" {
		t.Fatalf("empty baseline = %q, %v", previous, err)
	}
}
