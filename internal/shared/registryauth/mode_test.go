package registryauth

import "testing"

func TestModeValid(t *testing.T) {
	for _, mode := range []Mode{ModeAnonymous, ModeBasic} {
		if !mode.Valid() {
			t.Fatalf("Mode(%q).Valid() = false", mode)
		}
	}
	for _, mode := range []Mode{"", "token", "none"} {
		if mode.Valid() {
			t.Fatalf("Mode(%q).Valid() = true", mode)
		}
	}
}
