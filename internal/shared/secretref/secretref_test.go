package secretref

import "testing"

func TestAlias(t *testing.T) {
	if alias, err := Alias("secret://docker-production"); err != nil || alias != "docker-production" {
		t.Fatalf("alias = %q, %v", alias, err)
	}
	for _, value := range []string{"", "env://token", "secret://UPPER", "secret://../token"} {
		if _, err := Alias(value); err == nil {
			t.Errorf("%q accepted", value)
		}
	}
}
