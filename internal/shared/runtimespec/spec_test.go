package runtimespec

import (
	"errors"
	"testing"
)

func TestNormalizeAppliesResourceAndHealthDefaults(t *testing.T) {
	spec, err := Normalize(Spec{
		Ports:           []Port{{Name: "http", ContainerPort: 8080}},
		EnvironmentKeys: []string{"DATABASE_URL"},
		HealthCheck:     &HealthCheck{Command: []string{"check"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if spec.Resources.CPUMilli != DefaultCPUMilli ||
		spec.Resources.MemoryBytes != DefaultMemoryBytes ||
		spec.HealthCheck.IntervalSeconds != 30 ||
		spec.Ports[0].Protocol != "tcp" {
		t.Fatalf("normalized spec = %+v", spec)
	}
}

func TestNormalizeRejectsDuplicateAndUnsafeDeclarations(t *testing.T) {
	for _, spec := range []Spec{
		{Ports: []Port{{Name: "HTTP", ContainerPort: 80}}},
		{EnvironmentKeys: []string{"INVALID-NAME"}},
		{EnvironmentKeys: []string{"PORT", "PORT"}},
		{Resources: Resources{CPUMilli: 1, MemoryBytes: DefaultMemoryBytes}},
	} {
		if _, err := Normalize(spec); !errors.Is(err, ErrInvalid) {
			t.Fatalf("spec %+v error = %v", spec, err)
		}
	}
}

func TestValidateBindingsReturnsOnlyDeclaredValues(t *testing.T) {
	values, err := ValidateBindings(
		Spec{EnvironmentKeys: []string{"DATABASE_URL"}},
		map[string]string{"DATABASE_URL": "mongo", "UNDECLARED": "ignored"},
	)
	if err != nil || len(values) != 1 || values[0] != "DATABASE_URL=mongo" {
		t.Fatalf("values = %v, error = %v", values, err)
	}
}
