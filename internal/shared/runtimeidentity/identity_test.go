package runtimeidentity

import "testing"

func TestContainerNameIsStableAndSeparatesFields(t *testing.T) {
	first, err := ContainerName("project-1", "application-1", "environment-1", "target-1")
	if err != nil {
		t.Fatal(err)
	}
	second, err := ContainerName("project-1", "application-1", "environment-1", "target-1")
	if err != nil {
		t.Fatal(err)
	}
	if first != second || len(first) != len("owndock-")+24 {
		t.Fatalf("container names = %q, %q", first, second)
	}
	ambiguousLeft, _ := ContainerName("project-1", "ab", "c", "target-1")
	ambiguousRight, _ := ContainerName("project-1", "a", "bc", "target-1")
	if ambiguousLeft == ambiguousRight {
		t.Fatalf("field boundaries produced the same name %q", ambiguousLeft)
	}
}

func TestContainerNameRejectsInvalidSlot(t *testing.T) {
	for _, value := range []string{"", " project-1", "project-1\x00hidden"} {
		if _, err := ContainerName(value, "application-1", "environment-1", "target-1"); err == nil {
			t.Fatalf("ContainerName(%q) succeeded", value)
		}
	}
}
