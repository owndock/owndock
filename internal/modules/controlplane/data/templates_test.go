package data

import (
	"errors"
	"testing"

	"github.com/owndock/owndock/internal/modules/controlplane/biz"
)

func TestBuiltInTemplateCatalogReturnsDetachedValidatedPresets(t *testing.T) {
	catalog := NewBuiltInTemplateCatalog()
	items, err := catalog.ListTemplates(t.Context())
	if err != nil || len(items) != 2 {
		t.Fatalf("templates = %+v, error = %v", items, err)
	}
	for _, item := range items {
		if _, err := biz.NormalizeTemplate(item); err != nil {
			t.Fatalf("template %q: %v", item.ID, err)
		}
	}
	items[0].Preset.RuntimeSpec.Ports[0].ContainerPort = 9090
	item, err := catalog.GetTemplate(t.Context(), "http-service")
	if err != nil || item.Preset.RuntimeSpec.Ports[0].ContainerPort != 8080 {
		t.Fatalf("detached template = %+v, error = %v", item, err)
	}
	if _, err := catalog.GetTemplate(t.Context(), "missing"); !errors.Is(err, biz.ErrNotFound) {
		t.Fatalf("missing template error = %v", err)
	}
}
