package application

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/owndock/owndock/internal/modules/application/data"
)

func TestCreateAndList(t *testing.T) {
	service := NewService(data.NewMemoryRepository())
	create := httptest.NewRecorder()
	service.Create(create, httptest.NewRequest(http.MethodPost, "/api/applications", strings.NewReader(`{"name":"demo"}`)))
	if create.Code != http.StatusCreated {
		t.Fatalf("create status = %d", create.Code)
	}
	var item map[string]any
	if err := json.NewDecoder(create.Body).Decode(&item); err != nil || item["name"] != "demo" {
		t.Fatalf("create response = %v, err = %v", item, err)
	}

	list := httptest.NewRecorder()
	service.List(list, httptest.NewRequest(http.MethodGet, "/api/applications", nil))
	if list.Code != http.StatusOK || !strings.Contains(list.Body.String(), "demo") {
		t.Fatalf("list response = %d %s", list.Code, list.Body.String())
	}
}
