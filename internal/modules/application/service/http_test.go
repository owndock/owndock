package service

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/owndock/owndock/internal/modules/application/biz"
	"github.com/owndock/owndock/internal/modules/application/data"
)

func newTestHTTP() *HTTP {
	return NewHTTP(biz.NewUseCase(
		data.NewMemoryRepository(),
		func() (string, error) { return "app-1", nil },
		func() time.Time { return time.Unix(0, 0) },
	))
}

func TestCreateAndList(t *testing.T) {
	service := newTestHTTP()
	create := httptest.NewRecorder()
	service.Create(create, httptest.NewRequest(http.MethodPost, "/api/v1/applications", strings.NewReader(`{"name":"demo"}`)))
	if create.Code != http.StatusCreated {
		t.Fatalf("create status = %d", create.Code)
	}
	var item map[string]any
	if err := json.NewDecoder(create.Body).Decode(&item); err != nil || item["name"] != "demo" {
		t.Fatalf("create response = %v, err = %v", item, err)
	}

	list := httptest.NewRecorder()
	service.List(list, httptest.NewRequest(http.MethodGet, "/api/v1/applications", nil))
	if list.Code != http.StatusOK || !strings.Contains(list.Body.String(), "demo") {
		t.Fatalf("list response = %d %s", list.Code, list.Body.String())
	}
}

func TestCreateDuplicateName(t *testing.T) {
	service := newTestHTTP()
	request := func(name string) *httptest.ResponseRecorder {
		recorder := httptest.NewRecorder()
		service.Create(recorder, httptest.NewRequest(http.MethodPost, "/api/v1/applications", strings.NewReader(`{"name":"`+name+`"}`)))
		return recorder
	}
	if request("demo").Code != http.StatusCreated {
		t.Fatal("first create should succeed")
	}
	if request("DEMO").Code != http.StatusConflict {
		t.Fatal("duplicate name should return conflict")
	}
}
