package service

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/owndock/owndock/internal/modules/environment/biz"
	"github.com/owndock/owndock/internal/modules/environment/data"
)

func TestCreateAndList(t *testing.T) {
	service := NewHTTP(biz.NewUseCase(
		data.NewMemoryRepository(),
		func() (string, error) { return "env-1", nil },
		func() time.Time { return time.Unix(0, 0) },
	))
	recorder := httptest.NewRecorder()
	service.Handle(recorder, httptest.NewRequest(http.MethodPost, "/api/v1/environments", strings.NewReader(`{"name":"local","provider":"docker"}`)))
	if recorder.Code != http.StatusCreated || !strings.Contains(recorder.Body.String(), `"status":"active"`) {
		t.Fatalf("create response = %d %s", recorder.Code, recorder.Body.String())
	}

	list := httptest.NewRecorder()
	service.Handle(list, httptest.NewRequest(http.MethodGet, "/api/v1/environments", nil))
	if list.Code != http.StatusOK || !strings.Contains(list.Body.String(), "local") {
		t.Fatalf("list response = %d %s", list.Code, list.Body.String())
	}
}
