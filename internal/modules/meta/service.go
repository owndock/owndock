package meta

import (
	"net/http"
	"runtime"

	"github.com/owndock/owndock/internal/platform/httpx"
)

type BuildInfo struct {
	Service   string
	Version   string
	Commit    string
	BuildTime string
}

type Service struct {
	info BuildInfo
}

type versionResponse struct {
	Service   string `json:"service"`
	Version   string `json:"version"`
	Commit    string `json:"commit"`
	BuildTime string `json:"build_time"`
	GoVersion string `json:"go_version"`
}

func NewService(info BuildInfo) *Service {
	return &Service{info: info}
}

func (s *Service) Version(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		httpx.ErrorRequest(w, r, http.StatusMethodNotAllowed, "method_not_allowed")
		return
	}
	httpx.JSON(w, http.StatusOK, versionResponse{
		Service:   s.info.Service,
		Version:   s.info.Version,
		Commit:    s.info.Commit,
		BuildTime: s.info.BuildTime,
		GoVersion: runtime.Version(),
	})
}
