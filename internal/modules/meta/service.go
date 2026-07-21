package meta

import (
	"encoding/json"
	"net/http"
	"runtime"
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
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method_not_allowed"})
		return
	}
	writeJSON(w, http.StatusOK, versionResponse{
		Service:   s.info.Service,
		Version:   s.info.Version,
		Commit:    s.info.Commit,
		BuildTime: s.info.BuildTime,
		GoVersion: runtime.Version(),
	})
}

func writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}
