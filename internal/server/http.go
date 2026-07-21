package server

import (
	"encoding/json"
	"net/http"

	"github.com/go-kratos/kratos/v2/log"
	"github.com/go-kratos/kratos/v2/middleware/logging"
	"github.com/go-kratos/kratos/v2/middleware/recovery"
	kratoshttp "github.com/go-kratos/kratos/v2/transport/http"

	"github.com/owndock/owndock/internal/modules/meta"
	platformconfig "github.com/owndock/owndock/internal/platform/config"
	"github.com/owndock/owndock/internal/platform/health"
)

func NewHTTPServer(
	cfg platformconfig.HTTP,
	healthChecker *health.Checker,
	metaService *meta.Service,
	logger log.Logger,
) (*kratoshttp.Server, error) {
	timeout, err := cfg.TimeoutDuration()
	if err != nil {
		return nil, err
	}

	srv := kratoshttp.NewServer(
		kratoshttp.Address(cfg.Address),
		kratoshttp.Timeout(timeout),
		kratoshttp.Middleware(
			recovery.Recovery(),
			logging.Server(logger),
		),
		kratoshttp.NotFoundHandler(errorHandler(http.StatusNotFound, "not_found")),
		kratoshttp.MethodNotAllowedHandler(errorHandler(http.StatusMethodNotAllowed, "method_not_allowed")),
	)

	srv.HandleFunc("/livez", healthChecker.Live)
	srv.HandleFunc("/readyz", healthChecker.Ready)
	srv.HandleFunc("/api/meta/version", metaService.Version)
	return srv, nil
}

func errorHandler(status int, code string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		w.WriteHeader(status)
		_ = json.NewEncoder(w).Encode(map[string]string{"error": code})
	})
}
