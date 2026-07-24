package server

import (
	"fmt"
	"net/http"

	"github.com/go-kratos/kratos/v2/log"
	kratoshttp "github.com/go-kratos/kratos/v2/transport/http"

	applicationservice "github.com/owndock/owndock/internal/modules/application/service"
	deploymentservice "github.com/owndock/owndock/internal/modules/deployment/service"
	environmentservice "github.com/owndock/owndock/internal/modules/environment/service"
	"github.com/owndock/owndock/internal/modules/meta"
	platformconfig "github.com/owndock/owndock/internal/platform/config"
	"github.com/owndock/owndock/internal/platform/health"
	"github.com/owndock/owndock/internal/platform/httpx"
	"github.com/owndock/owndock/internal/platform/id"
	"github.com/owndock/owndock/internal/platform/observability"
)

const apiV1 = "/api/v1"

// EngineeringSamples groups replaceable technical examples that are not
// accepted product modules. A nil value keeps every sample route unregistered.
type EngineeringSamples struct {
	Application *applicationservice.HTTP
	Environment *environmentservice.HTTP
	Deployment  *deploymentservice.HTTP
}

func NewHTTPServer(
	cfg platformconfig.HTTP,
	healthChecker *health.Checker,
	metaService *meta.Service,
	samples *EngineeringSamples,
	metrics *observability.Metrics,
	tracing *observability.Tracing,
	logger log.Logger,
) (*kratoshttp.Server, error) {
	timeout, err := cfg.TimeoutDuration()
	if err != nil {
		return nil, err
	}

	srv := kratoshttp.NewServer(
		kratoshttp.Address(cfg.Address),
		kratoshttp.Timeout(timeout),
		kratoshttp.Filter(
			httpx.RequestID(id.New),
			tracing.Instrument,
			httpx.AccessLog(logger),
			httpx.Recovery(logger),
			metrics.Instrument,
		),
		kratoshttp.NotFoundHandler(errorHandler(http.StatusNotFound, "not_found")),
		kratoshttp.MethodNotAllowedHandler(errorHandler(http.StatusMethodNotAllowed, "method_not_allowed")),
	)

	srv.HandleFunc("/livez", healthChecker.Live)
	srv.HandleFunc("/readyz", healthChecker.Ready)
	srv.Handle("/metrics", metrics.Handler())
	srv.HandleFunc(apiV1+"/meta/version", metaService.Version)
	if samples != nil {
		if samples.Application == nil || samples.Environment == nil || samples.Deployment == nil {
			return nil, fmt.Errorf("engineering sample services must be provided together")
		}
		srv.HandleFunc(apiV1+"/applications", samples.Application.Handle)
		srv.HandleFunc(apiV1+"/environments", samples.Environment.Handle)
		srv.HandleFunc(apiV1+"/deployments", samples.Deployment.Handle)
	}
	return srv, nil
}

func errorHandler(status int, code string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		httpx.ErrorRequest(w, r, status, code)
	})
}
