package server

import (
	"fmt"
	"net/http"
	"strings"

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

type ProductAPI struct {
	identity             http.Handler
	agentEnrollment      http.Handler
	protected            http.Handler
	protectedDeployment  http.Handler
	protectedManagedHost http.Handler
}

func NewProductAPIWithDeploymentAndManagedHost(
	identity http.Handler,
	controlPlane http.Handler,
	deployment http.Handler,
	managedHost http.Handler,
	authenticate func(http.Handler) http.Handler,
) (*ProductAPI, error) {
	api, err := NewProductAPIWithDeployment(
		identity, controlPlane, deployment, authenticate,
	)
	if err != nil {
		return nil, err
	}
	if managedHost == nil {
		return nil, fmt.Errorf("product managed host API is required")
	}
	api.agentEnrollment = managedHost
	api.protectedManagedHost = authenticate(managedHost)
	return api, nil
}

func NewProductAPI(identity http.Handler, controlPlane http.Handler, authenticate func(http.Handler) http.Handler) (*ProductAPI, error) {
	if identity == nil || controlPlane == nil || authenticate == nil {
		return nil, fmt.Errorf("product API requires identity, control plane, and authentication middleware")
	}
	return &ProductAPI{identity: identity, protected: authenticate(controlPlane)}, nil
}

func NewProductAPIWithDeployment(
	identity http.Handler,
	controlPlane http.Handler,
	deployment http.Handler,
	authenticate func(http.Handler) http.Handler,
) (*ProductAPI, error) {
	api, err := NewProductAPI(identity, controlPlane, authenticate)
	if err != nil {
		return nil, err
	}
	if deployment == nil {
		return nil, fmt.Errorf("product deployment API is required")
	}
	api.protectedDeployment = authenticate(deployment)
	return api, nil
}

func (p *ProductAPI) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	switch {
	case strings.HasPrefix(r.URL.Path, apiV1+"/auth/"):
		p.identity.ServeHTTP(w, r)
	case p.agentEnrollment != nil &&
		r.URL.Path == apiV1+"/agent/enrollments:exchange":
		p.agentEnrollment.ServeHTTP(w, r)
	case p.protectedDeployment != nil && isProjectDeploymentPath(r.URL.Path):
		p.protectedDeployment.ServeHTTP(w, r)
	case p.protectedManagedHost != nil &&
		(r.URL.Path == apiV1+"/managed-hosts" ||
			strings.HasPrefix(r.URL.Path, apiV1+"/managed-hosts/")):
		p.protectedManagedHost.ServeHTTP(w, r)
	case r.URL.Path == apiV1+"/projects",
		r.URL.Path == apiV1+"/audit-events",
		strings.HasPrefix(r.URL.Path, apiV1+"/projects/"):
		p.protected.ServeHTTP(w, r)
	default:
		httpx.ErrorRequest(w, r, http.StatusNotFound, "not_found")
	}
}

func isProjectDeploymentPath(path string) bool {
	segments := strings.Split(strings.Trim(path, "/"), "/")
	return len(segments) >= 5 && segments[0] == "api" && segments[1] == "v1" &&
		segments[2] == "projects" && segments[3] != "" && segments[4] == "deployments"
}

func NewHTTPServer(
	cfg platformconfig.HTTP,
	healthChecker *health.Checker,
	metaService *meta.Service,
	samples *EngineeringSamples,
	productAPI *ProductAPI,
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
	if productAPI != nil {
		srv.HandlePrefix(apiV1+"/auth/", productAPI)
		srv.Handle(apiV1+"/agent/enrollments:exchange", productAPI)
		srv.Handle(apiV1+"/projects", productAPI)
		srv.HandlePrefix(apiV1+"/projects/", productAPI)
		srv.Handle(apiV1+"/audit-events", productAPI)
		srv.Handle(apiV1+"/managed-hosts", productAPI)
		srv.HandlePrefix(apiV1+"/managed-hosts/", productAPI)
	}
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
