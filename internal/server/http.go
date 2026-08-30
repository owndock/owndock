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
	"github.com/owndock/owndock/internal/platform/localization"
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
	protectedInventory   http.Handler
	protectedBuild       http.Handler
	protectedSupplyChain http.Handler
	protectedTerminal    http.Handler
	terminal             http.Handler
	build                http.Handler
	ingress              http.Handler
}

func (p *ProductAPI) WithSupplyChain(
	supplyChainAPI http.Handler,
	authenticate func(http.Handler) http.Handler,
) error {
	if supplyChainAPI == nil || authenticate == nil {
		return fmt.Errorf("product supply-chain API is required")
	}
	p.protectedSupplyChain = authenticate(supplyChainAPI)
	return nil
}

func (p *ProductAPI) WithTerminal(
	terminalAPI http.Handler,
	authenticate func(http.Handler) http.Handler,
) error {
	if terminalAPI == nil || authenticate == nil {
		return fmt.Errorf("product terminal API is required")
	}
	p.protectedTerminal = authenticate(terminalAPI)
	p.terminal = terminalAPI
	return nil
}

func (p *ProductAPI) WithIngressProtection(protect func(http.Handler) http.Handler) error {
	if protect == nil {
		return fmt.Errorf("product ingress protection is required")
	}
	p.ingress = protect(http.HandlerFunc(p.route))
	if p.ingress == nil {
		return fmt.Errorf("product ingress protection returned no handler")
	}
	return nil
}

func (p *ProductAPI) WithBuild(
	buildAPI http.Handler,
	authenticate func(http.Handler) http.Handler,
) error {
	if buildAPI == nil || authenticate == nil {
		return fmt.Errorf("product build API is required")
	}
	p.protectedBuild = authenticate(buildAPI)
	p.build = buildAPI
	return nil
}

func (p *ProductAPI) WithRuntimeInventory(
	inventory http.Handler,
	authenticate func(http.Handler) http.Handler,
) error {
	if inventory == nil || authenticate == nil {
		return fmt.Errorf("product runtime inventory API is required")
	}
	p.protectedInventory = authenticate(inventory)
	return nil
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
	if p.ingress != nil {
		p.ingress.ServeHTTP(w, r)
		return
	}
	p.route(w, r)
}

func (p *ProductAPI) route(w http.ResponseWriter, r *http.Request) {
	switch {
	case p.build != nil && isExternalBuildHookPath(r.URL.Path):
		p.build.ServeHTTP(w, r)
	case p.build != nil && isExternalBuildTriggerPath(r.URL.Path):
		p.build.ServeHTTP(w, r)
	case strings.HasPrefix(r.URL.Path, apiV1+"/auth/"):
		p.identity.ServeHTTP(w, r)
	case p.agentEnrollment != nil &&
		r.URL.Path == apiV1+"/agent/enrollments:exchange":
		p.agentEnrollment.ServeHTTP(w, r)
	case p.protectedInventory != nil && isRuntimeInventoryPath(r.URL.Path):
		p.protectedInventory.ServeHTTP(w, r)
	case p.terminal != nil && isTerminalConnectPath(r.URL.Path):
		p.terminal.ServeHTTP(w, r)
	case p.protectedTerminal != nil && isTerminalPath(r.URL.Path):
		p.protectedTerminal.ServeHTTP(w, r)
	case p.protectedSupplyChain != nil && isSupplyChainPath(r.URL.Path):
		p.protectedSupplyChain.ServeHTTP(w, r)
	case p.protectedBuild != nil && isProjectBuildPath(r.URL.Path):
		p.protectedBuild.ServeHTTP(w, r)
	case p.protectedDeployment != nil && isProjectDeploymentPath(r.URL.Path):
		p.protectedDeployment.ServeHTTP(w, r)
	case p.protectedManagedHost != nil &&
		(r.URL.Path == apiV1+"/managed-hosts" ||
			strings.HasPrefix(r.URL.Path, apiV1+"/managed-hosts/")):
		p.protectedManagedHost.ServeHTTP(w, r)
	case r.URL.Path == apiV1+"/projects",
		r.URL.Path == apiV1+"/audit-events",
		r.URL.Path == apiV1+"/templates",
		strings.HasPrefix(r.URL.Path, apiV1+"/templates/"),
		strings.HasPrefix(r.URL.Path, apiV1+"/projects/"):
		p.protected.ServeHTTP(w, r)
	default:
		httpx.ErrorRequest(w, r, http.StatusNotFound, "not_found")
	}
}

func isTerminalPath(path string) bool {
	segments := strings.Split(strings.Trim(path, "/"), "/")
	if len(segments) == 3 && segments[0] == "api" && segments[1] == "v1" &&
		segments[2] == "terminal-policy" {
		return true
	}
	if len(segments) == 4 && segments[0] == "api" && segments[1] == "v1" &&
		segments[2] == "terminal-sessions" && segments[3] != "" {
		return true
	}
	if len(segments) == 5 && segments[0] == "api" && segments[1] == "v1" &&
		segments[2] == "projects" && segments[3] != "" && segments[4] == "terminal-policy" {
		return true
	}
	if len(segments) == 6 && segments[0] == "api" && segments[1] == "v1" &&
		segments[2] == "projects" && segments[3] != "" &&
		segments[4] == "terminal-sessions" && segments[5] == "container" {
		return true
	}
	return len(segments) == 5 && segments[0] == "api" && segments[1] == "v1" &&
		segments[2] == "managed-hosts" && segments[3] != "" && segments[4] == "terminal-sessions"
}

func isTerminalConnectPath(path string) bool {
	segments := strings.Split(strings.Trim(path, "/"), "/")
	return len(segments) == 4 && segments[0] == "api" && segments[1] == "v1" &&
		segments[2] == "terminal-sessions" &&
		strings.HasSuffix(segments[3], ":connect") &&
		strings.TrimSuffix(segments[3], ":connect") != ""
}

func isExternalBuildHookPath(path string) bool {
	segments := strings.Split(strings.Trim(path, "/"), "/")
	return len(segments) == 5 && segments[0] == "api" && segments[1] == "v1" &&
		segments[2] == "build-hooks" && segments[3] != "" && segments[4] != ""
}

func isExternalBuildTriggerPath(path string) bool {
	segments := strings.Split(strings.Trim(path, "/"), "/")
	return len(segments) == 4 && segments[0] == "api" && segments[1] == "v1" &&
		segments[2] == "build-triggers" && segments[3] != ""
}

func isRuntimeInventoryPath(path string) bool {
	segments := strings.Split(strings.Trim(path, "/"), "/")
	return len(segments) == 5 && segments[0] == "api" && segments[1] == "v1" &&
		(segments[2] == "projects" || segments[2] == "managed-hosts") &&
		segments[3] != "" && segments[4] == "runtime-inventory"
}

func isProjectDeploymentPath(path string) bool {
	segments := strings.Split(strings.Trim(path, "/"), "/")
	return len(segments) >= 5 && segments[0] == "api" && segments[1] == "v1" &&
		segments[2] == "projects" && segments[3] != "" && segments[4] == "deployments"
}

func isProjectBuildPath(path string) bool {
	segments := strings.Split(strings.Trim(path, "/"), "/")
	if len(segments) < 5 || segments[0] != "api" || segments[1] != "v1" ||
		segments[2] != "projects" || segments[3] == "" {
		return false
	}
	if segments[4] == "repository-credentials" || segments[4] == "source-repositories" ||
		segments[4] == "builds" || segments[4] == "artifacts" {
		return true
	}
	return len(segments) >= 7 && segments[4] == "applications" && segments[5] != "" &&
		segments[6] == "build-configurations"
}

func isSupplyChainPath(path string) bool {
	segments := strings.Split(strings.Trim(path, "/"), "/")
	if (len(segments) == 5 || len(segments) == 6) && segments[0] == "api" &&
		segments[1] == "v1" && segments[2] == "projects" && segments[3] != "" &&
		segments[4] == "deployment-policies" {
		return len(segments) == 5 || segments[5] != ""
	}
	if (len(segments) == 5 || len(segments) == 6) && segments[0] == "api" &&
		segments[1] == "v1" && segments[2] == "projects" && segments[3] != "" &&
		segments[4] == "vulnerability-waivers" {
		return len(segments) == 5 || segments[5] != ""
	}
	if (len(segments) == 5 || len(segments) == 6) && segments[0] == "api" &&
		segments[1] == "v1" && segments[2] == "projects" && segments[3] != "" &&
		segments[4] == "signature-trust-policies" {
		return len(segments) == 5 || segments[5] != ""
	}
	if (len(segments) == 5 || len(segments) == 6) && segments[0] == "api" &&
		segments[1] == "v1" && segments[2] == "projects" && segments[3] != "" &&
		segments[4] == "signature-signing-profiles" {
		return len(segments) == 5 || segments[5] != ""
	}
	return (len(segments) == 7 || len(segments) == 8) &&
		segments[0] == "api" && segments[1] == "v1" && segments[2] == "projects" &&
		segments[3] != "" && segments[4] == "artifacts" && segments[5] != "" &&
		(segments[6] == "evidence" || segments[6] == "verifications" || segments[6] == "signature-verifications" ||
			segments[6] == "vulnerability-observation" || segments[6] == "vulnerability-scans") &&
		(len(segments) == 7 || segments[6] == "evidence" && segments[7] != "")
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
			httpx.BrowserHeaders(),
			localization.HTTP(),
			httpx.RequestID(id.New),
			httpx.BrowserCORS(cfg.CORSAllowedOrigins),
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
		srv.Handle(apiV1+"/templates", productAPI)
		srv.HandlePrefix(apiV1+"/templates/", productAPI)
		srv.HandlePrefix(apiV1+"/build-triggers/", productAPI)
		srv.HandlePrefix(apiV1+"/build-hooks/", productAPI)
		srv.Handle(apiV1+"/managed-hosts", productAPI)
		srv.HandlePrefix(apiV1+"/managed-hosts/", productAPI)
		srv.Handle(apiV1+"/terminal-policy", productAPI)
		srv.HandlePrefix(apiV1+"/terminal-sessions/", productAPI)
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
