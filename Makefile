.PHONY: fmt fmt-check mod-verify vet test test-integration test-runtime-integration build api-validate api-breaking check vuln run

VERSION ?= dev
COMMIT ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo unknown)
BUILD_TIME ?= $(shell date -u +%Y-%m-%dT%H:%M:%SZ)
LDFLAGS := -X main.version=$(VERSION) -X main.commit=$(COMMIT) -X main.buildTime=$(BUILD_TIME)
GOVULNCHECK_VERSION := v1.6.0
OASDIFF_VERSION := v1.25.0

fmt:
	gofmt -w $$(find . -name '*.go' -not -path './vendor/*')

fmt-check:
	@test -z "$$(gofmt -l $$(find . -name '*.go' -not -path './vendor/*'))"

mod-verify:
	go mod verify

vet:
	go vet ./...

test:
	go test ./...

test-integration:
	OWNDOCK_RUN_MONGO_INTEGRATION=1 go test ./internal/platform/mongo -run TestMongoReplicaSetIntegration -count=1 -timeout=5m

test-runtime-integration:
	OWNDOCK_RUN_DOCKER_INTEGRATION=1 go test ./internal/modules/deployment/data -run TestDockerGatewayEngineIntegration -count=1 -timeout=5m

build:
	go build -trimpath -ldflags "$(LDFLAGS)" -o bin/owndock ./cmd/server

api-validate:
	go run github.com/oasdiff/oasdiff@$(OASDIFF_VERSION) validate --allow-external-refs=false --fail-on WARN api/openapi.yaml

api-breaking:
	@test -n "$(BASE_SPEC)" || (echo "BASE_SPEC is required, for example main:api/openapi.yaml" && exit 2)
	go run github.com/oasdiff/oasdiff@$(OASDIFF_VERSION) breaking --allow-external-refs=false --fail-on ERR "$(BASE_SPEC)" api/openapi.yaml

check: fmt-check mod-verify vet test api-validate build

vuln:
	go run golang.org/x/vuln/cmd/govulncheck@$(GOVULNCHECK_VERSION) ./...

run:
	go run ./cmd/server -conf configs/config.yaml
