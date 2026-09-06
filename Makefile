.PHONY: fmt fmt-check mod-verify vet test workflow-validate test-integration test-changed-coverage test-runtime-integration test-build-integration test-git-compatibility test-supply-chain-integration test-vulnerability-integration test-vulnerability-db-updater-image test-private-sigstore-integration test-build-security test-terminal-security test-community-deployment test-release-candidate test-agent-package test-agent-release test-agent-systemd test-agent-enrollment-process test-agent-control-process test-agent-rotation-process test-agent-dual-process build build-server build-agent build-build-worker build-build-egress-gateway build-evidence-worker build-vulnerability-db-updater package-agent package-agent-release docker-build-worker docker-build-egress-gateway docker-evidence-worker docker-vulnerability-db-updater api-validate api-breaking check vuln run run-agent run-build-worker run-build-egress-gateway run-evidence-worker run-vulnerability-db-updater

VERSION ?= dev
COMMIT ?= $(shell git rev-parse HEAD 2>/dev/null || echo unknown)
BUILD_TIME ?= $(shell git show -s --format=%cI HEAD 2>/dev/null || date -u +%Y-%m-%dT%H:%M:%SZ)
LDFLAGS := -X main.version=$(VERSION) -X main.commit=$(COMMIT) -X main.buildTime=$(BUILD_TIME)
GOVULNCHECK_VERSION := v1.6.0
OASDIFF_VERSION := v1.25.0
ACTIONLINT_VERSION := v1.7.12
AGENT_GOOS ?= linux
AGENT_GOARCH ?= amd64
ALLOW_DIRTY_RELEASE ?= 0
AGENT_RELEASE_BINARY := bin/owndock-agent-$(AGENT_GOOS)-$(AGENT_GOARCH)
CHANGED_COVERAGE_THRESHOLD ?= 80
CHANGED_COVERAGE_DIRECTORY ?= bin/coverage
CHANGED_COVERAGE_EXCLUSIONS ?= .github/changed-coverage-exclusions.txt

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

workflow-validate:
	go run github.com/rhysd/actionlint/cmd/actionlint@$(ACTIONLINT_VERSION) .github/workflows/*.yml

test-integration:
	OWNDOCK_RUN_MONGO_INTEGRATION=1 go test ./internal/platform/mongo -run TestMongoReplicaSetIntegration -count=1 -timeout=5m

test-changed-coverage:
	@test -n "$(COVERAGE_BASE)" || (echo "COVERAGE_BASE must be an immutable Git commit" && exit 2)
	@mkdir -p $(CHANGED_COVERAGE_DIRECTORY)
	go test -count=1 -covermode=atomic \
		-coverprofile=$(CHANGED_COVERAGE_DIRECTORY)/unit.out ./...
	go test -count=1 -covermode=atomic -coverpkg=./internal/modules/... \
		-coverprofile=$(CHANGED_COVERAGE_DIRECTORY)/http-contract.out \
		./internal/server -run TestHTTPImplementationMatchesOpenAPI
	OWNDOCK_RUN_MONGO_INTEGRATION=1 go test -count=1 -timeout=5m \
		-covermode=atomic -coverpkg=./internal/modules/... \
		-coverprofile=$(CHANGED_COVERAGE_DIRECTORY)/mongo.out \
		./internal/platform/mongo -run TestMongoReplicaSetIntegration
	OWNDOCK_RUN_SUPPLY_CHAIN_INTEGRATION=1 go test -count=1 -timeout=3m \
		-covermode=atomic -coverpkg=./internal/modules/... \
		-coverprofile=$(CHANGED_COVERAGE_DIRECTORY)/supply-chain.out \
		./internal/modules/supplychain/data -run 'Test.*WithRealRegistry'
	go run ./internal/tools/changedcoverage \
		-base "$(COVERAGE_BASE)" \
		-profile $(CHANGED_COVERAGE_DIRECTORY)/unit.out \
		-profile $(CHANGED_COVERAGE_DIRECTORY)/http-contract.out \
		-profile $(CHANGED_COVERAGE_DIRECTORY)/mongo.out \
		-profile $(CHANGED_COVERAGE_DIRECTORY)/supply-chain.out \
		-exclude-file $(CHANGED_COVERAGE_EXCLUSIONS) \
		-threshold $(CHANGED_COVERAGE_THRESHOLD)

test-runtime-integration:
	OWNDOCK_RUN_DOCKER_INTEGRATION=1 go test ./internal/modules/deployment/data -run TestDockerGatewayEngineIntegration -count=1 -timeout=5m
	OWNDOCK_RUN_DOCKER_INTEGRATION=1 go test ./internal/agent/runtime -run TestDockerExecutorIntegration -count=1 -timeout=5m

test-build-integration:
	OWNDOCK_RUN_BUILDKIT_INTEGRATION=1 go test ./internal/modules/build/data \
		-run TestBuildKitRootlessMTLSRegistryIntegration -count=1 -timeout=5m

test-git-compatibility:
	go test ./internal/modules/build/data \
		-run 'TestGit(HTTPSProbeAndCheckoutUseExplicitCAAndProxy|SSHProberUsesPinnedHostAndDeployKeyAgainstRealService|CheckoutRejectsHighlyCompressedRepositoryExpansion|CheckoutRejectsLargeIncompressiblePackBeforeCheckout|CheckoutRejectsDeepAndHighFileCountRepositoriesBeforeMaterialization|TreeInspectionRejectsUntrustedExpansionBeforeCheckout)' \
		-count=1 -timeout=2m

test-supply-chain-integration:
	OWNDOCK_RUN_SUPPLY_CHAIN_INTEGRATION=1 go test ./internal/modules/supplychain/data \
		-run 'Test.*WithRealRegistry' -count=1 -timeout=3m

test-vulnerability-integration:
	OWNDOCK_RUN_VULNERABILITY_INTEGRATION=1 go test ./internal/modules/supplychain/data \
		-run TestTrivyVulnerabilityScanWithPinnedDatabaseAndRegistry -count=1 -timeout=8m

test-vulnerability-db-updater-image:
	$(MAKE) docker-vulnerability-db-updater VERSION=integration
	@test "$$(docker image inspect owndock-vulnerability-db-updater:integration --format '{{.Config.User}}')" = "65532:65532"
	docker run --rm --read-only --cap-drop ALL --security-opt no-new-privileges:true \
		--pids-limit 64 --memory 2g --cpus 1 \
		--tmpfs /tmp:rw,noexec,nosuid,nodev,size=268435456,mode=1777 \
		--volume /var/lib/owndock/trivy-db \
		owndock-vulnerability-db-updater:integration -timeout 8m

test-private-sigstore-integration:
	OWNDOCK_RUN_PRIVATE_SIGSTORE_INTEGRATION=1 go test ./internal/modules/supplychain/data \
		-run TestCosignKeylessVerificationWithPrivateSigstore -count=1 -timeout=5m

test-build-security:
	go test -race ./internal/modules/build/... -count=1
	$(MAKE) test-git-compatibility
	OWNDOCK_RUN_STORAGE_QUOTA_INTEGRATION=1 go test ./internal/modules/build/worker \
		-run TestWorkspaceHardQuotaDockerIntegration -count=1 -timeout=2m
	OWNDOCK_RUN_MONGO_INTEGRATION=1 go test ./internal/platform/mongo \
		-run TestMongoReplicaSetIntegration -count=1 -timeout=5m
	$(MAKE) test-supply-chain-integration
	$(MAKE) test-vulnerability-integration
	$(MAKE) test-vulnerability-db-updater-image
	OWNDOCK_RUN_SERVER_INGRESS_INTEGRATION=1 go test ./cmd/server \
		-run TestServerProcessIngressDoesNotReflectSecrets -count=1 -timeout=3m
	OWNDOCK_RUN_BUILDKIT_INTEGRATION=1 go test ./internal/modules/build/data \
		-run TestBuildKitRootlessMTLSRegistryIntegration -count=1 -timeout=5m

test-terminal-security:
	go test -race ./internal/modules/terminal/... ./internal/shared/terminalprotocol \
		./internal/shared/agentprotocol ./internal/agent/control ./internal/agent/runtime \
		./internal/modules/managedhost/data ./internal/modules/managedhost/service \
		./internal/platform/observability -count=1

# test-release-candidate is the repeatable repository-local gate for an
# immutable release tag. Customer-equivalent remote hosts, browser E2E and
# external KMS/Registry matrices remain explicit system acceptance gates.
test-community-deployment:
	go test ./deploy -count=1
	sh -n deploy/prepare-community-secrets.sh deploy/mongodb/init-replica-set.sh
	@command -v docker >/dev/null 2>&1 || (echo "docker CLI is required to validate the community Compose file" >&2; exit 2)
	@docker compose version >/dev/null 2>&1 || (echo "docker compose is required to validate the community Compose file" >&2; exit 2)
	@OWNDOCK_SERVER_IMAGE=ghcr.io/owndock/owndock@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa \
		OWNDOCK_MONGODB_KEYFILE_PATH=/dev/null \
		OWNDOCK_MONGODB_ROOT_USERNAME_PATH=/dev/null \
		OWNDOCK_MONGODB_ROOT_PASSWORD_PATH=/dev/null \
		OWNDOCK_BOOTSTRAP_TOKEN_PATH=/dev/null \
		OWNDOCK_MONGODB_URI_PATH=/dev/null \
		docker compose -f deploy/community.compose.yaml config --quiet

test-release-candidate: check test-community-deployment
	go test -race ./... -count=1
	$(MAKE) test-integration
	$(MAKE) test-runtime-integration
	$(MAKE) test-agent-package
	$(MAKE) test-agent-release
	$(MAKE) test-agent-control-process
	$(MAKE) test-agent-rotation-process
	$(MAKE) test-agent-dual-process
	$(MAKE) test-terminal-security

test-agent-package:
	go test ./packaging/agent ./internal/tools/agentpackage -count=1
	sh -n packaging/agent/owndock-agentctl
	sh -n packaging/agent/enrollment_process_integration_test.sh
	sh -n packaging/agent/rotation_process_integration_test.sh
	sh -n packaging/agent/dual_control_process_integration_test.sh

test-agent-release:
	go test ./packaging/release ./internal/tools/releasemanifest -count=1
	sh -n packaging/release/verify-agent-release

test-agent-systemd:
	@test "$$(uname -s)" = "Linux" || (echo "test-agent-systemd requires Linux" && exit 2)
	go build -trimpath -o bin/owndock-agent-systemd-fixture ./packaging/agent/testdata/fakeagent
	sudo packaging/agent/systemd_integration_test.sh bin/owndock-agent-systemd-fixture

test-agent-enrollment-process:
	@test "$$(uname -s)" = "Linux" || (echo "test-agent-enrollment-process requires Linux" && exit 2)
	go build -trimpath -ldflags "-X main.version=0.0.0-system -X main.commit=$(COMMIT) -X main.buildTime=$(BUILD_TIME)" \
		-o bin/owndock-agent-enrollment-client ./cmd/agent
	go build -trimpath -o bin/owndock-agent-enrollment-fixture ./internal/tools/agentenrollmentfixture
	sudo packaging/agent/enrollment_process_integration_test.sh \
		bin/owndock-agent-enrollment-client bin/owndock-agent-enrollment-fixture

test-agent-control-process:
	go build -trimpath -ldflags "$(LDFLAGS)" -o bin/owndock-agent-conformance-client ./cmd/agent
	go build -trimpath -o bin/owndock-agent-conformance-server ./internal/tools/agentconformance
	packaging/agent/control_process_integration_test.sh \
		bin/owndock-agent-conformance-client \
		bin/owndock-agent-conformance-server \
		bin/owndock-agent-conformance-server

test-agent-rotation-process:
	go build -trimpath -ldflags "$(LDFLAGS)" -o bin/owndock-agent-rotation-client ./cmd/agent
	go build -trimpath -o bin/owndock-agent-rotation-server ./internal/tools/agentconformance
	packaging/agent/rotation_process_integration_test.sh \
		bin/owndock-agent-rotation-client bin/owndock-agent-rotation-server

test-agent-dual-process:
	go build -trimpath -ldflags "$(LDFLAGS)" -o bin/owndock-agent-dual-client ./cmd/agent
	go build -trimpath -o bin/owndock-agent-dual-server ./internal/tools/agentconformance
	packaging/agent/dual_control_process_integration_test.sh \
		bin/owndock-agent-dual-client bin/owndock-agent-dual-server

build: build-server build-agent build-build-worker build-build-egress-gateway build-evidence-worker build-vulnerability-db-updater

build-server:
	go build -trimpath -ldflags "$(LDFLAGS)" -o bin/owndock ./cmd/server

build-agent:
	go build -trimpath -ldflags "$(LDFLAGS)" -o bin/owndock-agent ./cmd/agent

package-agent:
	@test "$(VERSION)" != "dev" || (echo "VERSION must be an immutable release version" && exit 2)
	@test "$(ALLOW_DIRTY_RELEASE)" = "1" || test -z "$$(git status --porcelain --untracked-files=normal)" || \
		(echo "refusing to package a dirty worktree; commit first or use ALLOW_DIRTY_RELEASE=1 for local validation only" && exit 2)
	@mkdir -p bin dist
	CGO_ENABLED=0 GOOS=$(AGENT_GOOS) GOARCH=$(AGENT_GOARCH) go build \
		-trimpath -ldflags "$(LDFLAGS)" -o $(AGENT_RELEASE_BINARY) ./cmd/agent
	go run ./internal/tools/agentpackage \
		-binary $(AGENT_RELEASE_BINARY) -version $(VERSION) \
		-os $(AGENT_GOOS) -arch $(AGENT_GOARCH) -output dist

package-agent-release:
	@test "$(VERSION)" != "dev" || (echo "VERSION must be an immutable release version" && exit 2)
	$(MAKE) package-agent VERSION=$(VERSION) COMMIT=$(COMMIT) AGENT_GOOS=linux AGENT_GOARCH=amd64
	$(MAKE) package-agent VERSION=$(VERSION) COMMIT=$(COMMIT) AGENT_GOOS=linux AGENT_GOARCH=arm64
	go run ./internal/tools/releasemanifest \
		-version $(VERSION) -commit $(COMMIT) -output dist \
		-verifier packaging/release/verify-agent-release

build-build-worker:
	go build -trimpath -ldflags "$(LDFLAGS)" -o bin/owndock-build-worker ./cmd/build-worker

build-build-egress-gateway:
	go build -trimpath -ldflags "$(LDFLAGS)" -o bin/owndock-build-egress-gateway ./cmd/build-egress-gateway

build-evidence-worker:
	go build -trimpath -ldflags "$(LDFLAGS)" -o bin/owndock-evidence-worker ./cmd/evidence-worker

build-vulnerability-db-updater:
	go build -trimpath -ldflags "$(LDFLAGS)" -o bin/owndock-vulnerability-db-updater ./cmd/vulnerability-db-updater

docker-build-worker:
	docker build --file Dockerfile.build-worker \
		--build-arg VERSION=$(VERSION) --build-arg COMMIT=$(COMMIT) \
		--build-arg BUILD_TIME=$(BUILD_TIME) \
		--tag owndock-build-worker:$(VERSION) .

docker-build-egress-gateway:
	docker build --file Dockerfile.build-egress-gateway \
		--build-arg VERSION=$(VERSION) --build-arg COMMIT=$(COMMIT) \
		--build-arg BUILD_TIME=$(BUILD_TIME) \
		--tag owndock-build-egress-gateway:$(VERSION) .

docker-evidence-worker:
	docker build --file Dockerfile.evidence-worker \
		--build-arg VERSION=$(VERSION) --build-arg COMMIT=$(COMMIT) \
		--build-arg BUILD_TIME=$(BUILD_TIME) \
		--tag owndock-evidence-worker:$(VERSION) .

docker-vulnerability-db-updater:
	docker build --file Dockerfile.vulnerability-db-updater \
		--build-arg VERSION=$(VERSION) --build-arg COMMIT=$(COMMIT) \
		--build-arg BUILD_TIME=$(BUILD_TIME) \
		--tag owndock-vulnerability-db-updater:$(VERSION) .

api-validate:
	go run github.com/oasdiff/oasdiff@$(OASDIFF_VERSION) validate --allow-external-refs=false --fail-on WARN api/openapi.yaml

api-breaking:
	@test -n "$(BASE_SPEC)" || (echo "BASE_SPEC is required, for example main:api/openapi.yaml" && exit 2)
	go run github.com/oasdiff/oasdiff@$(OASDIFF_VERSION) breaking --allow-external-refs=false --fail-on ERR "$(BASE_SPEC)" api/openapi.yaml

check: fmt-check mod-verify vet test workflow-validate api-validate build

vuln:
	go run golang.org/x/vuln/cmd/govulncheck@$(GOVULNCHECK_VERSION) ./...

run:
	go run ./cmd/server -conf configs/config.yaml

run-agent:
	go run ./cmd/agent -conf configs/agent.yaml

run-build-worker:
	go run ./cmd/build-worker -conf configs/config.yaml

run-build-egress-gateway:
	go run ./cmd/build-egress-gateway -conf configs/config.yaml

run-evidence-worker:
	go run ./cmd/evidence-worker -conf configs/config.yaml

run-vulnerability-db-updater:
	go run ./cmd/vulnerability-db-updater
