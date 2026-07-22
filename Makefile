.PHONY: fmt fmt-check mod-verify vet test build check run

VERSION ?= dev
COMMIT ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo unknown)
BUILD_TIME ?= $(shell date -u +%Y-%m-%dT%H:%M:%SZ)
LDFLAGS := -X main.version=$(VERSION) -X main.commit=$(COMMIT) -X main.buildTime=$(BUILD_TIME)

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

build:
	go build -trimpath -ldflags "$(LDFLAGS)" -o bin/owndock ./cmd/server

check: fmt-check mod-verify vet test build

run:
	go run ./cmd/server -conf configs/config.yaml
