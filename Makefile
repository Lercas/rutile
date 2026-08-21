.PHONY: help build install test test-linux lint security smoke release-check clean

BINARY  := rutile
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo 1.0.0)
LDFLAGS := -ldflags "-X main.version=$(VERSION)"

help: ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*?## "}; {printf "  %-14s %s\n", $$1, $$2}'

build: ## Build the rutile binary
	go build $(LDFLAGS) -o $(BINARY) ./cmd/rutile

install: ## Install to GOPATH/bin
	go install $(LDFLAGS) ./cmd/rutile

test: ## Run unit + integration tests
	go test -race ./...

test-linux: ## Run the full test suite on Linux via Docker
	docker run --rm -v "$(PWD)":/src -v rutile-gomod:/go/pkg/mod -w /src \
		golang:1.25 go test -race ./...

lint: ## Run golangci-lint (if installed) or go vet
	@command -v golangci-lint >/dev/null && golangci-lint run ./... || go vet ./...

security: ## Run static security and reachable-vulnerability scans
	go run github.com/securego/gosec/v2/cmd/gosec@v2.28.0 -quiet -exclude=G104,G204,G304,G702,G703 ./...
	go run golang.org/x/vuln/cmd/govulncheck@v1.7.0 ./...

smoke: ## Run the end-to-end smoke test in a sandbox
	bash scripts/smoke.sh

release-check: lint security test smoke test-linux ## Everything that must be green for a release
	@echo "release-check passed for $(VERSION)"

clean: ## Remove build artifacts
	rm -f $(BINARY)
