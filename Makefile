BINARY := ktls
BUILD_DIR := bin
COVERAGE_FILE := coverage.out
COVERAGE_HTML := coverage.html

.DEFAULT_GOAL := help

.PHONY: help build test test-integration cover lint lint-fix fmt vet tidy update bench clean tools

help: ## Show this help.
	@grep -E '^[a-zA-Z0-9_.-]+:.*?## .*$$' $(MAKEFILE_LIST) | \
		awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-22s\033[0m %s\n", $$1, $$2}'

build: ## Compile the library and any commands.
	@mkdir -p $(BUILD_DIR)
	go build ./...

test: ## Run unit tests with race detection, shuffle, timeout, and coverage.
	go clean -testcache && \
    CGO_ENABLED=1 go test -race -shuffle=on -timeout=2m -covermode=atomic -coverprofile=$(COVERAGE_FILE) ./...

test-integration: ## Run integration tests selected by the integration build tag.
	go clean -testcache && \
	CGO_ENABLED=1 go test -race -shuffle=on -timeout=5m -tags=integration ./...

cover: test ## Render the unit-test coverage report as HTML.
	go tool cover -html=$(COVERAGE_FILE) -o $(COVERAGE_HTML)
	@printf 'Coverage report written to %s\n' $(COVERAGE_HTML)

lint: ## Run the required static-analysis suite.
	golangci-lint run ./...

lint-fix: ## Apply safe formatter and linter fixes, then report remaining findings.
	golangci-lint run --fix ./...

tidy: ## Normalize module metadata and verify every dependency.
	go mod tidy
	go mod verify

update: ## Upgrade all dependencies to their latest minor/patch versions.
	go get -u ./...
	go mod tidy
	go mod verify

bench: ## Run all benchmarks with memory allocation statistics.
	go clean -testcache
	CGO_ENABLED=0 go test -run='^$$' -bench=. -benchmem ./...

clean: ## Remove locally generated build and coverage artifacts.
	rm -rf $(BUILD_DIR) $(COVERAGE_FILE) $(COVERAGE_HTML)
