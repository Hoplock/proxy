# SecureCommandProxy — developer entry points.
# See docs/PROTOCOL.md before contributing.

GO ?= go
GOLANGCI_LINT ?= golangci-lint
PYTHON ?= python3
BIN_DIR := bin
CONFIG ?= config.yaml
LISTEN ?= 127.0.0.1:8080
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
LDFLAGS := -X main.version=$(VERSION)

.PHONY: all build test vet lint fmt license-check openapi-check tidy run-bastion run-mock clean

all: build vet test lint

## build: compile all binaries into $(BIN_DIR)
build:
	$(GO) build -ldflags "$(LDFLAGS)" -o $(BIN_DIR)/bastion ./cmd/bastion
	$(GO) build -ldflags "$(LDFLAGS)" -o $(BIN_DIR)/mock-management ./cmd/mock-management
	$(GO) build ./...

## test: run all unit tests with the race detector
test:
	$(GO) test -race ./...

## vet: run go vet
vet:
	$(GO) vet ./...

## lint: run golangci-lint
lint:
	$(GOLANGCI_LINT) run

## fmt: apply formatting via golangci-lint formatters
fmt:
	$(GOLANGCI_LINT) fmt

## license-check: verify every tracked .go file carries the license header
license-check:
	@missing=""; \
	for f in $$(git ls-files --cached --others --exclude-standard '*.go'); do \
		head -n 2 "$$f" | grep -q 'SPDX-License-Identifier: LicenseRef-Proprietary' || missing="$$missing $$f"; \
	done; \
	if [ -n "$$missing" ]; then \
		echo "missing license header (see docs/LICENSE-HEADER.md):"; \
		for f in $$missing; do echo "  $$f"; done; \
		exit 1; \
	fi; \
	echo "license headers OK"

## openapi-check: validate the management API contract as an OpenAPI 3 document
## (needs `pip install openapi-spec-validator`; CI installs it)
openapi-check:
	$(PYTHON) -c 'from openapi_spec_validator import validate; \
	from openapi_spec_validator.readers import read_from_filename; \
	spec, _ = read_from_filename("api/management.yaml"); \
	validate(spec); \
	print("api/management.yaml is a valid OpenAPI 3 document")'

## tidy: tidy and verify go.mod/go.sum
tidy:
	$(GO) mod tidy

## run-bastion: run the bastion daemon (CONFIG=path to override)
run-bastion:
	$(GO) run ./cmd/bastion -config $(CONFIG)

## run-mock: run the mock management server (LISTEN=host:port to override)
run-mock:
	$(GO) run ./cmd/mock-management -listen $(LISTEN)

## clean: remove build output
clean:
	rm -rf $(BIN_DIR)
