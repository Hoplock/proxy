# Hoplock Proxy — developer entry points.
# See docs/PROTOCOL.md before contributing.

GO ?= go
GOLANGCI_LINT ?= golangci-lint
PYTHON ?= python3
BIN_DIR := bin
CONFIG ?= config.yaml
LISTEN ?= 127.0.0.1:8080
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
LDFLAGS := -X main.version=$(VERSION)

SSHD_DIR := deploy/sshd
SSHD_PORT ?= 2022

.PHONY: all build test test-sshd vet lint fmt license-check openapi-check tidy run-proxy run-mock clean

all: build vet test lint

## build: compile all binaries into $(BIN_DIR)
build:
	$(GO) build -ldflags "$(LDFLAGS)" -o $(BIN_DIR)/hoplock-proxy ./cmd/proxy
	$(GO) build -ldflags "$(LDFLAGS)" -o $(BIN_DIR)/mock-control ./cmd/mock-control
	$(GO) build ./...

## test: run all unit tests with the race detector
test:
	$(GO) test -race ./...

## test-sshd: run the target-credential tests against a real sshd in a container
## (needs docker; phase 0012 folds this into the e2e topology and CI)
test-sshd:
	@set -e; \
	rm -rf $(SSHD_DIR)/keys; mkdir -p $(SSHD_DIR)/keys; \
	ssh-keygen -q -t ed25519 -N "" -C hoplock-management -f $(SSHD_DIR)/keys/management_key; \
	ssh-keygen -q -t ed25519 -N "" -C hoplock-brokered -f $(SSHD_DIR)/keys/brokered_key; \
	HOPLOCK_SSHD_PORT=$(SSHD_PORT) docker compose -f $(SSHD_DIR)/compose.yaml up -d --build; \
	trap 'HOPLOCK_SSHD_PORT=$(SSHD_PORT) docker compose -f $(SSHD_DIR)/compose.yaml down -v >/dev/null 2>&1; rm -rf $(SSHD_DIR)/keys' EXIT; \
	for i in $$(seq 1 60); do \
		if ssh-keyscan -p $(SSHD_PORT) 127.0.0.1 2>/dev/null | grep -q ssh; then break; fi; \
		sleep 1; \
	done; \
	HOPLOCK_TEST_SSHD_ADDR=127.0.0.1:$(SSHD_PORT) \
	HOPLOCK_TEST_SSHD_MANAGEMENT_KEY=$(SSHD_DIR)/keys/management_key \
	HOPLOCK_TEST_SSHD_PROVISIONING_USER=root \
	HOPLOCK_TEST_SSHD_BROKERED_USER=netadmin \
	HOPLOCK_TEST_SSHD_BROKERED_KEY=$(SSHD_DIR)/keys/brokered_key \
	$(GO) test -count=1 -v -run TestSSHD ./internal/auth/target/

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

## openapi-check: validate the Control API contract as an OpenAPI 3 document
## (needs `pip install openapi-spec-validator`; CI installs it)
openapi-check:
	$(PYTHON) -c 'from openapi_spec_validator import validate; \
	from openapi_spec_validator.readers import read_from_filename; \
	spec, _ = read_from_filename("api/control.yaml"); \
	validate(spec); \
	print("api/control.yaml is a valid OpenAPI 3 document")'

## tidy: tidy and verify go.mod/go.sum
tidy:
	$(GO) mod tidy

## run-proxy: run the proxy daemon (CONFIG=path to override)
run-proxy:
	$(GO) run ./cmd/proxy -config $(CONFIG)

## run-mock: run the mock Hoplock Control (LISTEN=host:port to override)
run-mock:
	$(GO) run ./cmd/mock-control -listen $(LISTEN)

## clean: remove build output
clean:
	rm -rf $(BIN_DIR)
