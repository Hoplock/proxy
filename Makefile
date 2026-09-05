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

DEPLOY_DIR := deploy
SSHD_PORT ?= 2022
E2E_PROJECT := hoplock-e2e
COMPOSE := docker compose -p $(E2E_PROJECT) -f $(DEPLOY_DIR)/compose.yaml
E2E_CLEAN := rm -rf $(DEPLOY_DIR)/keys $(DEPLOY_DIR)/bin $(DEPLOY_DIR)/control/fixtures.yaml
# The target node on its own, published on a host port. It shares the e2e
# topology's image and material, and its own compose project so the two can be
# up at once without either tearing down the other's containers.
SSHD_COMPOSE := HOPLOCK_SSHD_PORT=$(SSHD_PORT) docker compose -p hoplock-sshd -f $(DEPLOY_DIR)/target/compose.yaml

.PHONY: all build test test-sshd test-sshd-up test-sshd-run test-sshd-down \
	e2e e2e-build e2e-up e2e-down vet lint fmt license-check \
	openapi-check vulncheck tidy run-proxy run-mock clean

all: build vet test lint

## build: compile all binaries into $(BIN_DIR)
build:
	$(GO) build -ldflags "$(LDFLAGS)" -o $(BIN_DIR)/hoplock-proxy ./cmd/proxy
	$(GO) build -ldflags "$(LDFLAGS)" -o $(BIN_DIR)/mock-control ./cmd/mock-control
	$(GO) build ./...

## test: run all unit tests with the race detector
test:
	$(GO) test -race ./...

## test-sshd: bring the target container up, run the tests against its real
## sshd, tear it down (needs docker). It shares the e2e topology's target image
## and material; see deploy/README.md.
test-sshd: test-sshd-up
	@set -e; \
	trap '$(MAKE) --no-print-directory test-sshd-down >/dev/null 2>&1' EXIT; \
	$(MAKE) --no-print-directory test-sshd-run

## test-sshd-up: generate key material and start the target container, waiting
## for its sshd to answer (leaves it running, which is what makes a failing
## test debuggable)
test-sshd-up:
	$(DEPLOY_DIR)/gen-material.sh
	$(SSHD_COMPOSE) up -d --build
	@echo "waiting for the target's sshd on 127.0.0.1:$(SSHD_PORT)"; \
	for i in $$(seq 1 60); do \
		if ssh-keyscan -p $(SSHD_PORT) 127.0.0.1 2>/dev/null | grep -q ssh; then exit 0; fi; \
		sleep 1; \
	done; \
	echo "the target's sshd did not answer within 60s; its log follows" >&2; \
	$(SSHD_COMPOSE) logs --no-color --tail 200; \
	exit 1

## test-sshd-run: the tests alone, against a container that is already up
#
# The two key paths are ABSOLUTE, and that is not tidiness. `go test` runs each
# test binary with its own PACKAGE DIRECTORY as the working directory, so a
# relative path here resolves against internal/auth/target/ rather than the
# repository root, and every test fails with "no such file or directory" on
# material that is sitting right where it was generated. This target carried
# that bug from phase 0007 until the CI job started running it.
test-sshd-run:
	HOPLOCK_TEST_SSHD_ADDR=127.0.0.1:$(SSHD_PORT) \
	HOPLOCK_TEST_SSHD_MANAGEMENT_KEY=$(CURDIR)/$(DEPLOY_DIR)/keys/management_key \
	HOPLOCK_TEST_SSHD_PROVISIONING_USER=root \
	HOPLOCK_TEST_SSHD_BROKERED_USER=netadmin \
	HOPLOCK_TEST_SSHD_BROKERED_KEY=$(CURDIR)/$(DEPLOY_DIR)/keys/brokered_key \
	$(GO) test -count=1 -v -timeout 15m -run TestSSHD ./internal/auth/target/

## test-sshd-down: stop the target container and remove what it generated
test-sshd-down:
	-$(SSHD_COMPOSE) down -v
	$(E2E_CLEAN)

## e2e: bring the 5-node topology up, run the scenario suite, tear it down.
## This is the prototype's acceptance gate (docs/PLAN.md §9); see deploy/README.md.
e2e: e2e-up
	@set -e; \
	trap '$(COMPOSE) down -v --remove-orphans >/dev/null 2>&1; $(E2E_CLEAN)' EXIT; \
	$(GO) test -tags e2e -count=1 -v -timeout 20m ./test/e2e/

## e2e-build: build the Linux binaries the topology's images copy in
e2e-build:
	CGO_ENABLED=0 GOOS=linux $(GO) build -ldflags "$(LDFLAGS)" -o $(DEPLOY_DIR)/bin/hoplock-proxy ./cmd/proxy
	CGO_ENABLED=0 GOOS=linux $(GO) build -ldflags "$(LDFLAGS)" -o $(DEPLOY_DIR)/bin/mock-control ./cmd/mock-control
	CGO_ENABLED=0 GOOS=linux $(GO) build -ldflags "$(LDFLAGS)" -o $(DEPLOY_DIR)/bin/hoplock-fake-device ./cmd/fake-device

## e2e-up: generate key material and start the topology (leaves it running,
## which is what makes a failing scenario debuggable)
e2e-up: e2e-build
	$(DEPLOY_DIR)/gen-material.sh
	$(COMPOSE) up -d --build

## e2e-down: stop the topology and remove everything it generated
e2e-down:
	-$(COMPOSE) down -v --remove-orphans
	$(E2E_CLEAN)

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

## vulncheck: report vulnerabilities REACHABLE from this module's code
##
## golang.org/x/crypto/ssh is not an incidental dependency here, it is the
## proxy's SSH implementation, and its advisory rate is high — so "is our SSH
## stack currently vulnerable?" has to be an answer CI produces rather than a
## chore someone remembers.
##
## It downloads the vulnerability database from https://vuln.go.dev at run time.
## GitHub-hosted runners reach it; some development sandboxes cannot, and the
## failure is an opaque 403 that reads like a broken tool. That case is reported
## as a skip below, and this target is deliberately NOT in docs/PROTOCOL.md's
## Definition of Done: CI is where this check must pass.
vulncheck:
	@out=$$($(GO) run golang.org/x/vuln/cmd/govulncheck@latest ./... 2>&1); status=$$?; \
	if [ $$status -ne 0 ] && printf '%s' "$$out" | grep -qiE 'vuln\.go\.dev|403|forbidden|no such host|proxy\.golang\.org'; then \
		echo "vulncheck: cannot reach vuln.go.dev — this check runs in CI"; \
		exit 0; \
	fi; \
	printf '%s\n' "$$out"; \
	exit $$status

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
