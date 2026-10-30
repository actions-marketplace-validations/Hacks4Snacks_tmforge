# Makefile for Threat Model Forge (tmforge)

# ---------------------------------------------------------------------------
# Configuration (override on the command line, e.g. `make build CONFIG=Debug`)
# ---------------------------------------------------------------------------
DOTNET       ?= dotnet
CONFIG       ?= Release
NPM          ?= npm

TRAVERSAL    := dirs.proj
SOLUTION     := ThreatModelForge.slnx
CLI_PROJECT  := src/ThreatModelForge.Cli/ThreatModelForge.Cli.csproj
API_PROJECT  := src/ThreatModelForge.Api/ThreatModelForge.Api.csproj
WASM_PROJECT := src/ThreatModelForge.Wasm/ThreatModelForge.Wasm.csproj
STUDIO_DIR   := src/ThreatModelForge.Studio

ARTIFACTS    := artifacts

# Version comes from Directory.Build.props <VersionPrefix> (release-please keeps it current).
VERSION      := $(shell grep -oE '<VersionPrefix>[^<]+</VersionPrefix>' Directory.Build.props | sed -E 's:</?VersionPrefix>::g' | tr -d '[:space:]')

# Container image coordinates (mirror docker-publish.yml).
REGISTRY     ?= ghcr.io
OWNER        ?= hacks4snacks
CLI_IMAGE    ?= tmforge-cli
API_IMAGE    ?= tmforge
PLATFORMS    ?= linux/amd64,linux/arm64
PORT         ?= 8080
NUGET_FEED   ?= https://api.nuget.org/v3/index.json
NPM_REGISTRY ?= https://registry.npmjs.org/

# Self-contained single-file publish targets (the release.yml RID matrix).
RIDS         := linux-x64 linux-arm64 win-x64 win-arm64 osx-x64 osx-arm64

# Arguments forwarded to `make run` / `make docker-run-cli`, e.g. `make run ARGS="analyze model.tm7"`.
ARGS         ?=

# ---------------------------------------------------------------------------
# Host RID detection (default target for `make binary`).
# ---------------------------------------------------------------------------
UNAME_S := $(shell uname -s)
UNAME_M := $(shell uname -m)
ifeq ($(UNAME_S),Darwin)
  ifeq ($(UNAME_M),arm64)
    HOST_RID := osx-arm64
  else
    HOST_RID := osx-x64
  endif
else ifeq ($(UNAME_S),Linux)
  ifeq ($(UNAME_M),aarch64)
    HOST_RID := linux-arm64
  else ifeq ($(UNAME_M),arm64)
    HOST_RID := linux-arm64
  else
    HOST_RID := linux-x64
  endif
else
  HOST_RID := linux-x64
endif
RID ?= $(HOST_RID)

.DEFAULT_GOAL := help

# ===========================================================================
# Meta
# ===========================================================================
.PHONY: help version
help: ## Show this help
	@echo "Threat Model Forge (tmforge) $(VERSION) — make targets:"
	@echo ""
	@grep -hE '^[a-zA-Z0-9_-]+:.*?## .*$$' $(MAKEFILE_LIST) \
		| sort \
		| awk 'BEGIN{FS=":.*?## "}{printf "  \033[36m%-18s\033[0m %s\n", $$1, $$2}'
	@echo ""
	@echo "Override vars, e.g.: make binary RID=linux-arm64 | make docker-run PORT=9000"

version: ## Print the resolved project version
	@echo $(VERSION)

# ===========================================================================
# Build & test
# ===========================================================================
.PHONY: restore build test test-studio format format-check coverage coverage-accept
restore: ## Restore NuGet packages
	$(DOTNET) restore $(TRAVERSAL)

build: ## Build the whole solution (also builds the Studio SPA via MSBuild)
	$(DOTNET) build $(TRAVERSAL) -c $(CONFIG)

test: ## Run the .NET test suite
	$(DOTNET) test $(TRAVERSAL) -c $(CONFIG)

test-studio: ## Run the Studio type-check + Vitest suite
	cd $(STUDIO_DIR) && $(NPM) ci && $(NPM) test

coverage: ## Measure coverage on both sides and enforce the committed floors
	$(DOTNET) test $(TRAVERSAL) -c $(CONFIG) \
		--collect:"XPlat Code Coverage" --results-directory TestResults/coverage
	python3 build/coverage-summary.py --results TestResults/coverage
	cd $(STUDIO_DIR) && $(NPM) run coverage

coverage-accept: ## Rewrite the .NET floors from the current run (after a deliberate improvement)
	$(DOTNET) test $(TRAVERSAL) -c $(CONFIG) \
		--collect:"XPlat Code Coverage" --results-directory TestResults/coverage
	python3 build/coverage-summary.py --results TestResults/coverage --update-floors

format: ## Apply `dotnet format` (whitespace, style, analyzers)
	$(DOTNET) format $(SOLUTION)

format-check: ## Verify formatting without writing changes
	$(DOTNET) format $(SOLUTION) --verify-no-changes

# ===========================================================================
# Binaries (the "easily build binaries" bit)
# ===========================================================================
.PHONY: cli binary binaries run
cli: ## Publish a portable (framework-dependent) CLI to artifacts/cli
	$(DOTNET) publish $(CLI_PROJECT) -c $(CONFIG) -o $(ARTIFACTS)/cli
	@echo "Portable CLI: run with 'dotnet $(ARTIFACTS)/cli/tmforge.dll ...'"

binary: ## Build a self-contained single-file binary for the host RID
	$(DOTNET) publish $(CLI_PROJECT) -c $(CONFIG) -r $(RID) -p:Standalone=true \
		-p:Version=$(VERSION) -o $(ARTIFACTS)/bin/$(RID)
	@echo "Standalone binary: $(ARTIFACTS)/bin/$(RID)/tmforge"

binaries: ## Build self-contained single-file binaries for every release RID
	@for rid in $(RIDS); do \
		echo "==> publishing $$rid"; \
		$(DOTNET) publish $(CLI_PROJECT) -c $(CONFIG) -r $$rid -p:Standalone=true \
			-p:Version=$(VERSION) -o $(ARTIFACTS)/bin/$$rid || exit 1; \
	done
	@echo "All binaries under $(ARTIFACTS)/bin/<rid>/"

run: ## Run the CLI from source. Pass args via ARGS="..."
	$(DOTNET) run --project $(CLI_PROJECT) -c $(CONFIG) -- $(ARGS)

# ===========================================================================
# Studio SPA / WASM engine / API host
# ===========================================================================
.PHONY: studio studio-dev wasm-install wasm run-api
studio: ## Build the Studio SPA production bundle
	cd $(STUDIO_DIR) && $(NPM) ci && $(NPM) run build

studio-dev: ## Start the Vite dev server for the Studio SPA
	cd $(STUDIO_DIR) && $(NPM) run dev

wasm-install: ## Install the WASM workloads (run once; needed before `make wasm`)
	$(DOTNET) workload install wasm-tools wasm-experimental

wasm: ## Publish the trimmed in-browser WASM engine to artifacts/wasm
	$(DOTNET) publish $(WASM_PROJECT) -c $(CONFIG) -o $(ARTIFACTS)/wasm

run-api: ## Run the /v1 engine API + Studio locally (default port 8080)
	ASPNETCORE_URLS=http://+:$(PORT) $(DOTNET) run --project $(API_PROJECT) -c $(CONFIG)

# ===========================================================================
# Containers (the "easily build containers" bit)
# ===========================================================================
.PHONY: docker docker-cli docker-api docker-run docker-run-cli \
        docker-push docker-push-cli docker-push-api
docker: docker-cli docker-api ## Build both container images locally

docker-cli: ## Build the CLI image (tmforge-cli)
	docker build -f build/Dockerfile --build-arg NUGET_FEED="$(NUGET_FEED)" \
		-t $(CLI_IMAGE):$(VERSION) -t $(CLI_IMAGE):latest .

docker-api: ## Build the API + Studio image (tmforge)
	docker build -f build/Dockerfile.api --build-arg NUGET_FEED="$(NUGET_FEED)" \
		--build-arg NPM_REGISTRY="$(NPM_REGISTRY)" \
		-t $(API_IMAGE):$(VERSION) -t $(API_IMAGE):latest .

docker-run: docker-api ## Run the API image (default port 8080)
	docker run --rm -p $(PORT):8080 $(API_IMAGE):$(VERSION)

docker-run-cli: docker-cli ## Run the CLI image. Pass args via ARGS="..."
	docker run --rm $(CLI_IMAGE):$(VERSION) $(ARGS)

# Multi-arch build + push to GHCR. Requires `docker login ghcr.io` and a buildx builder.
docker-push: docker-push-cli docker-push-api ## Build+push both multi-arch images to GHCR

docker-push-cli: ## Build+push the multi-arch CLI image to GHCR
	docker buildx build -f build/Dockerfile --platform $(PLATFORMS) \
		--build-arg NUGET_FEED="$(NUGET_FEED)" \
		-t $(REGISTRY)/$(OWNER)/$(CLI_IMAGE):$(VERSION) \
		-t $(REGISTRY)/$(OWNER)/$(CLI_IMAGE):latest --push .

docker-push-api: ## Build+push the multi-arch API image to GHCR
	docker buildx build -f build/Dockerfile.api --platform $(PLATFORMS) \
		--build-arg NUGET_FEED="$(NUGET_FEED)" --build-arg NPM_REGISTRY="$(NPM_REGISTRY)" \
		-t $(REGISTRY)/$(OWNER)/$(API_IMAGE):$(VERSION) \
		-t $(REGISTRY)/$(OWNER)/$(API_IMAGE):latest --push .

# ===========================================================================
# Housekeeping
# ===========================================================================
.PHONY: clean clean-studio distclean
clean: ## Remove .NET build output (out/, artifacts/, publish/, TestResults/)
	rm -rf out $(ARTIFACTS) publish TestResults

clean-studio: ## Remove Studio build output and node_modules
	rm -rf $(STUDIO_DIR)/dist $(STUDIO_DIR)/node_modules $(STUDIO_DIR)/coverage

distclean: clean clean-studio ## Remove all build output including Studio deps
