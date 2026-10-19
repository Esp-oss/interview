# Developer entry points.
#
# Everything the container workflow needs is `make up`; everything a reviewer
# wants to run by hand is one target away.

BIN_DIR  := bin
GO       ?= go
VERSION  ?= 1.0.0
COMPOSE  ?= docker compose

.DEFAULT_GOAL := help
.PHONY: help build test fuzz vet fmt check up down logs ps demo clean tidy

help: ## list targets
	@echo "build    compile the server and client into $(BIN_DIR)/"
	@echo "test     run the unit test suite"
	@echo "fuzz     run the crash-resistance fuzz test for 15s"
	@echo "vet      run go vet"
	@echo "fmt      list files that need gofmt"
	@echo "check    vet + fmt check + tests (what CI runs)"
	@echo "up       docker compose up --build"
	@echo "down     docker compose down --remove-orphans"
	@echo "logs     follow service logs"
	@echo "ps       container status"
	@echo "demo     run the client once against a running stack"
	@echo "clean    remove build output"

build: ## build both binaries
	@mkdir -p $(BIN_DIR)
	CGO_ENABLED=0 $(GO) build -trimpath -buildvcs=false \
	  -ldflags="-s -w -X main.version=$(VERSION)" -o $(BIN_DIR)/server ./cmd/server
	CGO_ENABLED=0 $(GO) build -trimpath -buildvcs=false \
	  -ldflags="-s -w -X main.version=$(VERSION)" -o $(BIN_DIR)/client ./cmd/client
	@echo "built $(BIN_DIR)/server and $(BIN_DIR)/client"

test: ## run unit tests
	$(GO) test ./...

fuzz: ## fuzz the engine for 15s (proves it cannot panic on hostile input)
	$(GO) test ./internal/engine -run '^$$' -fuzz FuzzIdentifyNoPanic -fuzztime 15s

vet: ## static analysis
	$(GO) vet ./...

fmt: ## report unformatted files
	@out="$$(gofmt -l cmd internal rules | grep -v '^vendor/' || true)"; \
	if [ -n "$$out" ]; then echo "needs gofmt: $$out"; exit 1; fi; \
	echo "gofmt: clean"

check: vet fmt test ## what CI runs

up: ## start the stack
	VERSION=$(VERSION) $(COMPOSE) up --build

down: ## stop the stack
	$(COMPOSE) down --remove-orphans

logs: ## follow logs
	$(COMPOSE) logs -f --tail=100

ps: ## container status
	$(COMPOSE) ps

demo: ## run the client once against the running stack
	$(COMPOSE) run --rm client

clean: ## remove build output
	rm -rf $(BIN_DIR)
