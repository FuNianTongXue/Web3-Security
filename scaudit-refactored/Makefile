.PHONY: help build build-linux build-desktop build-web build-cli run run-web run-desktop test clean docker-build docker-push deploy-dev deploy-prod

# Variables
APP_NAME=scaudit-api
VERSION?=$(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
BUILD_TIME=$(shell date -u '+%Y-%m-%d_%H:%M:%S')
DOCKER_REGISTRY=ghcr.io/yourorg
DOCKER_IMAGE=$(DOCKER_REGISTRY)/$(APP_NAME)
LDFLAGS=-w -s -X scaudit/internal/webapp.Version=$(VERSION) -X scaudit/internal/webapp.BuildTime=$(BUILD_TIME)
HOST?=127.0.0.1
PORT?=8088
NO_OPEN?=1
SKIP_BUILD?=0

# Use a workspace-local Go build cache by default so builds work in restricted
# environments (for example, when $HOME/Library/Caches is not writable).
GOCACHE ?= $(CURDIR)/.gocache
export GOCACHE

help: ## Display this help message
	@echo "SCaudit Platform - Make Commands"
	@echo ""
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-20s\033[0m %s\n", $$1, $$2}'

build: ## Build the application
	@echo "Building $(APP_NAME) $(VERSION)..."
	@mkdir -p bin
	go build -ldflags="$(LDFLAGS)" \
		-o bin/$(APP_NAME) ./cmd/scaudit-api

build-linux: ## Build for Linux
	@echo "Building $(APP_NAME) for Linux..."
	@mkdir -p bin
	GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build \
		-ldflags="$(LDFLAGS)" \
		-o bin/$(APP_NAME)-linux ./cmd/scaudit-api

build-desktop: ## Build desktop mode binary
	@echo "Building scaudit-desktop $(VERSION)..."
	@mkdir -p bin
	go build -ldflags="$(LDFLAGS)" -o bin/scaudit-desktop ./cmd/scaudit-desktop

build-web: ## Build web mode binary
	@echo "Building scaudit-web $(VERSION)..."
	@mkdir -p bin
	go build -ldflags="$(LDFLAGS)" -o bin/scaudit-web ./cmd/scaudit-web

build-cli: ## Build CLI binary
	@echo "Building scaudit CLI $(VERSION)..."
	@mkdir -p bin
	go build -o bin/scaudit ./cmd/scaudit

run: ## Run the application locally
	$(MAKE) run-desktop

run-web: ## Run the web server (no auto-open browser)
	@if [ "$(SKIP_BUILD)" != "1" ] && [ "$(SKIP_BUILD)" != "true" ] && [ "$(SKIP_BUILD)" != "yes" ]; then \
		$(MAKE) build; \
	elif [ ! -x bin/scaudit-api ]; then \
		$(MAKE) build; \
	fi
	./bin/scaudit-api -port $(PORT)

run-desktop: ## Run desktop mode (auto-open browser)
	@if [ "$(SKIP_BUILD)" != "1" ] && [ "$(SKIP_BUILD)" != "true" ] && [ "$(SKIP_BUILD)" != "yes" ]; then \
		$(MAKE) build-desktop; \
	elif [ ! -x bin/scaudit-desktop ]; then \
		$(MAKE) build-desktop; \
	fi
	@if [ "$(NO_OPEN)" = "1" ] || [ "$(NO_OPEN)" = "true" ] || [ "$(NO_OPEN)" = "yes" ]; then \
		./bin/scaudit-desktop -no-open -host $(HOST) -port $(PORT); \
	else \
		./bin/scaudit-desktop -host $(HOST) -port $(PORT); \
	fi

test: ## Run tests
	go test -v -race -cover ./...

test-coverage: ## Run tests with coverage report
	go test -v -race -coverprofile=coverage.out -covermode=atomic ./...
	go tool cover -html=coverage.out -o coverage.html
	@echo "Coverage report generated: coverage.html"

test-integration: ## Run integration tests
	go test -v -tags=integration ./...

lint: ## Run linter
	golangci-lint run --timeout 5m

fmt: ## Format code
	go fmt ./...
	gofmt -s -w .

vet: ## Run go vet
	go vet ./...

clean: ## Clean build artifacts
	rm -rf bin/
	rm -f coverage.out coverage.html
	go clean -cache -testcache

deps: ## Download dependencies
	go mod download
	go mod tidy

deps-update: ## Update dependencies
	go get -u ./...
	go mod tidy

security-check: ## Run security checks
	gosec -quiet ./...
	trivy fs --severity HIGH,CRITICAL .

docker-build: ## Build Docker image
	@echo "Building Docker image $(DOCKER_IMAGE):$(VERSION)..."
	docker build \
		--build-arg VERSION=$(VERSION) \
		--build-arg BUILD_TIME=$(BUILD_TIME) \
		-t $(DOCKER_IMAGE):$(VERSION) \
		-t $(DOCKER_IMAGE):latest \
		-f deployments/docker/Dockerfile .

docker-push: ## Push Docker image to registry
	@echo "Pushing Docker image $(DOCKER_IMAGE):$(VERSION)..."
	docker push $(DOCKER_IMAGE):$(VERSION)
	docker push $(DOCKER_IMAGE):latest

docker-run: ## Run Docker container locally
	docker run --rm -p 8088:8088 --env-file .env $(DOCKER_IMAGE):latest

compose-up: ## Start services with docker-compose
	cd deployments/docker && docker-compose up -d

compose-down: ## Stop services with docker-compose
	cd deployments/docker && docker-compose down

compose-logs: ## View docker-compose logs
	cd deployments/docker && docker-compose logs -f

migrate-up: ## Run database migrations
	migrate -path migrations -database "$(DATABASE_URL)" up

migrate-down: ## Rollback last migration
	migrate -path migrations -database "$(DATABASE_URL)" down 1

migrate-create: ## Create a new migration (use: make migrate-create NAME=add_users)
	migrate create -ext sql -dir migrations -seq $(NAME)

k8s-deploy: ## Deploy to Kubernetes
	kubectl apply -f deployments/kubernetes/

k8s-delete: ## Delete from Kubernetes
	kubectl delete -f deployments/kubernetes/

k8s-logs: ## View Kubernetes logs
	kubectl logs -f deployment/scaudit-api -n scaudit

k8s-status: ## Check Kubernetes status
	kubectl get pods,svc,ingress -n scaudit

dev: ## Run development environment
	air

install-tools: ## Install development tools
	go install github.com/cosmtrek/air@latest
	go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest
	go install github.com/securego/gosec/v2/cmd/gosec@latest
	curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sh -s -- -b $(go env GOPATH)/bin

generate-secrets: ## Generate secure secrets for .env
	@echo "Generating secure secrets..."
	@echo "JWT_SECRET=$(shell openssl rand -base64 32)"
	@echo "ENCRYPTION_KEY=$(shell openssl rand -base64 32)"
	@echo "DB_PASSWORD=$(shell openssl rand -base64 24)"
	@echo "REDIS_PASSWORD=$(shell openssl rand -base64 24)"
