.PHONY: run run-scanner run-agent build build-scanner build-agent test vet fmt check db-up db-down

VERSION ?= dev

# Primary platform API: authentication, organizations, RBAC, clusters and audit logs.
run:
	go run ./cmd/api

# Earlier single-operator scanner/findings API. Kept available for local scanner demos.
run-scanner:
	go run ./cmd/kubeshield-api

# Cluster agent: requires KUBESHIELD_API_URL and KUBESHIELD_AGENT_TOKEN.
run-agent:
	go run ./cmd/kubeshield-agent

build:
	mkdir -p bin
	go build -ldflags "-X main.version=$(VERSION)" -o bin/kubeshield-api ./cmd/api

build-scanner:
	mkdir -p bin
	go build -o bin/kubeshield-scanner-api ./cmd/kubeshield-api

build-agent:
	mkdir -p bin
	go build -o bin/kubeshield-agent ./cmd/kubeshield-agent

test:
	go test -race -count=1 ./...

vet:
	go vet ./...

fmt:
	gofmt -w $$(find . -name '*.go' -not -path './vendor/*')

check: vet test

db-up:
	docker compose up -d --wait postgres

db-down:
	docker compose down
