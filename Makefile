.PHONY: build test race vet certs clean playground cluster-playground

GOCACHE ?= /tmp/distributed-secrets-go-cache
GOPATH ?= /tmp/distributed-secrets-gopath

build:
	mkdir -p bin
	GOCACHE=$(GOCACHE) GOPATH=$(GOPATH) go build -o bin/secrets-server ./cmd/server
	GOCACHE=$(GOCACHE) GOPATH=$(GOPATH) go build -o bin/secretsctl ./cmd/secretsctl

test:
	GOCACHE=$(GOCACHE) GOPATH=$(GOPATH) go test ./...

race:
	GOCACHE=$(GOCACHE) GOPATH=$(GOPATH) go test -race ./...

vet:
	GOCACHE=$(GOCACHE) GOPATH=$(GOPATH) go vet ./...

certs:
	./scripts/dev-certs.sh

playground:
	./scripts/playground.sh

cluster-playground:
	./scripts/cluster-playground.sh

clean:
	rm -rf bin

