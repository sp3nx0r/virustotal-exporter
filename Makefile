BINARY  := virustotal-exporter
PKG     := ./cmd/virustotal-exporter
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
IMAGE   ?= ghcr.io/sp3nx0r/virustotal-exporter:$(VERSION)
LDFLAGS := -s -w -X main.version=$(VERSION)

.PHONY: all build test vet fmt run docker clean

all: vet test build

build:
	CGO_ENABLED=0 go build -trimpath -ldflags "$(LDFLAGS)" -o bin/$(BINARY) $(PKG)

test:
	go test ./...

vet:
	go vet ./...

fmt:
	gofmt -w .

run: build
	./bin/$(BINARY) $(ARGS)

docker:
	docker build --build-arg VERSION=$(VERSION) -t $(IMAGE) .

clean:
	rm -rf bin
