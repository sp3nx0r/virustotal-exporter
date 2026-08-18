BINARY  := virustotal-exporter
PKG     := ./cmd/virustotal-exporter
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
IMAGE   ?= ghcr.io/sp3nx0r/virustotal-exporter:$(VERSION)
LDFLAGS := -s -w -X main.version=$(VERSION)

# docker-run: for each setting, pass the value or a file path.
#   VT_API_KEY / VT_API_KEY_FILE — group-administrator VirusTotal API key
#   VT_GROUPS  / VT_GROUPS_FILE  — comma-separated VirusTotal group IDs
# If both a value and a file path are set, the file path wins.
PORT         ?= 9942
SECRETS_DIR  ?= /tmp/vt-secrets
API_KEY_FILE ?= $(SECRETS_DIR)/vt_api_key
GROUPS_FILE  ?= $(SECRETS_DIR)/vt_groups

.PHONY: all build test vet fmt run docker docker-run docker-run-check clean

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

docker-run-check:
	@ok=1; \
	if [ -z "$(VT_API_KEY)" ] && [ -z "$(VT_API_KEY_FILE)" ]; then \
		echo "API key: pass VT_API_KEY=<key> or VT_API_KEY_FILE=<path>"; \
		ok=0; \
	fi; \
	if [ -z "$(VT_GROUPS)" ] && [ -z "$(VT_GROUPS_FILE)" ]; then \
		echo "groups: pass VT_GROUPS=<id> or VT_GROUPS_FILE=<path>"; \
		ok=0; \
	fi; \
	if [ -n "$(VT_API_KEY_FILE)" ] && [ ! -r "$(VT_API_KEY_FILE)" ]; then \
		echo "VT_API_KEY_FILE is not readable: $(VT_API_KEY_FILE)"; \
		ok=0; \
	fi; \
	if [ -n "$(VT_GROUPS_FILE)" ] && [ ! -r "$(VT_GROUPS_FILE)" ]; then \
		echo "VT_GROUPS_FILE is not readable: $(VT_GROUPS_FILE)"; \
		ok=0; \
	fi; \
	if [ "$$ok" -ne 1 ]; then \
		echo "example: make docker-run VT_API_KEY=... VT_GROUPS=your_group_id"; \
		echo "     or: make docker-run VT_API_KEY_FILE=./key VT_GROUPS_FILE=./groups"; \
		exit 1; \
	fi

# Builds the image and runs it with *_FILE mounts.
# Usage:
#   make docker-run VT_API_KEY=... VT_GROUPS=...
#   make docker-run VT_API_KEY_FILE=/path/to/key VT_GROUPS_FILE=/path/to/groups
docker-run: docker-run-check docker
	@set -e; \
	key_file="$(VT_API_KEY_FILE)"; \
	groups_file="$(VT_GROUPS_FILE)"; \
	secrets_dir="$(SECRETS_DIR)"; \
	[ -n "$$secrets_dir" ] || secrets_dir=/tmp/vt-secrets; \
	if [ -z "$$key_file" ]; then \
		key_file="$(API_KEY_FILE)"; \
		[ -n "$$key_file" ] || key_file="$$secrets_dir/vt_api_key"; \
		mkdir -p "$$secrets_dir"; \
		printf '%s\n' "$(VT_API_KEY)" > "$$key_file"; \
		chmod 644 "$$key_file"; \
	fi; \
	if [ -z "$$groups_file" ]; then \
		groups_file="$(GROUPS_FILE)"; \
		[ -n "$$groups_file" ] || groups_file="$$secrets_dir/vt_groups"; \
		mkdir -p "$$secrets_dir"; \
		printf '%s\n' "$(VT_GROUPS)" > "$$groups_file"; \
		chmod 644 "$$groups_file"; \
	fi; \
	docker run --rm -p $(PORT):9942 \
		-e VT_API_KEY_FILE=/run/secrets/vt_api_key \
		-e VT_EXPORTER_VT_GROUPS_FILE=/run/secrets/vt_groups \
		-v "$$key_file":/run/secrets/vt_api_key:ro \
		-v "$$groups_file":/run/secrets/vt_groups:ro \
		"$(IMAGE)"

clean:
	rm -rf bin
