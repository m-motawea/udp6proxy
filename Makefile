VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
LDFLAGS := -s -w -X main.version=$(VERSION)

.PHONY: build test lint release clean

build:
	CGO_ENABLED=0 go build -trimpath -ldflags "$(LDFLAGS)" -o udp6proxy ./cmd/udp6proxy

test:
	go vet ./...
	go test -race ./...

release:
	mkdir -p dist
	for t in linux/amd64 linux/arm64 linux/arm darwin/arm64 darwin/amd64; do \
		os=$${t%/*}; arch=$${t#*/}; \
		CGO_ENABLED=0 GOOS=$$os GOARCH=$$arch go build -trimpath -ldflags "$(LDFLAGS)" -o dist/udp6proxy-$$os-$$arch ./cmd/udp6proxy; \
	done

clean:
	rm -rf udp6proxy dist
