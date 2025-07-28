.PHONY: all build test bench test-coverage lint verify install-tools
all: build test bench

build:
	go build ./...

test:
	go test ./...

bench:
	@echo "Running benchmarks..."
	go test -bench=. -run=^$$ -benchmem ./...

test-coverage:
	go test -race -coverprofile=coverage.out -covermode=atomic ./...

lint:
	@echo "Running linters..."
	@if command -v golangci-lint > /dev/null; then \
		golangci-lint run; \
	else \
		echo "golangci-lint not installed, skipping lint"; \
	fi

verify:
	go mod verify

install-tools:
	@echo "Installing tools..."
	@echo "No specific tools required for this library"