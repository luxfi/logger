.PHONY: all build test bench
all: build test bench

build:
	go build ./...

test:
	go test ./...

bench:
	@echo "Running benchmarks..."
	go test -bench=. -run=^$$ -benchmem ./...