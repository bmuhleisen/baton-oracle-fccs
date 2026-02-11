GOOS=$(shell go env GOOS)
GOARCH=$(shell go env GOARCH)
VERSION=$(shell git describe --tags --dirty --always)

ifeq ($(GOOS),windows)
OUTPUT_PATH=dist/$(GOOS)_$(GOARCH)/baton-oracle-fccs.exe
else
OUTPUT_PATH=dist/$(GOOS)_$(GOARCH)/baton-oracle-fccs
endif

.PHONY: build
build:
	go build -ldflags="-X main.version=$(VERSION)" -o $(OUTPUT_PATH) ./cmd/baton-oracle-fccs

.PHONY: update-deps
update-deps:
	go get -d -u ./...
	go mod tidy -v
	go mod vendor

.PHONY: add-dep
add-dep:
	go mod tidy -v
	go mod vendor

.PHONY: lint
lint:
	golangci-lint run

.PHONY: test
test:
	go test -v -race -coverprofile=coverage.out ./...

.PHONY: clean
clean:
	rm -rf dist/
	rm -f baton-oracle-fccs
	rm -f baton-oracle-fccs.exe
	rm -f coverage.out

.PHONY: ci
ci: lint test build
