.PHONY: check fmt lint test build scan

check: fmt lint test build scan
	@echo "✅ All CI/CD checks & E2E Scans passed! Ready to commit."

fmt:
	@echo "🧹 Formatting code..."
	go fmt ./...

lint:
	@echo "🔍 Running linter..."
	go vet ./...
	# 如果你有裝 golangci-lint，可以把下面這行取消註解
	# golangci-lint run

test:
	@echo "🧪 Running unit tests..."
	go test -race ./...

build:
	@echo "🔨 Verifying build..."
	go build -o tooltrust-scanner ./cmd/tooltrust-scanner

scan:
	@echo "🔎 Running E2E Scanner Test..."
	# 用剛編譯好的 binary，直接跑一次我們最自豪的 Live Server 掃描
	./tooltrust-scanner scan --server "npx -y @modelcontextprotocol/server-memory"
