.PHONY: run build test

# Build with the external linker and ad-hoc sign on macOS (works around
# "missing LC_UUID load command" with older Go toolchains).
build:
	go build -ldflags=-linkmode=external -o passgen .
	@if [ "$$(uname)" = "Darwin" ]; then codesign -s - -f passgen; fi

run: build
	./passgen

test:
	go test ./...
