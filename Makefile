# Makefile for building stacker as fully-static musl-linked binaries.
#
# Supported targets:
#   make                  – build for the host architecture (musl, static)
#   make amd64            – build x86_64 static musl binary
#   make arm64            – build aarch64 static musl binary
#   make all              – build both amd64 and arm64
#   make install          – install host binary to $(DESTDIR)$(PREFIX)/bin
#   make clean            – remove build artefacts
#   make setup            – install required system packages + rustup targets
#   make check            – verify the produced binary is truly static
#
# The binaries land in:
#   dist/stacker-amd64
#   dist/stacker-arm64

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

PACKAGE        := stacker
VERSION        := $(shell grep '^version' Cargo.toml | head -1 | sed 's/.*= *"\(.*\)"/\1/')
PREFIX         ?= /usr/local
DESTDIR        ?=
DIST_DIR       := dist
SCRIPTS_DIR    := scripts

# Rust targets
TARGET_AMD64   := x86_64-unknown-linux-musl
TARGET_ARM64   := aarch64-unknown-linux-musl

# Output binary names
BIN_AMD64      := $(DIST_DIR)/$(PACKAGE)-amd64
BIN_ARM64      := $(DIST_DIR)/$(PACKAGE)-arm64

# Cargo flags
CARGO          := cargo
CARGO_FLAGS    := --release
CARGO_MANIFEST := Cargo.toml

# Detect host arch to define a sensible default target
UNAME_M := $(shell uname -m)
ifeq ($(UNAME_M),x86_64)
    HOST_TARGET  := $(TARGET_AMD64)
    HOST_BIN     := $(BIN_AMD64)
else ifeq ($(UNAME_M),aarch64)
    HOST_TARGET  := $(TARGET_ARM64)
    HOST_BIN     := $(BIN_ARM64)
else
    $(error Unsupported host architecture: $(UNAME_M))
endif

# Allow the caller to override PATH so the scripts/ wrapper is always found.
# This ensures 'aarch64-linux-musl-gcc' (our clang wrapper) is resolved even
# when the directory is not in the user's PATH.
export PATH := $(CURDIR)/$(SCRIPTS_DIR):$(PATH)

# ---------------------------------------------------------------------------
# Phony targets
# ---------------------------------------------------------------------------

.PHONY: all amd64 arm64 default install clean setup check help

# ---------------------------------------------------------------------------
# Default: build for the host architecture
# ---------------------------------------------------------------------------

default: $(HOST_BIN)
	@echo ""
	@echo "Built static binary: $(HOST_BIN)"
	@file $(HOST_BIN)

# ---------------------------------------------------------------------------
# amd64 (x86_64-unknown-linux-musl)
# ---------------------------------------------------------------------------

amd64: $(BIN_AMD64)

$(BIN_AMD64): $(DIST_DIR) $(shell find src -name '*.rs') Cargo.toml Cargo.lock
	@echo "==> Building static amd64 binary (target: $(TARGET_AMD64))"
	$(CARGO) build $(CARGO_FLAGS) --target $(TARGET_AMD64)
	cp target/$(TARGET_AMD64)/release/$(PACKAGE) $@
	@echo "==> amd64 binary: $@"
	@file $@

# ---------------------------------------------------------------------------
# arm64 (aarch64-unknown-linux-musl)
# ---------------------------------------------------------------------------

arm64: $(BIN_ARM64)

$(BIN_ARM64): $(DIST_DIR) $(shell find src -name '*.rs') Cargo.toml Cargo.lock
	@echo "==> Building static arm64 binary (target: $(TARGET_ARM64))"
	$(CARGO) build $(CARGO_FLAGS) --target $(TARGET_ARM64)
	cp target/$(TARGET_ARM64)/release/$(PACKAGE) $@
	@echo "==> arm64 binary: $@"
	@file $@

# ---------------------------------------------------------------------------
# Build both architectures
# ---------------------------------------------------------------------------

all: amd64 arm64

# ---------------------------------------------------------------------------
# Output directory
# ---------------------------------------------------------------------------

$(DIST_DIR):
	mkdir -p $(DIST_DIR)

# ---------------------------------------------------------------------------
# Install the host binary
# ---------------------------------------------------------------------------

install: $(HOST_BIN)
	@echo "==> Installing $(HOST_BIN) to $(DESTDIR)$(PREFIX)/bin/$(PACKAGE)"
	install -d $(DESTDIR)$(PREFIX)/bin
	install -m 0755 $(HOST_BIN) $(DESTDIR)$(PREFIX)/bin/$(PACKAGE)

# ---------------------------------------------------------------------------
# Verify that the produced binaries are truly statically linked
# ---------------------------------------------------------------------------

check:
	@fail=0; \
	for bin in $(wildcard $(DIST_DIR)/$(PACKAGE)-*); do \
	    echo "Checking: $$bin"; \
	    if ldd "$$bin" 2>&1 | grep -qiE 'not a dynamic executable|statically linked'; then \
	        echo "  OK – static"; \
	    elif file "$$bin" | grep -q "statically linked"; then \
	        echo "  OK – static"; \
	    else \
	        echo "  FAIL – binary appears to be dynamically linked:"; \
	        ldd "$$bin" 2>&1 | sed 's/^/    /'; \
	        fail=1; \
	    fi; \
	done; \
	exit $$fail

# ---------------------------------------------------------------------------
# Clean
# ---------------------------------------------------------------------------

clean:
	$(CARGO) clean
	rm -rf $(DIST_DIR)

# ---------------------------------------------------------------------------
# Setup: install all required system dependencies and Rust targets
# ---------------------------------------------------------------------------
#
# What this installs:
#   musl-tools          – provides x86_64-linux-musl-gcc (native musl gcc wrapper)
#   musl-dev            – musl headers + static libc.a for the host arch
#   clang-19 lld-19     – used by scripts/aarch64-linux-musl-gcc to cross-link arm64
#   gcc-aarch64-linux-gnu – provides the aarch64 sysroot (crt1.o etc.) at
#                           /usr/aarch64-linux-gnu that clang needs at link time
#
# After installing packages we also add both musl Rust targets if missing.

setup:
	@echo "==> Installing system packages (requires sudo)"
	sudo apt-get update -qq
	sudo apt-get install -y \
	    musl-tools \
	    musl-dev \
	    clang-19 \
	    lld-19 \
	    gcc-aarch64-linux-gnu
	@echo "==> Making scripts/aarch64-linux-musl-gcc executable"
	chmod +x $(SCRIPTS_DIR)/aarch64-linux-musl-gcc
	@echo "==> Adding Rust targets via rustup"
	rustup target add $(TARGET_AMD64)
	rustup target add $(TARGET_ARM64)
	@echo ""
	@echo "Setup complete. You can now run:"
	@echo "  make amd64   – build for x86_64"
	@echo "  make arm64   – build for aarch64"
	@echo "  make all     – build both"

# ---------------------------------------------------------------------------
# Help
# ---------------------------------------------------------------------------

help:
	@echo "Usage: make [target]"
	@echo ""
	@echo "Targets:"
	@echo "  (default)   Build static musl binary for the host architecture"
	@echo "  amd64       Build static musl binary for x86_64"
	@echo "  arm64       Build static musl binary for aarch64"
	@echo "  all         Build both amd64 and arm64 binaries"
	@echo "  install     Install the host binary to \$(DESTDIR)\$(PREFIX)/bin"
	@echo "  check       Verify that built binaries are truly static"
	@echo "  clean       Remove build artefacts and the dist/ directory"
	@echo "  setup       Install required system packages and Rust targets"
	@echo "  help        Show this message"
	@echo ""
	@echo "Variables:"
	@echo "  PREFIX      Install prefix           (default: /usr/local)"
	@echo "  DESTDIR     Staging root for installs (default: empty)"
	@echo "  CARGO_FLAGS Extra flags passed to cargo (default: --release)"
	@echo ""
	@echo "Output:"
	@echo "  $(BIN_AMD64)"
	@echo "  $(BIN_ARM64)"
