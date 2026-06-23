# reoftpd — thin convenience wrappers over Cargo.
# Cargo is the real build system; these targets just save typing.
#
#   make build                       native release binary
#   make build-musl                  fully-static Linux binary (ARCH=x86_64|aarch64)
#   make test / lint / fmt
#   sudo make install                install the binary to $(PREFIX)/bin
#   sudo make install-units          install the systemd unit files
#   make help

PREFIX  ?= /usr/local
DESTDIR ?=
UNITDIR ?= /etc/systemd/system
ARCH    ?= x86_64

BINDIR      := $(DESTDIR)$(PREFIX)/bin
MUSL_TARGET := $(ARCH)-unknown-linux-musl
# Which binary `install` copies. Override for a musl build, e.g.
#   sudo make install BIN=target/$(MUSL_TARGET)/release/reoftpd
BIN ?= target/release/reoftpd

.PHONY: help build build-musl test lint fmt clean install install-units

help:
	@echo "Targets:"
	@echo "  build          cargo build --release            -> target/release/reoftpd"
	@echo "  build-musl     static Linux binary (ARCH=$(ARCH)) -> target/$(MUSL_TARGET)/release/reoftpd"
	@echo "  test lint fmt  cargo test / clippy -D warnings / fmt"
	@echo "  install        install \$$(BIN) to $(BINDIR)/reoftpd   (use sudo)"
	@echo "  install-units  install systemd units to $(DESTDIR)$(UNITDIR)  (use sudo)"
	@echo "  clean          cargo clean"
	@echo "Vars: PREFIX=$(PREFIX)  ARCH=$(ARCH)  DESTDIR=$(DESTDIR)  BIN=$(BIN)"

build:
	cargo build --release

# Fully-static Linux binary that runs on any glibc version, however old.
build-musl:
	rustup target add $(MUSL_TARGET)
	cargo build --release --target $(MUSL_TARGET)
	@echo "Static binary: target/$(MUSL_TARGET)/release/reoftpd"

test:
	cargo test

lint:
	cargo clippy --all-targets -- -D warnings

fmt:
	cargo fmt

# Install just the binary. Does not build (so it works for either native or
# musl output); run `make build` or `make build-musl` first.
install:
	install -d -m0755 $(BINDIR)
	install -m0755 $(BIN) $(BINDIR)/reoftpd
	@echo "Installed $(BIN) -> $(BINDIR)/reoftpd"

install-units:
	install -d -m0755 $(DESTDIR)$(UNITDIR)
	install -m0644 packaging/reoftpd.service         $(DESTDIR)$(UNITDIR)/reoftpd.service
	install -m0644 packaging/reoftpd-cleanup.service $(DESTDIR)$(UNITDIR)/reoftpd-cleanup.service
	install -m0644 packaging/reoftpd-cleanup.timer   $(DESTDIR)$(UNITDIR)/reoftpd-cleanup.timer
	@echo "Installed systemd units. Reload with: systemctl daemon-reload"

clean:
	cargo clean
