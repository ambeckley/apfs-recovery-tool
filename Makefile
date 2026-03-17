# APFS Recovery Tool - Makefile

CC = gcc
CFLAGS = -O3 -Wall -Wextra -std=c11

# OpenSSL and zlib flags
# macOS: Uses system OpenSSL or Homebrew OpenSSL
UNAME_S := $(shell uname -s)
ifeq ($(UNAME_S),Darwin)
    # Try Homebrew OpenSSL first, fall back to system
    OPENSSL_PREFIX := $(shell brew --prefix openssl@3 2>/dev/null || brew --prefix openssl 2>/dev/null || echo "/usr")
    CRYPTO_CFLAGS = -I$(OPENSSL_PREFIX)/include
    CRYPTO_LDFLAGS = -L$(OPENSSL_PREFIX)/lib -lcrypto -lz
else
    # Linux
    CRYPTO_CFLAGS =
    CRYPTO_LDFLAGS = -lcrypto -lz
endif

# Default target
all: apfs_recover

# Compile C recovery tool with encryption and compression support
apfs_recover: apfs_recover.c
	$(CC) $(CFLAGS) $(CRYPTO_CFLAGS) -o $@ $< $(CRYPTO_LDFLAGS)

# Clean build artifacts
clean:
	rm -f apfs_recover

# Install (optional)
install: apfs_recover
	cp apfs_recover /usr/local/bin/

.PHONY: all clean install




