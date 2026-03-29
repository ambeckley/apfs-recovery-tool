# APFS Recovery Tool

A recovery tool for Apple File System (APFS) volumes that handles both encrypted and unencrypted disk images. Built in C (performance) and Python (reference implementation).

**This project is for educational and research purposes. It is not intended as a replacement for existing commercial products.**

## Features

- Recovers files from corrupted APFS volumes by scanning every block for B-tree leaf nodes
- Handles APFS native encryption (FileVault) — derives VEK from password via PBKDF2 + RFC 3394 key unwrap
- AES-XTS decryption of file data blocks
- Transparent decompression (zlib, LZVN, LZFSE)
- Copy-on-Write (CoW) aware — finds old metadata versions when current ones are destroyed
- GPT partition table parsing
- Checkpoint superblock recovery
- Deleted file recovery via orphaned inode scanning
- Tested against 35 different corruption scenarios with 98.5% average recovery rate

## Requirements

- macOS (for creating/mounting test images) or Linux
- OpenSSL 3.x (for AES-XTS and PBKDF2)
- zlib
- Python 3.8+ with `cryptography` package (for Python implementation and tests)

### macOS (Homebrew)

```bash
brew install openssl@3
pip3 install cryptography
```

## Building

```bash
make
```

Or manually:

```bash
gcc -O3 -o apfs_recover apfs_recover.c \
    -I$(brew --prefix openssl@3)/include \
    -L$(brew --prefix openssl@3)/lib \
    -lcrypto -lz
```

## Usage

### C Tool

```bash
# Recover from an unencrypted APFS image
./apfs_recover <image.dmg> <output_dir>/

# Recover from an encrypted APFS image
./apfs_recover <image.dmg> <output_dir>/ --password <password>
```

### Python Tool

```bash
# Unencrypted recovery
python3 apfs_recover.py <image.dmg> <output_dir>/

# Encrypted recovery
python3 apfs_recover.py <image.dmg> <output_dir>/ --password <password>
```

## Testing

The test suite creates APFS disk images, applies 35 types of damage, runs recovery, and compares output against ground truth (files hashed from the mounted original image).

```bash
# Compare C vs Python on encrypted images across all 35 damage types
python3 test_python_vs_c.py

# Compare encrypted vs unencrypted recovery (C implementation)
python3 test_c_encrypted_vs_unencrypted.py

```

## How It Works

1. **Find the container** — parse GPT or scan for NXSB magic to locate the APFS partition
2. **Scan every block** — check each block against strict then lenient B-tree node validation
3. **Parse leaf nodes** — extract directory records, inodes, and extent mappings
4. **Deduplicate** — resolve CoW copies (keep newest), deduplicate directory records
5. **Reconstruct paths** — walk parent inodes back to root to build full file paths
6. **Extract files** — read extent blocks, decrypt if needed, decompress if needed, write to output

For encrypted volumes, the tool derives the Volume Encryption Key (VEK) from your password through APFS's key hierarchy (PBKDF2 → unwrap KEK → unwrap VEK) and uses AES-XTS to decrypt file data blocks. Metadata nodes are always plaintext.

## Important

- **Always work on copies.** Never run recovery tools on your only copy of a damaged disk.
- This tool is intended for recovering your own data from your own disks.
- Test image creation requires macOS (uses `hdiutil` and `diskutil`).

## License

MIT License

Copyright (c) 2025 Aaron Beckley

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
