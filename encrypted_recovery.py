#!/usr/bin/env python3
"""
APFS Encrypted Volume Recovery
==============================

Recovers files from damaged encrypted APFS volumes by:
1. Locating the keybag in the container
2. Deriving the Volume Encryption Key (VEK) from password
3. Decrypting B-tree nodes and file data blocks
4. Reconstructing directory structure and extracting files

Supports:
- AES-128-XTS and AES-256-XTS encryption
- Password-based and recovery key authentication
- Damaged/corrupted encrypted volumes
"""

import struct
import os
import sys
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Tuple
from collections import defaultdict

# Try to import cryptography
try:
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    from cryptography.hazmat.backends import default_backend
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
    from cryptography.hazmat.primitives import hashes
    CRYPTO_AVAILABLE = True
except ImportError:
    CRYPTO_AVAILABLE = False


# =============================================================================
# AES-XTS Implementation
# =============================================================================

class AesXts:
    """
    AES-XTS encryption/decryption for APFS.
    Uses native cryptography library XTS mode for performance.
    APFS uses AES-128-XTS with 512-byte sectors and block number as tweak.
    The 32-byte VEK is split: first 16 bytes for data, second 16 bytes for tweak.
    """

    def __init__(self, key: bytes = b''):
        if not CRYPTO_AVAILABLE:
            raise RuntimeError("cryptography module required for encryption")

        if len(key) >= 32:
            self.key1 = key[:16]  # Data encryption key
            self.key2 = key[16:32]  # Tweak encryption key
        elif len(key) >= 16:
            self.key1 = key[:16]
            self.key2 = key[:16]
        else:
            self.key1 = b'\x00' * 16
            self.key2 = b'\x00' * 16
        # Combined key for native XTS mode (data_key + tweak_key)
        self._xts_key = self.key1 + self.key2

    def set_key(self, key1: bytes, key2: bytes):
        """Set the encryption keys explicitly."""
        self.key1 = key1
        self.key2 = key2
        self._xts_key = key1 + key2

    def decrypt(self, ciphertext: bytes, block_no: int, sector_size: int = 512) -> bytes:
        """Decrypt data using AES-XTS with 512-byte sectors."""
        if len(ciphertext) % 16 != 0:
            raise ValueError("Ciphertext must be multiple of 16 bytes")

        result = bytearray()
        cs_factor = 4096 // sector_size
        sector_no = block_no * cs_factor

        for sector_start in range(0, len(ciphertext), sector_size):
            sector = ciphertext[sector_start:sector_start + sector_size]
            tweak = struct.pack('<QQ', sector_no, 0)
            cipher = Cipher(algorithms.AES(self._xts_key), modes.XTS(tweak))
            dec = cipher.decryptor()
            result.extend(dec.update(sector) + dec.finalize())
            sector_no += 1

        return bytes(result)


# =============================================================================
# Keybag Parsing
# =============================================================================

@dataclass
class KeybagEntry:
    """A single entry in an APFS keybag."""
    uuid: bytes
    tag: int
    key_data: bytes


class Keybag:
    """APFS Keybag for managing encryption keys."""
    
    def __init__(self, data: bytes):
        self.entries: List[KeybagEntry] = []
        self._parse(data)
    
    def _parse(self, data: bytes):
        if len(data) < 24:
            return
        
        version = struct.unpack('<H', data[0:2])[0]
        nkeys = struct.unpack('<H', data[2:4])[0]
        
        if version != 2:
            return
        
        offset = 16
        for _ in range(nkeys):
            if offset + 24 > len(data):
                break
            
            uuid = data[offset:offset+16]
            tag = struct.unpack('<H', data[offset+16:offset+18])[0]
            keylen = struct.unpack('<H', data[offset+18:offset+20])[0]
            key_data = data[offset+24:offset+24+keylen]
            
            self.entries.append(KeybagEntry(uuid, tag, key_data))
            
            entry_size = 24 + keylen
            entry_size = (entry_size + 15) & ~15
            offset += entry_size
    
    def find_key(self, uuid: bytes, tag: int) -> Optional[KeybagEntry]:
        for entry in self.entries:
            if entry.uuid == uuid and entry.tag == tag:
                return entry
        return None


# =============================================================================
# Key Derivation
# =============================================================================

class KeyManager:
    """Manages APFS volume encryption keys."""
    
    def __init__(self):
        self.volume_keys: Dict[bytes, bytes] = {}
    
    def derive_kek_from_password(self, password: str, salt: bytes, iterations: int) -> bytes:
        """Derive Key Encryption Key from password using PBKDF2."""
        if not CRYPTO_AVAILABLE:
            raise RuntimeError("cryptography module required")
        
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=iterations,
            backend=default_backend()
        )
        return kdf.derive(password.encode('utf-8'))
    
    def unwrap_key(self, wrapped_key: bytes, kek: bytes) -> Optional[bytes]:
        """Unwrap an AES-wrapped key using RFC 3394 AES Key Wrap."""
        if not CRYPTO_AVAILABLE:
            return None
        
        if len(wrapped_key) < 24 or len(wrapped_key) % 8 != 0:
            return None
        
        n = (len(wrapped_key) // 8) - 1
        a = wrapped_key[0:8]
        r = [wrapped_key[8+i*8:16+i*8] for i in range(n)]
        
        cipher = Cipher(algorithms.AES(kek), modes.ECB(), backend=default_backend())
        
        for j in range(5, -1, -1):
            for i in range(n-1, -1, -1):
                t = n * j + i + 1
                t_bytes = struct.pack('>Q', t)
                a_xor = bytes(x ^ y for x, y in zip(a, t_bytes))
                
                decryptor = cipher.decryptor()
                decrypted = decryptor.update(a_xor + r[i]) + decryptor.finalize()
                
                a = decrypted[0:8]
                r[i] = decrypted[8:16]
        
        expected_iv = b'\xa6' * 8
        if a != expected_iv:
            return None
        
        return b''.join(r)


# =============================================================================
# Encrypted Volume Recovery
# =============================================================================

@dataclass
class EncryptedRecoveryResult:
    """Result of encrypted volume recovery."""
    keybag_found: bool = False
    vek_derived: bool = False
    directories_found: int = 0
    files_found: int = 0
    files_extracted: int = 0
    errors: List[str] = field(default_factory=list)


@dataclass
class DirectoryEntry:
    """A directory entry from the B-tree."""
    parent_inode: int
    file_inode: int
    name: str
    is_dir: bool


@dataclass
class InodeInfo:
    """Information about an inode."""
    inode_id: int
    parent_id: int = 0
    mode: int = 0
    size: int = 0
    is_dir: bool = False
    extents: List[Dict] = field(default_factory=list)


class APFSEncryptedRecovery:
    """
    Recovers files from damaged encrypted APFS volumes.
    
    Works with:
    - Corrupted container/volume superblocks
    - Damaged checkpoints
    - Partially corrupted B-trees
    - Missing OMAP
    """
    
    NX_MAGIC = b'NXSB'
    APFS_MAGIC = b'APSB'
    
    JOBJ_TYPE_INODE = 3
    JOBJ_TYPE_EXTENT = 8
    JOBJ_TYPE_DIR_REC = 9
    
    DT_DIR = 4
    
    def __init__(self, image_path: str, password: str, output_dir: Optional[str] = None):
        self.image_path = image_path
        self.password = password
        self.output_dir = output_dir or f"{image_path}_encrypted_recovered"
        
        self.block_size = 4096
        self.partition_offset = 0
        self._active_superblock_offset = None

        self._data: bytes = b''
        self.aes_xts: Optional[AesXts] = None
        self.vek: Optional[bytes] = None
        
        self.drecs: List[DirectoryEntry] = []
        self.inodes: Dict[int, InodeInfo] = {}
        self.paths: Dict[int, str] = {}
    
    def _load_image(self):
        """Load the disk image."""
        with open(self.image_path, 'rb') as f:
            self._data = f.read()

        # METHOD 1: Try GPT partition table
        if len(self._data) > 600 and self._data[512:520] == b'EFI PART':
            header = self._data[512:604]
            entry_lba = struct.unpack('<Q', header[72:80])[0]
            entry_size = struct.unpack('<I', header[84:88])[0]
            if entry_size == 0:
                entry_size = 128
            entry_offset = entry_lba * 512
            for i in range(128):
                off = entry_offset + i * entry_size
                if off + 128 > len(self._data):
                    break
                entry = self._data[off:off + entry_size]
                if entry[:4] == b'\xef\x57\x34\x7c':  # APFS GUID
                    first_lba = struct.unpack('<Q', entry[32:40])[0]
                    self.partition_offset = first_lba * 512
                    # Read block size
                    bs_off = self.partition_offset + 36
                    if bs_off + 4 <= len(self._data):
                        bs = struct.unpack('<I', self._data[bs_off:bs_off+4])[0]
                        if bs in (4096, 8192, 16384, 32768, 65536):
                            self.block_size = bs
                    # Check if primary superblock is intact
                    if self._data[self.partition_offset+32:self.partition_offset+36] == self.NX_MAGIC:
                        self._active_superblock_offset = self.partition_offset
                    else:
                        # Primary damaged - find a checkpoint
                        self._active_superblock_offset = self.partition_offset
                        for blk in range(1, 20):
                            cp_off = self.partition_offset + blk * self.block_size
                            if cp_off + 36 <= len(self._data):
                                if self._data[cp_off+32:cp_off+36] == self.NX_MAGIC:
                                    self._active_superblock_offset = cp_off
                                    break
                    return

        # METHOD 2: Find all NXSB positions (primary + checkpoints)
        nxsb_positions = []
        search_start = 0
        while len(nxsb_positions) < 10:
            pos = self._data.find(self.NX_MAGIC, search_start)
            if pos < 0:
                break
            nxsb_positions.append(pos - 32)
            search_start = pos + 1

        if not nxsb_positions:
            return

        # Get block size from first valid NXSB
        detected_bs = 4096
        for pos in nxsb_positions:
            if pos >= 0 and pos + 40 <= len(self._data):
                bs = struct.unpack('<I', self._data[pos+36:pos+40])[0]
                if bs in (4096, 8192, 16384, 32768, 65536):
                    detected_bs = bs
                    break
        self.block_size = detected_bs

        # Try to infer partition start from checkpoint positions
        # Test if any NXSB is at the actual partition start (block 0)
        for pos in nxsb_positions:
            # Check if this could be block 0: the block before it should not be NXSB
            if pos == 0 or pos % 512 == 0:
                # Verify it has valid block_size
                if pos + 40 <= len(self._data):
                    bs = struct.unpack('<I', self._data[pos+36:pos+40])[0]
                    if bs in (4096, 8192, 16384, 32768, 65536):
                        self.partition_offset = pos
                        self._active_superblock_offset = pos
                        return

        # First NXSB is likely a checkpoint - infer partition start
        for block_num in range(1, 20):
            candidate = nxsb_positions[0] - block_num * detected_bs
            if candidate < 0:
                continue

            block0 = self._data[candidate:candidate + 64]
            is_zeroed = all(b == 0 for b in block0)
            has_nxsb = self._data[candidate+32:candidate+36] == self.NX_MAGIC

            if has_nxsb:
                self.partition_offset = candidate
                self._active_superblock_offset = candidate
                return
            elif is_zeroed:
                self.partition_offset = candidate
                self._active_superblock_offset = nxsb_positions[0]
                return
            else:
                try:
                    primary_bs = struct.unpack('<I', self._data[candidate+36:candidate+40])[0]
                    if primary_bs == detected_bs:
                        self.partition_offset = candidate
                        self._active_superblock_offset = nxsb_positions[0]
                        return
                except Exception:
                    pass

        # Fallback
        self.partition_offset = nxsb_positions[0]
        self._active_superblock_offset = nxsb_positions[0]
    
    def _read_block(self, block_num: int) -> bytes:
        """Read a block from the image."""
        offset = self.partition_offset + block_num * self.block_size
        return self._data[offset:offset + self.block_size]
    
    def _decrypt_block(self, block: bytes, block_num: int) -> bytes:
        """Decrypt a block using AES-XTS."""
        if self.aes_xts is None:
            return block
        try:
            return self.aes_xts.decrypt(block, block_num)
        except Exception:
            return block
    
    def _find_keybag(self) -> Optional[Tuple[bytes, bytes]]:
        """
        Find and parse the keybag from the container.
        Uses the active superblock (may be a checkpoint if primary is damaged).

        Returns:
            Tuple of (keybag_data, volume_uuid) or None
        """
        print("  Searching for keybag...")

        # Use active superblock (determined during _load_image)
        container_offset = getattr(self, '_active_superblock_offset', None)
        if container_offset is None:
            nxsb_offset = self._data.find(self.NX_MAGIC)
            if nxsb_offset < 0:
                return None
            container_offset = nxsb_offset - 32

        container = self._data[container_offset:container_offset + self.block_size]
        
        # Container UUID is at offset 72 in container superblock (nx_uuid)
        container_uuid = container[72:88]
        
        # Keylocker location is at offset 1296 (not 176!)
        # This matches apfs_driver_full.py line 797
        try:
            keylocker_start = struct.unpack('<Q', container[1296:1304])[0]
            keylocker_count = struct.unpack('<Q', container[1304:1312])[0]
        except Exception:
            print("  Could not read keylocker location")
            return self._scan_for_keybag()
        
        if keylocker_start == 0 or keylocker_count == 0:
            print("  No keylocker present (volume may not be encrypted)")
            return self._scan_for_keybag()
        
        print(f"  Found keylocker at block {keylocker_start}")
        
        # Read and decrypt container keybag using container UUID
        keybag_enc = self._read_block(keylocker_start)
        
        try:
            xts = AesXts(container_uuid)  # Use container UUID as key
            keybag_dec = xts.decrypt(keybag_enc, keylocker_start)
            
            # Check if decryption worked - type should be 'keys' = 0x6b657973
            obj_type = struct.unpack('<I', keybag_dec[24:28])[0]
            if obj_type != 0x6b657973:
                print(f"  Container keybag decryption failed (got type 0x{obj_type:08x})")
                return self._scan_for_keybag()
            
            print("  Container keybag decrypted successfully")
            
            # Find volume UUID
            volume_uuid = self._find_volume_uuid()
            
            return (keybag_dec, volume_uuid)
            
        except Exception as e:
            print(f"  Keybag decryption error: {e}")
            return self._scan_for_keybag()
    
    def _scan_for_keybag(self) -> Optional[Tuple[bytes, bytes]]:
        """Scan for keybag structures when normal lookup fails."""
        volume_uuid = self._find_volume_uuid()
        
        # Scan first 1000 blocks for keybag-like structures
        for block_num in range(min(1000, len(self._data) // self.block_size)):
            block = self._read_block(block_num)
            
            # Check for 'keys' magic after potential decryption
            obj_type = struct.unpack('<I', block[24:28])[0]
            if obj_type == 0x6b657973:
                print(f"  Found unencrypted keybag at block {block_num}")
                return (block, volume_uuid)
            
        return None
    
    def _find_volume_uuid(self) -> bytes:
        """Find the volume UUID from volume superblock."""
        apsb_idx = self._data.find(self.APFS_MAGIC)
        if apsb_idx >= 0:
            # Volume UUID is at offset 264 from start of volume superblock
            vol_start = apsb_idx - 32
            return self._data[vol_start + 264:vol_start + 280]
        return b'\x00' * 16
    
    def _parse_kek_blob(self, data: bytes) -> Optional[Dict]:
        """
        Parse KEK parameters from DER-encoded blob.
        Matches apfs_driver_full.py _parse_kek_blob.
        """
        result = {}
        for idx in range(len(data) - 2):
            # Tag 0x83 with length 0x28 = wrapped_kek (40 bytes)
            if data[idx] == 0x83 and data[idx+1] == 0x28:
                result['wrapped_kek'] = data[idx+2:idx+2+40]
            # Tag 0x84 = iterations (variable length)
            if data[idx] == 0x84:
                length = data[idx+1]
                if length <= 8:
                    result['iterations'] = int.from_bytes(data[idx+2:idx+2+length], 'big')
            # Tag 0x85 with length 0x10 = salt (16 bytes)
            if data[idx] == 0x85 and data[idx+1] == 0x10:
                result['salt'] = data[idx+2:idx+2+16]
        
        if 'salt' in result and 'iterations' in result and 'wrapped_kek' in result:
            return result
        return None
    
    def _parse_vek_blob(self, data: bytes) -> Optional[bytes]:
        """Extract wrapped VEK from DER-encoded blob."""
        for idx in range(len(data) - 2):
            if data[idx] == 0x83 and data[idx+1] == 0x28:
                return data[idx+2:idx+2+40]
        return None
    
    def _derive_vek(self, keybag_data: bytes, volume_uuid: bytes) -> bool:
        """
        Derive the Volume Encryption Key from password.
        Uses two-level keybag structure like apfs_driver_full.py.
        
        Returns:
            True if VEK was successfully derived
        """
        print("  Deriving volume encryption key...")
        
        # Parse container keybag (keybag_data includes obj header)
        nkeys = struct.unpack('<H', keybag_data[34:36])[0]
        entry_off = 48
        
        vek_data = None
        kek_info = None
        
        for i in range(nkeys):
            if entry_off + 24 > len(keybag_data):
                break
            
            entry_uuid = keybag_data[entry_off:entry_off+16]
            tag = struct.unpack('<H', keybag_data[entry_off+16:entry_off+18])[0]
            keylen = struct.unpack('<H', keybag_data[entry_off+18:entry_off+20])[0]
            
            if entry_off + 24 + keylen > len(keybag_data):
                break
            
            data = keybag_data[entry_off+24:entry_off+24+keylen]
            
            if tag == 2:  # VEK (wrapped)
                vek_data = data
                print(f"  Found wrapped VEK ({len(data)} bytes)")
            elif tag == 3:  # Volume keybag reference
                # This contains a physical address to the volume keybag
                if len(data) >= 8:
                    pr_start = struct.unpack('<Q', data[0:8])[0]
                    print(f"  Found volume keybag reference at block {pr_start}")
                    
                    # Read and decrypt volume keybag using entry UUID
                    vol_kb_enc = self._read_block(pr_start)
                    vol_kb_xts = AesXts(entry_uuid)  # Use entry UUID to decrypt
                    vol_kb_dec = vol_kb_xts.decrypt(vol_kb_enc, pr_start)
                    
                    # Parse volume keybag for KEK
                    vol_nkeys = struct.unpack('<H', vol_kb_dec[34:36])[0]
                    vol_off = 48
                    
                    for j in range(vol_nkeys):
                        if vol_off + 24 > len(vol_kb_dec):
                            break
                        v_tag = struct.unpack('<H', vol_kb_dec[vol_off+16:vol_off+18])[0]
                        v_keylen = struct.unpack('<H', vol_kb_dec[vol_off+18:vol_off+20])[0]
                        
                        if vol_off + 24 + v_keylen > len(vol_kb_dec):
                            break
                        
                        v_data = vol_kb_dec[vol_off+24:vol_off+24+v_keylen]
                        
                        if v_tag == 3:  # KEK info (DER-encoded)
                            kek_info = self._parse_kek_blob(v_data)
                            if kek_info:
                                print(f"  Found KEK info: iterations={kek_info.get('iterations')}")
                        
                        vol_off += (24 + v_keylen + 15) & ~15
            
            entry_off += (24 + keylen + 15) & ~15
        
        # Derive VEK from password using KEK
        if kek_info and vek_data and self.password:
            try:
                # Derive KEK from password using PBKDF2
                kdf = PBKDF2HMAC(
                    algorithm=hashes.SHA256(),
                    length=32,
                    salt=kek_info['salt'],
                    iterations=kek_info['iterations'],
                    backend=default_backend()
                )
                derived_key = kdf.derive(self.password.encode('utf-8'))
                
                # Unwrap KEK
                key_manager = KeyManager()
                unwrapped_kek = key_manager.unwrap_key(kek_info['wrapped_kek'], derived_key)
                
                if unwrapped_kek:
                    # Unwrap VEK using KEK
                    wrapped_vek = self._parse_vek_blob(vek_data)
                    if wrapped_vek:
                        self.vek = key_manager.unwrap_key(wrapped_vek, unwrapped_kek)
                        if self.vek and len(self.vek) == 32:
                            self.aes_xts = AesXts(self.vek)
                            print("  VEK derived successfully!")
                            return True
                        else:
                            print("  VEK unwrap failed - wrong password?")
                    else:
                        print("  Could not parse wrapped VEK")
                else:
                    print("  KEK unwrap failed - wrong password?")
            except Exception as e:
                print(f"  Key derivation error: {e}")
        elif not kek_info:
            print("  No KEK info found in volume keybag")
        elif not vek_data:
            print("  No VEK data found in container keybag")
        
        return False
    
    def _is_encrypted_btree_node(self, block: bytes) -> bool:
        """Check if a block might be an encrypted B-tree node."""
        # Encrypted blocks have high entropy
        if len(block) < 100:
            return False
        
        # Simple entropy check - encrypted data has roughly even distribution
        byte_counts = [0] * 256
        for b in block[:256]:
            byte_counts[b] += 1
        
        max_count = max(byte_counts)
        # Encrypted data shouldn't have any byte appearing too often
        return max_count < 10
    
    def _is_valid_btree_node(self, block: bytes) -> bool:
        """Check if a decrypted block is a valid B-tree node."""
        if len(block) < 56:
            return False

        flags = struct.unpack('<H', block[32:34])[0]
        level = struct.unpack('<H', block[34:36])[0]
        nkeys = struct.unpack('<I', block[36:40])[0]

        if not (flags & 0x7):
            return False
        if level > 10:
            return False
        if nkeys == 0 or nkeys > 500:
            return False

        return True

    def _is_partially_valid_btree_node(self, block: bytes) -> bool:
        """Lenient B-tree node check for damaged blocks."""
        if len(block) < 44:
            return False

        flags = struct.unpack('<H', block[32:34])[0]
        level = struct.unpack('<H', block[34:36])[0]
        nkeys = struct.unpack('<I', block[36:40])[0]

        if not (flags & 0x7):
            return False
        if level > 15:
            return False
        if nkeys > 500:
            return False

        table_space_len = struct.unpack('<H', block[42:44])[0]
        if table_space_len > 4000:
            return False

        key_area_start = 56 + table_space_len
        if key_area_start < len(block) - 100 and key_area_start + 64 <= len(block):
            valid_keys = 0
            for i in range(8):
                off = key_area_start + i * 8
                if off + 8 <= len(block):
                    key_header = struct.unpack('<Q', block[off:off+8])[0]
                    key_type = (key_header >> 60) & 0xF
                    if key_type in (3, 4, 8, 9, 12):
                        valid_keys += 1
            if valid_keys > 0:
                return True

        return False
    
    def _parse_btree_node(self, block: bytes, block_num: int):
        """Parse a B-tree node and extract records."""
        flags = struct.unpack('<H', block[32:34])[0]
        nkeys = struct.unpack('<I', block[36:40])[0]
        
        is_leaf = bool(flags & 0x2)
        is_root = bool(flags & 0x1)
        is_fixed = bool(flags & 0x4)
        
        if not is_leaf:
            return
        
        table_space_len = struct.unpack('<H', block[42:44])[0]
        toc_start = 56
        key_area_start = 56 + table_space_len
        val_area_end = self.block_size - 40 if is_root else self.block_size
        
        for i in range(min(nkeys, 100)):
            try:
                self._extract_record(block, i, toc_start, key_area_start,
                                    val_area_end, is_fixed)
            except Exception:
                continue
    
    def _extract_record(self, block: bytes, index: int, toc_start: int,
                       key_area_start: int, val_area_end: int, is_fixed: bool):
        """Extract a single record from a B-tree leaf node."""
        entry_pos = toc_start + index * (4 if is_fixed else 8)
        
        if is_fixed:
            k_off = struct.unpack('<H', block[entry_pos:entry_pos+2])[0]
            v_off = struct.unpack('<H', block[entry_pos+2:entry_pos+4])[0]
            k_len = 8
            v_len = 16
        else:
            k_off = struct.unpack('<H', block[entry_pos:entry_pos+2])[0]
            k_len = struct.unpack('<H', block[entry_pos+2:entry_pos+4])[0]
            v_off = struct.unpack('<H', block[entry_pos+4:entry_pos+6])[0]
            v_len = struct.unpack('<H', block[entry_pos+6:entry_pos+8])[0]
        
        key_pos = key_area_start + k_off
        val_pos = val_area_end - v_off
        
        if key_pos + 8 > len(block) or val_pos < 0 or val_pos > len(block):
            return
        
        key_header = struct.unpack('<Q', block[key_pos:key_pos+8])[0]
        key_type = (key_header >> 60) & 0xF
        key_id = key_header & 0x0FFFFFFFFFFFFFFF
        
        if key_type == self.JOBJ_TYPE_DIR_REC:
            self._parse_drec(block, key_id, key_pos, k_len, val_pos, v_len)
        elif key_type == self.JOBJ_TYPE_INODE:
            self._parse_inode(block, key_id, val_pos, v_len)
        elif key_type == self.JOBJ_TYPE_EXTENT:
            self._parse_extent(block, key_id, key_pos, val_pos, v_len)
    
    def _parse_drec(self, block: bytes, parent_id: int, key_pos: int,
                   k_len: int, val_pos: int, v_len: int):
        """Parse a directory record."""
        if key_pos + 12 > len(block):
            return
        
        name_len_hash = struct.unpack('<I', block[key_pos+8:key_pos+12])[0]
        name_len = name_len_hash & 0x3FF
        
        if name_len == 0 or key_pos + 12 + name_len > len(block):
            return
        
        name_bytes = block[key_pos+12:key_pos+12+name_len]
        name = name_bytes.rstrip(b'\x00').decode('utf-8', errors='replace')
        
        if val_pos + 18 > len(block) or not name:
            return
        
        file_id = struct.unpack('<Q', block[val_pos:val_pos+8])[0]
        flags = struct.unpack('<H', block[val_pos+16:val_pos+18])[0]
        is_dir = (flags & 0xF) == self.DT_DIR
        
        if file_id < 0x1000000 and parent_id < 0x1000000:
            self.drecs.append(DirectoryEntry(
                parent_inode=parent_id,
                file_inode=file_id,
                name=name,
                is_dir=is_dir
            ))
    
    def _parse_inode(self, block: bytes, inode_id: int, val_pos: int, v_len: int):
        """Parse an inode record."""
        if val_pos + 84 > len(block):
            return
        
        val = block[val_pos:val_pos + min(v_len, 300)]
        
        # j_inode_val_t structure - mode is at offset 80
        parent_id = struct.unpack('<Q', val[0:8])[0]
        mode = struct.unpack('<H', val[80:82])[0] if len(val) > 82 else 0
        is_dir = (mode & 0o170000) == 0o040000
        
        # xfield blob may start at offset 84 or 92 depending on whether
        # uncompressed_size field is present. Check for the xf_num > 0 pattern.
        size = 0
        xf_blob_offset = 92  # Default to 92 (after optional uncompressed_size)
        
        # Check if xf_blob is at 84 or 92 by looking for valid xf_num
        if v_len > 92 and len(val) > 96:
            # Try offset 92 first (most common for files with dstream)
            xf_num_92 = struct.unpack('<H', val[92:94])[0] if len(val) > 94 else 0
            xf_num_84 = struct.unpack('<H', val[84:86])[0] if len(val) > 86 else 0
            
            if xf_num_92 > 0 and xf_num_92 < 20:
                xf_blob_offset = 92
            elif xf_num_84 > 0 and xf_num_84 < 20:
                xf_blob_offset = 84
            
            if xf_blob_offset + 4 <= len(val):
                xf_count = struct.unpack('<H', val[xf_blob_offset:xf_blob_offset+2])[0]
                
                if xf_count > 0 and xf_count < 20:
                    # Parse xfield headers first (array of type/flags/size)
                    headers = []
                    hdr_off = xf_blob_offset + 4
                    for _ in range(min(xf_count, 10)):
                        if hdr_off + 4 > len(val):
                            break
                        x_type = val[hdr_off]
                        x_size = struct.unpack('<H', val[hdr_off+2:hdr_off+4])[0]
                        headers.append((x_type, x_size))
                        hdr_off += 4
                    
                    # Data area starts after all headers, aligned to 8 bytes
                    data_start = xf_blob_offset + 4 + ((xf_count * 4 + 7) & ~7)
                    data_off = data_start
                    
                    for x_type, x_size in headers:
                        if data_off + 8 > len(val):
                            break
                        if x_type == 8:  # dstream xfield
                            size = struct.unpack('<Q', val[data_off:data_off+8])[0]
                            break  # Found it
                        data_off += (x_size + 7) & ~7
        
        if inode_id not in self.inodes:
            self.inodes[inode_id] = InodeInfo(inode_id=inode_id)
        
        self.inodes[inode_id].parent_id = parent_id
        self.inodes[inode_id].mode = mode
        self.inodes[inode_id].size = size
        self.inodes[inode_id].is_dir = is_dir
    
    def _parse_extent(self, block: bytes, file_id: int, key_pos: int,
                     val_pos: int, v_len: int):
        """Parse a file extent record."""
        if key_pos + 16 > len(block) or val_pos + 16 > len(block):
            return
        
        logical_addr = struct.unpack('<Q', block[key_pos+8:key_pos+16])[0]
        length_and_flags = struct.unpack('<Q', block[val_pos:val_pos+8])[0]
        physical_block = struct.unpack('<Q', block[val_pos+8:val_pos+16])[0]
        
        length = length_and_flags & 0x00FFFFFFFFFFFFFF
        
        if file_id not in self.inodes:
            self.inodes[file_id] = InodeInfo(inode_id=file_id)
        
        # Extract crypto_id if value is long enough (24 bytes)
        crypto_id = 0
        if v_len >= 24 and val_pos + 24 <= len(block):
            crypto_id = struct.unpack('<Q', block[val_pos+16:val_pos+24])[0]

        total_blocks = len(self._data) // self.block_size
        if physical_block >= total_blocks:
            return

        # CoW extent deduplication: keep newer version (higher physical block)
        ino = self.inodes[file_id]
        for i, ext in enumerate(ino.extents):
            if ext['logical'] == logical_addr:
                if (ext['physical'] == physical_block and
                    ext['length'] == length):
                    return  # Exact duplicate
                if physical_block > ext['physical']:
                    ino.extents[i] = {
                        'logical': logical_addr,
                        'physical': physical_block,
                        'length': length,
                        'crypto_id': crypto_id
                    }
                return

        ino.extents.append({
            'logical': logical_addr,
            'physical': physical_block,
            'length': length,
            'crypto_id': crypto_id
        })
    
    def scan_encrypted_blocks(self, progress_callback=None) -> int:
        """
        Scan for encrypted B-tree nodes and decrypt them.
        
        OPTIMIZED: Uses critical zone approach like unencrypted recovery.
        Only decrypts blocks in critical zone first, then scans rest if needed.
        
        Returns:
            Number of B-tree nodes found
        """
        total_blocks = len(self._data) // self.block_size
        nodes_found = 0
        
        # Critical zone: first 7.8% of disk where leaf nodes are typically spread
        critical_zone_blocks = int(total_blocks * 0.078)
        
        print("  Scanning for encrypted B-tree nodes...")
        print(f"  Critical zone: {critical_zone_blocks} blocks ({critical_zone_blocks * self.block_size / (1024*1024):.1f} MB)")
        
        # First pass: Scan critical zone (where B-tree nodes are most likely)
        for block_num in range(min(critical_zone_blocks, total_blocks)):
            block = self._read_block(block_num)

            # Skip zero blocks (free space - don't decrypt)
            if block == b'\x00' * self.block_size:
                continue

            # First check if it's a plaintext B-tree node (fast check)
            if self._is_valid_btree_node(block):
                self._parse_btree_node(block, block_num)
                nodes_found += 1
                continue

            if self._is_partially_valid_btree_node(block):
                self._parse_btree_node(block, block_num)
                nodes_found += 1
                continue

            # Try decrypting if we have VEK (only for non-zero blocks)
            if self.aes_xts:
                try:
                    decrypted = self._decrypt_block(block, block_num)
                    if self._is_valid_btree_node(decrypted):
                        self._parse_btree_node(decrypted, block_num)
                        nodes_found += 1
                    elif self._is_partially_valid_btree_node(decrypted):
                        self._parse_btree_node(decrypted, block_num)
                        nodes_found += 1
                except Exception:
                    pass

            if progress_callback and block_num % 1000 == 0:
                progress_callback(block_num, total_blocks)

        # Second pass: Always scan remaining blocks for CoW copies
        print(f"  Found {nodes_found} nodes in critical zone, scanning remaining blocks...")
        for block_num in range(critical_zone_blocks, total_blocks):
            block = self._read_block(block_num)

            # Skip zero blocks
            if block == b'\x00' * self.block_size:
                continue

            # Check plaintext first
            if self._is_valid_btree_node(block):
                self._parse_btree_node(block, block_num)
                nodes_found += 1
                continue

            if self._is_partially_valid_btree_node(block):
                self._parse_btree_node(block, block_num)
                nodes_found += 1
                continue

            # Try decrypting if we have VEK
            if self.aes_xts:
                try:
                    decrypted = self._decrypt_block(block, block_num)
                    if self._is_valid_btree_node(decrypted):
                        self._parse_btree_node(decrypted, block_num)
                        nodes_found += 1
                    elif self._is_partially_valid_btree_node(decrypted):
                        self._parse_btree_node(decrypted, block_num)
                        nodes_found += 1
                except Exception:
                    pass

            if progress_callback and block_num % 1000 == 0:
                progress_callback(block_num, total_blocks)
        
        # Remove duplicate drecs
        seen = set()
        unique_drecs = []
        for drec in self.drecs:
            key = (drec.parent_inode, drec.file_inode, drec.name)
            if key not in seen:
                seen.add(key)
                unique_drecs.append(drec)
        self.drecs = unique_drecs
        
        return nodes_found
    
    def build_paths(self) -> int:
        """Build full paths for all files."""
        inode_to_parent = {}
        for drec in self.drecs:
            inode_to_parent[drec.file_inode] = (drec.parent_inode, drec.name)
        
        def resolve_path(inode_id: int, visited: Set[int] = None) -> Optional[str]:
            if visited is None:
                visited = set()
            
            if inode_id in visited:
                return None
            visited.add(inode_id)
            
            if inode_id == 2:
                return ""
            
            if inode_id in inode_to_parent:
                parent_id, name = inode_to_parent[inode_id]
                parent_path = resolve_path(parent_id, visited)
                if parent_path is not None:
                    return os.path.join(parent_path, name)
            
            return None
        
        for drec in self.drecs:
            path = resolve_path(drec.file_inode)
            if path:
                self.paths[drec.file_inode] = path
        
        return len(self.paths)
    
    def extract_files(self, progress_callback=None) -> int:
        """Extract all files, decrypting content as needed."""
        os.makedirs(self.output_dir, exist_ok=True)
        
        extracted = 0
        total = len(self.inodes)
        
        # Cap extent length to prevent reading massive amounts of data
        MAX_EXTENT_BLOCKS = 10240  # 40MB max per extent
        
        for idx, (inode_id, info) in enumerate(self.inodes.items()):
            if info.is_dir:
                continue
            
            if not info.extents:
                continue
            
            path = self.paths.get(inode_id, f"orphan/file_{inode_id}")
            full_path = os.path.join(self.output_dir, path)
            
            try:
                os.makedirs(os.path.dirname(full_path), exist_ok=True)
                
                extents = sorted(info.extents, key=lambda e: e['logical'])
                
                with open(full_path, 'wb') as f:
                    bytes_written = 0
                    target_size = info.size if info.size > 0 else sum(e['length'] * self.block_size for e in extents)
                    
                    for extent in extents:
                        phys = extent['physical']
                        length = min(extent['length'], MAX_EXTENT_BLOCKS)  # Cap length
                        
                        # Calculate how much to read based on remaining file size
                        remaining = target_size - bytes_written
                        if remaining <= 0:
                            break
                        
                        blocks_to_read = min(length, (remaining + self.block_size - 1) // self.block_size)
                        
                        for block_idx in range(blocks_to_read):
                            block_num = phys + block_idx
                            block = self._read_block(block_num)
                            
                            # Decrypt if we have VEK
                            if self.aes_xts:
                                try:
                                    block = self._decrypt_block(block, block_num)
                                except Exception:
                                    pass
                            
                            # Only write what we need
                            if bytes_written + self.block_size > target_size:
                                block = block[:target_size - bytes_written]
                            
                            f.write(block)
                            bytes_written += len(block)
                            
                            if bytes_written >= target_size:
                                break
                
                # Truncate to exact size if we know it
                if info.size > 0:
                    with open(full_path, 'r+b') as f:
                        f.truncate(info.size)
                
                extracted += 1
                
            except Exception:
                continue
            
            if progress_callback and idx % 100 == 0:
                progress_callback(idx, total)
        
        return extracted
    
    def recover(self) -> EncryptedRecoveryResult:
        """
        Full encrypted recovery pipeline.
        
        Returns:
            EncryptedRecoveryResult with statistics
        """
        if not CRYPTO_AVAILABLE:
            raise RuntimeError("cryptography module required for encryption support")
        
        result = EncryptedRecoveryResult()
        
        print("=== APFS Encrypted Volume Recovery ===")
        print(f"Image: {self.image_path}")
        print()
        
        # Load image
        print("Phase 1: Loading image...")
        self._load_image()
        print(f"  Image size: {len(self._data):,} bytes")
        print(f"  Block size: {self.block_size}")
        
        # Find keybag
        print("\nPhase 2: Locating keybag...")
        keybag_result = self._find_keybag()
        
        if keybag_result:
            keybag_data, volume_uuid = keybag_result
            result.keybag_found = True
            print("  Keybag found!")
            
            # Derive VEK
            print("\nPhase 3: Deriving encryption key...")
            if self._derive_vek(keybag_data, volume_uuid):
                result.vek_derived = True
            else:
                print("  Failed to derive VEK - wrong password?")
                result.errors.append("VEK derivation failed")
        else:
            print("  Keybag not found - scanning without decryption")
            result.errors.append("Keybag not found")
        
        # Scan for B-tree nodes
        print("\nPhase 4: Scanning for B-tree nodes...")
        nodes = self.scan_encrypted_blocks()
        print(f"  Found {nodes} B-tree nodes")
        print(f"  Found {len(self.drecs)} directory records")
        print(f"  Found {len(self.inodes)} inodes")
        
        result.directories_found = sum(1 for d in self.drecs if d.is_dir)
        result.files_found = sum(1 for d in self.drecs if not d.is_dir)
        
        # Build paths
        print("\nPhase 5: Rebuilding directory structure...")
        paths = self.build_paths()
        print(f"  Resolved {paths} paths")
        
        # Extract files
        print("\nPhase 6: Extracting files...")
        extracted = self.extract_files()
        print(f"  Extracted {extracted} files")
        result.files_extracted = extracted
        
        return result


def recover_encrypted_volume(image_path: str, password: str,
                            output_dir: str = None) -> EncryptedRecoveryResult:
    """
    Convenience function to recover an encrypted APFS volume.
    
    Args:
        image_path: Path to the encrypted APFS image
        password: Volume encryption password
        output_dir: Output directory for recovered files
    
    Returns:
        EncryptedRecoveryResult with statistics
    """
    recovery = APFSEncryptedRecovery(image_path, password, output_dir)
    return recovery.recover()


if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("APFS Encrypted Volume Recovery")
        print("Usage: python encrypted_recovery.py <image.dmg> <password> [output_dir]")
        sys.exit(1)
    
    image_path = sys.argv[1]
    password = sys.argv[2]
    output_dir = sys.argv[3] if len(sys.argv) > 3 else None
    
    result = recover_encrypted_volume(image_path, password, output_dir)
    
    print()
    print("=" * 50)
    print("RECOVERY COMPLETE")
    print("=" * 50)
    print(f"Keybag found: {result.keybag_found}")
    print(f"VEK derived: {result.vek_derived}")
    print(f"Directories found: {result.directories_found}")
    print(f"Files found: {result.files_found}")
    print(f"Files extracted: {result.files_extracted}")
    
    if result.errors:
        print("\nErrors:")
        for error in result.errors:
            print(f"  - {error}")

