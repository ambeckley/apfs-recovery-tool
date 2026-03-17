#!/usr/bin/env python3
"""
APFS Damage Simulator
=====================

Simulates various types of filesystem corruption for testing recovery algorithms.
Each damage type represents a realistic failure scenario.

WARNING: This tool modifies disk images! Always work with copies!
"""

import os
import sys
import struct
import random
import shutil
from dataclasses import dataclass
from typing import Optional, List, Tuple
from enum import Enum, auto


class DamageType(Enum):
    """Types of damage that can be inflicted on an APFS filesystem."""
    
    # Container-level damage
    CONTAINER_SUPERBLOCK_ZERO = auto()       # Zero out primary superblock
    CONTAINER_SUPERBLOCK_MAGIC = auto()      # Corrupt NXSB magic
    CONTAINER_SUPERBLOCK_CHECKSUM = auto()   # Invalid checksum
    CONTAINER_ALL_CHECKPOINTS = auto()       # Damage all checkpoint superblocks
    
    # Volume-level damage
    VOLUME_SUPERBLOCK_ZERO = auto()          # Zero out volume superblock
    VOLUME_SUPERBLOCK_MAGIC = auto()         # Corrupt APSB magic
    VOLUME_OMAP_CORRUPT = auto()             # Corrupt OMAP root
    
    # B-tree damage
    BTREE_ROOT_ZERO = auto()                 # Zero out root tree node
    BTREE_ROOT_MAGIC = auto()                # Corrupt B-tree node header
    BTREE_TOC_SCRAMBLE = auto()              # Scramble TOC entries
    BTREE_LEAF_DELETE = auto()               # Delete random leaf nodes
    BTREE_KEYS_CORRUPT = auto()              # Corrupt key data
    
    # File/directory damage
    DREC_DELETE = auto()                     # Delete directory records
    INODE_CORRUPT = auto()                   # Corrupt inode entries
    EXTENT_DELETE = auto()                   # Delete extent records
    
    # Data damage
    FILE_DATA_OVERWRITE = auto()             # Overwrite file data blocks
    FILE_DATA_PARTIAL = auto()               # Partial overwrite
    RANDOM_BLOCKS = auto()                   # Random block corruption
    
    # Structural damage
    GPT_CORRUPT = auto()                     # Corrupt GPT header
    PARTITION_TABLE = auto()                 # Damage partition table
    
    # Severe damage scenarios
    SEVERE_HEAD_CRASH = auto()               # Large head crash (many blocks)
    MULTIPLE_LEAF_DESTRUCTION = auto()       # Destroy many leaf nodes
    CASCADING_CORRUPTION = auto()            # Multiple simultaneous damage types
    CRITICAL_ZONE_DESTRUCTION = auto()       # Destroy critical zone (first 8%)
    TOTAL_STRUCTURE_DAMAGE = auto()          # Damage superblock + OMAP + B-tree root

    # Additional damage scenarios
    KEYBAG_DESTROY = auto()                  # Destroy container/volume keybag blocks
    BITMAP_CORRUPT = auto()                  # Corrupt space manager bitmap
    CHECKPOINT_MAP_DESTROY = auto()          # Destroy checkpoint mapping blocks
    MIDDLE_THIRD_WIPE = auto()               # Wipe middle third of partition
    SCATTERED_BIT_ROT = auto()               # Bit rot across many blocks (1-2 bits per block)
    TAIL_CRASH = auto()                      # Head crash at END of disk
    INTERLEAVED_ZERO = auto()                # Zero every other block in metadata region
    ALL_SUPERBLOCKS_DESTROY = auto()         # Destroy container + all volume superblocks
    OMAP_AND_CATALOG_DESTROY = auto()        # Destroy both OMAP and catalog B-tree roots
    EXTENT_OVERFLOW_CORRUPT = auto()         # Corrupt extent overflow records specifically


@dataclass
class DamageReport:
    """Report of damage inflicted on a filesystem."""
    damage_type: DamageType
    description: str
    blocks_affected: List[int]
    bytes_modified: int
    original_data: Optional[bytes] = None  # For potential undo


class APFSDamageSimulator:
    """
    Simulates various types of APFS filesystem damage for recovery testing.
    """
    
    # APFS magic constants
    NX_MAGIC = b'NXSB'
    APFS_MAGIC = b'APSB'
    
    def __init__(self, image_path: str):
        self.image_path = image_path
        self.block_size = 4096
        self.partition_offset = 0
        self.damage_history: List[DamageReport] = []
        
    def _find_partition(self):
        """Find the APFS partition offset."""
        with open(self.image_path, 'rb') as f:
            file_size = f.seek(0, 2)
            f.seek(0)
            
            # Check for raw APFS at offset 0
            f.seek(32)
            if f.read(4) == self.NX_MAGIC:
                self.partition_offset = 0
                f.seek(36)
                bs = struct.unpack('<I', f.read(4))[0]
                if bs >= 4096 and bs <= 65536:
                    self.block_size = bs
                return
            
            # Check for GPT and parse partition table
            f.seek(512)
            if f.read(8) == b'EFI PART':
                # Read GPT header
                f.seek(512)
                header = f.read(92)
                if len(header) >= 92:
                    # Get partition entry LBA (offset 72 in GPT header)
                    entry_lba = struct.unpack('<Q', header[72:80])[0]
                    entry_size = struct.unpack('<I', header[84:88])[0]
                    
                    # Read partition entries
                    f.seek(entry_lba * 512)
                    for i in range(128):
                        entry = f.read(entry_size if entry_size > 0 else 128)
                        if len(entry) < 128:
                            break
                        
                        # Check type GUID (first 16 bytes)
                        type_guid = entry[:16]
                        # APFS GUID: 7C3457EF-0000-11AA-AA11-00306543ECAC
                        if type_guid[:4] == b'\xef\x57\x34\x7c':
                            # Get first LBA (offset 32 in partition entry)
                            if len(entry) >= 40:
                                first_lba = struct.unpack('<Q', entry[32:40])[0]
                                self.partition_offset = first_lba * 512
                                # Read block size from superblock
                                f.seek(self.partition_offset + 36)
                                bs = struct.unpack('<I', f.read(4))[0]
                                if bs >= 4096 and bs <= 65536:
                                    self.block_size = bs
                                return
            
            # Fallback: Search for NXSB in chunks (handles large images)
            chunk_size = 50 * 1024 * 1024  # 50MB chunks
            search_limit = min(file_size, 500 * 1024 * 1024)  # Search up to 500MB
            offset = 0
            
            while offset < search_limit:
                f.seek(offset)
                data = f.read(chunk_size)
                idx = data.find(self.NX_MAGIC)
                if idx >= 0:
                    self.partition_offset = offset + idx - 32
                    # Read block size
                    f.seek(self.partition_offset + 36)
                    bs = struct.unpack('<I', f.read(4))[0]
                    if bs >= 4096 and bs <= 65536:
                        self.block_size = bs
                    return
                offset += chunk_size - 100  # Small overlap
                
        raise ValueError("Could not find APFS partition")
    
    def _read_block(self, block_num: int) -> bytes:
        """Read a block from the image."""
        with open(self.image_path, 'rb') as f:
            f.seek(self.partition_offset + block_num * self.block_size)
            return f.read(self.block_size)
    
    def _write_block(self, block_num: int, data: bytes):
        """Write a block to the image."""
        with open(self.image_path, 'r+b') as f:
            f.seek(self.partition_offset + block_num * self.block_size)
            f.write(data)
    
    def _get_container_superblock(self) -> Tuple[int, bytes]:
        """Get the container superblock block number and data."""
        data = self._read_block(0)
        if data[32:36] == self.NX_MAGIC:
            return 0, data
        raise ValueError("Container superblock not found at block 0")
    
    def _get_checkpoint_info(self, container_sb: bytes) -> Tuple[int, int, int, int]:
        """Extract checkpoint descriptor and data area info.

        nx_superblock_t layout:
          offset 96:  nx_xp_desc_base (paddr_t / int64)
          offset 104: nx_xp_data_base (paddr_t / int64)
          offset 112: nx_xp_desc_blocks (uint32)
          offset 116: nx_xp_data_blocks (uint32)
        """
        xp_desc_base = struct.unpack('<q', container_sb[96:104])[0]
        xp_data_base = struct.unpack('<q', container_sb[104:112])[0]
        xp_desc_blocks = struct.unpack('<I', container_sb[112:116])[0]
        xp_data_blocks = struct.unpack('<I', container_sb[116:120])[0]
        return xp_desc_base, xp_desc_blocks, xp_data_base, xp_data_blocks
    
    def inflict_damage(self, damage_type: DamageType, **kwargs) -> DamageReport:
        """
        Inflict specific type of damage on the filesystem.
        
        Returns a DamageReport describing what was modified.
        """
        self._find_partition()
        
        damage_methods = {
            DamageType.CONTAINER_SUPERBLOCK_ZERO: self._damage_container_sb_zero,
            DamageType.CONTAINER_SUPERBLOCK_MAGIC: self._damage_container_sb_magic,
            DamageType.CONTAINER_SUPERBLOCK_CHECKSUM: self._damage_container_sb_checksum,
            DamageType.CONTAINER_ALL_CHECKPOINTS: self._damage_all_checkpoints,
            DamageType.VOLUME_SUPERBLOCK_ZERO: self._damage_volume_sb_zero,
            DamageType.VOLUME_SUPERBLOCK_MAGIC: self._damage_volume_sb_magic,
            DamageType.VOLUME_OMAP_CORRUPT: self._damage_volume_omap,
            DamageType.BTREE_ROOT_ZERO: self._damage_btree_root_zero,
            DamageType.BTREE_ROOT_MAGIC: self._damage_btree_root_magic,
            DamageType.BTREE_TOC_SCRAMBLE: self._damage_btree_toc,
            DamageType.BTREE_LEAF_DELETE: self._damage_btree_leaves,
            DamageType.BTREE_KEYS_CORRUPT: self._damage_btree_keys,
            DamageType.DREC_DELETE: self._damage_drec_delete,
            DamageType.INODE_CORRUPT: self._damage_inode_corrupt,
            DamageType.EXTENT_DELETE: self._damage_extent_delete,
            DamageType.FILE_DATA_OVERWRITE: self._damage_file_data,
            DamageType.FILE_DATA_PARTIAL: self._damage_file_partial,
            DamageType.RANDOM_BLOCKS: self._damage_random_blocks,
            DamageType.GPT_CORRUPT: self._damage_gpt,
            DamageType.PARTITION_TABLE: self._damage_partition_table,
            DamageType.SEVERE_HEAD_CRASH: self._damage_severe_head_crash,
            DamageType.MULTIPLE_LEAF_DESTRUCTION: self._damage_multiple_leaves,
            DamageType.CASCADING_CORRUPTION: self._damage_cascading,
            DamageType.CRITICAL_ZONE_DESTRUCTION: self._damage_critical_zone,
            DamageType.TOTAL_STRUCTURE_DAMAGE: self._damage_total_structure,
            DamageType.KEYBAG_DESTROY: self._damage_keybag,
            DamageType.BITMAP_CORRUPT: self._damage_bitmap,
            DamageType.CHECKPOINT_MAP_DESTROY: self._damage_checkpoint_map,
            DamageType.MIDDLE_THIRD_WIPE: self._damage_middle_third,
            DamageType.SCATTERED_BIT_ROT: self._damage_bit_rot,
            DamageType.TAIL_CRASH: self._damage_tail_crash,
            DamageType.INTERLEAVED_ZERO: self._damage_interleaved_zero,
            DamageType.ALL_SUPERBLOCKS_DESTROY: self._damage_all_superblocks,
            DamageType.OMAP_AND_CATALOG_DESTROY: self._damage_omap_and_catalog,
            DamageType.EXTENT_OVERFLOW_CORRUPT: self._damage_extent_overflow,
        }
        
        method = damage_methods.get(damage_type)
        if not method:
            raise ValueError(f"Unknown damage type: {damage_type}")
        
        report = method(**kwargs)
        self.damage_history.append(report)
        return report
    
    # ==================== Container Damage Methods ====================
    
    def _damage_container_sb_zero(self, **kwargs) -> DamageReport:
        """Zero out the primary container superblock at block 0."""
        original = self._read_block(0)
        zeros = b'\x00' * self.block_size
        self._write_block(0, zeros)
        
        return DamageReport(
            damage_type=DamageType.CONTAINER_SUPERBLOCK_ZERO,
            description="Zeroed out primary container superblock at block 0",
            blocks_affected=[0],
            bytes_modified=self.block_size,
            original_data=original
        )
    
    def _damage_container_sb_magic(self, **kwargs) -> DamageReport:
        """Corrupt the NXSB magic bytes."""
        block_num = 0
        data = bytearray(self._read_block(block_num))
        original = bytes(data)
        
        # Corrupt magic at offset 32
        data[32:36] = b'XXXX'
        self._write_block(block_num, bytes(data))
        
        return DamageReport(
            damage_type=DamageType.CONTAINER_SUPERBLOCK_MAGIC,
            description="Corrupted NXSB magic bytes in container superblock",
            blocks_affected=[block_num],
            bytes_modified=4,
            original_data=original
        )
    
    def _damage_container_sb_checksum(self, **kwargs) -> DamageReport:
        """Corrupt the checksum in the container superblock."""
        block_num = 0
        data = bytearray(self._read_block(block_num))
        original = bytes(data)
        
        # Corrupt checksum at offset 0-8
        data[0:8] = b'\xff\xff\xff\xff\xff\xff\xff\xff'
        self._write_block(block_num, bytes(data))
        
        return DamageReport(
            damage_type=DamageType.CONTAINER_SUPERBLOCK_CHECKSUM,
            description="Corrupted Fletcher-64 checksum in container superblock",
            blocks_affected=[block_num],
            bytes_modified=8,
            original_data=original
        )
    
    def _damage_all_checkpoints(self, **kwargs) -> DamageReport:
        """Damage all checkpoint superblocks in the descriptor area."""
        _, container_sb = self._get_container_superblock()
        xp_desc_base, xp_desc_blocks, _, _ = self._get_checkpoint_info(container_sb)
        
        blocks_affected = []
        total_bytes = 0
        
        for i in range(xp_desc_blocks):
            block_num = xp_desc_base + i
            data = bytearray(self._read_block(block_num))
            
            # Check if it's a container superblock
            if data[32:36] == self.NX_MAGIC:
                data[32:36] = b'DEAD'  # Corrupt magic
                self._write_block(block_num, bytes(data))
                blocks_affected.append(block_num)
                total_bytes += 4
        
        return DamageReport(
            damage_type=DamageType.CONTAINER_ALL_CHECKPOINTS,
            description=f"Corrupted {len(blocks_affected)} checkpoint superblocks",
            blocks_affected=blocks_affected,
            bytes_modified=total_bytes
        )
    
    # ==================== Volume Damage Methods ====================
    
    def _damage_volume_sb_zero(self, **kwargs) -> DamageReport:
        """Zero out the volume superblock."""
        # Search the partition for APSB magic in chunks (handles large images)
        file_size = os.path.getsize(self.image_path)
        chunk_size = 50 * 1024 * 1024  # 50MB chunks
        search_limit = min(file_size - self.partition_offset, 1024 * 1024 * 1024)  # Up to 1GB
        
        with open(self.image_path, 'rb') as f:
            offset = 0
            while offset < search_limit:
                f.seek(self.partition_offset + offset)
                data = f.read(chunk_size)
                
                idx = data.find(self.APFS_MAGIC)
                if idx >= 0:
                    # Calculate absolute position and block number
                    abs_offset = offset + idx
                    # APSB magic is at offset 32 within the block
                    block_start = ((abs_offset - 32) // self.block_size) * self.block_size
                    block_num = block_start // self.block_size
                    
                    # Verify magic at offset 32 in block
                    f.seek(self.partition_offset + block_start + 32)
                    if f.read(4) == self.APFS_MAGIC:
                        # Read original block
                        f.seek(self.partition_offset + block_start)
                        original = f.read(self.block_size)
                        
                        # Zero it out
                        self._write_block(block_num, b'\x00' * self.block_size)
                        
                        return DamageReport(
                            damage_type=DamageType.VOLUME_SUPERBLOCK_ZERO,
                            description=f"Zeroed out volume superblock at block {block_num}",
                            blocks_affected=[block_num],
                            bytes_modified=self.block_size,
                            original_data=original
                        )
                
                offset += chunk_size - 100  # Small overlap
        
        raise ValueError("Could not find volume superblock to damage")
    
    def _damage_volume_sb_magic(self, **kwargs) -> DamageReport:
        """Corrupt the APSB magic in volume superblock."""
        # Search partition for APSB in chunks (handles large images)
        file_size = os.path.getsize(self.image_path)
        chunk_size = 50 * 1024 * 1024
        search_limit = min(file_size - self.partition_offset, 1024 * 1024 * 1024)
        
        with open(self.image_path, 'rb') as f:
            offset = 0
            while offset < search_limit:
                f.seek(self.partition_offset + offset)
                data = f.read(chunk_size)
                
                idx = data.find(self.APFS_MAGIC)
                if idx >= 0:
                    abs_offset = offset + idx
                    block_num = abs_offset // self.block_size
                    offset_in_block = abs_offset % self.block_size
                    
                    block_data = bytearray(self._read_block(block_num))
                    original = bytes(block_data)
                    block_data[offset_in_block:offset_in_block+4] = b'DEAD'
                    self._write_block(block_num, bytes(block_data))
                    
                    return DamageReport(
                        damage_type=DamageType.VOLUME_SUPERBLOCK_MAGIC,
                        description=f"Corrupted APSB magic at block {block_num}",
                        blocks_affected=[block_num],
                        bytes_modified=4,
                        original_data=original
                    )
                
                offset += chunk_size - 100
        
        raise ValueError("Could not find APSB magic")
    
    def _damage_volume_omap(self, **kwargs) -> DamageReport:
        """Corrupt the volume OMAP tree root."""
        # Find volume superblock in chunks (handles large images)
        file_size = os.path.getsize(self.image_path)
        chunk_size = 50 * 1024 * 1024
        search_limit = min(file_size - self.partition_offset, 1024 * 1024 * 1024)
        
        idx = -1
        data = None
        with open(self.image_path, 'rb') as f:
            offset = 0
            while offset < search_limit:
                f.seek(self.partition_offset + offset)
                data = f.read(chunk_size)
                idx = data.find(self.APFS_MAGIC)
                if idx >= 0:
                    break
                offset += chunk_size - 100
        
        if idx < 0:
            raise ValueError("Could not find volume superblock")
        
        # OMAP OID is at offset 80 in APSB (after magic at 32)
        omap_oid = struct.unpack('<Q', data[idx+48:idx+56])[0]
        
        # Resolve OMAP physical address (simplified - assume direct mapping)
        # In reality would need to check container OMAP
        omap_block = omap_oid
        
        omap_data = bytearray(self._read_block(omap_block))
        original = bytes(omap_data)
        
        # Corrupt the OMAP tree root pointer at offset 48
        omap_data[48:56] = b'\xff\xff\xff\xff\xff\xff\xff\xff'
        self._write_block(omap_block, bytes(omap_data))
        
        return DamageReport(
            damage_type=DamageType.VOLUME_OMAP_CORRUPT,
            description=f"Corrupted OMAP tree root at block {omap_block}",
            blocks_affected=[omap_block],
            bytes_modified=8,
            original_data=original
        )
    
    # ==================== B-tree Damage Methods ====================
    
    def _damage_btree_root_zero(self, **kwargs) -> DamageReport:
        """Zero out the root tree node."""
        # Find root tree via volume superblock
        blocks = self._find_btree_nodes()
        if not blocks:
            raise ValueError("No B-tree nodes found")
        
        # Assume first found is root (simplified)
        root_block = blocks[0]
        original = self._read_block(root_block)
        self._write_block(root_block, b'\x00' * self.block_size)
        
        return DamageReport(
            damage_type=DamageType.BTREE_ROOT_ZERO,
            description=f"Zeroed out B-tree root at block {root_block}",
            blocks_affected=[root_block],
            bytes_modified=self.block_size,
            original_data=original
        )
    
    def _damage_btree_root_magic(self, **kwargs) -> DamageReport:
        """Corrupt B-tree node header flags."""
        blocks = self._find_btree_nodes()
        if not blocks:
            raise ValueError("No B-tree nodes found")
        
        root_block = blocks[0]
        data = bytearray(self._read_block(root_block))
        original = bytes(data)
        
        # Corrupt btree header flags at offset 32
        data[32:34] = b'\xff\xff'
        self._write_block(root_block, bytes(data))
        
        return DamageReport(
            damage_type=DamageType.BTREE_ROOT_MAGIC,
            description=f"Corrupted B-tree header flags at block {root_block}",
            blocks_affected=[root_block],
            bytes_modified=2,
            original_data=original
        )
    
    def _damage_btree_toc(self, **kwargs) -> DamageReport:
        """Scramble B-tree TOC (Table of Contents) entries."""
        blocks = self._find_btree_nodes()
        if not blocks:
            raise ValueError("No B-tree nodes found")
        
        target_block = blocks[0]
        data = bytearray(self._read_block(target_block))
        original = bytes(data)
        
        # TOC starts at offset 56, scramble the first 64 bytes
        toc_data = list(data[56:120])
        random.shuffle(toc_data)
        data[56:120] = bytes(toc_data)
        
        self._write_block(target_block, bytes(data))
        
        return DamageReport(
            damage_type=DamageType.BTREE_TOC_SCRAMBLE,
            description=f"Scrambled B-tree TOC at block {target_block}",
            blocks_affected=[target_block],
            bytes_modified=64,
            original_data=original
        )
    
    def _damage_btree_leaves(self, **kwargs) -> DamageReport:
        """Delete (zero out) random leaf nodes."""
        blocks = self._find_btree_nodes()
        if len(blocks) < 2:
            raise ValueError("Not enough B-tree nodes to damage")
        
        # Skip first (root), damage random leaves
        leaves = blocks[1:]
        num_to_damage = min(3, len(leaves))
        targets = random.sample(leaves, num_to_damage)
        
        for block in targets:
            self._write_block(block, b'\x00' * self.block_size)
        
        return DamageReport(
            damage_type=DamageType.BTREE_LEAF_DELETE,
            description=f"Deleted {num_to_damage} B-tree leaf nodes",
            blocks_affected=targets,
            bytes_modified=num_to_damage * self.block_size
        )
    
    def _damage_btree_keys(self, **kwargs) -> DamageReport:
        """Corrupt key data in B-tree nodes."""
        blocks = self._find_btree_nodes()
        if not blocks:
            raise ValueError("No B-tree nodes found")
        
        target_block = blocks[0]
        data = bytearray(self._read_block(target_block))
        original = bytes(data)
        
        # Corrupt key area (typically starts around offset 120-200)
        for i in range(150, 250, 16):
            if i < len(data):
                data[i:i+8] = b'\xde\xad\xbe\xef\xca\xfe\xba\xbe'
        
        self._write_block(target_block, bytes(data))
        
        return DamageReport(
            damage_type=DamageType.BTREE_KEYS_CORRUPT,
            description=f"Corrupted B-tree keys at block {target_block}",
            blocks_affected=[target_block],
            bytes_modified=48,
            original_data=original
        )
    
    def _find_btree_nodes(self) -> List[int]:
        """Find B-tree nodes by scanning for characteristic patterns."""
        nodes = []
        
        with open(self.image_path, 'rb') as f:
            f.seek(self.partition_offset)
            block_num = 0
            
            while True:
                data = f.read(self.block_size)
                if len(data) < self.block_size:
                    break
                
                # Check for B-tree node characteristics
                # Flags at offset 32, level at 34, nkeys at 36
                if len(data) >= 40:
                    flags = struct.unpack('<H', data[32:34])[0]
                    level = struct.unpack('<H', data[34:36])[0]
                    nkeys = struct.unpack('<I', data[36:40])[0]
                    
                    # Valid B-tree node has flags in reasonable range
                    # and level < 10, nkeys < 1000
                    if (flags & 0x7) != 0 and level < 10 and 0 < nkeys < 1000:
                        # Check for valid object type
                        obj_type = struct.unpack('<I', data[24:28])[0] & 0xFFFF
                        if obj_type in [2, 3, 11, 13, 14]:  # B-tree object types
                            nodes.append(block_num)
                
                block_num += 1
                if block_num > 10000:  # Limit search
                    break
        
        return nodes
    
    # ==================== Directory/File Damage Methods ====================
    
    def _damage_drec_delete(self, **kwargs) -> DamageReport:
        """Delete directory record entries from B-tree leaves."""
        blocks = self._find_btree_nodes()
        blocks_affected = []
        
        for block_num in blocks[1:3]:  # Damage a couple leaf nodes
            data = bytearray(self._read_block(block_num))
            
            # Find and zero out drec entries (type 9 in key header)
            for offset in range(120, 3000, 8):
                if offset + 8 <= len(data):
                    key_header = struct.unpack('<Q', data[offset:offset+8])[0]
                    key_type = (key_header >> 60) & 0xF
                    
                    if key_type == 9:  # DREC type
                        # Zero out the name following the key header
                        data[offset+12:offset+64] = b'\x00' * 52
                        blocks_affected.append(block_num)
                        break
            
            self._write_block(block_num, bytes(data))
        
        return DamageReport(
            damage_type=DamageType.DREC_DELETE,
            description=f"Deleted directory records from {len(blocks_affected)} blocks",
            blocks_affected=blocks_affected,
            bytes_modified=len(blocks_affected) * 52
        )
    
    def _damage_inode_corrupt(self, **kwargs) -> DamageReport:
        """Corrupt inode entries."""
        blocks = self._find_btree_nodes()
        blocks_affected = []
        
        for block_num in blocks[:2]:
            data = bytearray(self._read_block(block_num))
            
            # Find inode entries (type 3 in key header)
            for offset in range(120, 3000, 8):
                if offset + 8 <= len(data):
                    key_header = struct.unpack('<Q', data[offset:offset+8])[0]
                    key_type = (key_header >> 60) & 0xF
                    
                    if key_type == 3:  # INODE type
                        # Corrupt the inode value
                        val_offset = offset + 100  # Approximate
                        if val_offset + 20 < len(data):
                            data[val_offset:val_offset+20] = b'\xff' * 20
                            blocks_affected.append(block_num)
                            break
            
            self._write_block(block_num, bytes(data))
        
        return DamageReport(
            damage_type=DamageType.INODE_CORRUPT,
            description=f"Corrupted inodes in {len(blocks_affected)} blocks",
            blocks_affected=blocks_affected,
            bytes_modified=len(blocks_affected) * 20
        )
    
    def _damage_extent_delete(self, **kwargs) -> DamageReport:
        """Delete file extent records."""
        blocks = self._find_btree_nodes()
        blocks_affected = []
        
        for block_num in blocks:
            data = bytearray(self._read_block(block_num))
            modified = False
            
            # Find extent entries (type 8 in key header)
            for offset in range(120, 3000, 8):
                if offset + 8 <= len(data):
                    key_header = struct.unpack('<Q', data[offset:offset+8])[0]
                    key_type = (key_header >> 60) & 0xF
                    
                    if key_type == 8:  # EXTENT type
                        # Zero out the extent key and value
                        data[offset:offset+32] = b'\x00' * 32
                        modified = True
                        break
            
            if modified:
                self._write_block(block_num, bytes(data))
                blocks_affected.append(block_num)
                if len(blocks_affected) >= 2:
                    break
        
        return DamageReport(
            damage_type=DamageType.EXTENT_DELETE,
            description=f"Deleted extent records from {len(blocks_affected)} blocks",
            blocks_affected=blocks_affected,
            bytes_modified=len(blocks_affected) * 32
        )
    
    # ==================== Data Damage Methods ====================
    
    def _damage_file_data(self, **kwargs) -> DamageReport:
        """Overwrite file data blocks with garbage."""
        # Find data blocks (blocks not containing metadata)
        _, container_sb = self._get_container_superblock()
        block_count = struct.unpack('<Q', container_sb[40:48])[0]
        
        # Pick some blocks in the middle (likely data)
        start_block = block_count // 4
        blocks_to_damage = [start_block + i for i in range(5)]
        
        garbage = os.urandom(self.block_size)
        for block in blocks_to_damage:
            self._write_block(block, garbage)
        
        return DamageReport(
            damage_type=DamageType.FILE_DATA_OVERWRITE,
            description=f"Overwrote {len(blocks_to_damage)} data blocks with garbage",
            blocks_affected=blocks_to_damage,
            bytes_modified=len(blocks_to_damage) * self.block_size
        )
    
    def _damage_file_partial(self, **kwargs) -> DamageReport:
        """Partially overwrite file data (first 512 bytes of blocks)."""
        _, container_sb = self._get_container_superblock()
        block_count = struct.unpack('<Q', container_sb[40:48])[0]
        
        start_block = block_count // 3
        blocks_to_damage = [start_block + i for i in range(3)]
        
        for block in blocks_to_damage:
            data = bytearray(self._read_block(block))
            data[:512] = os.urandom(512)
            self._write_block(block, bytes(data))
        
        return DamageReport(
            damage_type=DamageType.FILE_DATA_PARTIAL,
            description=f"Partially overwrote {len(blocks_to_damage)} blocks",
            blocks_affected=blocks_to_damage,
            bytes_modified=len(blocks_to_damage) * 512
        )
    
    def _damage_random_blocks(self, **kwargs) -> DamageReport:
        """Corrupt random blocks throughout the filesystem."""
        num_blocks = kwargs.get('num_blocks', 10)
        
        _, container_sb = self._get_container_superblock()
        block_count = struct.unpack('<Q', container_sb[40:48])[0]
        
        # Avoid first 20 blocks (metadata) and last 10
        safe_range = range(20, min(block_count - 10, 5000))
        targets = random.sample(list(safe_range), min(num_blocks, len(safe_range)))
        
        for block in targets:
            data = bytearray(self._read_block(block))
            # Flip random bits
            for _ in range(100):
                pos = random.randint(0, len(data) - 1)
                data[pos] ^= random.randint(1, 255)
            self._write_block(block, bytes(data))
        
        return DamageReport(
            damage_type=DamageType.RANDOM_BLOCKS,
            description=f"Corrupted {len(targets)} random blocks",
            blocks_affected=targets,
            bytes_modified=len(targets) * 100
        )
    
    # ==================== Structural Damage Methods ====================
    
    def _damage_gpt(self, **kwargs) -> DamageReport:
        """Corrupt the GPT header."""
        with open(self.image_path, 'r+b') as f:
            f.seek(512)
            original = f.read(512)
            
            # Corrupt GPT signature
            f.seek(512)
            f.write(b'DEADBEEF' + original[8:])
        
        return DamageReport(
            damage_type=DamageType.GPT_CORRUPT,
            description="Corrupted GPT header signature",
            blocks_affected=[1],  # LBA 1
            bytes_modified=8,
            original_data=original
        )
    
    def _damage_partition_table(self, **kwargs) -> DamageReport:
        """Damage the partition table entries."""
        with open(self.image_path, 'r+b') as f:
            # GPT partition entries start at LBA 2
            f.seek(1024)
            original = f.read(128)  # First partition entry
            
            f.seek(1024)
            f.write(b'\x00' * 128)  # Zero out first entry
        
        return DamageReport(
            damage_type=DamageType.PARTITION_TABLE,
            description="Zeroed out first GPT partition entry",
            blocks_affected=[2],
            bytes_modified=128,
            original_data=original
        )
    
    # ==================== Severe Damage Methods ====================
    
    def _damage_severe_head_crash(self, **kwargs) -> DamageReport:
        """Severe head crash - destroy many blocks from start."""
        num_blocks = kwargs.get('num_blocks', 15000)  # Default: 15,000 blocks (~60MB)
        
        partition_offset_blocks = self.partition_offset // self.block_size
        blocks_to_damage = list(range(partition_offset_blocks, 
                                      partition_offset_blocks + num_blocks))
        
        for block_num in blocks_to_damage:
            self._write_block(block_num, b'\x00' * self.block_size)
        
        return DamageReport(
            damage_type=DamageType.SEVERE_HEAD_CRASH,
            description=f"Severe head crash: destroyed {num_blocks} blocks from start",
            blocks_affected=blocks_to_damage[:100],  # Store first 100 for report
            bytes_modified=num_blocks * self.block_size
        )
    
    def _damage_multiple_leaves(self, **kwargs) -> DamageReport:
        """Destroy many leaf nodes (50% or more).
        
        IMPORTANT: Finds leaf nodes that actually contain directory records,
        not just any B-tree nodes. This ensures we're actually destroying
        the directory structure.
        """
        blocks = self._find_btree_nodes()
        if len(blocks) < 4:
            raise ValueError("Not enough B-tree nodes to damage")
        
        # Find leaf nodes that actually contain directory records
        # This is critical - we want to destroy nodes with DIR_REC records
        drec_leaf_nodes = []
        for block_num in blocks:
            try:
                data = self._read_block(block_num)
                if len(data) < 56:
                    continue
                flags = struct.unpack('<H', data[32:34])[0]
                is_leaf = bool(flags & 0x2)
                
                if not is_leaf:
                    continue
                
                # Check if this node contains directory records
                nkeys = struct.unpack('<I', data[36:40])[0]
                table_space_len = struct.unpack('<H', data[42:44])[0]
                is_root = bool(flags & 0x1)
                is_fixed = bool(flags & 0x4)
                
                toc_start = 56
                key_area_start = 56 + table_space_len
                val_area_end = self.block_size - 40 if is_root else self.block_size
                
                has_drec = False
                for i in range(min(nkeys, 50)):  # Check first 50 keys
                    try:
                        entry_pos = toc_start + i * (4 if is_fixed else 8)
                        if is_fixed:
                            k_off = struct.unpack('<H', data[entry_pos:entry_pos+2])[0]
                        else:
                            k_off = struct.unpack('<H', data[entry_pos:entry_pos+2])[0]
                        
                        key_pos = key_area_start + k_off
                        if key_pos + 8 <= len(data):
                            key_header = struct.unpack('<Q', data[key_pos:key_pos+8])[0]
                            key_type = (key_header >> 60) & 0xF
                            if key_type == 9:  # JOBJ_TYPE_DIR_REC
                                has_drec = True
                                break
                    except Exception:
                        continue
                
                if has_drec:
                    drec_leaf_nodes.append(block_num)
            except Exception:
                continue
        
        # If we can't find nodes with DIR_REC, fall back to all leaf nodes
        # (but this is less accurate)
        if len(drec_leaf_nodes) == 0:
            for block_num in blocks:
                try:
                    data = self._read_block(block_num)
                    if len(data) < 34:
                        continue
                    flags = struct.unpack('<H', data[32:34])[0]
                    if flags & 0x2:  # Leaf flag
                        drec_leaf_nodes.append(block_num)
                except Exception:
                    continue
        
        if len(drec_leaf_nodes) == 0:
            raise ValueError("No leaf nodes found to damage")
        
        percent = kwargs.get('percent', 50)  # Default: 50% of leaves
        num_to_damage = max(1, int(len(drec_leaf_nodes) * percent / 100))
        num_to_damage = min(num_to_damage, len(drec_leaf_nodes))
        
        targets = random.sample(drec_leaf_nodes, num_to_damage)
        
        for block in targets:
            self._write_block(block, b'\x00' * self.block_size)
        
        return DamageReport(
            damage_type=DamageType.MULTIPLE_LEAF_DESTRUCTION,
            description=f"Destroyed {num_to_damage}/{len(drec_leaf_nodes)} directory record leaf nodes ({percent}%)",
            blocks_affected=targets,
            bytes_modified=num_to_damage * self.block_size
        )
    
    def _damage_cascading(self, **kwargs) -> DamageReport:
        """Cascading corruption - multiple simultaneous damage types."""
        reports = []
        
        # Damage superblock
        try:
            reports.append(self._damage_container_sb_magic())
        except Exception:
            pass
        
        # Damage OMAP
        try:
            reports.append(self._damage_volume_omap())
        except Exception:
            pass
        
        # Scramble multiple B-tree TOCs
        try:
            blocks = self._find_btree_nodes()
            for block in random.sample(blocks[:10], min(3, len(blocks))):
                data = bytearray(self._read_block(block))
                original = bytes(data)
                # Scramble TOC
                toc_start = 56
                for i in range(8):
                    offset = toc_start + i * 8
                    if offset + 8 < len(data):
                        data[offset:offset+8] = struct.pack('<Q', random.randint(0, 2**64-1))
                self._write_block(block, bytes(data))
                reports.append(DamageReport(
                    damage_type=DamageType.BTREE_TOC_SCRAMBLE,
                    description=f"Scrambled B-tree TOC at block {block}",
                    blocks_affected=[block],
                    bytes_modified=64,
                    original_data=original
                ))
        except Exception:
            pass
        
        # Corrupt random blocks
        try:
            reports.append(self._damage_random_blocks(num_blocks=20))
        except Exception:
            pass
        
        return DamageReport(
            damage_type=DamageType.CASCADING_CORRUPTION,
            description=f"Cascading corruption: {len(reports)} damage types applied",
            blocks_affected=sum([r.blocks_affected for r in reports], []),
            bytes_modified=sum(r.bytes_modified for r in reports)
        )
    
    def _damage_critical_zone(self, **kwargs) -> DamageReport:
        """Destroy the critical zone (first 8% where leaf nodes are)."""
        partition_offset_blocks = self.partition_offset // self.block_size
        
        # Get total block count
        try:
            _, container_sb = self._get_container_superblock()
            block_count = struct.unpack('<Q', container_sb[40:48])[0]
        except Exception:
            # Estimate from file size
            with open(self.image_path, 'rb') as f:
                f.seek(0, 2)
                file_size = f.tell()
            block_count = (file_size - self.partition_offset) // self.block_size
        
        # Critical zone: first 8% of partition
        critical_zone_blocks = int(block_count * 0.08)
        blocks_to_damage = list(range(partition_offset_blocks, 
                                      partition_offset_blocks + critical_zone_blocks))
        
        # Corrupt (not zero) to make it harder
        for block_num in blocks_to_damage:
            data = bytearray(self._read_block(block_num))
            # Corrupt random bytes
            for _ in range(min(100, len(data) // 10)):
                pos = random.randint(0, len(data) - 1)
                data[pos] = random.randint(0, 255)
            self._write_block(block_num, bytes(data))
        
        return DamageReport(
            damage_type=DamageType.CRITICAL_ZONE_DESTRUCTION,
            description=f"Destroyed critical zone: {critical_zone_blocks} blocks (8% of disk)",
            blocks_affected=blocks_to_damage[:100],  # Store first 100
            bytes_modified=critical_zone_blocks * self.block_size
        )
    
    def _damage_total_structure(self, **kwargs) -> DamageReport:
        """Total structure damage - superblock + OMAP + B-tree root."""
        reports = []
        
        # Damage container superblock
        try:
            reports.append(self._damage_container_sb_magic())
        except Exception:
            pass
        
        # Damage volume superblock
        try:
            reports.append(self._damage_volume_sb_magic())
        except Exception:
            pass
        
        # Damage OMAP
        try:
            reports.append(self._damage_volume_omap())
        except Exception:
            pass
        
        # Damage B-tree root
        try:
            reports.append(self._damage_btree_root_zero())
        except Exception:
            pass
        
        # Scramble TOC of multiple nodes
        try:
            blocks = self._find_btree_nodes()
            for block in random.sample(blocks[:5], min(2, len(blocks))):
                data = bytearray(self._read_block(block))
                original = bytes(data)
                toc_start = 56
                for i in range(16):
                    offset = toc_start + i * 8
                    if offset + 8 < len(data):
                        data[offset:offset+8] = struct.pack('<Q', random.randint(0, 2**64-1))
                self._write_block(block, bytes(data))
                reports.append(DamageReport(
                    damage_type=DamageType.BTREE_TOC_SCRAMBLE,
                    description=f"Scrambled B-tree TOC at block {block}",
                    blocks_affected=[block],
                    bytes_modified=128,
                    original_data=original
                ))
        except Exception:
            pass
        
        return DamageReport(
            damage_type=DamageType.TOTAL_STRUCTURE_DAMAGE,
            description=f"Total structure damage: {len(reports)} critical structures damaged",
            blocks_affected=sum([r.blocks_affected for r in reports], []),
            bytes_modified=sum(r.bytes_modified for r in reports)
        )


    # ==================== Additional Damage Methods ====================

    def _damage_keybag(self, **kwargs) -> DamageReport:
        """Destroy keybag blocks (container and volume keybags).

        Keybags are stored at specific locations referenced by the container
        superblock. Without keybags, encrypted volumes can't be unlocked.
        For unencrypted volumes, this tests that we don't crash on missing keybags.
        """
        _, container_sb = self._get_container_superblock()
        blocks_damaged = []

        # Container keybag is at xp_desc_base + some offset
        # Keybags are typically near the superblock area
        # Destroy blocks 1-5 (common keybag locations)
        for block_num in range(1, 6):
            self._write_block(block_num, os.urandom(self.block_size))
            blocks_damaged.append(block_num)

        # Also look for blocks containing keybag signatures ('keys' or 'recs')
        partition_blocks = self.partition_offset // self.block_size
        for block_num in range(partition_blocks, partition_blocks + 100):
            try:
                data = self._read_block(block_num)
                # Check for keybag-like structures (media keybag obj type = 0x6B657973)
                obj_type = struct.unpack('<I', data[24:28])[0] & 0xFFFF
                if obj_type in (0x6B, 0x6C):  # keybag types
                    self._write_block(block_num, os.urandom(self.block_size))
                    blocks_damaged.append(block_num)
            except Exception:
                continue

        return DamageReport(
            damage_type=DamageType.KEYBAG_DESTROY,
            description=f"Destroyed {len(blocks_damaged)} keybag blocks",
            blocks_affected=blocks_damaged,
            bytes_modified=len(blocks_damaged) * self.block_size
        )

    def _damage_bitmap(self, **kwargs) -> DamageReport:
        """Corrupt space manager allocation bitmap.

        The space manager tracks which blocks are allocated. Corrupting the
        bitmap means the FS doesn't know what's free vs used.
        """
        _, container_sb = self._get_container_superblock()
        block_count = struct.unpack('<Q', container_sb[40:48])[0]
        blocks_damaged = []

        # Space manager is referenced from container superblock
        # Typically in the first few hundred blocks
        partition_blocks = self.partition_offset // self.block_size
        for block_num in range(partition_blocks, partition_blocks + 200):
            try:
                data = self._read_block(block_num)
                obj_type = struct.unpack('<I', data[24:28])[0] & 0xFFFF
                # Space manager type = 0x05, bitmap type = 0x07
                if obj_type in (0x05, 0x07):
                    corrupted = bytearray(data)
                    # Flip lots of bits in the bitmap data
                    for i in range(64, len(corrupted), 8):
                        corrupted[i] ^= 0xFF
                    self._write_block(block_num, bytes(corrupted))
                    blocks_damaged.append(block_num)
            except Exception:
                continue

        # If we didn't find specific bitmap blocks, corrupt blocks in the
        # typical bitmap region (after checkpoint area)
        if len(blocks_damaged) == 0:
            bitmap_start = partition_blocks + 50
            for block_num in range(bitmap_start, bitmap_start + 20):
                data = bytearray(self._read_block(block_num))
                for i in range(0, len(data), 16):
                    data[i] ^= 0xFF
                self._write_block(block_num, bytes(data))
                blocks_damaged.append(block_num)

        return DamageReport(
            damage_type=DamageType.BITMAP_CORRUPT,
            description=f"Corrupted {len(blocks_damaged)} bitmap/space manager blocks",
            blocks_affected=blocks_damaged,
            bytes_modified=len(blocks_damaged) * self.block_size
        )

    def _damage_checkpoint_map(self, **kwargs) -> DamageReport:
        """Destroy checkpoint mapping blocks.

        APFS uses checkpoint maps to track valid metadata blocks.
        Without these, the FS can't find the latest valid state.
        """
        _, container_sb = self._get_container_superblock()
        blocks_damaged = []

        # nx_superblock_t layout:
        # offset 96:  nx_xp_desc_base (paddr_t / int64) - checkpoint descriptor base
        # offset 104: nx_xp_data_base (paddr_t / int64) - checkpoint data base
        # offset 112: nx_xp_desc_blocks (uint32) - descriptor block count
        # But these are WITHIN the container (relative to partition start)
        try:
            xp_desc_base = struct.unpack('<q', container_sb[96:104])[0]
            xp_data_base = struct.unpack('<q', container_sb[104:112])[0]
            xp_desc_blocks = struct.unpack('<I', container_sb[112:116])[0]
            xp_data_blocks = struct.unpack('<I', container_sb[116:120])[0]

            # Destroy checkpoint descriptor blocks
            if 0 < xp_desc_base < 100000 and xp_desc_blocks < 1000:
                for i in range(xp_desc_blocks):
                    block_num = xp_desc_base + i
                    self._write_block(block_num, b'\xDE\xAD' * (self.block_size // 2))
                    blocks_damaged.append(block_num)

            # Destroy checkpoint data blocks
            if 0 < xp_data_base < 100000 and xp_data_blocks < 1000:
                for i in range(xp_data_blocks):
                    block_num = xp_data_base + i
                    self._write_block(block_num, b'\xDE\xAD' * (self.block_size // 2))
                    blocks_damaged.append(block_num)
        except Exception:
            pass

        if len(blocks_damaged) == 0:
            # Fallback: destroy blocks 2-30 (typical checkpoint area)
            for block_num in range(2, 30):
                self._write_block(block_num, b'\xDE\xAD' * (self.block_size // 2))
                blocks_damaged.append(block_num)

        return DamageReport(
            damage_type=DamageType.CHECKPOINT_MAP_DESTROY,
            description=f"Destroyed {len(blocks_damaged)} checkpoint mapping blocks",
            blocks_affected=blocks_damaged,
            bytes_modified=len(blocks_damaged) * self.block_size
        )

    def _damage_middle_third(self, **kwargs) -> DamageReport:
        """Wipe the middle third of the partition.

        Simulates catastrophic media failure in the middle of the disk.
        File data stored in the middle is lost, but metadata at the start
        and end should survive.
        """
        _, container_sb = self._get_container_superblock()
        block_count = struct.unpack('<Q', container_sb[40:48])[0]

        start = block_count // 3
        end = (block_count * 2) // 3
        blocks_to_wipe = list(range(start, end))

        for block_num in blocks_to_wipe:
            self._write_block(block_num, b'\x00' * self.block_size)

        return DamageReport(
            damage_type=DamageType.MIDDLE_THIRD_WIPE,
            description=f"Wiped middle third: blocks {start}-{end} ({len(blocks_to_wipe)} blocks)",
            blocks_affected=blocks_to_wipe[:100],
            bytes_modified=len(blocks_to_wipe) * self.block_size
        )

    def _damage_bit_rot(self, **kwargs) -> DamageReport:
        """Scattered bit rot across many blocks.

        Simulates aging media where individual bits flip randomly.
        Only 1-2 bits per block, but across hundreds of blocks.
        This is subtle corruption that may not be immediately obvious.
        """
        _, container_sb = self._get_container_superblock()
        block_count = struct.unpack('<Q', container_sb[40:48])[0]

        num_blocks = kwargs.get('num_blocks', min(500, block_count // 4))
        targets = random.sample(range(10, min(block_count, 50000)), num_blocks)

        for block_num in targets:
            data = bytearray(self._read_block(block_num))
            # Flip 1-2 random bits
            for _ in range(random.randint(1, 2)):
                byte_pos = random.randint(0, len(data) - 1)
                bit_pos = random.randint(0, 7)
                data[byte_pos] ^= (1 << bit_pos)
            self._write_block(block_num, bytes(data))

        return DamageReport(
            damage_type=DamageType.SCATTERED_BIT_ROT,
            description=f"Bit rot: flipped 1-2 bits in {num_blocks} blocks",
            blocks_affected=targets[:100],
            bytes_modified=num_blocks * 2
        )

    def _damage_tail_crash(self, **kwargs) -> DamageReport:
        """Head crash at the END of disk.

        Unlike SEVERE_HEAD_CRASH which hits the start (metadata region),
        this destroys the tail where file data is typically stored.
        Metadata should survive but large files may lose data.
        Only destroys the last 5% to avoid wiping B-tree leaf nodes
        that APFS may place in the tail region on small volumes.
        """
        _, container_sb = self._get_container_superblock()
        block_count = struct.unpack('<Q', container_sb[40:48])[0]

        # Destroy last 5% of partition
        percent = kwargs.get('percent', 5)
        crash_blocks = int(block_count * percent / 100)
        start = block_count - crash_blocks
        blocks_damaged = list(range(start, block_count))

        for block_num in blocks_damaged:
            self._write_block(block_num, b'\x00' * self.block_size)

        return DamageReport(
            damage_type=DamageType.TAIL_CRASH,
            description=f"Tail crash: destroyed last {crash_blocks} blocks ({percent}%)",
            blocks_affected=blocks_damaged[:100],
            bytes_modified=crash_blocks * self.block_size
        )

    def _damage_interleaved_zero(self, **kwargs) -> DamageReport:
        """Zero every other block in the metadata region.

        Simulates stripe failure in a RAID-like arrangement, or
        periodic write failures. Metadata region alternates between
        valid and zeroed blocks.
        """
        _, container_sb = self._get_container_superblock()
        block_count = struct.unpack('<Q', container_sb[40:48])[0]

        # Metadata region: blocks 10-10% of disk (skip first 10 blocks
        # which contain superblock and keybag — we test those separately)
        metadata_end = int(block_count * 0.10)
        blocks_damaged = []

        for block_num in range(10, metadata_end, 2):  # Every other block, skip keybag area
            self._write_block(block_num, b'\x00' * self.block_size)
            blocks_damaged.append(block_num)

        return DamageReport(
            damage_type=DamageType.INTERLEAVED_ZERO,
            description=f"Zeroed every other block in metadata region ({len(blocks_damaged)} blocks)",
            blocks_affected=blocks_damaged[:100],
            bytes_modified=len(blocks_damaged) * self.block_size
        )

    def _damage_all_superblocks(self, **kwargs) -> DamageReport:
        """Destroy ALL superblocks — container AND all volume superblocks.

        More aggressive than CONTAINER_SUPERBLOCK_ZERO. Finds and destroys
        every NXSB and APSB magic in the image.
        """
        blocks_damaged = []
        partition_blocks = self.partition_offset // self.block_size

        # Scan first 500 blocks for any superblock signatures
        for block_num in range(partition_blocks, partition_blocks + 500):
            try:
                data = self._read_block(block_num)
                if len(data) < 36:
                    continue
                magic = data[32:36]
                if magic in (self.NX_MAGIC, self.APFS_MAGIC):
                    self._write_block(block_num, b'\x00' * self.block_size)
                    blocks_damaged.append(block_num)
            except Exception:
                continue

        return DamageReport(
            damage_type=DamageType.ALL_SUPERBLOCKS_DESTROY,
            description=f"Destroyed {len(blocks_damaged)} superblocks (container + volume)",
            blocks_affected=blocks_damaged,
            bytes_modified=len(blocks_damaged) * self.block_size
        )

    def _damage_omap_and_catalog(self, **kwargs) -> DamageReport:
        """Destroy both OMAP and catalog B-tree roots.

        The OMAP translates virtual OIDs to physical block addresses,
        and the catalog B-tree holds all file/directory metadata.
        Destroying both forces the recovery tool to scan raw blocks.
        """
        blocks_damaged = []
        partition_blocks = self.partition_offset // self.block_size

        # Find OMAP and B-tree root nodes
        for block_num in range(partition_blocks, partition_blocks + 500):
            try:
                data = self._read_block(block_num)
                if len(data) < 36:
                    continue
                obj_type = struct.unpack('<I', data[24:28])[0] & 0xFFFF
                # OMAP type = 0x0B, B-tree type = 0x02 (with root flag)
                if obj_type in (0x0B, 0x02):
                    self._write_block(block_num, b'\x00' * self.block_size)
                    blocks_damaged.append(block_num)
            except Exception:
                continue

        # Also destroy any B-tree root nodes we find
        try:
            btree_blocks = self._find_btree_nodes()
            for block_num in btree_blocks[:5]:
                data = self._read_block(block_num)
                flags = struct.unpack('<H', data[32:34])[0]
                if flags & 0x1:  # Root flag
                    self._write_block(block_num, b'\x00' * self.block_size)
                    blocks_damaged.append(block_num)
        except Exception:
            pass

        return DamageReport(
            damage_type=DamageType.OMAP_AND_CATALOG_DESTROY,
            description=f"Destroyed {len(blocks_damaged)} OMAP and catalog root blocks",
            blocks_affected=blocks_damaged,
            bytes_modified=len(blocks_damaged) * self.block_size
        )

    def _damage_extent_overflow(self, **kwargs) -> DamageReport:
        """Corrupt extent records specifically within B-tree leaf nodes.

        Finds leaf nodes containing extent records (type 8) and corrupts
        just the extent value data (physical block pointers), leaving
        other record types intact. This tests recovery when extent
        mappings are wrong but inodes and drecs are fine.
        """
        btree_blocks = self._find_btree_nodes()
        blocks_damaged = []
        extents_corrupted = 0

        for block_num in btree_blocks:
            try:
                data = bytearray(self._read_block(block_num))
                if len(data) < 56:
                    continue
                flags = struct.unpack('<H', data[32:34])[0]
                if not (flags & 0x2):  # Not a leaf
                    continue

                nkeys = struct.unpack('<I', data[36:40])[0]
                table_space_len = struct.unpack('<H', data[42:44])[0]
                is_root = bool(flags & 0x1)
                is_fixed = bool(flags & 0x4)

                toc_start = 56
                key_area_start = 56 + table_space_len
                val_area_end = self.block_size - 40 if is_root else self.block_size

                modified = False
                for i in range(min(nkeys, 100)):
                    entry_pos = toc_start + i * (4 if is_fixed else 8)
                    if is_fixed:
                        if entry_pos + 4 > len(data):
                            break
                        k_off = struct.unpack('<H', data[entry_pos:entry_pos+2])[0]
                        v_off = struct.unpack('<H', data[entry_pos+2:entry_pos+4])[0]
                    else:
                        if entry_pos + 8 > len(data):
                            break
                        k_off = struct.unpack('<H', data[entry_pos:entry_pos+2])[0]
                        v_off = struct.unpack('<H', data[entry_pos+4:entry_pos+6])[0]

                    key_pos = key_area_start + k_off
                    if key_pos + 8 > len(data):
                        continue

                    key_header = struct.unpack('<Q', data[key_pos:key_pos+8])[0]
                    key_type = (key_header >> 60) & 0xF

                    if key_type == 8:  # EXTENT record
                        val_pos = val_area_end - v_off
                        if val_pos + 16 <= len(data) and val_pos > 0:
                            # Corrupt physical block pointer (offset 8 in value)
                            data[val_pos+8:val_pos+16] = os.urandom(8)
                            modified = True
                            extents_corrupted += 1

                if modified:
                    self._write_block(block_num, bytes(data))
                    blocks_damaged.append(block_num)
            except Exception:
                continue

        return DamageReport(
            damage_type=DamageType.EXTENT_OVERFLOW_CORRUPT,
            description=f"Corrupted {extents_corrupted} extent records in {len(blocks_damaged)} blocks",
            blocks_affected=blocks_damaged,
            bytes_modified=extents_corrupted * 8
        )


def create_damaged_copy(source_path: str, dest_path: str, damage_types: List[DamageType]) -> List[DamageReport]:
    """
    Create a damaged copy of a disk image for testing.
    
    Args:
        source_path: Path to original (healthy) disk image
        dest_path: Path to write damaged copy
        damage_types: List of damage types to inflict
    
    Returns:
        List of DamageReports describing the damage
    """
    # Copy the image
    shutil.copy2(source_path, dest_path)
    
    # Inflict damage
    simulator = APFSDamageSimulator(dest_path)
    reports = []
    
    for damage_type in damage_types:
        try:
            report = simulator.inflict_damage(damage_type)
            reports.append(report)
            print(f"[DAMAGE] {report.description}")
        except Exception as e:
            print(f"[ERROR] Failed to inflict {damage_type.name}: {e}")
    
    return reports


if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("APFS Damage Simulator")
        print()
        print("Usage: python damage_simulator.py <source.dmg> <output.dmg> [damage_types...]")
        print()
        print("Damage types:")
        for dt in DamageType:
            print(f"  {dt.name}")
        print()
        print("Example:")
        print("  python damage_simulator.py clean.dmg damaged.dmg CONTAINER_SUPERBLOCK_ZERO")
        sys.exit(1)
    
    source = sys.argv[1]
    output = sys.argv[2]
    
    if len(sys.argv) > 3:
        damage_types = [DamageType[name] for name in sys.argv[3:]]
    else:
        damage_types = [DamageType.CONTAINER_SUPERBLOCK_MAGIC]
    
    print(f"Creating damaged copy: {source} -> {output}")
    print(f"Damage types: {[dt.name for dt in damage_types]}")
    print()
    
    reports = create_damaged_copy(source, output, damage_types)
    
    print()
    print("=== Damage Summary ===")
    for report in reports:
        print(f"  {report.damage_type.name}: {len(report.blocks_affected)} blocks, {report.bytes_modified} bytes")

