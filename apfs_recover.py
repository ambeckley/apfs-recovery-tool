#!/usr/bin/env python3
"""
APFS Recovery Tool - Production Version
========================================

Unified recovery tool for both encrypted and unencrypted APFS filesystems.
"""

import os
import sys
import argparse
from typing import Optional

# Import recovery classes from sibling modules
try:
    from directory_reconstructor import (
        APFSDirectoryReconstructor,
        reconstruct_directory
    )
    DIRECTORY_RECONSTRUCTOR_AVAILABLE = True
except ImportError as e:
    print(f"ERROR: Failed to import directory_reconstructor: {e}")
    DIRECTORY_RECONSTRUCTOR_AVAILABLE = False

try:
    from encrypted_recovery import (
        APFSEncryptedRecovery,
        recover_encrypted_volume,
        CRYPTO_AVAILABLE
    )
    ENCRYPTED_RECOVERY_AVAILABLE = True
except ImportError:
    ENCRYPTED_RECOVERY_AVAILABLE = False
    CRYPTO_AVAILABLE = False


def recover_unencrypted(image_path: str, output_dir: str, show_progress: bool = True):
    """Recover from unencrypted APFS volume."""
    if not DIRECTORY_RECONSTRUCTOR_AVAILABLE:
        raise RuntimeError("directory_reconstructor module not available")
    
    print("Using unencrypted recovery method...")
    print()
    
    reconstructor = APFSDirectoryReconstructor(image_path, output_dir)
    result = reconstructor.reconstruct(show_progress=show_progress)
    
    return {
        'success': result.files_extracted > 0,
        'is_encrypted': False,
        'directories_found': result.directories_found,
        'files_found': result.files_found,
        'paths_resolved': result.paths_resolved,
        'files_extracted': result.files_extracted,
        'compressed_files': result.compressed_files,
        'deleted_files_found': result.deleted_files_found,
        'deleted_files_recovered': result.deleted_files_recovered,
        'scan_time': result.scan_time,
        'build_time': result.build_time,
        'extract_time': result.extract_time,
        'total_time': result.total_time,
        'blocks_scanned': result.blocks_scanned,
        'errors': result.errors
    }


def recover_encrypted(image_path: str, password: str, output_dir: str):
    """Recover from encrypted APFS volume."""
    if not ENCRYPTED_RECOVERY_AVAILABLE:
        raise RuntimeError("encrypted_recovery module not available")
    
    if not CRYPTO_AVAILABLE:
        raise RuntimeError("cryptography module required for encrypted volumes")
    
    print("Using encrypted recovery method...")
    print()
    
    recovery = APFSEncryptedRecovery(image_path, password, output_dir)
    result = recovery.recover()
    
    return {
        'success': result.vek_derived and result.files_extracted > 0,
        'is_encrypted': True,
        'keybag_found': result.keybag_found,
        'vek_derived': result.vek_derived,
        'directories_found': result.directories_found,
        'files_found': result.files_found,
        'files_extracted': result.files_extracted,
        'errors': result.errors
    }


def check_encryption(image_path: str) -> bool:
    """Check if volume is encrypted by looking for keybag."""
    try:
        with open(image_path, 'rb') as f:
            data = f.read()
        
        # Find container superblock
        nxsb_offset = data.find(b'NXSB')
        if nxsb_offset < 0:
            return False
        
        partition_offset = nxsb_offset - 32
        
        # Check for keybag location in container superblock (offset 1296)
        if partition_offset + 1312 <= len(data):
            import struct
            keylocker_start = struct.unpack('<Q', 
                data[partition_offset+1296:partition_offset+1304])[0]
            keylocker_count = struct.unpack('<Q', 
                data[partition_offset+1304:partition_offset+1312])[0]
            
            return keylocker_start > 0 and keylocker_count > 0
        
        return False
    except:
        return False


def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(
        description='APFS Recovery Tool - Recover files from damaged APFS images',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''
Examples:
  # Recover from unencrypted volume
  %(prog)s damaged.dmg
  
  # Recover from encrypted volume
  %(prog)s encrypted.dmg --password "mypassword"
  
  # Specify output directory
  %(prog)s damaged.dmg --output recovered_files/
  
  # Quiet mode (errors only)
  %(prog)s damaged.dmg --quiet

Features:
  - Automatically detects encryption
  - Supports both encrypted and unencrypted volumes
  - Decompresses zlib/lzvn/lzfse compressed files
  - Recovers deleted file fragments
  - Handles severe filesystem damage
        '''
    )
    
    parser.add_argument('image', help='Path to the APFS disk image')
    parser.add_argument('-p', '--password', 
                       help='Password for encrypted volumes (required if encrypted)')
    parser.add_argument('-o', '--output', 
                       help='Output directory for recovered files')
    parser.add_argument('-q', '--quiet', action='store_true',
                       help='Quiet mode (errors only)')
    parser.add_argument('-v', '--verbose', action='store_true',
                       help='Verbose output')
    
    args = parser.parse_args()
    
    if not os.path.exists(args.image):
        print(f"ERROR: Image not found: {args.image}", file=sys.stderr)
        sys.exit(1)
    
    output_dir = args.output or f"{args.image}_recovered"
    show_progress = not args.quiet
    
    print("=" * 70)
    print("APFS Recovery Tool")
    print("=" * 70)
    print(f"Image: {args.image}")
    print(f"Output: {output_dir}")
    print()
    
    # Check encryption status
    if show_progress:
        print("Checking encryption status...")
    
    is_encrypted = check_encryption(args.image)
    
    try:
        # Recover based on encryption status and password
        if args.password:
            # Password provided - try encrypted recovery
            if not ENCRYPTED_RECOVERY_AVAILABLE:
                print("ERROR: Encrypted recovery module not available", file=sys.stderr)
                sys.exit(1)
            
            if not CRYPTO_AVAILABLE:
                print("ERROR: cryptography module required for encrypted volumes", file=sys.stderr)
                print("Install with: pip install cryptography", file=sys.stderr)
                sys.exit(1)
            
            if is_encrypted:
                print("  ✓ Volume is ENCRYPTED")
            else:
                print("  ⚠ Volume encryption not detected, but password provided")
                print("  Attempting encrypted recovery anyway...")
            
            print()
            result = recover_encrypted(args.image, args.password, output_dir)
            
        elif is_encrypted:
            # Encrypted but no password
            print("  ✓ Volume is ENCRYPTED")
            print()
            print("ERROR: Password required for encrypted volume!")
            print("Please provide password with --password option")
            sys.exit(1)
            
        else:
            # Unencrypted
            print("  ✓ Volume is UNENCRYPTED")
            print()
            result = recover_unencrypted(args.image, output_dir, show_progress)
        
        # Print summary
        if not args.quiet:
            print()
            print("=" * 70)
            print("RECOVERY COMPLETE")
            print("=" * 70)
            
            if result.get('success'):
                print("Status: ✓ SUCCESS")
            else:
                print("Status: ✗ FAILED")
                if 'errors' in result and result['errors']:
                    print("\nErrors:")
                    for error in result['errors']:
                        print(f"  - {error}")
            
            print()
            print("Results:")
            
            if result.get('is_encrypted'):
                print(f"  Volume type:        Encrypted")
                print(f"  Keybag found:       {result.get('keybag_found', False)}")
                print(f"  VEK derived:        {result.get('vek_derived', False)}")
            else:
                print(f"  Volume type:        Unencrypted")
            
            print(f"  Directories found:  {result.get('directories_found', 0)}")
            print(f"  Files found:        {result.get('files_found', 0)}")
            print(f"  Files extracted:    {result.get('files_extracted', 0)}")
            
            if 'compressed_files' in result:
                print(f"  Compressed files:   {result['compressed_files']}")
            
            if 'total_time' in result:
                print()
                print("Timing:")
                print(f"  Total time:         {result.get('total_time', 0):.2f}s")
                print(f"  Scan time:          {result.get('scan_time', 0):.2f}s")
                print(f"  Build time:         {result.get('build_time', 0):.2f}s")
                print(f"  Extract time:       {result.get('extract_time', 0):.2f}s")
            
            print()
            print(f"Recovered files saved to: {output_dir}")
        
        # Exit with appropriate code
        sys.exit(0 if result.get('success') else 1)
        
    except KeyboardInterrupt:
        print("\n\nRecovery interrupted by user", file=sys.stderr)
        sys.exit(130)
    except Exception as e:
        print(f"\nERROR: {e}", file=sys.stderr)
        if args.verbose:
            import traceback
            traceback.print_exc()
        sys.exit(1)


if __name__ == '__main__':
    main()
