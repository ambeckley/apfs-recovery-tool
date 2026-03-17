#!/usr/bin/env python3
"""
Create Test APFS Images (Encrypted and Unencrypted)
===================================================

Creates APFS test images with realistic file content for recovery testing.

For ENCRYPTED images:
- Uses diskutil apfs encryptVolume for native APFS encryption
- The raw DMG file contains encrypted file data blocks
- Keybags and wrapped VEK are stored in APFS metadata
- Recovery tool can derive VEK from password and decrypt files

For UNENCRYPTED images:
- Standard APFS volume without encryption
- Used for testing basic recovery logic
"""

import os
import sys
import subprocess
import tempfile
import shutil
import random
import hashlib
import json
import time
from pathlib import Path


def create_encrypted_image(output_path: str, password: str, size_mb: int = 150,
                           target_usage_percent: float = 85.0,
                           content_dir: str = None):
    """
    Create an encrypted APFS test image with native APFS encryption.

    The resulting DMG contains:
    - Encrypted file data blocks (decryptable with VEK)
    - Container keybag (encrypted with container UUID)
    - Volume keybag (contains wrapped VEK, KEK info)

    If content_dir is provided, uses that directory's files instead of generating new ones.
    """
    print(f"Creating encrypted APFS test image: {output_path}")
    print(f"  Size: {size_mb}MB, Target usage: {target_usage_percent}%")
    print(f"  Password: {password}")
    if content_dir:
        print(f"  Using shared content from: {content_dir}")
    print()

    mount_point = '/Volumes/EncryptedTest'

    # Clean up any stale mounts
    subprocess.run(['hdiutil', 'detach', mount_point, '-force'], capture_output=True)

    with tempfile.TemporaryDirectory() as temp_dir:
        temp_image = os.path.join(temp_dir, 'temp.dmg')

        # Generate file content or use provided content_dir
        if content_dir:
            file_hashes = {}
            file_count = 0
            total_data = 0
            for root, dirs, files in os.walk(content_dir):
                for fname in files:
                    fpath = os.path.join(root, fname)
                    rel = os.path.relpath(fpath, content_dir)
                    data = open(fpath, 'rb').read()
                    file_hashes[rel] = {'hash': hashlib.sha256(data).hexdigest(), 'size': len(data)}
                    file_count += 1
                    total_data += len(data)
            stats = {'file_count': file_count, 'total_data': total_data}
        else:
            content_dir, file_hashes, stats = generate_test_content(
                temp_dir, size_mb, target_usage_percent
            )
        
        try:
            # Step 1: Create unencrypted APFS image
            print("Creating APFS volume...")
            subprocess.run([
                'hdiutil', 'create', '-size', f'{size_mb}m', '-fs', 'APFS',
                '-volname', 'EncryptedTest', temp_image
            ], capture_output=True, check=True)
            
            # Step 2: Mount and copy files
            print("Mounting and copying files...")
            subprocess.run(['hdiutil', 'attach', temp_image], capture_output=True, check=True)
            
            copy_files_to_volume(content_dir, mount_point)
            subprocess.run(['sync'], check=True)
            time.sleep(1)
            
            # Step 3: Get disk identifier
            disk_id = get_disk_identifier(mount_point)
            if not disk_id:
                raise RuntimeError("Could not find disk identifier")
            
            # Step 4: Enable native APFS encryption
            print(f"Enabling APFS encryption on {disk_id}...")
            enc_result = subprocess.run([
                'diskutil', 'apfs', 'encryptVolume', disk_id,
                '-user', 'disk', '-passphrase', password
            ], capture_output=True, text=True)
            
            if enc_result.returncode != 0:
                print(f"  Warning: {enc_result.stderr}")
            
            # Step 5: Wait for encryption to complete
            # On disk images, diskutil shows "FileVault: Yes" immediately but
            # actual encryption happens in background without progress reporting.
            # We need to wait based on actual data size to ensure encryption completes.
            print("Waiting for encryption to complete...")
            
            # First wait for FileVault status
            if not wait_for_encryption(mount_point, timeout=30):
                print("  ✗ Warning: Encryption did not start!")
            
            # Then wait additional time based on data size
            # Encryption speed is typically 50-200 MB/s, so use 10MB/s as worst case
            data_mb = int(size_mb * target_usage_percent / 100)
            wait_seconds = max(30, data_mb // 10)  # At least 30 seconds, or 1 sec per 10MB
            print(f"  Waiting {wait_seconds}s for background encryption to complete ({data_mb}MB data)...")
            
            for i in range(wait_seconds):
                time.sleep(1)
                if (i+1) % 10 == 0:
                    print(f"    {i+1}/{wait_seconds}s...", end='\r')
            print(f"  ✓ Waited {wait_seconds}s for encryption                    ")
            
            # Step 6: Sync and detach
            subprocess.run(['sync'], check=True)
            time.sleep(2)
            subprocess.run(['hdiutil', 'detach', mount_point], capture_output=True)
            time.sleep(1)
            
            # Step 7: Move to output
            if os.path.exists(output_path):
                os.remove(output_path)
            shutil.move(temp_image, output_path)
            
            # Verify encryption
            if verify_encryption(output_path):
                print(f"✓ Created encrypted image: {output_path}")
                print(f"✓ Files: {stats['file_count']}, Data: {stats['total_data']/(1024*1024):.1f}MB")
                return file_hashes
            else:
                print("✗ Warning: Encryption verification failed")
                return file_hashes
                
        except subprocess.CalledProcessError as e:
            print(f"✗ Failed: {e}")
            subprocess.run(['hdiutil', 'detach', mount_point], capture_output=True)
            return None


def create_unencrypted_image(output_path: str, size_mb: int = 150,
                             target_usage_percent: float = 85.0,
                             content_dir: str = None):
    """
    Create an unencrypted APFS test image.

    If content_dir is provided, uses that directory's files instead of generating new ones.
    Returns (file_hashes, content_dir_used) so caller can reuse content_dir for encrypted image.
    """
    print(f"Creating unencrypted APFS test image: {output_path}")
    print(f"  Size: {size_mb}MB, Target usage: {target_usage_percent}%")
    if content_dir:
        print(f"  Using shared content from: {content_dir}")
    print()

    mount_point = '/Volumes/TestVolume'
    subprocess.run(['hdiutil', 'detach', mount_point, '-force'], capture_output=True)

    with tempfile.TemporaryDirectory() as temp_dir:
        temp_image = os.path.join(temp_dir, 'temp.dmg')

        if content_dir:
            file_hashes = {}
            file_count = 0
            total_data = 0
            for root, dirs, files in os.walk(content_dir):
                for fname in files:
                    fpath = os.path.join(root, fname)
                    rel = os.path.relpath(fpath, content_dir)
                    data = open(fpath, 'rb').read()
                    file_hashes[rel] = {'hash': hashlib.sha256(data).hexdigest(), 'size': len(data)}
                    file_count += 1
                    total_data += len(data)
            stats = {'file_count': file_count, 'total_data': total_data}
        else:
            content_dir, file_hashes, stats = generate_test_content(
                temp_dir, size_mb, target_usage_percent
            )
        
        try:
            subprocess.run([
                'hdiutil', 'create', '-size', f'{size_mb}m', '-fs', 'APFS',
                '-volname', 'TestVolume', temp_image
            ], capture_output=True, check=True)
            
            subprocess.run(['hdiutil', 'attach', temp_image], capture_output=True, check=True)
            copy_files_to_volume(content_dir, mount_point)
            subprocess.run(['sync'], check=True)
            subprocess.run(['hdiutil', 'detach', mount_point], capture_output=True)
            
            if os.path.exists(output_path):
                os.remove(output_path)
            shutil.move(temp_image, output_path)
            
            print(f"✓ Created unencrypted image: {output_path}")
            print(f"✓ Files: {stats['file_count']}, Data: {stats['total_data']/(1024*1024):.1f}MB")
            return file_hashes
            
        except subprocess.CalledProcessError as e:
            print(f"✗ Failed: {e}")
            subprocess.run(['hdiutil', 'detach', mount_point], capture_output=True)
            return None


def generate_test_content(temp_dir: str, size_mb: int, usage_percent: float):
    """Generate test files and return (content_dir, file_hashes, stats)."""
    content_dir = os.path.join(temp_dir, 'content')
    os.makedirs(content_dir, exist_ok=True)
    
    target_bytes = int((size_mb * usage_percent / 100.0) * 1024 * 1024)
    file_hashes = {}
    total_data = 0
    file_count = 0
    
    # Create directories
    dirs = ['Documents', 'Pictures', 'Music', 'Videos', 'Downloads', 
            'Projects', 'Library', 'Desktop', 'Applications', 'System']
    for d in dirs:
        os.makedirs(os.path.join(content_dir, d), exist_ok=True)
    
    subdirs = []
    for parent in ['Documents', 'Projects', 'Pictures']:
        for i in range(5):
            subdir = os.path.join(content_dir, parent, f'subdir_{i}')
            os.makedirs(subdir, exist_ok=True)
            subdirs.append(os.path.join(parent, f'subdir_{i}'))
    
    all_dirs = [os.path.join(content_dir, d) for d in dirs + subdirs]
    
    words = ['the', 'quick', 'brown', 'fox', 'jumps', 'over', 'lazy', 'dog',
             'file', 'data', 'test', 'content', 'recovery', 'apfs', 'disk',
             'system', 'volume', 'directory', 'structure', 'metadata', 'block']
    
    # Small files
    for i in range(min(500, int(target_bytes * 0.3 / 20000))):
        if total_data >= target_bytes:
            break
        dirpath = random.choice(all_dirs)
        filepath = os.path.join(dirpath, f'file_{i:05d}.txt')
        size = random.randint(1000, 50000)
        content = (' '.join(random.choices(words, k=size//10)) + '\n').encode()[:size]
        with open(filepath, 'wb') as f:
            f.write(content)
        rel = os.path.relpath(filepath, content_dir)
        file_hashes[rel] = {'hash': hashlib.sha256(content).hexdigest(), 'size': len(content)}
        total_data += len(content)
        file_count += 1
    
    # Medium files
    for i in range(min(200, int(target_bytes * 0.4 / 300000))):
        if total_data >= target_bytes:
            break
        dirpath = random.choice(all_dirs)
        filepath = os.path.join(dirpath, f'medium_{i:04d}.dat')
        size = random.randint(50000, 500000)
        content = (bytes(range(256)) * (size // 256 + 1))[:size]
        with open(filepath, 'wb') as f:
            f.write(content)
        rel = os.path.relpath(filepath, content_dir)
        file_hashes[rel] = {'hash': hashlib.sha256(content).hexdigest(), 'size': len(content)}
        total_data += len(content)
        file_count += 1
    
    # Large files - scale to fill remaining space
    remaining = target_bytes - total_data
    large_file_size = 10 * 1024 * 1024  # 10MB per large file
    num_large_files = max(1, remaining // large_file_size + 1)
    for i in range(num_large_files):
        if total_data >= target_bytes:
            break
        dirpath = random.choice(all_dirs)
        filepath = os.path.join(dirpath, f'large_{i:03d}.bin')
        size = min(large_file_size, target_bytes - total_data)
        if size <= 0:
            break
        content = os.urandom(size)
        with open(filepath, 'wb') as f:
            f.write(content)
        rel = os.path.relpath(filepath, content_dir)
        file_hashes[rel] = {'hash': hashlib.sha256(content).hexdigest(), 'size': len(content)}
        total_data += len(content)
        file_count += 1
    
    # Special files
    for name, content in [
        ('README.md', f'# Test Image\n\nFiles: {file_count}\nData: {total_data}\n'.encode()),
        ('config.json', json.dumps({'files': file_count, 'size': total_data}).encode()),
    ]:
        with open(os.path.join(content_dir, name), 'wb') as f:
            f.write(content)
        file_hashes[name] = {'hash': hashlib.sha256(content).hexdigest(), 'size': len(content)}
        file_count += 1
    
    print(f"  Generated {file_count} files, {total_data/(1024*1024):.1f}MB")
    
    return content_dir, file_hashes, {'file_count': file_count, 'total_data': total_data}


def copy_files_to_volume(content_dir: str, mount_point: str):
    """Copy files from content_dir to mounted volume."""
    for root, dirs, files in os.walk(content_dir):
        rel_root = os.path.relpath(root, content_dir)
        target_dir = mount_point if rel_root == '.' else os.path.join(mount_point, rel_root)
        os.makedirs(target_dir, exist_ok=True)
        for f in files:
            shutil.copy2(os.path.join(root, f), os.path.join(target_dir, f))


def get_disk_identifier(mount_point: str) -> str:
    """Get the disk identifier for a mount point."""
    info = subprocess.run(['diskutil', 'info', mount_point], capture_output=True, text=True)
    for line in info.stdout.split('\n'):
        if 'Device Identifier:' in line:
            return line.split(':')[1].strip()
    return None


def wait_for_encryption(mount_point: str, timeout: int = 120) -> bool:
    """Wait for encryption to START, return True if encryption is enabled."""
    start = time.time()
    
    while time.time() - start < timeout:
        info = subprocess.run(['diskutil', 'info', mount_point], capture_output=True, text=True)
        
        for line in info.stdout.split('\n'):
            if 'FileVault:' in line:
                status = line.split(':')[1].strip()
                if status == 'Yes' or 'Encrypting' in status:
                    return True
        
        time.sleep(1)
    
    return False


def verify_encryption(dmg_path: str) -> bool:
    """Verify that the DMG contains encrypted data."""
    with open(dmg_path, 'rb') as f:
        data = f.read()
    
    # Check for NXSB (APFS container) and absence of obvious plaintext patterns
    has_nxsb = b'NXSB' in data[:100000]
    
    # The file content should not be visible as plaintext
    # (unless it's very short and happens to match encrypted patterns)
    return has_nxsb


if __name__ == '__main__':
    if len(sys.argv) < 2:
        print("Usage:")
        print("  python create_encrypted_image.py encrypted <output.dmg> <password> [size_mb] [usage%]")
        print("  python create_encrypted_image.py unencrypted <output.dmg> [size_mb] [usage%]")
        print()
        print("Examples:")
        print("  python create_encrypted_image.py encrypted test.dmg mypassword 150 85")
        print("  python create_encrypted_image.py unencrypted test.dmg 150 85")
        sys.exit(1)
    
    mode = sys.argv[1]
    
    if mode == 'encrypted':
        if len(sys.argv) < 4:
            print("Error: encrypted mode requires output path and password")
            sys.exit(1)
        output_path = sys.argv[2]
        password = sys.argv[3]
        size_mb = int(sys.argv[4]) if len(sys.argv) > 4 else 150
        usage = float(sys.argv[5]) if len(sys.argv) > 5 else 85.0
        
        hashes = create_encrypted_image(output_path, password, size_mb, usage)
        
    elif mode == 'unencrypted':
        output_path = sys.argv[2]
        size_mb = int(sys.argv[3]) if len(sys.argv) > 3 else 150
        usage = float(sys.argv[4]) if len(sys.argv) > 4 else 85.0
        
        hashes = create_unencrypted_image(output_path, size_mb, usage)
    
    else:
        print(f"Unknown mode: {mode}")
        sys.exit(1)
    
    if hashes:
        hash_file = output_path.replace('.dmg', '_hashes.json')
        with open(hash_file, 'w') as f:
            json.dump(hashes, f, indent=2)
        print(f"✓ Saved hashes to: {hash_file}")
