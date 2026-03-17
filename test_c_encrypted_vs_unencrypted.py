#!/usr/bin/env python3
"""
Compare C Implementation: Unencrypted vs Encrypted Recovery
============================================================

Tests the C implementation on both unencrypted and encrypted volumes
with the same damage types and compares recovery rates.

Ground truth is established by mounting the DMG and hashing every file.
"""

import os
import sys
import json
import time
import subprocess
import hashlib
import shutil
from pathlib import Path
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass

# Unbuffered print
import functools
print = functools.partial(print, flush=True)

# Add parent directory for imports
parent_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, parent_dir)
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from damage_simulator import APFSDamageSimulator, DamageType
from create_encrypted_image import (
    create_encrypted_image, create_unencrypted_image, generate_test_content
)


@dataclass
class ComparisonResult:
    damage_type: str
    unencrypted_rate: float
    encrypted_rate: float
    unencrypted_matches: int
    encrypted_matches: int
    unencrypted_total: int
    encrypted_total: int
    difference: float
    unencrypted_time: float
    encrypted_time: float


def hash_mounted_volume(mount_point: str) -> Dict[str, dict]:
    """Walk a mounted volume and hash every file. Returns {rel_path: {hash, size}}."""
    hashes = {}
    mp = Path(mount_point)
    for f in mp.rglob('*'):
        if f.is_file():
            rel = str(f.relative_to(mp))
            # Skip macOS metadata
            if rel.startswith('.') or '/..' in rel or '.DS_Store' in rel:
                continue
            if '/.fseventsd' in rel or '/.Spotlight' in rel or '/.Trashes' in rel:
                continue
            try:
                data = f.read_bytes()
                hashes[rel] = {
                    'hash': hashlib.sha256(data).hexdigest(),
                    'size': len(data)
                }
            except Exception:
                pass
    return hashes


def mount_dmg(dmg_path: str, password: str = None) -> Optional[str]:
    """Mount a DMG, return the mount point path or None.

    For APFS native encryption: attach without mount, find the APFS container,
    unlock with password, return the mount point.
    """
    try:
        if password:
            # APFS native encryption: attach without mounting first
            result = subprocess.run(
                ['hdiutil', 'attach', dmg_path, '-nobrowse', '-nomount'],
                capture_output=True, text=True, timeout=60
            )
            if result.returncode != 0:
                print(f"    Attach failed: {result.stderr.strip()}")
                return None

            # Find the APFS synthesized disk (container)
            # Output lines like: /dev/disk6  GUID_partition_scheme
            #                    /dev/disk6s1  Apple_APFS
            #                    /dev/disk7  EF57347C-...  (APFS container)
            #                    /dev/disk7s1  41504653-...  (APFS volume)
            parent_disk = None
            volume_disk = None
            for line in result.stdout.strip().split('\n'):
                parts = line.split()
                if len(parts) >= 1:
                    dev = parts[0]
                    if 'GUID' in line:
                        parent_disk = dev
                    # Keep updating - the LAST s1 entry is the APFS synthesized volume
                    if dev.startswith('/dev/disk') and 's1' in dev:
                        volume_disk = dev

            if not volume_disk:
                print(f"    Could not find APFS volume disk")
                if parent_disk:
                    subprocess.run(['hdiutil', 'detach', parent_disk, '-force'], capture_output=True)
                return None

            # Unlock the encrypted volume
            unlock = subprocess.run(
                ['diskutil', 'apfs', 'unlockVolume', volume_disk, '-passphrase', password],
                capture_output=True, text=True, timeout=60
            )
            if unlock.returncode != 0:
                print(f"    Unlock failed: {unlock.stderr.strip()}")
                if parent_disk:
                    subprocess.run(['hdiutil', 'detach', parent_disk, '-force'], capture_output=True)
                return None

            # Find where it mounted
            info = subprocess.run(['diskutil', 'info', volume_disk], capture_output=True, text=True)
            for line in info.stdout.split('\n'):
                if 'Mount Point:' in line:
                    mp = line.split(':', 1)[1].strip()
                    if mp and mp != 'Not Mounted':
                        return mp

            print(f"    Volume unlocked but mount point not found")
            if parent_disk:
                subprocess.run(['hdiutil', 'detach', parent_disk, '-force'], capture_output=True)
            return None

        else:
            # Unencrypted: simple attach
            result = subprocess.run(
                ['hdiutil', 'attach', dmg_path, '-nobrowse'],
                capture_output=True, text=True, timeout=60
            )
            if result.returncode != 0:
                print(f"    Attach failed: {result.stderr.strip()}")
                return None

            for line in result.stdout.strip().split('\n'):
                parts = line.split('\t')
                if len(parts) >= 3:
                    mp = parts[-1].strip()
                    if mp.startswith('/Volumes/'):
                        return mp
    except Exception as e:
        print(f"    Mount failed: {e}")
    return None


def unmount_dmg(mount_point: str):
    """Unmount a DMG. Finds the parent disk and detaches the whole thing."""
    try:
        # Find the device for this mount point
        info = subprocess.run(['diskutil', 'info', mount_point], capture_output=True, text=True)
        dev = None
        for line in info.stdout.split('\n'):
            if 'Part of Whole:' in line:
                dev = '/dev/' + line.split(':')[1].strip()
                break
        if dev:
            subprocess.run(['hdiutil', 'detach', dev, '-force'], capture_output=True, timeout=30)
        else:
            subprocess.run(['hdiutil', 'detach', mount_point, '-force'], capture_output=True, timeout=30)
    except Exception:
        subprocess.run(['hdiutil', 'detach', mount_point, '-force'], capture_output=True)


def get_ground_truth(dmg_path: str, password: str = None) -> Dict[str, dict]:
    """Mount DMG, hash all files, unmount. This IS the ground truth."""
    mount_point = mount_dmg(dmg_path, password)
    if not mount_point:
        print(f"  ✗ Failed to mount {dmg_path}")
        return {}

    try:
        hashes = hash_mounted_volume(mount_point)
        return hashes
    finally:
        unmount_dmg(mount_point)
        time.sleep(1)


def verify_recovery(recovered_dir: str, ground_truth: Dict[str, dict]) -> Tuple[int, int]:
    """Compare recovered files against ground truth hashes."""
    rec_path = Path(recovered_dir)
    matches = 0
    total = len(ground_truth)

    # Build hash map of recovered files
    recovered = {}
    for f in rec_path.rglob('*'):
        if f.is_file():
            rel = str(f.relative_to(rec_path))
            try:
                data = f.read_bytes()
                recovered[rel] = hashlib.sha256(data).hexdigest()
            except Exception:
                pass

    # Check each ground truth file
    for rel_path, info in ground_truth.items():
        expected_hash = info['hash'] if isinstance(info, dict) else info
        if recovered.get(rel_path) == expected_hash:
            matches += 1

    return matches, total


def run_c_recovery(image_path: str, output_dir: str, password: str = None) -> Tuple[dict, float]:
    """Run C recovery tool, return (stats, elapsed_time)."""
    c_program = Path(__file__).parent / "apfs_recover"
    if not c_program.exists():
        return {'error': 'C program not found'}, 0.0

    start = time.time()
    cmd = [str(c_program), image_path, output_dir, '--quiet']
    if password:
        cmd.extend(['--password', password])

    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=1800)
        elapsed = time.time() - start

        if result.returncode != 0:
            return {'error': f'Return code {result.returncode}', 'stderr': result.stderr[:200]}, elapsed

        files = len([f for f in Path(output_dir).rglob('*') if f.is_file()]) if Path(output_dir).exists() else 0
        return {'success': True, 'files_extracted': files}, elapsed
    except subprocess.TimeoutExpired:
        return {'error': 'Timed out'}, time.time() - start
    except Exception as e:
        return {'error': str(e)}, time.time() - start


def test_damage_type(base_unencrypted: str, base_encrypted: str,
                     truth_unenc: Dict, truth_enc: Dict,
                     damage_type: DamageType, work_dir: Path,
                     password: str, damage_kwargs: dict = None) -> ComparisonResult:
    """Test one damage type on both images."""
    if damage_kwargs is None:
        damage_kwargs = {}

    print(f"\n  Testing {damage_type.name}...")

    damaged_unenc = work_dir / f"damaged_unenc_{damage_type.name}.dmg"
    damaged_enc = work_dir / f"damaged_enc_{damage_type.name}.dmg"
    out_unenc = work_dir / f"recovered_unenc_{damage_type.name}"
    out_enc = work_dir / f"recovered_enc_{damage_type.name}"

    # Clean up
    for f in [damaged_unenc, damaged_enc]:
        if f.exists(): f.unlink()
    for d in [out_unenc, out_enc]:
        subprocess.run(['rm', '-rf', str(d)], capture_output=True)
    out_unenc.mkdir(exist_ok=True)
    out_enc.mkdir(exist_ok=True)

    # Apply damage
    try:
        shutil.copy2(base_unencrypted, damaged_unenc)
        shutil.copy2(base_encrypted, damaged_enc)

        sim = APFSDamageSimulator(str(damaged_unenc))
        sim.inflict_damage(damage_type, **damage_kwargs)
        sim = APFSDamageSimulator(str(damaged_enc))
        sim.inflict_damage(damage_type, **damage_kwargs)
    except Exception as e:
        print(f"    ✗ Failed to apply damage: {e}")
        for f in [damaged_unenc, damaged_enc]:
            if f.exists(): f.unlink()
        for d in [out_unenc, out_enc]:
            subprocess.run(['rm', '-rf', str(d)], capture_output=True)
        return ComparisonResult(damage_type.name, 0, 0, 0, 0, 0, 0, 0, 0, 0)

    # Recover unencrypted
    _, unenc_time = run_c_recovery(str(damaged_unenc), str(out_unenc))
    unenc_matches, unenc_total = verify_recovery(str(out_unenc), truth_unenc)
    unenc_rate = unenc_matches / unenc_total if unenc_total > 0 else 0.0

    # Recover encrypted
    _, enc_time = run_c_recovery(str(damaged_enc), str(out_enc), password)
    enc_matches, enc_total = verify_recovery(str(out_enc), truth_enc)
    enc_rate = enc_matches / enc_total if enc_total > 0 else 0.0

    print(f"    Unencrypted: {unenc_rate*100:.1f}% ({unenc_matches}/{unenc_total}), {unenc_time:.2f}s")
    print(f"    Encrypted:   {enc_rate*100:.1f}% ({enc_matches}/{enc_total}), {enc_time:.2f}s")
    diff = enc_rate - unenc_rate
    if abs(diff) > 0.01:
        print(f"    ⚠ Difference: {diff*100:+.1f}%")

    # Clean up test artifacts
    for f in [damaged_unenc, damaged_enc]:
        if f.exists(): f.unlink()
    for d in [out_unenc, out_enc]:
        subprocess.run(['rm', '-rf', str(d)], capture_output=True)

    return ComparisonResult(
        damage_type=damage_type.name,
        unencrypted_rate=unenc_rate,
        encrypted_rate=enc_rate,
        unencrypted_matches=unenc_matches,
        encrypted_matches=enc_matches,
        unencrypted_total=unenc_total,
        encrypted_total=enc_total,
        difference=diff,
        unencrypted_time=unenc_time,
        encrypted_time=enc_time
    )


def main():
    print("=" * 70)
    print("C Implementation: Unencrypted vs Encrypted Recovery Comparison")
    print("=" * 70)
    print()

    script_dir = Path(__file__).parent.resolve()
    work_dir = script_dir / "test_c_encrypted_vs_unencrypted"
    work_dir.mkdir(exist_ok=True)

    base_unencrypted = work_dir / "base_unencrypted.dmg"
    base_encrypted = work_dir / "base_encrypted.dmg"
    password = "testpass123"

    print(f"Working directory: {work_dir}")
    print("Note: Test artifacts are cleaned up after each test to save disk space.")
    print()

    # Step 1: Create images from SAME content
    print("Step 1: Creating test images from shared content...")
    size_mb = 1024
    usage_pct = 85.0

    need_create = not base_unencrypted.exists() or not base_encrypted.exists()
    if need_create:
        import tempfile
        # Generate content once, use for both images
        with tempfile.TemporaryDirectory() as temp_dir:
            print("  Generating shared test content...")
            shared_content_dir, _, stats = generate_test_content(temp_dir, size_mb, usage_pct)

            if not base_unencrypted.exists():
                print("  Creating unencrypted image from shared content...")
                hashes = create_unencrypted_image(
                    str(base_unencrypted), size_mb=size_mb,
                    target_usage_percent=usage_pct, content_dir=shared_content_dir
                )
                if not hashes:
                    print("  ✗ Failed to create unencrypted image")
                    return 1
            else:
                print(f"  ✓ Using existing: {base_unencrypted}")

            if not base_encrypted.exists():
                print("  Creating encrypted image from same shared content...")
                hashes = create_encrypted_image(
                    str(base_encrypted), password=password, size_mb=size_mb,
                    target_usage_percent=usage_pct, content_dir=shared_content_dir
                )
                if not hashes:
                    print("  ✗ Failed to create encrypted image")
                    return 1
            else:
                print(f"  ✓ Using existing: {base_encrypted}")
    else:
        print(f"  ✓ Using existing: {base_unencrypted}")
        print(f"  ✓ Using existing: {base_encrypted}")

    # Step 2: Establish ground truth by mounting and hashing
    print("\nStep 2: Establishing ground truth from DMGs...")

    truth_file_unenc = work_dir / "ground_truth_unencrypted.json"
    truth_file_enc = work_dir / "ground_truth_encrypted.json"

    if truth_file_unenc.exists():
        with open(truth_file_unenc) as f:
            truth_unenc = json.load(f)
        print(f"  ✓ Loaded cached unencrypted ground truth: {len(truth_unenc)} files")
    else:
        print("  Mounting unencrypted DMG to hash files...")
        truth_unenc = get_ground_truth(str(base_unencrypted))
        if not truth_unenc:
            print("  ✗ Failed to get unencrypted ground truth")
            return 1
        with open(truth_file_unenc, 'w') as f:
            json.dump(truth_unenc, f, indent=2)
        print(f"  ✓ Unencrypted ground truth: {len(truth_unenc)} files")

    if truth_file_enc.exists():
        with open(truth_file_enc) as f:
            truth_enc = json.load(f)
        print(f"  ✓ Loaded cached encrypted ground truth: {len(truth_enc)} files")
    else:
        print("  Mounting encrypted DMG to hash files...")
        truth_enc = get_ground_truth(str(base_encrypted), password)
        if not truth_enc:
            print("  ✗ Failed to get encrypted ground truth")
            return 1
        with open(truth_file_enc, 'w') as f:
            json.dump(truth_enc, f, indent=2)
        print(f"  ✓ Encrypted ground truth: {len(truth_enc)} files")

    # Step 3: Test all damage types
    print("\nStep 3: Getting all damage types...")
    all_damage_types = list(DamageType)
    print(f"  Found {len(all_damage_types)} damage types")

    print("\nStep 4: Testing all damage types...")
    print("=" * 70)

    results = []
    total_start = time.time()

    for i, dt in enumerate(all_damage_types, 1):
        print(f"\n[{i}/{len(all_damage_types)}] {dt.name}")

        kwargs = {}
        if dt == DamageType.MULTIPLE_LEAF_DESTRUCTION:
            kwargs['percent'] = 25

        result = test_damage_type(
            str(base_unencrypted), str(base_encrypted),
            truth_unenc, truth_enc,
            dt, work_dir, password, kwargs
        )
        results.append(result)

    total_time = time.time() - total_start

    # Step 5: Report
    print("\n" + "=" * 70)
    print("COMPARISON RESULTS SUMMARY")
    print("=" * 70)

    print(f"\nGround truth: {len(truth_unenc)} unencrypted files, {len(truth_enc)} encrypted files")
    print(f"Total damage types tested: {len(results)}")
    print(f"Total test time: {total_time:.1f}s")
    print()

    unenc_avg = sum(r.unencrypted_rate for r in results) / len(results) if results else 0
    enc_avg = sum(r.encrypted_rate for r in results) / len(results) if results else 0

    print("Average Recovery Rates:")
    print(f"  Unencrypted: {unenc_avg*100:.1f}%")
    print(f"  Encrypted:   {enc_avg*100:.1f}%")
    print(f"  Difference:  {(enc_avg - unenc_avg)*100:+.1f}%")
    print()

    significant = [r for r in results if abs(r.difference) > 0.01]
    if significant:
        print(f"Damage types with >1% difference ({len(significant)}):")
        for r in sorted(significant, key=lambda x: abs(x.difference), reverse=True):
            print(f"  {r.damage_type:40s} Unenc: {r.unencrypted_rate*100:5.1f}% ({r.unencrypted_matches}/{r.unencrypted_total})  "
                  f"Enc: {r.encrypted_rate*100:5.1f}% ({r.encrypted_matches}/{r.encrypted_total})  "
                  f"Diff: {r.difference*100:+6.1f}%")
        print()

    perfect = [r for r in results if abs(r.difference) < 0.001]
    print(f"Perfect matches (difference < 0.1%): {len(perfect)}/{len(results)}")

    # Show all results
    print(f"\nAll results:")
    for r in results:
        marker = "  " if abs(r.difference) < 0.001 else "⚠ "
        print(f"  {marker}{r.damage_type:40s} Unenc: {r.unencrypted_rate*100:5.1f}%  Enc: {r.encrypted_rate*100:5.1f}%")

    # Save report
    report_path = work_dir / "encrypted_vs_unencrypted_report.json"
    report = {
        'test_date': time.strftime('%Y-%m-%d %H:%M:%S'),
        'ground_truth_unencrypted_files': len(truth_unenc),
        'ground_truth_encrypted_files': len(truth_enc),
        'total_damage_types': len(results),
        'total_time': total_time,
        'average_unencrypted_rate': unenc_avg,
        'average_encrypted_rate': enc_avg,
        'results': [
            {
                'damage_type': r.damage_type,
                'unencrypted_rate': r.unencrypted_rate,
                'encrypted_rate': r.encrypted_rate,
                'unencrypted_matches': r.unencrypted_matches,
                'encrypted_matches': r.encrypted_matches,
                'unencrypted_total': r.unencrypted_total,
                'encrypted_total': r.encrypted_total,
                'difference': r.difference,
                'unencrypted_time': r.unencrypted_time,
                'encrypted_time': r.encrypted_time
            }
            for r in results
        ]
    }
    with open(report_path, 'w') as f:
        json.dump(report, f, indent=2)

    print(f"\nDetailed report saved to: {report_path}")
    print("=" * 70)
    return 0


if __name__ == '__main__':
    sys.exit(main())
