#!/usr/bin/env python3
"""
Compare Python vs C Recovery Implementation
=============================================

Tests both Python and C tools on the same damaged encrypted images and compares recovery rates.
Reuses images and ground truth from test_c_encrypted_vs_unencrypted/.
"""

import os
import sys
import json
import time
import hashlib
import subprocess
import shutil
from pathlib import Path
from typing import Dict, Optional, Tuple

# Add parent directory for imports
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from damage_simulator import APFSDamageSimulator, DamageType
from create_encrypted_image import (
    create_encrypted_image, create_unencrypted_image, generate_test_content
)

# Force unbuffered output
import functools
print = functools.partial(print, flush=True)


def get_ground_truth(dmg_path: str, password: str = None) -> Dict:
    """Mount a DMG, hash all files, unmount. Returns {rel_path: {hash, size}}."""
    # Detach any stale mounts
    for vol in ['/Volumes/TestVolume', '/Volumes/EncryptedTest']:
        subprocess.run(['hdiutil', 'detach', vol, '-force'],
                       capture_output=True, timeout=30)

    mount_point = None
    dev_disk = None

    try:
        if password:
            # APFS native encryption: attach without mounting, then unlock
            result = subprocess.run(
                ['hdiutil', 'attach', dmg_path, '-nobrowse', '-nomount'],
                capture_output=True, text=True, timeout=60
            )
            if result.returncode != 0:
                print(f"  ✗ Failed to attach {dmg_path}: {result.stderr.strip()}")
                return {}

            # Parse device nodes
            lines = result.stdout.strip().split('\n')
            dev_disk = lines[0].split()[0].strip()  # e.g., /dev/disk6

            # Find the APFS volume to unlock
            apfs_vol = None
            for line in lines:
                parts = line.split()
                if len(parts) >= 1 and 's1' in parts[0] and 'Apple_APFS' not in line:
                    # This is likely the volume device (e.g., disk7s1)
                    apfs_vol = parts[0].strip()

            if not apfs_vol:
                # Try to find it via diskutil
                for line in lines:
                    parts = line.split()
                    for p in parts:
                        if p.startswith('/dev/disk') and 's1' in p and p != dev_disk + 's1':
                            apfs_vol = p.strip()
                            break

            if apfs_vol:
                result = subprocess.run(
                    ['diskutil', 'apfs', 'unlockVolume', apfs_vol, '-passphrase', password],
                    capture_output=True, text=True, timeout=60
                )
                if result.returncode != 0:
                    print(f"  ✗ Failed to unlock: {result.stderr.strip()}")
                    subprocess.run(['hdiutil', 'detach', dev_disk, '-force'], capture_output=True)
                    return {}

                # Find mount point
                result = subprocess.run(
                    ['diskutil', 'info', apfs_vol],
                    capture_output=True, text=True, timeout=30
                )
                for line in result.stdout.split('\n'):
                    if 'Mount Point' in line:
                        mp = line.split(':', 1)[1].strip()
                        if mp and mp != 'Not Mounted':
                            mount_point = mp
                            break
        else:
            result = subprocess.run(
                ['hdiutil', 'attach', dmg_path, '-nobrowse'],
                capture_output=True, text=True, timeout=60
            )
            if result.returncode != 0:
                print(f"  ✗ Failed to mount {dmg_path}: {result.stderr.strip()}")
                return {}

            lines = result.stdout.strip().split('\n')
            dev_disk = lines[0].split()[0].strip()
            for line in lines:
                parts = line.split('\t')
                if len(parts) >= 3 and parts[-1].strip().startswith('/Volumes/'):
                    mount_point = parts[-1].strip()
                    break

        if not mount_point:
            print(f"  ✗ Could not find mount point")
            if dev_disk:
                subprocess.run(['hdiutil', 'detach', dev_disk, '-force'], capture_output=True)
            return {}

        # Hash all files
        hashes = {}
        base = Path(mount_point)
        for fpath in sorted(base.rglob('*')):
            if fpath.is_file():
                rel = str(fpath.relative_to(base))
                if rel.startswith('.') or '/.Trashes' in rel or '/.fseventsd' in rel:
                    continue
                try:
                    data = fpath.read_bytes()
                    hashes[rel] = {
                        'hash': hashlib.sha256(data).hexdigest(),
                        'size': len(data)
                    }
                except Exception:
                    pass

        return hashes

    finally:
        if dev_disk:
            subprocess.run(['hdiutil', 'detach', dev_disk, '-force'],
                           capture_output=True, timeout=30)


def verify_recovery(output_dir: str, ground_truth: Dict) -> Tuple[int, int]:
    """Compare recovered files against ground truth hashes."""
    recovered = {}
    base = Path(output_dir)
    if base.exists():
        for fpath in sorted(base.rglob('*')):
            if fpath.is_file():
                rel = str(fpath.relative_to(base))
                try:
                    data = fpath.read_bytes()
                    recovered[rel] = hashlib.sha256(data).hexdigest()
                except Exception:
                    pass

    matches = 0
    total = len(ground_truth)
    for rel_path, info in ground_truth.items():
        expected_hash = info['hash'] if isinstance(info, dict) else info
        if recovered.get(rel_path) == expected_hash:
            matches += 1

    return matches, total


def run_c_recovery(image_path: str, output_dir: str, password: str = None) -> Tuple[int, float]:
    """Run C tool recovery, return (files_extracted, elapsed_time)."""
    c_program = Path(__file__).parent / "apfs_recover"
    if not c_program.exists():
        print(f"  ERROR: C program not found at {c_program}")
        return 0, 0.0

    start = time.time()
    cmd = [str(c_program), image_path, output_dir, '--quiet']
    if password:
        cmd.extend(['--password', password])

    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=1800)
        elapsed = time.time() - start
        if result.returncode != 0:
            return 0, elapsed
        count = len([f for f in Path(output_dir).rglob('*') if f.is_file()]) if Path(output_dir).exists() else 0
        return count, elapsed
    except subprocess.TimeoutExpired:
        return 0, time.time() - start


def run_python_recovery(image_path: str, output_dir: str, password: str = None) -> Tuple[int, float]:
    """Run Python tool recovery, return (files_extracted, elapsed_time)."""
    py_script = Path(__file__).parent / "apfs_recover.py"

    start = time.time()
    cmd = [sys.executable, str(py_script), image_path, '--output', output_dir, '--quiet']
    if password:
        cmd.extend(['--password', password])

    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=1800)
        elapsed = time.time() - start
        if result.returncode != 0:
            print(f"    Python stderr: {result.stderr[:200]}")
            return 0, elapsed
        count = len([f for f in Path(output_dir).rglob('*') if f.is_file()]) if Path(output_dir).exists() else 0
        return count, elapsed
    except subprocess.TimeoutExpired:
        return 0, time.time() - start


def main():
    print("=" * 80)
    print("Python vs C Recovery Comparison (Encrypted)")
    print("=" * 80)
    print()

    script_dir = Path(__file__).parent.resolve()
    work_dir = script_dir / "test_python_vs_c"
    work_dir.mkdir(exist_ok=True)

    password = "testpass123"
    size_mb = 1024

    # Reuse images from encrypted_vs_unencrypted test if they exist
    shared_dir = script_dir / "test_c_encrypted_vs_unencrypted"
    base_enc = shared_dir / "base_encrypted.dmg"
    truth_file = work_dir / "ground_truth_encrypted.json"

    if not base_enc.exists():
        # Create our own
        base_enc = work_dir / "base_encrypted.dmg"
        if not base_enc.exists():
            print("Creating encrypted test image...")
            hashes = create_encrypted_image(
                str(base_enc), password=password,
                size_mb=size_mb, target_usage_percent=85.0
            )
            if not hashes:
                print("  ✗ Failed to create encrypted image")
                return 1
    else:
        print(f"  Reusing: {base_enc}")

    # Get ground truth
    if truth_file.exists():
        with open(truth_file) as f:
            ground_truth = json.load(f)
        print(f"  ✓ Loaded cached ground truth: {len(ground_truth)} files")
    else:
        print("  Mounting encrypted DMG to establish ground truth...")
        ground_truth = get_ground_truth(str(base_enc), password)
        if not ground_truth:
            print("  ✗ Failed to get ground truth")
            return 1
        with open(truth_file, 'w') as f:
            json.dump(ground_truth, f, indent=2)
        print(f"  ✓ Ground truth: {len(ground_truth)} files")

    total = len(ground_truth)
    damage_types = list(DamageType)
    print(f"\nTesting {len(damage_types)} damage types on encrypted image ({total} files)...")
    print("=" * 80)

    results = []

    for i, dt in enumerate(damage_types):
        print(f"\n[{i+1}/{len(damage_types)}] {dt.name}")

        damaged = work_dir / f"damaged_{dt.name}.dmg"
        c_out = work_dir / f"c_out_{dt.name}"
        py_out = work_dir / f"py_out_{dt.name}"

        try:
            shutil.copy2(base_enc, damaged)
            sim = APFSDamageSimulator(str(damaged))
            sim.inflict_damage(dt)
        except Exception as e:
            print(f"  ✗ Failed to apply damage: {e}")
            if damaged.exists():
                damaged.unlink()
            results.append({'damage': dt.name, 'error': str(e)})
            continue

        # Clean output dirs
        for d in [c_out, py_out]:
            subprocess.run(['rm', '-rf', str(d)], capture_output=True)
            d.mkdir(exist_ok=True)

        # Run C tool
        _, c_time = run_c_recovery(str(damaged), str(c_out), password)
        c_matches, _ = verify_recovery(str(c_out), ground_truth)

        # Run Python tool
        _, py_time = run_python_recovery(str(damaged), str(py_out), password)
        py_matches, _ = verify_recovery(str(py_out), ground_truth)

        c_rate = c_matches / total * 100 if total else 0
        py_rate = py_matches / total * 100 if total else 0
        diff = py_rate - c_rate

        flag = "  ⚠" if abs(diff) > 0.5 else "   "
        print(f"{flag} C={c_rate:.1f}% ({c_matches}/{total}) {c_time:.1f}s  |  Py={py_rate:.1f}% ({py_matches}/{total}) {py_time:.1f}s  |  Diff={diff:+.1f}%")

        results.append({
            'damage': dt.name,
            'c_rate': c_rate, 'py_rate': py_rate,
            'c_matches': c_matches, 'py_matches': py_matches,
            'c_time': c_time, 'py_time': py_time,
            'diff': diff,
        })

        # Cleanup
        if damaged.exists():
            damaged.unlink()
        for d in [c_out, py_out]:
            subprocess.run(['rm', '-rf', str(d)], capture_output=True)

    # Summary
    print("\n" + "=" * 80)
    print("PYTHON vs C COMPARISON SUMMARY")
    print("=" * 80)

    valid = [r for r in results if 'error' not in r]
    if valid:
        avg_c = sum(r['c_rate'] for r in valid) / len(valid)
        avg_py = sum(r['py_rate'] for r in valid) / len(valid)
        total_c_time = sum(r['c_time'] for r in valid)
        total_py_time = sum(r['py_time'] for r in valid)

        print(f"\nGround truth: {total} files")
        print(f"Average Recovery:  C={avg_c:.1f}%  Py={avg_py:.1f}%  Diff={avg_py - avg_c:+.1f}%")
        print(f"Total Time:        C={total_c_time:.0f}s  Py={total_py_time:.0f}s")

        print(f"\nAll results:")
        for r in valid:
            flag = "  ⚠" if abs(r['diff']) > 0.5 else "   "
            print(f"{flag} {r['damage']:<40} C={r['c_rate']:5.1f}%  Py={r['py_rate']:5.1f}%  Diff={r['diff']:+.1f}%")

        # Show where Python beats C or vice versa
        py_better = [r for r in valid if r['diff'] > 0.5]
        c_better = [r for r in valid if r['diff'] < -0.5]

        if py_better:
            print(f"\nPython better than C ({len(py_better)}):")
            for r in py_better:
                print(f"  {r['damage']:<40} +{r['diff']:.1f}% ({r['py_matches'] - r['c_matches']} more files)")
        if c_better:
            print(f"\nC better than Python ({len(c_better)}):")
            for r in c_better:
                print(f"  {r['damage']:<40} {r['diff']:.1f}% ({r['c_matches'] - r['py_matches']} more files)")
        if not py_better and not c_better:
            print(f"\n✓ Python and C match within 0.5% on all {len(valid)} damage types!")

    # Save report
    report_path = work_dir / "python_vs_c_report.json"
    with open(report_path, 'w') as f:
        json.dump(results, f, indent=2)
    print(f"\nReport saved to: {report_path}")


if __name__ == '__main__':
    main()
