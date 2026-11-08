#!/usr/bin/env python3
"""Explicit opt-in tool install. Pinned release bytes, SHA-256 checked before extraction.
Linux amd64/arm64 only. Android may need proot; no system/global changes.
"""
import argparse
import hashlib
import io
from pathlib import Path
import platform
import tarfile
from urllib.request import urlopen

RELEASES = {
 'gitleaks': ('gitleaks/gitleaks','v8.30.1',{
  'x86_64':('gitleaks_8.30.1_linux_x64.tar.gz','551f6fc83ea457d62a0d98237cbad105af8d557003051f41f3e7ca7b3f2470eb'),
  'aarch64':('gitleaks_8.30.1_linux_arm64.tar.gz','e4a487ee7ccd7d3a7f7ec08657610aa3606637dab924210b3aee62570fb4b080')}),
 'osv-scanner': ('google/osv-scanner','v2.7.0',{
  'x86_64':('osv-scanner_linux_amd64','160c6253e2922e9e0a6a9771c5c4c40a4b3c6090b34a3cdd5e80c96cc2e4218b'),
  'aarch64':('osv-scanner_linux_arm64','4061ef4c021ed3c47f203b818f337e351336cc5cd67c0274fc36bd1dfc728dd7')}),
 'trivy': ('aquasecurity/trivy','v0.76.2',{
  'x86_64':('trivy_0.76.2_Linux-64bit.tar.gz','bc0fc726e017b8927a62b2d3531d7a84ee01769daf5c99ed866dced54089fdbf'),
  'aarch64':('trivy_0.76.2_Linux-ARM64.tar.gz','ab9d51f86e6a5fb936f605faff6b593ac51bc378fff4d3e8b9d58358b9c367c3')})}

def install(destination, machine=None):
    machine = machine or platform.machine()
    if machine not in ('x86_64','aarch64') or platform.system() != 'Linux':
        raise ValueError('Only Linux x86_64/aarch64 supported; install tools separately on other hosts')
    destination = Path(destination)
    destination.mkdir(mode=0o700, parents=True, exist_ok=True)
    for binary,(repo,tag,assets) in RELEASES.items():
        asset,digest = assets[machine]
        with urlopen(f'https://github.com/{repo}/releases/download/{tag}/{asset}', timeout=90) as response:
            raw = response.read(200_000_000)
        if hashlib.sha256(raw).hexdigest() != digest:
            raise ValueError(f'Checksum mismatch: {asset}')
        if asset.endswith('.tar.gz'):
            with tarfile.open(fileobj=io.BytesIO(raw), mode='r:gz') as archive:
                member = archive.getmember(binary)
                if not member.isfile(): raise ValueError('Expected regular executable')
                raw = archive.extractfile(member).read()
        output = destination / binary
        # Never overwrite an existing binary or follow symlinks.
        with output.open('xb') as stream: stream.write(raw)
        output.chmod(0o700)
        print(f'Installed {binary} {tag}; upstream release asset SHA-256 verified')

if __name__ == '__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--destination',required=True)
    args=parser.parse_args()
    install(args.destination)
