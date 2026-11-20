"""Build a KernelSU Next ZIP; never include pairing keys or install anything."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import zipfile

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--go', help='Go executable (overrides the PATH lookup)')
    args = parser.parse_args()
    bundled_go = ROOT / '.tools/go1.27.4/go/bin/go.exe'
    go = args.go or shutil.which('go') or (str(bundled_go) if bundled_go.is_file() else None)
    if go is None:
        parser.error('install Go 1.23 or later or provide --go')
    props = dict(line.split('=', 1) for line in (HERE / 'module/module.prop').read_text(encoding='utf-8').splitlines() if '=' in line)
    version = props['version']
    out = HERE / 'out' / f'usb-{version}'
    out.mkdir(parents=True, exist_ok=True)
    env = {**os.environ, 'GOOS':'linux', 'GOARCH':'arm64', 'CGO_ENABLED':'0', 'GOTOOLCHAIN':'local'}
    binary = out / 'vantad'
    subprocess.run([go, 'build', '-trimpath', '-ldflags=-s -w', '-o', str(binary), '.'],
                   cwd=HERE / 'device', env=env, check=True)
    output = out / f'vanta-mcp-usb-{version}.zip'
    hashes = {}
    with zipfile.ZipFile(output, 'w', compression=zipfile.ZIP_DEFLATED) as archive:
        for source in sorted((HERE / 'module').iterdir()):
            if source.is_file():
                archive.write(source, source.name)
                hashes[source.name] = hashlib.sha256(source.read_bytes()).hexdigest()
        archive.write(binary, 'bin/vantad')
        hashes['bin/vantad'] = hashlib.sha256(binary.read_bytes()).hexdigest()
    hashes['zip'] = hashlib.sha256(output.read_bytes()).hexdigest()
    (out / 'manifest.json').write_text(json.dumps(hashes, indent=2)+'\n', encoding='utf-8')
    print(output)

if __name__ == '__main__':
    main()
