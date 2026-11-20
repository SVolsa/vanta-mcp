"""Inventory APK entries without extracting archive-controlled paths."""
import hashlib
import json
import re
import shutil
import struct
import subprocess
import sys
import tempfile
import zipfile
from pathlib import Path


def file_digest(stream):
    digest = hashlib.sha256()
    for block in iter(lambda: stream.read(1024 * 1024), b""):
        digest.update(block)
    return digest.hexdigest()


def native_details(archive, item, result):
    header = archive.fp
    header.seek(item.header_offset)
    signature, name_length, extra_length = struct.unpack("<4s22xHH", header.read(30))
    if signature != b"PK\x03\x04":
        raise ValueError("invalid APK local ZIP header")
    output = result.stdout
    elf_class = re.search(r"^\s*Class:\s*(\S+)", output, re.M)
    elf_type = re.search(r"^\s*Type:\s*(\S+)", output, re.M)
    byte_order = re.search(r"^\s*Data:\s*(.+)$", output, re.M)
    segments = []
    for line in re.findall(r"^\s*LOAD\s+([^\n]+)$", output, re.M):
        fields = line.split()
        if len(fields) < 6 or not all(re.fullmatch(r"0x[\da-f]+", value, re.I) for value in (fields[0], fields[1], fields[-1])):
            raise ValueError("llvm-readelf returned an unexpected LOAD segment")
        segments.append(dict(offset=fields[0], vaddr=fields[1], align=fields[-1]))
    return dict(elf_class=elf_class[1] if elf_class else None, elf_type=elf_type[1] if elf_type else None,
                byte_order=byte_order[1].strip() if byte_order else None, load_segments=segments,
                needed=re.findall(r"^\s*\S+\s+\(NEEDED\)\s+Shared library: \[([^\]\r\n]+)\]", output, re.M),
                zip_stored=item.compress_type == zipfile.ZIP_STORED,
                zip_data_offset=item.header_offset + 30 + name_length + extra_length)


def inspect_apk(apk, readelf, max_bytes, max_entries, details=""):
    entries = []
    total = 0
    seen = set()
    with zipfile.ZipFile(apk) as archive, tempfile.TemporaryDirectory(prefix="vanta-apk-") as spool:
        if len(archive.infolist()) > 100000:
            raise ValueError("too many APK ZIP entries")
        for item in archive.infolist():
            name = item.filename
            if name in seen:
                raise ValueError(f"duplicate APK ZIP entry: {name!r}")
            seen.add(name)
            native = re.fullmatch(r"lib/([A-Za-z0-9_-]+)/([^/\\]+\.so)", name)
            if not native and name not in {"AndroidManifest.xml", "resources.arsc"} and not re.fullmatch(r"classes[0-9]*\.dex", name):
                continue
            total += item.file_size
            if total > int(max_bytes) or len(entries) >= int(max_entries):
                raise ValueError("APK inventory exceeds its decompressed size or entry limit")
            kind = "native" if native else "dex" if name.endswith(".dex") else "manifest" if name == "AndroidManifest.xml" else "resources"
            with archive.open(item) as stream:
                if native:
                    library = Path(spool) / "native.elf"
                    with library.open("wb") as out:
                        shutil.copyfileobj(stream, out)
                    with library.open("rb") as data:
                        digest = file_digest(data)
                else:
                    digest = file_digest(stream)
            entry = dict(path=name, kind=kind, bytes=item.file_size, sha256=digest)
            if native:
                flags = ["-lW", "-dW"] if details == "native-details" else []
                result = subprocess.run([readelf, "-h", "-n", *flags, str(library)], capture_output=True, text=True, timeout=15, errors="replace")
                build = re.search(r"Build ID:\s*([0-9a-f]+)\b", result.stdout, re.I)
                machine = re.search(r"^\s*Machine:\s*(.+)$", result.stdout, re.M)
                entry.update(abi=native.group(1), build_id=build[1].lower() if build else None,
                             machine=machine[1].strip() if machine else None, elf_readable=result.returncode == 0)
                if flags:
                    entry.update(native_details(archive, item, result))
            entries.append(entry)
    return entries


if __name__ == "__main__":
    print(json.dumps(inspect_apk(*sys.argv[1:])))
