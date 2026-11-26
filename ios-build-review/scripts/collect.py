#!/usr/bin/env python3
"""Collect local evidence for Codex. Never execute the inspected product."""
import argparse
import json
import os
import plistlib
import shutil
import stat
import subprocess
import sys
import tempfile
import zipfile
from pathlib import Path
from xml.parsers.expat import ExpatError


MACH = {bytes.fromhex(value) for value in (
    "feedface", "cefaedfe", "feedfacf", "cffaedfe",
    "cafebabe", "bebafeca", "cafebabf", "bfbafeca",
)}
BUNDLES = {".app", ".appex", ".framework", ".xpc", ".bundle"}
HERMES = bytes.fromhex("c61fbc03c103191f")


def path_parts(name):
    parts = name.rstrip("/").split("/")
    if "\\" in name or any(part in ("", ".", "..") for part in parts):
        raise ValueError(f"Unexpected ZIP path: {name!r}")
    return parts


def record_gap(gaps, path, reason):
    gaps.append({"path": str(path), "reason": str(reason)})


def extract_ipa(source, directory, gaps):
    """Write ordinary members before internal links. Never extract through links."""
    directory.mkdir()
    links = []
    outside = set()
    with zipfile.ZipFile(source) as archive:
        members = []
        for member in archive.infolist():
            parts = path_parts(member.filename)
            if len(parts) >= 2 and parts[0] == "Payload" and parts[1].lower().endswith(".app"):
                members.append((parts, member))
            else:
                outside.add(parts[0])
        required = sum(member.file_size for _, member in members)
        if required > shutil.disk_usage(directory).free:
            raise ValueError(f"Insufficient scratch space to unpack {required} bytes")
        for parts, member in members:
            path = directory.joinpath(*parts)
            mode = member.external_attr >> 16
            path.parent.mkdir(parents=True, exist_ok=True)
            if stat.S_ISLNK(mode):
                if member.file_size > 4096:
                    record_gap(gaps, member.filename, "Oversized symlink target skipped")
                    continue
                target = os.fsdecode(archive.read(member))
                # Restrict archive links to downward/sibling paths. A link chain
                # then cannot escape an app or redirect extraction elsewhere.
                if not target or Path(target).is_absolute() or ".." in Path(target).parts:
                    record_gap(gaps, member.filename, "Non-local or parent-relative symlink skipped")
                else:
                    links.append((path, target))
            elif member.is_dir():
                path.mkdir(exist_ok=True)
            elif stat.S_IFMT(mode) in (0, stat.S_IFREG):
                try:
                    with archive.open(member) as src, path.open("xb") as dst:
                        shutil.copyfileobj(src, dst)
                    path.chmod(0o700 if mode & 0o111 else 0o600)
                except (RuntimeError, NotImplementedError, zipfile.BadZipFile) as exc:
                    if path.exists():
                        path.unlink()
                    record_gap(gaps, member.filename, exc)
            else:
                record_gap(gaps, member.filename, "Special file skipped")
    for path, target in links:
        path.symlink_to(target)
    return directory / "Payload", sorted(outside)


def walk(root, gaps):
    def on_error(error):
        record_gap(gaps, error.filename, error.strerror)
    return os.walk(root, onerror=on_error, followlinks=False)


def valid_macho(header):
    if header[:4] not in MACH:
        return False
    # A Java class can begin with the same bytes as a universal Mach-O.
    if header[:4] == bytes.fromhex("cafebabe") and int.from_bytes(header[4:8], "big") > 255:
        return False
    return True


def inventory(app, base, gaps):
    bundles = []
    images = []
    resources = []
    links = []
    external_links = []
    for current, dirs, files in walk(app, gaps):
        directory = Path(current)
        if directory.suffix.lower() in BUNDLES:
            bundles.append(str(directory.relative_to(base)))
        dirs.sort()
        files.sort()
        directories = set(dirs)
        for name in dirs + files:
            path = directory / name
            rel = str(path.relative_to(base))
            if path.is_symlink():
                try:
                    path.resolve(strict=True).relative_to(app)
                    links.append(rel)
                except (ValueError, RuntimeError, OSError):
                    external_links.append(rel)
                    record_gap(gaps, rel, "Broken, cyclic or external symlink; do not follow")
                continue
            if name in directories:
                continue
            try:
                if not stat.S_ISREG(path.stat().st_mode):
                    record_gap(gaps, rel, "Special file skipped")
                    continue
                with path.open("rb") as stream:
                    header = stream.read(12)
                if valid_macho(header):
                    images.append(rel)
                else:
                    kind = "file"
                    if header.startswith(HERMES):
                        kind = "hermes-bytecode"
                    elif header.startswith(b"\xaf\x1b\xb1\xfa"):
                        kind = "il2cpp-metadata"
                    resources.append([rel, kind])
            except OSError as exc:
                record_gap(gaps, rel, exc)
    return bundles, images, resources, links, external_links


def probe(command, destination):
    # Keep human-readable tool output private and off the model's input stream.
    path = destination.with_suffix(".txt")
    if not shutil.which(command[0]):
        return {"tool_missing": command[0]}
    with path.open("wb") as out:
        try:
            result = subprocess.run(command, stdin=subprocess.DEVNULL, stdout=out,
                                    stderr=subprocess.STDOUT, check=False, timeout=180)
        except (OSError, subprocess.TimeoutExpired) as exc:
            return {"error": str(exc), "file": path.name}
    return {"status": result.returncode, "file": path.name}


def examine(source, scratch):
    gaps = []
    extra = []
    if source.is_file() and source.suffix.lower() == ".ipa":
        base, extra = extract_ipa(source, scratch / "unpacked", gaps)
    elif source.is_dir() and source.suffix.lower() == ".xcarchive":
        base = source / "Products" / "Applications"
        base.resolve(strict=True).relative_to(source)
    else:
        raise ValueError("Expected an .ipa file or an .xcarchive directory")
    products = []
    for path in sorted(base.iterdir()):
        if path.suffix.lower() == ".app":
            if path.is_symlink() or not path.is_dir():
                record_gap(gaps, path.name, "Product is not an ordinary app directory")
            else:
                products.append(path)
    if not products:
        raise ValueError("No application product in Payload or Products/Applications")

    evidence = scratch / "evidence"
    evidence.mkdir()
    result = {"source": str(source), "product_base": str(base), "gaps": gaps,
              "outside_payload_top_level": extra, "products": []}
    for index, app in enumerate(products):
        bundles, images, resources, links, unsafe = inventory(app, base, gaps)
        product = {"app": app.name, "bundles": {}, "images": {}, "resources": resources,
                   "internal_links": links, "skipped_links": unsafe}
        result["products"].append(product)
        for number, rel in enumerate(bundles):
            bundle = base / rel
            item = {}
            product["bundles"][rel] = item
            info = bundle / "Info.plist"
            if bundle.suffix == ".bundle" and not info.is_file():
                continue
            try:
                info.resolve(strict=True).relative_to(app)
                with info.open("rb") as stream:
                    data = plistlib.load(stream)
                if not isinstance(data, dict):
                    raise ValueError("Info.plist root is not a dictionary")
                for key in ("CFBundleIdentifier", "CFBundleExecutable", "CFBundleVersion",
                            "CFBundleShortVersionString", "CFBundlePackageType"):
                    if key in data:
                        item[key] = str(data[key])
            except (OSError, ValueError, RuntimeError, plistlib.InvalidFileException,
                    OverflowError, TypeError, ExpatError) as exc:
                record_gap(gaps, str(info.relative_to(base)), exc)
            if bundle.suffix in {".app", ".appex", ".xpc", ".framework"}:
                if unsafe or (source.is_file() and any("symlink" in str(g["reason"]) for g in gaps)):
                    item["verify_skipped"] = "Link validation incomplete; verify original bundle locally"
                else:
                    item["verify"] = probe(["codesign", "--verify", "--strict", "--verbose=2", str(bundle)],
                                           evidence / f"p{index}-bundle{number}-verify")
        for number, rel in enumerate(images):
            path = str(base / rel)
            commands = {
                "load_commands": ["otool", "-arch", "all", "-l", path],
                "symbols": ["nm", "-arch", "all", "-m", path],
                "signature": ["codesign", "-d", "--verbose=4", path],
                "entitlements": ["codesign", "-d", "--entitlements", "-", path],
            }
            product["images"][rel] = {
                key: probe(cmd, evidence / f"p{index}-image{number}-{key}")
                for key, cmd in commands.items()
            }
    output = scratch / "inventory.json"
    output.write_text(json.dumps(result, ensure_ascii=True, indent=2), encoding="utf-8")
    return output


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("artifact", type=Path)
    parser.add_argument("--work", type=Path, required=True,
                        help="Existing local scratch parent outside the inspected archive")
    args = parser.parse_args()
    scratch = None
    try:
        source = args.artifact.expanduser().resolve(strict=True)
        parent = args.work.expanduser().resolve(strict=True)
        if source == parent or source in parent.parents:
            raise ValueError("Choose a scratch directory outside the artifact")
        scratch = Path(tempfile.mkdtemp(prefix="ios-review-", dir=parent))
        print(examine(source, scratch))
    except (OSError, ValueError, RuntimeError, zipfile.BadZipFile) as exc:
        if scratch is not None:
            shutil.rmtree(scratch)
        sys.exit(f"Collection failed: {exc}")


if __name__ == "__main__":
    main()
