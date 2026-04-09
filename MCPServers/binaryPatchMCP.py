#!/usr/bin/env python3
"""
FastMCP server for bounded binary patching with LIEF + Keystone.

This server writes patched copies to an explicit output path. It does not try to
replace Ghidra's analysis UX or mutate a live Ghidra database.
"""

from __future__ import annotations

import argparse
import hashlib
import logging
import os
import re
import sys
from pathlib import Path
from typing import Any, Iterable

from fastmcp import FastMCP

REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from artifact_paths import describe_tool_output_root, resolve_tool_output_path  # noqa: E402

logger = logging.getLogger(__name__)

try:
    import lief  # type: ignore

    LIEF_IMPORT_ERROR = ""
except Exception as exc:  # pragma: no cover - dependency presence varies by environment
    lief = None  # type: ignore
    LIEF_IMPORT_ERROR = str(exc)

try:
    from keystone import (  # type: ignore
        Ks,
        KS_ARCH_ARM,
        KS_ARCH_ARM64,
        KS_ARCH_X86,
        KS_MODE_32,
        KS_MODE_64,
        KS_MODE_ARM,
        KS_MODE_LITTLE_ENDIAN,
        KS_MODE_THUMB,
    )

    KEYSTONE_IMPORT_ERROR = ""
except Exception as exc:  # pragma: no cover - dependency presence varies by environment
    Ks = None  # type: ignore
    KS_ARCH_ARM = KS_ARCH_ARM64 = KS_ARCH_X86 = None  # type: ignore
    KS_MODE_32 = KS_MODE_64 = KS_MODE_ARM = KS_MODE_LITTLE_ENDIAN = KS_MODE_THUMB = None  # type: ignore
    KEYSTONE_IMPORT_ERROR = str(exc)

IS_WINDOWS = sys.platform.startswith("win")
_DRIVE_RE = re.compile(r"^/([A-Za-z]):/")
_MNT_RE = re.compile(r"^/mnt/([A-Za-z])/(.*)")

mcp = FastMCP(
    "binary_patch_mcp",
    instructions=(
        "MCP server for bounded binary patching. Use it only when the user explicitly wants a patched "
        "output binary or an emitted on-disk modification, and prefer writing patched copies to a new path."
    ),
)


def normalize_user_path(path: str) -> str:
    value = (path or "").strip()
    if not value:
        return value

    if IS_WINDOWS:
        match = _DRIVE_RE.match(value)
        if match:
            return value[1:]

        match = _MNT_RE.match(value)
        if match:
            drive = match.group(1).upper()
            rest = match.group(2).replace("/", "\\")
            return f"{drive}:\\{rest}"

    return os.path.expandvars(os.path.expanduser(value))


def ensure_existing_path(path: str) -> str:
    candidate = Path(normalize_user_path(path))
    if not candidate.is_absolute():
        candidate = candidate.resolve()
    if not candidate.exists():
        raise FileNotFoundError(f"path not found: {candidate}")
    return str(candidate)


def ensure_output_path(path: str) -> str:
    candidate = resolve_tool_output_path("binary_patch", normalize_user_path(path))
    candidate.parent.mkdir(parents=True, exist_ok=True)
    return str(candidate)


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _parse_int(value: Any, field_name: str) -> int:
    if isinstance(value, int):
        return int(value)
    text = str(value or "").strip()
    if not text:
        raise ValueError(f"{field_name} is required")
    try:
        return int(text, 0)
    except Exception as exc:
        raise ValueError(f"invalid integer for {field_name}: {value!r}") from exc


def _clean_hex_bytes(hex_bytes: str) -> bytes:
    text = str(hex_bytes or "").strip()
    if not text:
        raise ValueError("hex_bytes is required")
    text = text.replace("0x", "").replace("\\x", "").replace(",", " ")
    text = re.sub(r"[^0-9A-Fa-f]", "", text)
    if not text:
        raise ValueError("hex_bytes did not contain any hex digits")
    if len(text) % 2:
        raise ValueError("hex_bytes must contain an even number of hex digits")
    return bytes.fromhex(text)


def _binary_format_name(binary: Any) -> str:
    fmt = getattr(binary, "format", None)
    if fmt is None:
        return "unknown"
    return str(fmt).split(".")[-1].lower()


def _imagebase(binary: Any) -> int:
    value = getattr(binary, "imagebase", None)
    if isinstance(value, int):
        return int(value)
    optional_header = getattr(binary, "optional_header", None)
    if optional_header is not None:
        candidate = getattr(optional_header, "imagebase", None)
        if isinstance(candidate, int):
            return int(candidate)
    return 0


def _entrypoint(binary: Any) -> int:
    value = getattr(binary, "entrypoint", None)
    if isinstance(value, int):
        return int(value)
    return 0


def _section_records(binary: Any) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    for section in list(getattr(binary, "sections", []) or []):
        raw_offset = getattr(section, "offset", None)
        if raw_offset is None:
            raw_offset = getattr(section, "pointerto_raw_data", None)
        raw_size = getattr(section, "size", None)
        if raw_size is None:
            raw_size = getattr(section, "sizeof_raw_data", None)
        virtual_address = getattr(section, "virtual_address", None)
        virtual_size = getattr(section, "virtual_size", None)
        records.append(
            {
                "name": str(getattr(section, "name", "") or ""),
                "raw_offset": int(raw_offset or 0),
                "raw_size": int(raw_size or 0),
                "virtual_address": int(virtual_address or 0),
                "virtual_size": int(virtual_size or raw_size or 0),
            }
        )
    return records


def _segment_records(binary: Any) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    for segment in list(getattr(binary, "segments", []) or []):
        records.append(
            {
                "file_offset": int(getattr(segment, "file_offset", 0) or 0),
                "file_size": int(getattr(segment, "physical_size", 0) or getattr(segment, "file_size", 0) or 0),
                "virtual_address": int(getattr(segment, "virtual_address", 0) or 0),
                "virtual_size": int(getattr(segment, "virtual_size", 0) or 0),
            }
        )
    return records


def _rva_to_offset(binary: Any, rva: int) -> int:
    if hasattr(binary, "rva_to_offset"):
        try:
            value = binary.rva_to_offset(rva)
            if value is not None:
                return int(value)
        except Exception:
            pass
    for section in _section_records(binary):
        start = int(section["virtual_address"])
        size = max(int(section["virtual_size"]), int(section["raw_size"]))
        end = start + size
        if start <= rva < end:
            return int(section["raw_offset"]) + (rva - start)
    raise ValueError(f"unable to map RVA 0x{rva:x} to file offset")


def _va_to_offset(binary: Any, va: int) -> int:
    fmt = _binary_format_name(binary)
    imagebase = _imagebase(binary)
    if fmt == "pe":
        rva = va - imagebase if imagebase and va >= imagebase else va
        return _rva_to_offset(binary, int(rva))

    for segment in _segment_records(binary):
        start = int(segment["virtual_address"])
        size = int(segment["virtual_size"])
        end = start + size
        if start <= va < end:
            return int(segment["file_offset"]) + (va - start)

    for section in _section_records(binary):
        start = int(section["virtual_address"])
        size = max(int(section["virtual_size"]), int(section["raw_size"]))
        end = start + size
        if start <= va < end:
            return int(section["raw_offset"]) + (va - start)

    raise ValueError(f"unable to map VA 0x{va:x} to file offset")


def _offset_to_va(binary: Any, file_offset: int) -> int:
    fmt = _binary_format_name(binary)
    imagebase = _imagebase(binary)
    for section in _section_records(binary):
        start = int(section["raw_offset"])
        size = int(section["raw_size"])
        end = start + size
        if start <= file_offset < end:
            rva = int(section["virtual_address"]) + (file_offset - start)
            if fmt == "pe" and imagebase:
                return imagebase + rva
            return rva

    for segment in _segment_records(binary):
        start = int(segment["file_offset"])
        size = int(segment["file_size"])
        end = start + size
        if start <= file_offset < end:
            return int(segment["virtual_address"]) + (file_offset - start)

    return 0


def _resolve_patch_offset(binary: Any, address: Any, address_kind: str) -> tuple[int, int]:
    kind = str(address_kind or "file_offset").strip().lower()
    numeric = _parse_int(address, "address")
    if kind == "file_offset":
        offset = int(numeric)
        va = _offset_to_va(binary, offset)
        return offset, va
    if kind == "rva":
        offset = _rva_to_offset(binary, int(numeric))
        imagebase = _imagebase(binary)
        va = imagebase + int(numeric) if imagebase else int(numeric)
        return offset, va
    if kind == "va":
        offset = _va_to_offset(binary, int(numeric))
        return offset, int(numeric)
    raise ValueError("address_kind must be one of: file_offset, rva, va")


def _load_binary_for_patch(file_path: str) -> tuple[str, Path, Any]:
    if lief is None:
        raise RuntimeError(f"LIEF is not installed: {LIEF_IMPORT_ERROR}")
    resolved_input = ensure_existing_path(file_path)
    input_path = Path(resolved_input)
    binary = lief.parse(str(input_path))
    if binary is None:
        raise RuntimeError(f"LIEF could not parse binary: {input_path}")
    return resolved_input, input_path, binary


def _prepare_output(input_path: Path, output_path: str, force: bool) -> Path:
    resolved_output = Path(ensure_output_path(output_path))
    if resolved_output.exists() and not force:
        raise FileExistsError(f"output already exists: {resolved_output}")
    if resolved_output.resolve() == input_path.resolve() and not force:
        raise FileExistsError("output_path must differ from file_path unless force=true")
    return resolved_output


def _write_patched_copy(input_path: Path, output_path: Path, patched_bytes: bytes) -> None:
    output_path.write_bytes(patched_bytes)
    if not output_path.exists():
        raise RuntimeError(f"failed to write patched file: {output_path}")


def _verify_expected(data: bytes, offset: int, expected_original_hex: str) -> bytes:
    if not expected_original_hex:
        return b""
    expected = _clean_hex_bytes(expected_original_hex)
    actual = bytes(data[offset : offset + len(expected)])
    if actual != expected:
        raise ValueError(
            f"expected bytes mismatch at file offset 0x{offset:x}: expected {expected.hex()} got {actual.hex()}"
        )
    return actual


def _assemble_arch(architecture: str) -> tuple[Any, Any, bytes]:
    if Ks is None:
        raise RuntimeError(f"Keystone is not installed: {KEYSTONE_IMPORT_ERROR}")
    arch = str(architecture or "x86_64").strip().lower()
    if arch in {"x86_64", "amd64", "x64"}:
        return KS_ARCH_X86, KS_MODE_64, b"\x90"
    if arch in {"x86", "i386", "x86_32"}:
        return KS_ARCH_X86, KS_MODE_32, b"\x90"
    if arch in {"arm64", "aarch64"}:
        return KS_ARCH_ARM64, KS_MODE_LITTLE_ENDIAN, bytes.fromhex("1f2003d5")
    if arch in {"thumb"}:
        return KS_ARCH_ARM, KS_MODE_THUMB | KS_MODE_LITTLE_ENDIAN, bytes.fromhex("00bf")
    if arch in {"arm", "arm32"}:
        return KS_ARCH_ARM, KS_MODE_ARM | KS_MODE_LITTLE_ENDIAN, bytes.fromhex("00f020e3")
    raise ValueError("unsupported architecture; use x86, x86_64, arm64, arm, or thumb")


def _pad_bytes(payload: bytes, target_size: int, pad_mode: str, nop_bytes: bytes) -> bytes:
    if target_size <= len(payload):
        return payload
    mode = str(pad_mode or "none").strip().lower()
    missing = target_size - len(payload)
    if mode == "none":
        raise ValueError(f"assembled bytes are {len(payload)} bytes but patch_size is {target_size}; set pad_mode")
    if mode == "zero":
        return payload + (b"\x00" * missing)
    if mode == "nop":
        if not nop_bytes:
            raise ValueError("nop padding is not available for this architecture")
        if missing % len(nop_bytes) != 0:
            raise ValueError(
                f"patch_size {target_size} is not aligned to the architecture NOP width of {len(nop_bytes)} bytes"
            )
        return payload + (nop_bytes * (missing // len(nop_bytes)))
    raise ValueError("pad_mode must be one of: none, nop, zero")


def _result_common(binary: Any, input_path: Path, output_path: Path, file_offset: int, va: int, patch_bytes: bytes, original: bytes) -> dict[str, Any]:
    return {
        "ok": True,
        "input_path": str(input_path),
        "output_path": str(output_path),
        "format": _binary_format_name(binary),
        "entrypoint": hex(_entrypoint(binary)),
        "imagebase": hex(_imagebase(binary)) if _imagebase(binary) else "",
        "resolved_file_offset": hex(file_offset),
        "resolved_va": hex(va) if va else "",
        "patch_size": len(patch_bytes),
        "original_bytes": original.hex(),
        "patched_bytes": patch_bytes.hex(),
        "output_sha256": sha256_file(output_path),
    }


@mcp.tool()
def binaryPatchHelp() -> dict[str, Any]:
    """Describe supported patch operations and dependency status."""
    output_root = describe_tool_output_root("binary_patch")
    return {
        "ok": True,
        "dependencies": {
            "lief_available": lief is not None,
            "lief_error": LIEF_IMPORT_ERROR,
            "keystone_available": Ks is not None,
            "keystone_error": KEYSTONE_IMPORT_ERROR,
        },
        "tools": [
            "binaryPatchHelp",
            "binaryPatchInspect",
            "binaryPatchBytes",
            "binaryPatchAssemble",
        ],
        "output_root": output_root,
        "notes": [
            "Writes patched copies to an explicit output path under the server-controlled binary_patch output root.",
            "Output paths outside the allowed root are rejected server-side.",
            "Use address_kind=file_offset for the most deterministic behavior.",
            "Use address_kind=rva or va when you want format-aware address translation through LIEF.",
            "Prefer this tool when you need an emitted patched binary; prefer Ghidra for reverse engineering, naming, comments, and type recovery.",
        ],
    }


@mcp.tool()
def binaryPatchInspect(file_path: str) -> dict[str, Any]:
    """Parse a binary with LIEF and return format and layout metadata useful for patch planning."""
    try:
        resolved_input, input_path, binary = _load_binary_for_patch(file_path)
        return {
            "ok": True,
            "file_path": resolved_input,
            "format": _binary_format_name(binary),
            "entrypoint": hex(_entrypoint(binary)),
            "imagebase": hex(_imagebase(binary)) if _imagebase(binary) else "",
            "sections": _section_records(binary),
            "segments": _segment_records(binary),
            "sha256": sha256_file(input_path),
        }
    except Exception as exc:
        logger.exception("binaryPatchInspect failed")
        return {"ok": False, "error": f"{type(exc).__name__}: {exc}"}


@mcp.tool()
def binaryPatchBytes(
    file_path: str,
    output_path: str,
    hex_bytes: str,
    address: str,
    address_kind: str = "file_offset",
    expected_original_hex: str = "",
    force: bool = False,
) -> dict[str, Any]:
    """Patch explicit bytes into a copied output file at a file offset, RVA, or VA."""
    try:
        resolved_input, input_path, binary = _load_binary_for_patch(file_path)
        _ = resolved_input
        output = _prepare_output(input_path, output_path, force=force)
        patch_bytes = _clean_hex_bytes(hex_bytes)
        file_offset, va = _resolve_patch_offset(binary, address, address_kind)
        raw = bytearray(input_path.read_bytes())
        if file_offset < 0:
            raise ValueError("resolved patch offset is negative")
        if file_offset + len(patch_bytes) > len(raw):
            raise ValueError(
                f"patch extends beyond end of file: offset=0x{file_offset:x} size={len(patch_bytes)} file_size={len(raw)}"
            )
        original = _verify_expected(raw, file_offset, expected_original_hex) or bytes(raw[file_offset : file_offset + len(patch_bytes)])
        raw[file_offset : file_offset + len(patch_bytes)] = patch_bytes
        _write_patched_copy(input_path, output, bytes(raw))
        result = _result_common(binary, input_path, output, file_offset, va, patch_bytes, original)
        result["address_kind"] = address_kind
        result["address"] = str(address)
        result["allowed_output_root"] = describe_tool_output_root("binary_patch")
        return result
    except Exception as exc:
        logger.warning("binaryPatchBytes rejected request or failed to patch: %s", exc)
        logger.exception("binaryPatchBytes failed")
        return {
            "ok": False,
            "error": f"{type(exc).__name__}: {exc}",
            "allowed_output_root": describe_tool_output_root("binary_patch"),
        }


@mcp.tool()
def binaryPatchAssemble(
    file_path: str,
    output_path: str,
    assembly: str,
    address: str,
    address_kind: str = "file_offset",
    architecture: str = "x86_64",
    patch_size: int = 0,
    pad_mode: str = "none",
    expected_original_hex: str = "",
    force: bool = False,
) -> dict[str, Any]:
    """Assemble instructions with Keystone and patch the resulting bytes into a copied output file."""
    try:
        if not str(assembly or "").strip():
            raise ValueError("assembly is required")
        resolved_input, input_path, binary = _load_binary_for_patch(file_path)
        _ = resolved_input
        output = _prepare_output(input_path, output_path, force=force)
        ks_arch, ks_mode, nop_bytes = _assemble_arch(architecture)
        file_offset, va = _resolve_patch_offset(binary, address, address_kind)
        assembler = Ks(ks_arch, ks_mode)
        encoded, _ = assembler.asm(str(assembly), addr=int(va or 0))
        patch_bytes = bytes(encoded or [])
        if not patch_bytes:
            raise RuntimeError("assembly produced no bytes")
        if int(patch_size or 0) > 0:
            patch_bytes = _pad_bytes(patch_bytes, int(patch_size), pad_mode, nop_bytes)

        raw = bytearray(input_path.read_bytes())
        if file_offset < 0:
            raise ValueError("resolved patch offset is negative")
        if file_offset + len(patch_bytes) > len(raw):
            raise ValueError(
                f"patch extends beyond end of file: offset=0x{file_offset:x} size={len(patch_bytes)} file_size={len(raw)}"
            )
        original = _verify_expected(raw, file_offset, expected_original_hex) or bytes(raw[file_offset : file_offset + len(patch_bytes)])
        raw[file_offset : file_offset + len(patch_bytes)] = patch_bytes
        _write_patched_copy(input_path, output, bytes(raw))
        result = _result_common(binary, input_path, output, file_offset, va, patch_bytes, original)
        result["address_kind"] = address_kind
        result["address"] = str(address)
        result["architecture"] = architecture
        result["assembly"] = str(assembly)
        result["pad_mode"] = pad_mode
        result["allowed_output_root"] = describe_tool_output_root("binary_patch")
        return result
    except Exception as exc:
        logger.warning("binaryPatchAssemble rejected request or failed to patch: %s", exc)
        logger.exception("binaryPatchAssemble failed")
        return {
            "ok": False,
            "error": f"{type(exc).__name__}: {exc}",
            "allowed_output_root": describe_tool_output_root("binary_patch"),
        }


def main() -> None:
    parser = argparse.ArgumentParser(description="MCP server for bounded binary patching")
    parser.add_argument("--mcp-host", type=str, default="127.0.0.1")
    parser.add_argument("--mcp-port", type=int, default=8096)
    parser.add_argument("--transport", choices=["stdio", "sse"], default="stdio")
    args = parser.parse_args()

    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(name)s: %(message)s")

    if args.transport == "stdio":
        mcp.run(show_banner=False)
    else:
        mcp.run(transport="sse", host=args.mcp_host, port=args.mcp_port, show_banner=False)


if __name__ == "__main__":
    main()
