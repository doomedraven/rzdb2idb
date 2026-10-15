# SPDX-License-Identifier: LGPL-3.0-only
"""CLI entrypoints for rzdb2idb, idb2rzdb, and rzdb-inspect."""

from __future__ import annotations

import argparse
import json
import shutil
import sys
from pathlib import Path
from typing import List, Optional

from .idb_codec import apply_ir_to_ida, ensure_fast_idausr, extract_ir_from_ida
from .rzdb_codec import load_rzdb, save_rzdb


def convert_rzdb_to_idb(
    rzdb_path: Path | str,
    out_idb_path: Path | str,
    binary_path: Optional[Path | str] = None,
    rebase_delta: int = 0,
    auto_analysis: bool = True,
) -> dict:
    """Converts a Rizin .rzdb project into an IDA Pro .i64/.idb database."""
    ensure_fast_idausr()
    import idapro

    ir = load_rzdb(rzdb_path)
    out_idb = Path(out_idb_path).resolve()

    if out_idb.exists():
        open_target = str(out_idb)
    else:
        bin_cand = (
            Path(binary_path)
            if binary_path
            else (
                Path(ir.binary_abs_path)
                if ir.binary_abs_path and Path(ir.binary_abs_path).exists()
                else Path(ir.binary_raw_path)
            )
        )
        if not bin_cand or not bin_cand.exists():
            raise FileNotFoundError(
                f"Target binary not found (tried {bin_cand!r}). Pass --bin <path_to_binary>."
            )
        # Copy binary next to out_idb if needed so idapro creates the .i64 at out_idb
        expected_default_i64 = bin_cand.resolve().with_suffix(bin_cand.suffix + ".i64")
        open_target = str(bin_cand.resolve())

    rc = idapro.open_database(open_target, run_auto_analysis=auto_analysis)
    if rc != 0:
        raise RuntimeError(f"idapro.open_database({open_target!r}) failed with code {rc}")

    try:
        stats = apply_ir_to_ida(ir, rebase_delta=rebase_delta)
    finally:
        idapro.close_database(save=True)

    # If idapro created <binary>.i64 and the user requested a custom --out path, move it
    if not out_idb.exists():
        created_i64 = Path(f"{open_target}.i64")
        created_idb = Path(f"{open_target}.idb")
        if created_i64.exists():
            shutil.move(str(created_i64), str(out_idb))
        elif created_idb.exists():
            shutil.move(str(created_idb), str(out_idb))

    return {
        "out_idb": str(out_idb),
        "types_applied": stats.types_applied,
        "functions_applied": stats.functions_applied,
        "prototypes_applied": stats.prototypes_applied,
        "vars_applied": stats.vars_applied,
        "flags_applied": stats.flags_applied,
        "comments_applied": stats.comments_applied,
        "strings_applied": stats.strings_applied,
        "marks_applied": stats.marks_applied,
        "xrefs_applied": stats.xrefs_applied,
        "breakpoints_applied": stats.breakpoints_applied,
    }


def convert_idb_to_rzdb(
    idb_path: Path | str,
    out_rzdb_path: Path | str,
    binary_path: Optional[Path | str] = None,
    template_rzdb: Optional[Path | str] = None,
    rebase_delta: int = 0,
    compress: bool = True,
) -> dict:
    """Converts an IDA Pro .i64/.idb database into a Rizin .rzdb project."""
    ensure_fast_idausr()
    import idapro

    idb_abs = str(Path(idb_path).resolve())
    rc = idapro.open_database(idb_abs, run_auto_analysis=False)
    if rc != 0:
        raise RuntimeError(f"idapro.open_database({idb_abs!r}) failed with code {rc}")

    try:
        ir = extract_ir_from_ida(binary_path=str(binary_path) if binary_path else None)
    finally:
        idapro.close_database(save=False)

    if rebase_delta != 0:
        ir.apply_rebase(rebase_delta)

    save_rzdb(ir, out_rzdb_path, template_rzdb=template_rzdb, compress=compress)
    return {
        "out_rzdb": str(Path(out_rzdb_path).resolve()),
        "functions": len(ir.functions),
        "blocks": len(ir.blocks),
        "structs": len(ir.structs),
        "enums": len(ir.enums),
        "callables": len(ir.callables),
        "flags": len(ir.flags),
        "meta": len(ir.meta),
        "marks": len(ir.marks),
        "xrefs": len(ir.xrefs),
        "breakpoints": len(ir.breakpoints),
    }


def main_rzdb2idb(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(description="Convert Rizin .rzdb project to IDA Pro .i64/.idb")
    parser.add_argument("--rzdb", "-r", required=True, help="Input Rizin .rzdb project file")
    parser.add_argument("--out", "-o", required=True, help="Output IDA .i64/.idb database path")
    parser.add_argument("--bin", "-b", default=None, help="Target binary path (if not existing .i64)")
    parser.add_argument(
        "--rebase",
        default="0",
        help="Optional address delta (e.g. 0x1000 or -0x400000) to add to all Rizin EAs",
    )
    parser.add_argument(
        "--no-auto",
        action="store_true",
        help="Disable IDA auto-analysis when creating a new database from binary",
    )
    args = parser.parse_args(argv)
    delta = int(args.rebase, 0)
    summary = convert_rzdb_to_idb(
        rzdb_path=args.rzdb,
        out_idb_path=args.out,
        binary_path=args.bin,
        rebase_delta=delta,
        auto_analysis=not args.no_auto,
    )
    print(json.dumps(summary, indent=2))
    return 0


def main_idb2rzdb(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(description="Convert IDA Pro .i64/.idb database to Rizin .rzdb")
    parser.add_argument("--idb", "-i", required=True, help="Input IDA .i64/.idb database file")
    parser.add_argument("--out", "-o", required=True, help="Output Rizin .rzdb project file")
    parser.add_argument("--bin", "-b", default=None, help="Override binary path stored in .rzdb")
    parser.add_argument("--template", "-t", default=None, help="Optional existing .rzdb template")
    parser.add_argument("--rebase", default="0", help="Optional address delta to add to all IDA EAs")
    parser.add_argument("--raw", action="store_true", help="Save .rzdb as uncompressed SDB plaintext")
    args = parser.parse_args(argv)
    delta = int(args.rebase, 0)
    summary = convert_idb_to_rzdb(
        idb_path=args.idb,
        out_rzdb_path=args.out,
        binary_path=args.bin,
        template_rzdb=args.template,
        rebase_delta=delta,
        compress=not args.raw,
    )
    print(json.dumps(summary, indent=2))
    return 0


def main_inspect(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(description="Inspect a Rizin .rzdb project file as JSON")
    parser.add_argument("rzdb", help="Path to .rzdb file")
    args = parser.parse_args(argv)
    ir = load_rzdb(args.rzdb)
    summary = {
        "version": ir.version,
        "binary_raw_path": ir.binary_raw_path,
        "binary_abs_path": ir.binary_abs_path,
        "arch": ir.arch,
        "bits": ir.bits,
        "functions_count": len(ir.functions),
        "blocks_count": len(ir.blocks),
        "flags_count": len(ir.flags),
        "meta_count": len(ir.meta),
        "marks_count": len(ir.marks),
        "xrefs_count": len(ir.xrefs),
        "breakpoints_count": len(ir.breakpoints),
        "structs": list(ir.structs.keys()),
        "unions": list(ir.unions.keys()),
        "enums": list(ir.enums.keys()),
        "typedefs": list(ir.typedefs.keys()),
        "callables": list(ir.callables.keys()),
    }
    print(json.dumps(summary, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main_inspect())
