# SPDX-License-Identifier: LGPL-3.0-only
"""Unit and integration tests for rzdb2ida: SDB text codec, Rizin .rzdb <-> IDA Pro .i64 round-trip."""

from __future__ import annotations

import json
import os
import shutil
import subprocess
from pathlib import Path

import pytest

from rzdb2ida.cli import convert_idb_to_rzdb, convert_rzdb_to_idb
from rzdb2ida.model import (
    BasicBlockIR,
    BreakpointIR,
    CallableArgIR,
    CallableIR,
    EnumCaseIR,
    EnumTypeIR,
    FlagIR,
    FunctionIR,
    FunctionVarIR,
    GlobalVarIR,
    MarkIR,
    MetaItemIR,
    ProjectIR,
    StructFieldIR,
    StructTypeIR,
    TypedefIR,
    UnionTypeIR,
    XrefIR,
)
from rzdb2ida.rzdb_codec import load_rzdb, save_rzdb
from rzdb2ida.sdb_text import SdbNode, parse_sdb_text, serialize_sdb_text

RIZIN_BIN = Path(os.environ.get("RIZIN_BIN") or shutil.which("rizin") or "/tmp/rizin-prefix/bin/rizin")
RIZIN_REPO = Path(os.environ.get("RIZIN_REPO", str(Path(__file__).resolve().parents[2] / "rizin")))
SAMPLE_ELF = RIZIN_REPO / "test/bins/elf/crackme0x05"


def test_sdb_text_escaping_roundtrip() -> None:
    root = SdbNode()
    root.set("type", "rizin rz-db project")
    root.set("/leading_slash", "val=with=equals\nand\nnewlines\\slash")
    sub = root.ns("core/sub/with/slash", create=True)
    assert sub is not None
    sub.set("k=1", "v1\r\nv2")

    raw = serialize_sdb_text(root, sort=True)
    parsed = parse_sdb_text(raw)
    assert parsed.get("type") == "rizin rz-db project"
    assert parsed.get("/leading_slash") == "val=with=equals\nand\nnewlines\\slash"
    sub_parsed = parsed.ns("core/sub/with/slash")
    assert sub_parsed is not None
    assert sub_parsed.get("k=1") == "v1\r\nv2"


def test_project_ir_rzdb_lossless_roundtrip(tmp_path: Path) -> None:
    ir = ProjectIR(
        version=26,
        binary_raw_path=str(SAMPLE_ELF),
        binary_abs_path=str(SAMPLE_ELF.resolve()),
        core_offset=0x08048450,
        arch="x86",
        bits=32,
    )
    ir.blocks[0x08048450] = BasicBlockIR(
        addr=0x08048450,
        size=24,
        jump=0x08048470,
        fail=0x08048468,
        colorize=0x00FF00,
        ninstr=1,
    )
    ir.functions[0x08048450] = FunctionIR(
        addr=0x08048450,
        name="mw_check_serial",
        bits=32,
        cc="cdecl",
        stack=32,
        maxstack=32,
        bp_frame=True,
        noreturn=False,
        bbs=[0x08048450],
        vars=[
            FunctionVarIR(
                name="user_input",
                var_type="int32_t",
                storage_type="stack",
                stack_off=-16,
                kind="v",
                comment="user serial buffer",
            )
        ],
    )
    ir.structs["mw_config_t"] = StructTypeIR(
        name="mw_config_t",
        members=[
            StructFieldIR(name="magic", field_type="uint32_t", offset=0, size=32),
            StructFieldIR(name="key", field_type="uint32_t", offset=4, size=32),
        ],
    )
    ir.enums["mw_mode_e"] = EnumTypeIR(
        name="mw_mode_e",
        cases=[EnumCaseIR(name="MODE_INIT", val=1), EnumCaseIR(name="MODE_RUN", val=2)],
    )
    ir.typedefs["mw_u32"] = TypedefIR(name="mw_u32", target_type="uint32_t")
    ir.callables["mw_check_serial"] = CallableIR(
        name="mw_check_serial",
        ret_type="int32_t",
        args=[CallableArgIR(name="buf", arg_type="char *")],
        cc="cdecl",
    )
    ir.flags.append(FlagIR(name="g_secret_val", offset=0x0804A020, size=4, space="symbols", color="red"))
    ir.meta.append(MetaItemIR(addr=0x08048450, meta_type="C", size=1, str_val="Entry of serial check"))
    ir.marks.append(
        MarkIR(
            name="important_check",
            from_addr=0x08048450,
            to_addr=0x08048468,
            color="green",
            comment="Bookmark on serial check",
        )
    )
    ir.xrefs.append(XrefIR(from_addr=0x08048450, to_addr=0x0804A020, xref_type="d"))
    ir.breakpoints[0x08048450] = BreakpointIR(addr=0x08048450, size=1, enabled=1, hw=0, cond="eax==1")

    rzdb_file = tmp_path / "test_unit.rzdb"
    save_rzdb(ir, rzdb_file, compress=True)
    loaded = load_rzdb(rzdb_file)

    assert loaded.functions[0x08048450].name == "mw_check_serial"
    assert loaded.functions[0x08048450].vars[0].name == "user_input"
    assert loaded.functions[0x08048450].vars[0].stack_off == -16
    assert "mw_config_t" in loaded.structs
    assert [m.name for m in loaded.structs["mw_config_t"].members] == ["magic", "key"]
    assert "mw_mode_e" in loaded.enums
    assert loaded.callables["mw_check_serial"].ret_type == "int32_t"
    assert any(f.name == "g_secret_val" and f.offset == 0x0804A020 for f in loaded.flags)
    assert any(m.str_val == "Entry of serial check" for m in loaded.meta)
    assert len(loaded.marks) == 1 and loaded.marks[0].name == "important_check"
    assert len(loaded.xrefs) == 1 and loaded.xrefs[0].to_addr == 0x0804A020
    assert 0x08048450 in loaded.breakpoints


@pytest.mark.skipif(
    not RIZIN_BIN.exists() or not SAMPLE_ELF.exists(),
    reason="rizin binary or test/bins/elf/crackme0x05 not found",
)
def test_end_to_end_rizin_to_ida_and_back(tmp_path: Path) -> None:
    """
    End-to-end integration test:
    1. Uses real `rizin` CLI to analyze `crackme0x05`, add custom function name, comment,
       flag, C struct/enum, mark, xref, and breakpoint, and saves `from_rizin.rzdb`.
    2. Runs `convert_rzdb_to_idb` (headless IDA Pro 9.5 via `idapro`) to produce `crackme.i64`.
    3. Runs `convert_idb_to_rzdb` on `crackme.i64` to produce `from_ida.rzdb`.
    4. Loads `from_ida.rzdb` back into real `rizin` (`rizin -p from_ida.rzdb`) and verifies
       zero project load errors and full preservation of functions, types, comments, flags,
       marks, xrefs, and breakpoints.
    """
    bin_copy = tmp_path / "crackme0x05"
    shutil.copy2(SAMPLE_ELF, bin_copy)
    rzdb_from_rizin = tmp_path / "from_rizin.rzdb"

    rz_cmds = "; ".join(
        [
            "aa",
            "afn mw_parell @ 0x08048484",
            "CCu Rizin comment at parell @ 0x08048484",
            "f+ mw_custom_flag 4 @ 0x0804a020",
            'td "struct mw_pkt { uint32_t id; uint32_t crc; };"',
            'td "enum mw_state { ST_IDLE = 1, ST_BUSY = 2 };"',
            'm+ mark_parell 0x08048494 "Critical check loop" @ 0x08048484',
            "axd 0x0804a020 @ 0x08048484",
            "db @ 0x08048484",
            f"Ps {rzdb_from_rizin}",
        ]
    )
    res = subprocess.run(
        [str(RIZIN_BIN), "-N", "-q", "-c", rz_cmds, str(bin_copy)],
        capture_output=True,
        text=True,
        check=True,
    )
    assert rzdb_from_rizin.exists(), f"Rizin failed to save .rzdb: {res.stderr}"

    # Verify our codec parses Rizin's native .rzdb output cleanly
    ir1 = load_rzdb(rzdb_from_rizin)
    assert 0x08048484 in ir1.functions
    assert ir1.functions[0x08048484].name == "mw_parell"
    assert "mw_pkt" in ir1.structs
    assert "mw_state" in ir1.enums
    assert any(f.name == "mw_custom_flag" and f.offset == 0x0804A020 for f in ir1.flags)
    assert any(m.name == "mark_parell" for m in ir1.marks)
    assert any(x.from_addr == 0x08048484 and x.to_addr == 0x0804A020 for x in ir1.xrefs)
    assert 0x08048484 in ir1.breakpoints

    # Convert .rzdb -> .i64 via headless IDA Pro
    idb_out = tmp_path / "crackme0x05.i64"
    idb_stats = convert_rzdb_to_idb(
        rzdb_path=rzdb_from_rizin,
        out_idb_path=idb_out,
        binary_path=bin_copy,
    )
    assert idb_out.exists()
    assert idb_stats["functions_applied"] > 0
    assert idb_stats["types_applied"] >= 2
    assert idb_stats["flags_applied"] >= 1
    assert idb_stats["comments_applied"] >= 1
    assert idb_stats["marks_applied"] >= 1
    assert idb_stats["xrefs_applied"] >= 1
    assert idb_stats["breakpoints_applied"] >= 1

    # Convert .i64 -> .rzdb via headless IDA Pro
    rzdb_from_ida = tmp_path / "from_ida.rzdb"
    rzdb_stats = convert_idb_to_rzdb(
        idb_path=idb_out,
        out_rzdb_path=rzdb_from_ida,
        binary_path=bin_copy,
    )
    assert rzdb_from_ida.exists()
    assert rzdb_stats["functions"] > 0
    assert rzdb_stats["structs"] >= 1
    assert rzdb_stats["enums"] >= 1
    assert rzdb_stats["flags"] >= 1
    assert rzdb_stats["marks"] >= 1
    assert rzdb_stats["xrefs"] >= 1
    assert rzdb_stats["breakpoints"] >= 1

    # Load `from_ida.rzdb` into real Rizin CLI and verify zero errors + intact annotations
    verify_cmds = "; ".join(
        [
            f"Po {rzdb_from_ida}",
            "afij @ 0x08048484",
            "afvlj @ 0x08048484",
            "CClj",
            "flj",
            "tsj",
            "tej",
            "mlj",
            "axlj",
            "dblj",
        ]
    )
    vres = subprocess.run(
        [str(RIZIN_BIN), "-N", "-q", "-c", verify_cmds, "--"],
        capture_output=True,
        text=True,
        check=True,
    )
    assert "ERROR" not in vres.stderr, f"Rizin reported errors loading IDA-exported .rzdb: {vres.stderr}"
    assert "mw_parell" in vres.stdout
    assert "Rizin comment at parell" in vres.stdout
    assert "mw_custom_flag" in vres.stdout
    assert "mw_pkt" in vres.stdout
    assert "mw_state" in vres.stdout
    assert "mark_parell" in vres.stdout
    assert "134520864" in vres.stdout
    assert "134513796" in vres.stdout or "0x08048484" in vres.stdout


def test_cli_inspect_entrypoint(tmp_path: Path, capsys) -> None:
    """Verifies the `rzdb-inspect` CLI entrypoint outputs valid JSON summary."""
    from rzdb2ida.cli import main_inspect

    ir = ProjectIR(
        version=26,
        binary_raw_path="/bin/ls",
        arch="x86",
        bits=64,
        base_addr=0x400000,
    )
    ir.functions[0x401000] = FunctionIR(
        addr=0x401000,
        name="main",
        bbs=[0x401000],
    )
    ir.blocks[0x401000] = BasicBlockIR(addr=0x401000, size=16, ninstr=1)
    rzdb_file = tmp_path / "inspect_test.rzdb"
    save_rzdb(ir, rzdb_file)

    rc = main_inspect([str(rzdb_file)])
    assert rc == 0
    captured = capsys.readouterr()
    assert '"functions_count": 1' in captured.out
    assert '"blocks_count": 1' in captured.out

