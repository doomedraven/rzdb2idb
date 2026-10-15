# SPDX-License-Identifier: LGPL-3.0-only
"""Bidirectional codec between ProjectIR and IDA Pro (.i64/.idb) via IDAPython / idalib."""

from __future__ import annotations

import os
import re
import shutil
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Optional, Tuple

from .model import (
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

# Color mapping between Rizin color names and IDA BGR 0xBBGGRR integers
RZ_COLOR_TO_BGR: Dict[str, int] = {
    "red": 0x0000FF,
    "green": 0x00FF00,
    "blue": 0xFF0000,
    "yellow": 0x00FFFF,
    "cyan": 0xFFFF00,
    "magenta": 0xFF00FF,
    "white": 0xFFFFFF,
    "black": 0x000000,
}

BGR_TO_RZ_COLOR: Dict[int, str] = {v: k for k, v in RZ_COLOR_TO_BGR.items()}

MARK_COMMENT_PREFIX = "[RZ_MARK "
MARK_COMMENT_RE = re.compile(
    r"^\[RZ_MARK\s+(?P<name>[^\s\]]+)\s+0x(?P<from>[0-9a-fA-F]+)\.\.0x(?P<to>[0-9a-fA-F]+)"
    r"(?:\s+color=(?P<color>[^\s\]]+))?"
    r"(?:\s+real=(?P<real>[^\]]+))?\]\s*(?P<cmt>.*)$"
)
BP_COMMENT_RE = re.compile(
    r"^\[RZ_BP\s+0x(?P<addr>[0-9a-fA-F]+)\s+size=(?P<size>\d+)\s+hw=(?P<hw>[01])\s+enabled=(?P<enabled>[01])"
    r"(?:\s+cond=(?P<cond>[^\]]+))?\]$"
)

# Default auto-generated Rizin flag prefixes that should not overwrite IDA symbols unless user-named
AUTO_FLAG_PREFIXES = (
    "section.",
    "segment.",
    "reloc.",
    "imp.",
    "loc._",
    "str.",
    "obj.",
)


@dataclass
class ApplyStats:
    types_applied: int = 0
    functions_applied: int = 0
    prototypes_applied: int = 0
    vars_applied: int = 0
    flags_applied: int = 0
    comments_applied: int = 0
    strings_applied: int = 0
    marks_applied: int = 0
    xrefs_applied: int = 0
    breakpoints_applied: int = 0


def ensure_fast_idausr() -> str:
    """Creates a local IDAUSR directory without slow network FUSE plugin symlinks."""
    if os.environ.get("IDAUSR"):
        return os.environ["IDAUSR"]
    home_idapro = Path.home() / ".idapro"
    cache_idausr = Path.home() / ".cache" / "rzdb2ida" / "idausr"
    cache_idausr.mkdir(parents=True, exist_ok=True)
    for fname in ("ida-config.json", "ida.reg"):
        src = home_idapro / fname
        dst = cache_idausr / fname
        if src.exists() and not dst.exists():
            shutil.copy2(src, dst)
    for lic in home_idapro.glob("*.hexlic"):
        dst = cache_idausr / lic.name
        if not dst.exists():
            shutil.copy2(lic, dst)
    os.environ["IDAUSR"] = str(cache_idausr)
    return str(cache_idausr)


def _format_c_declarations(ir: ProjectIR) -> str:
    """Formats ProjectIR typedefs, enums, structs, and unions as valid C declarations for IDA."""
    lines: List[str] = []

    # 1. Forward declarations for structs and unions
    for st_name in sorted(ir.structs.keys()):
        lines.append(f"struct {st_name};")
    for un_name in sorted(ir.unions.keys()):
        lines.append(f"union {un_name};")

    # 2. Enums
    for en_name, en in ir.enums.items():
        if not en.cases:
            continue
        body = ", ".join(f"{c.name} = 0x{c.val:x}" for c in en.cases)
        lines.append(f"enum {en_name} {{ {body} }};")

    # 3. Typedefs
    for td_name, td in ir.typedefs.items():
        target = td.target_type.strip()
        if target and td_name:
            lines.append(f"typedef {target} {td_name};")

    # 4. Unions
    for un_name, un in ir.unions.items():
        if not un.members:
            continue
        fields = " ".join(_format_member_decl(m) for m in un.members)
        lines.append(f"union {un_name} {{ {fields} }};")

    # 5. Structs (ordered by offset)
    for st_name, st in ir.structs.items():
        if not st.members:
            continue
        sorted_members = sorted(st.members, key=lambda m: m.offset)
        fields = " ".join(_format_member_decl(m) for m in sorted_members)
        lines.append(f"struct {st_name} {{ {fields} }};")

    return "\n".join(lines)


def _format_member_decl(m: StructFieldIR) -> str:
    """Handles C array types like 'char[16]' -> 'char name[16];'."""
    ft = m.field_type.strip()
    if "[" in ft and ft.endswith("]"):
        bracket_idx = ft.index("[")
        base_t = ft[:bracket_idx].strip()
        arr_part = ft[bracket_idx:]
        return f"{base_t} {m.name}{arr_part};"
    return f"{ft} {m.name};"


def _parse_type_to_tinfo(type_str: str):
    """Parses a C type string into an ida_typeinf.tinfo_t object."""
    import ida_typeinf

    tif = ida_typeinf.tinfo_t()
    clean = type_str.strip()
    if not clean:
        return None
    decl = f"{clean} __tmp_var;"
    if "[" in clean and clean.endswith("]"):
        bidx = clean.index("[")
        decl = f"{clean[:bidx]} __tmp_var{clean[bidx:]};"
    flags = ida_typeinf.PT_SIL | ida_typeinf.PT_TYP
    if ida_typeinf.parse_decl(tif, ida_typeinf.get_idati(), decl, flags) is not None:
        return tif
    # Try prefixing with struct / enum if it's a known user type name
    for prefix in ("struct ", "enum ", "union "):
        if ida_typeinf.parse_decl(tif, ida_typeinf.get_idati(), f"{prefix}{decl}", flags) is not None:
            return tif
    return None


def apply_ir_to_ida(ir: ProjectIR, rebase_delta: int = 0) -> ApplyStats:
    """Applies a ProjectIR to the currently open IDA Pro database."""
    import ida_auto
    import ida_bytes
    import ida_dbg
    import ida_frame
    import ida_funcs
    import ida_idaapi
    import ida_idd
    import ida_moves
    import ida_nalt
    import ida_name
    import ida_typeinf
    import ida_xref

    if rebase_delta != 0:
        ir.apply_rebase(rebase_delta)

    stats = ApplyStats()
    idati = ida_typeinf.get_idati()

    # 1. C Types Pass
    c_decls = _format_c_declarations(ir)
    if c_decls.strip():
        err_cnt = ida_typeinf.parse_decls(idati, c_decls, None, ida_typeinf.HTI_DCL)
        stats.types_applied = (
            len(ir.structs) + len(ir.unions) + len(ir.enums) + len(ir.typedefs)
        )

    # 2. Functions & Basic Blocks Pass
    for faddr, fcn in sorted(ir.functions.items()):
        end_ea = ida_idaapi.BADADDR
        if fcn.bbs:
            # Find contiguous entry chunk end if possible
            entry_blk = ir.blocks.get(faddr)
            if entry_blk and entry_blk.size > 0:
                end_ea = faddr + entry_blk.size

        existing_pfn = ida_funcs.get_func(faddr)
        if existing_pfn is None or existing_pfn.start_ea != faddr:
            ida_bytes.del_items(faddr, ida_bytes.DELIT_SIMPLE, 1)
            ida_auto.auto_make_code(faddr)
            if not ida_funcs.add_func(faddr, ida_idaapi.BADADDR):
                if end_ea != ida_idaapi.BADADDR:
                    ida_funcs.add_func(faddr, end_ea)
            existing_pfn = ida_funcs.get_func(faddr)

        if existing_pfn is not None:
            stats.functions_applied += 1
            if fcn.noreturn or faddr in ir.noreturn_addrs:
                existing_pfn.flags |= ida_funcs.FUNC_NORET
                ida_funcs.update_func(existing_pfn)

        # Apply function name (strip Rizin's default 'fcn.' / 'sym.' prefixes if appropriate, or keep user name)
        clean_fname = fcn.name
        if clean_fname.startswith("sym.") and not clean_fname.startswith("sym.imp."):
            clean_fname = clean_fname[4:]
        if not clean_fname.startswith("fcn.") and not clean_fname.startswith("sub_"):
            if ida_name.set_name(
                faddr, clean_fname, ida_name.SN_NOCHECK | ida_name.SN_NOWARN | ida_name.SN_FORCE
            ):
                pass

        # Apply basic block colors
        for bb_addr in fcn.bbs:
            blk = ir.blocks.get(bb_addr)
            if blk and blk.colorize:
                ida_nalt.set_item_color(bb_addr, blk.colorize)

    # 3. Function Prototypes (callables) & Variables Pass
    for faddr, fcn in sorted(ir.functions.items()):
        pfn = ida_funcs.get_func(faddr)
        raw_name = fcn.name
        stripped_name = raw_name.removeprefix("sym.imp.").removeprefix("sym.")
        cal = ir.callables.get(raw_name) or ir.callables.get(stripped_name)
        if cal is not None:
            ret_s = cal.ret_type or "int64_t"
            args_s = ", ".join(f"{a.arg_type} {a.name}" for a in cal.args) if cal.args else "void"
            cc_s = ""
            if cal.cc in ("cdecl", "stdcall", "fastcall", "thiscall"):
                cc_s = f"__{cal.cc} "
            cdecl = f"{ret_s} {cc_s}{stripped_name}({args_s});"
            if ida_typeinf.apply_cdecl(idati, faddr, cdecl, ida_typeinf.TINFO_DEFINITE):
                stats.prototypes_applied += 1

        if pfn is None:
            continue

        for var in fcn.vars:
            if var.storage_type == "reg" and var.reg_name:
                rc = ida_frame.add_regvar(
                    pfn,
                    pfn.start_ea,
                    pfn.end_ea,
                    var.reg_name,
                    var.name,
                    var.comment or "",
                )
                if rc == ida_frame.REGVAR_ERROR_OK:
                    stats.vars_applied += 1
            elif var.storage_type == "stack" and var.stack_off is not None:
                tif = _parse_type_to_tinfo(var.var_type)
                if tif is None:
                    tif = _parse_type_to_tinfo("int64_t")
                if tif is not None:
                    # Ensure function has a frame before defining stkvars
                    if pfn.frame == ida_idaapi.BADADDR or ida_frame.get_frame_size(pfn) == 0:
                        local_sz = max(abs(var.stack_off) + 16, fcn.stack, 0x20)
                        ida_frame.add_frame(pfn, local_sz, 0, 0)
                    if ida_frame.define_stkvar(pfn, var.name, var.stack_off, tif):
                        stats.vars_applied += 1

    # 4. Flags / Labels & Global Variables Pass
    func_addrs = set(ir.functions.keys())
    for fl in ir.flags:
        if fl.offset in func_addrs:
            if fl.color and fl.color in RZ_COLOR_TO_BGR:
                ida_nalt.set_item_color(fl.offset, RZ_COLOR_TO_BGR[fl.color])
            if fl.comment:
                ida_bytes.set_cmt(fl.offset, fl.comment, False)
                stats.comments_applied += 1
            continue
        if any(fl.name.startswith(pfx) for pfx in AUTO_FLAG_PREFIXES):
            continue
        label = fl.realname if (fl.demangled and fl.realname) else fl.name
        if label.startswith("sym."):
            label = label[4:]
        if ida_name.set_name(
            fl.offset, label, ida_name.SN_NOCHECK | ida_name.SN_NOWARN | ida_name.SN_FORCE
        ):
            stats.flags_applied += 1
        if fl.color and fl.color in RZ_COLOR_TO_BGR:
            ida_nalt.set_item_color(fl.offset, RZ_COLOR_TO_BGR[fl.color])
        if fl.comment:
            ida_bytes.set_cmt(fl.offset, fl.comment, False)
            stats.comments_applied += 1

    for gv_addr, gv in sorted(ir.global_vars.items()):
        ida_name.set_name(
            gv_addr, gv.name, ida_name.SN_NOCHECK | ida_name.SN_NOWARN | ida_name.SN_FORCE
        )
        tif = _parse_type_to_tinfo(gv.var_type)
        if tif is not None:
            ida_typeinf.apply_tinfo(gv_addr, tif, ida_typeinf.TINFO_DEFINITE)

    # 5. Meta (Comments, Strings, Data) Pass
    for m in ir.meta:
        if m.meta_type == "C" and m.str_val:
            existing = ida_bytes.get_cmt(m.addr, False)
            if existing and m.str_val not in existing:
                ida_bytes.set_cmt(m.addr, f"{existing}\n{m.str_val}", False)
            else:
                ida_bytes.set_cmt(m.addr, m.str_val, False)
            stats.comments_applied += 1
        elif m.meta_type == "s" and m.size > 0:
            if ida_bytes.create_strlit(m.addr, m.size, ida_nalt.STRTYPE_C):
                stats.strings_applied += 1
        elif m.meta_type == "d" and m.size in (1, 2, 4, 8):
            flag_map = {
                1: ida_bytes.byte_flag(),
                2: ida_bytes.word_flag(),
                4: ida_bytes.dword_flag(),
                8: ida_bytes.qword_flag(),
            }
            ida_bytes.create_data(m.addr, flag_map[m.size], m.size, ida_idaapi.BADADDR)

    # 6. Marks / Bookmarks Pass
    for idx, bm in enumerate(ir.marks, start=1):
        color_part = f" color={bm.color}" if bm.color else ""
        real_part = f" real={bm.realname}" if bm.realname else ""
        cmt_part = bm.comment or ""
        tag = f"[RZ_MARK {bm.name} 0x{bm.from_addr:x}..0x{bm.to_addr:x}{color_part}{real_part}] {cmt_part}".strip()
        existing_rep = ida_bytes.get_cmt(bm.from_addr, True)
        if existing_rep and tag not in existing_rep:
            ida_bytes.set_cmt(bm.from_addr, f"{existing_rep}\n{tag}", True)
        else:
            ida_bytes.set_cmt(bm.from_addr, tag, True)
        if bm.color and bm.color in RZ_COLOR_TO_BGR:
            ida_nalt.set_item_color(bm.from_addr, RZ_COLOR_TO_BGR[bm.color])
        try:
            pl = ida_moves.idaplace_t(bm.from_addr, 0)
            le = ida_moves.lochist_entry_t(pl, ida_moves.graph_location_info_t())
            ida_moves.bookmarks_t_mark(le, idx, bm.name, tag, None)
        except Exception:
            pass
        stats.marks_applied += 1

    # 7. Cross-References Pass
    for x in ir.xrefs:
        if x.xref_type == "C":
            ida_xref.add_cref(x.from_addr, x.to_addr, ida_xref.fl_CN | ida_xref.XREF_USER)
            stats.xrefs_applied += 1
        elif x.xref_type == "c":
            ida_xref.add_cref(x.from_addr, x.to_addr, ida_xref.fl_JN | ida_xref.XREF_USER)
            stats.xrefs_applied += 1
        elif x.xref_type == "w":
            ida_xref.add_dref(x.from_addr, x.to_addr, ida_xref.dr_W | ida_xref.XREF_USER)
            stats.xrefs_applied += 1
        elif x.xref_type in ("d", "s"):
            ida_xref.add_dref(x.from_addr, x.to_addr, ida_xref.dr_R | ida_xref.XREF_USER)
            stats.xrefs_applied += 1

    # 8. Breakpoints Pass
    bpt_soft = getattr(ida_idd, "BPT_SOFT", 4)
    bpt_exec = getattr(ida_idd, "BPT_EXEC", 0)
    bpt_rdwr = getattr(ida_idd, "BPT_RDWR", 2)
    for addr, bp in sorted(ir.breakpoints.items()):
        bpt = ida_dbg.bpt_t()
        bpt.ea = addr
        bpt.size = max(1, bp.size)
        if bp.hw:
            bpt.type = bpt_rdwr if bp.perm >= 2 else bpt_exec
        else:
            bpt.type = bpt_soft
        if bp.enabled:
            bpt.flags = ida_dbg.BPT_ENABLED
        else:
            bpt.flags = 0
        if bp.cond:
            bpt.condition = bp.cond
        added_bpt = bool(
            ida_dbg.add_bpt(bpt) or ida_dbg.add_bpt(addr, max(1, bp.size), bpt.type)
        )
        if added_bpt and not bp.enabled:
            ida_dbg.enable_bpt(addr, False)
        cond_part = f" cond={bp.cond}" if bp.cond else ""
        bp_tag = f"[RZ_BP 0x{addr:x} size={max(1, bp.size)} hw={1 if bp.hw else 0} enabled={1 if bp.enabled else 0}{cond_part}]"
        existing_rep = ida_bytes.get_cmt(addr, True)
        if existing_rep and bp_tag not in existing_rep:
            ida_bytes.set_cmt(addr, f"{existing_rep}\n{bp_tag}", True)
        elif not existing_rep:
            ida_bytes.set_cmt(addr, bp_tag, True)
        stats.breakpoints_applied += 1

    return stats


def _extract_types_from_ida(ir: ProjectIR) -> None:
    """Extracts user-defined structs, unions, enums, and typedefs from IDA's local type library."""
    import ida_typeinf

    idati = ida_typeinf.get_idati()
    limit = ida_typeinf.get_ordinal_limit(idati)
    for ord_idx in range(1, limit):
        tif = ida_typeinf.tinfo_t()
        if not tif.get_numbered_type(idati, ord_idx):
            continue
        tname = tif.get_type_name()
        if not tname or tname.startswith("$"):
            continue
        if tif.is_enum():
            etd = ida_typeinf.enum_type_data_t()
            if tif.get_enum_details(etd):
                cases = [EnumCaseIR(name=edm.name, val=int(edm.value)) for edm in etd]
                ir.enums[tname] = EnumTypeIR(name=tname, cases=cases)
        elif tif.is_udt():
            udt = ida_typeinf.udt_type_data_t()
            if tif.get_udt_details(udt):
                members: List[StructFieldIR] = []
                for udm in udt:
                    mtype_str = str(udm.type) or "uint8_t"
                    byte_off = int(udm.offset) // 8
                    members.append(
                        StructFieldIR(name=udm.name, field_type=mtype_str, offset=byte_off, size=0)
                    )
                if tif.is_union():
                    ir.unions[tname] = UnionTypeIR(name=tname, members=members)
                else:
                    ir.structs[tname] = StructTypeIR(name=tname, members=members)
        elif tif.is_typeref():
            next_name = tif.get_next_type_name()
            if next_name:
                ir.typedefs[tname] = TypedefIR(name=tname, target_type=next_name)


def extract_ir_from_ida(binary_path: Optional[str] = None) -> ProjectIR:
    """Extracts functions, blocks, variables, types, comments, flags, marks, xrefs, and breakpoints from IDA."""
    import ida_bytes
    import ida_dbg
    import ida_frame
    import ida_funcs
    import ida_gdl
    import ida_ida
    import ida_idaapi
    import ida_idd
    import ida_nalt
    import ida_name
    import ida_segment
    import ida_typeinf
    import ida_xref
    import idautils

    ir = ProjectIR(version=26)
    inp_path = binary_path or ida_nalt.get_input_file_path() or ""
    if inp_path:
        ir.binary_raw_path = inp_path
        ir.binary_abs_path = str(Path(inp_path).resolve())

    procname = (ida_ida.inf_get_procname() or "").lower()
    if "metapc" in procname or "80" in procname or "x86" in procname:
        ir.arch = "x86"
    elif "arm" in procname:
        ir.arch = "arm"
    elif "mips" in procname:
        ir.arch = "mips"
    elif "ppc" in procname:
        ir.arch = "ppc"
    elif "riscv" in procname:
        ir.arch = "riscv"

    ir.bits = 64 if ida_ida.inf_is_64bit() else (32 if ida_ida.inf_is_32bit_exactly() else 16)
    imgbase = ida_nalt.get_imagebase()
    if imgbase and imgbase != ida_idaapi.BADADDR:
        ir.base_addr = int(imgbase)
    ir.core_offset = int(ida_ida.inf_get_start_ea() if ida_ida.inf_get_start_ea() != ida_idaapi.BADADDR else (imgbase or 0))

    # 1. C Types
    _extract_types_from_ida(ir)

    # 2. Functions, Basic Blocks, Prototypes, Stack & Reg Variables
    for f_ea in idautils.Functions():
        pfn = ida_funcs.get_func(f_ea)
        if pfn is None:
            continue
        fname = ida_name.get_name(f_ea) or f"fcn.{f_ea:08x}"
        is_noret = bool(pfn.flags & ida_funcs.FUNC_NORET)
        if is_noret:
            ir.noreturn_addrs.append(int(f_ea))
            ir.noreturn_funcs.append(fname)

        bbs: List[int] = []
        fc = ida_gdl.FlowChart(pfn)
        for blk in fc:
            bsize = int(blk.end_ea - blk.start_ea)
            if bsize <= 0:
                continue
            baddr = int(blk.start_ea)
            bbs.append(baddr)
            succs = list(blk.succs())
            jump_ea: Optional[int] = None
            fail_ea: Optional[int] = None
            if len(succs) == 1:
                jump_ea = int(succs[0].start_ea)
            elif len(succs) >= 2:
                # In IDA flowcharts, if one successor is immediately adjacent (blk.end_ea), it is fail_ea
                s0, s1 = int(succs[0].start_ea), int(succs[1].start_ea)
                if s0 == int(blk.end_ea):
                    fail_ea, jump_ea = s0, s1
                else:
                    jump_ea, fail_ea = s0, s1

            bcolor = ida_nalt.get_item_color(baddr)
            colorize = int(bcolor) if bcolor != 0xFFFFFFFF else 0
            ir.blocks[baddr] = BasicBlockIR(
                addr=baddr,
                size=bsize,
                jump=jump_ea,
                fail=fail_ea,
                colorize=colorize,
                ninstr=1,
            )

        if not bbs and int(pfn.end_ea - pfn.start_ea) > 0:
            baddr = int(pfn.start_ea)
            bsize = int(pfn.end_ea - pfn.start_ea)
            bbs.append(baddr)
            ir.blocks[baddr] = BasicBlockIR(addr=baddr, size=bsize, ninstr=1)

        # Function signature / callable
        ftif = ida_typeinf.tinfo_t()
        if ida_nalt.get_tinfo(ftif, f_ea) and ftif.is_func():
            ftd = ida_typeinf.func_type_data_t()
            if ftif.get_func_details(ftd):
                args = [
                    CallableArgIR(name=fa.name or f"arg{i}", arg_type=str(fa.type) or "int64_t")
                    for i, fa in enumerate(ftd)
                ]
                ret_str = str(ftd.rettype) or "int64_t"
                ir.callables[fname] = CallableIR(
                    name=fname,
                    ret_type=ret_str,
                    args=args,
                    noret=is_noret,
                )

        # Stack variables from frame tinfo
        fvars: List[FunctionVarIR] = []
        frame_tif = ida_typeinf.tinfo_t()
        if ida_frame.get_func_frame(frame_tif, pfn):
            fudt = ida_typeinf.udt_type_data_t()
            if frame_tif.get_udt_details(fudt):
                for udm in fudt:
                    if not udm.name or udm.name in (
                        "__return_address",
                        "__saved_registers",
                        " r",
                        " s",
                    ):
                        continue
                    if ida_frame.is_anonymous_member_name(udm.name):
                        continue
                    soff = int(udm.offset) // 8
                    fpoff = int(ida_frame.soff_to_fpoff(pfn, soff))
                    vtype_s = str(udm.type) or "int64_t"
                    fvars.append(
                        FunctionVarIR(
                            name=udm.name,
                            var_type=vtype_s,
                            storage_type="stack",
                            stack_off=fpoff,
                            kind="a" if fpoff > 0 else "v",
                        )
                    )

        ir.functions[int(f_ea)] = FunctionIR(
            addr=int(f_ea),
            name=fname,
            bits=ir.bits or 64,
            stack=int(ida_frame.get_frame_size(pfn)),
            maxstack=int(ida_frame.get_frame_size(pfn)),
            ninstr=max(1, len(bbs)),
            bp_frame=bool(pfn.flags & ida_funcs.FUNC_FRAME),
            noreturn=is_noret,
            bbs=bbs,
            vars=fvars,
        )

    # 3. Names / Flags
    func_set = set(ir.functions.keys())
    for ea, name in idautils.Names():
        if not name or int(ea) in func_set:
            continue
        color_bgr = ida_nalt.get_item_color(ea)
        rz_color = BGR_TO_RZ_COLOR.get(int(color_bgr)) if color_bgr != 0xFFFFFFFF else None
        ir.flags.append(
            FlagIR(
                name=name,
                offset=int(ea),
                size=max(1, int(ida_bytes.get_item_size(ea))),
                space="symbols",
                color=rz_color,
            )
        )

    # 4. Comments, Strings, Marks, and User Xrefs across segments
    seen_xrefs: set[Tuple[int, int, str]] = set()
    for seg_ea in idautils.Segments():
        seg = ida_segment.getseg(seg_ea)
        if seg is None:
            continue
        for head_ea in idautils.Heads(seg.start_ea, seg.end_ea):
            ea_int = int(head_ea)
            # Regular comment
            reg_cmt = ida_bytes.get_cmt(head_ea, False)
            if reg_cmt:
                ir.meta.append(MetaItemIR(addr=ea_int, meta_type="C", size=1, str_val=reg_cmt))
            # Repeatable comment (check if it encodes an RZ_MARK bookmark)
            rep_cmt = ida_bytes.get_cmt(head_ea, True)
            if rep_cmt:
                rem_lines: List[str] = []
                for line in rep_cmt.splitlines():
                    m = MARK_COMMENT_RE.match(line.strip())
                    if m:
                        ir.marks.append(
                            MarkIR(
                                name=m.group("name"),
                                from_addr=int(m.group("from"), 16),
                                to_addr=int(m.group("to"), 16),
                                color=m.group("color"),
                                realname=m.group("real"),
                                comment=m.group("cmt") or None,
                            )
                        )
                        continue
                    mbp = BP_COMMENT_RE.match(line.strip())
                    if mbp:
                        bp_addr = int(mbp.group("addr"), 16)
                        ir.breakpoints[bp_addr] = BreakpointIR(
                            addr=bp_addr,
                            size=max(1, int(mbp.group("size"))),
                            enabled=int(mbp.group("enabled")),
                            hw=int(mbp.group("hw")),
                            cond=mbp.group("cond") or None,
                        )
                        continue
                    rem_lines.append(line)
                if rem_lines and not reg_cmt:
                    ir.meta.append(
                        MetaItemIR(addr=ea_int, meta_type="C", size=1, str_val="\n".join(rem_lines))
                    )

            # User-defined code/data xrefs from head_ea
            xb = ida_xref.xrefblk_t()
            ok = xb.first_from(head_ea, ida_xref.XREF_ALL)
            while ok:
                if xb.user and xb.to != ida_idaapi.BADADDR:
                    if xb.iscode:
                        xtype = "C" if xb.type in (ida_xref.fl_CN, ida_xref.fl_CF) else "c"
                    else:
                        xtype = "w" if xb.type == ida_xref.dr_W else "d"
                    key = (ea_int, int(xb.to), xtype)
                    if key not in seen_xrefs:
                        seen_xrefs.add(key)
                        ir.xrefs.append(XrefIR(from_addr=ea_int, to_addr=int(xb.to), xref_type=xtype))
                ok = xb.next_from()

    # 5. Breakpoints
    bpt_soft = getattr(ida_idd, "BPT_SOFT", 4)
    bpt_qty = ida_dbg.get_bpt_qty()
    for i in range(bpt_qty):
        bpt = ida_dbg.bpt_t()
        if ida_dbg.getn_bpt(i, bpt) and bpt.ea != ida_idaapi.BADADDR:
            is_hw = 1 if bpt.type != bpt_soft else 0
            ir.breakpoints[int(bpt.ea)] = BreakpointIR(
                addr=int(bpt.ea),
                size=max(1, int(bpt.size)),
                enabled=1 if (bpt.flags & ida_dbg.BPT_ENABLED) else 0,
                hw=is_hw,
                cond=str(bpt.condition) if bpt.condition else None,
            )

    return ir
