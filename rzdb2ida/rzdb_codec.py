# SPDX-License-Identifier: LGPL-3.0-only
"""Bidirectional codec between Rizin .rzdb (SDB + JSON, v26) and ProjectIR."""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any, Dict, List, Optional

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
    SwitchCaseIR,
    SwitchOpIR,
    TypedefIR,
    UnionTypeIR,
    VarAccessIR,
    XrefIR,
)
from .sdb_text import SdbNode, load_sdb_file, save_sdb_file

RZ_PROJECT_TYPE = "rizin rz-db project"
RZ_PROJECT_VERSION = 26


def _parse_int(val: str | int, default: int = 0) -> int:
    if isinstance(val, int):
        return val
    try:
        return int(str(val).strip(), 0)
    except (ValueError, TypeError):
        return default


def _hex(addr: int) -> str:
    return f"0x{addr:x}"


def _load_blocks(blocks_ns: Optional[SdbNode], ir: ProjectIR) -> None:
    if not blocks_ns:
        return
    for k, v in blocks_ns.kvs.items():
        addr = _parse_int(k, -1)
        if addr < 0:
            continue
        data = json.loads(v)
        sw_op: Optional[SwitchOpIR] = None
        if "switch_op" in data and isinstance(data["switch_op"], dict):
            sw = data["switch_op"]
            cases = [
                SwitchCaseIR(
                    addr=int(c.get("addr", 0)),
                    jump=int(c.get("jump", 0)),
                    value=int(c.get("value", 0)),
                )
                for c in sw.get("cases", [])
                if isinstance(c, dict)
            ]
            sw_op = SwitchOpIR(
                addr=int(sw.get("addr", 0)),
                min_val=int(sw.get("min", 0)),
                max_val=int(sw.get("max", 0)),
                def_val=int(sw.get("def", 0)),
                cases=cases,
            )
        # Note: Rizin negates sp and sp_delta when storing in JSON
        sp_entry = -int(data["sp"]) if "sp" in data else None
        sp_delta = [-int(x) for x in data.get("sp_delta", [])]
        ir.blocks[addr] = BasicBlockIR(
            addr=addr,
            size=int(data.get("size", 0)),
            jump=int(data["jump"]) if "jump" in data else None,
            fail=int(data["fail"]) if "fail" in data else None,
            traced=bool(data.get("traced", False)),
            colorize=int(data.get("colorize", 0)),
            ninstr=int(data.get("ninstr", 1)),
            op_pos=[int(x) for x in data.get("op_pos", [])],
            sp_entry=sp_entry,
            sp_delta=sp_delta,
            cmpval=int(data["cmpval"]) if "cmpval" in data else None,
            cmpreg=data.get("cmpreg"),
            switch_op=sw_op,
        )


def _load_functions(functions_ns: Optional[SdbNode], noreturn_ns: Optional[SdbNode], ir: ProjectIR) -> None:
    if noreturn_ns:
        for k, v in noreturn_ns.kvs.items():
            if v.lower() != "true" and v != "1":
                continue
            if k.startswith("addr.") and k.endswith(".noreturn"):
                hex_part = k[len("addr.") : -len(".noreturn")]
                try:
                    ir.noreturn_addrs.append(int(hex_part, 16))
                except ValueError:
                    pass
            elif k.startswith("func.") and k.endswith(".noreturn"):
                fn_name = k[len("func.") : -len(".noreturn")]
                ir.noreturn_funcs.append(fn_name)

    if not functions_ns:
        return
    noret_set = set(ir.noreturn_addrs)
    for k, v in functions_ns.kvs.items():
        addr = _parse_int(k, -1)
        if addr < 0:
            continue
        data = json.loads(v)
        fvars: List[FunctionVarIR] = []
        for vj in data.get("vars", []):
            if not isinstance(vj, dict):
                continue
            vname = vj.get("name")
            vtype = vj.get("type", "int64_t")
            if not vname:
                continue
            storage_type = "stack"
            stack_off: Optional[int] = None
            reg_name: Optional[str] = None
            if "storage" in vj and isinstance(vj["storage"], dict):
                st = vj["storage"]
                storage_type = st.get("type", "stack")
                if storage_type == "stack":
                    stack_off = int(st.get("stack", 0))
                elif storage_type == "reg":
                    reg_name = st.get("reg")
            elif "stack" in vj:
                storage_type = "stack"
                stack_off = int(vj["stack"])
            elif "reg" in vj:
                storage_type = "reg"
                reg_name = str(vj["reg"])

            accs: List[VarAccessIR] = []
            for aj in vj.get("accs", []):
                if isinstance(aj, dict) and "off" in aj and "reg" in aj:
                    accs.append(
                        VarAccessIR(
                            offset=int(aj["off"]),
                            access_type=str(aj.get("type", "r")),
                            reg=str(aj["reg"]),
                            sp_addend=int(aj.get("sp", 0)),
                        )
                    )
            fvars.append(
                FunctionVarIR(
                    name=vname,
                    var_type=vtype,
                    storage_type=storage_type,
                    stack_off=stack_off,
                    reg_name=reg_name,
                    kind=str(vj.get("kind", "v")),
                    comment=vj.get("cmt"),
                    accesses=accs,
                )
            )

        noret = bool(data.get("noreturn", False)) or (addr in noret_set)
        ir.functions[addr] = FunctionIR(
            addr=addr,
            name=str(data.get("name", f"fcn.{addr:08x}")),
            bits=int(data.get("bits", 0)),
            fcn_type=int(data.get("type", 0)),
            cc=data.get("cc"),
            stack=int(data.get("stack", 0)),
            maxstack=int(data.get("maxstack", 0)),
            ninstr=int(data.get("ninstr", 0)),
            bp_frame=bool(data.get("bp_frame", False)),
            bp_off=int(data.get("bp_off", 0)),
            pure=bool(data.get("pure", False)),
            noreturn=noret,
            bbs=[int(x) for x in data.get("bbs", [])],
            imports=[str(x) for x in data.get("imports", [])],
            vars=fvars,
            labels={str(lk): int(lv) for lk, lv in data.get("labels", {}).items()},
        )


def _load_xrefs(xrefs_ns: Optional[SdbNode], ir: ProjectIR) -> None:
    if not xrefs_ns:
        return
    for k, v in xrefs_ns.kvs.items():
        from_addr = _parse_int(k, -1)
        if from_addr < 0:
            continue
        arr = json.loads(v)
        if not isinstance(arr, list):
            continue
        for item in arr:
            if isinstance(item, dict) and "to" in item:
                ir.xrefs.append(
                    XrefIR(
                        from_addr=from_addr,
                        to_addr=int(item["to"]),
                        xref_type=str(item.get("type", "c")),
                    )
                )


def _load_meta(meta_ns: Optional[SdbNode], ir: ProjectIR) -> None:
    if not meta_ns:
        return
    for k, v in meta_ns.kvs.items():
        addr = _parse_int(k, -1)
        if addr < 0:
            continue
        arr = json.loads(v)
        if not isinstance(arr, list):
            continue
        for item in arr:
            if not isinstance(item, dict) or "type" not in item:
                continue
            ir.meta.append(
                MetaItemIR(
                    addr=addr,
                    meta_type=str(item["type"]),
                    size=int(item.get("size", 1)),
                    str_val=item.get("str"),
                    subtype=int(item.get("subtype", 0)),
                    space=item.get("space"),
                )
            )


def _load_types(types_ns: Optional[SdbNode], ir: ProjectIR) -> None:
    if not types_ns:
        return
    kvs = types_ns.kvs
    for k, kind in kvs.items():
        if "." in k:
            continue
        if kind == "struct":
            members_csv = kvs.get(f"struct.{k}", "")
            members: List[StructFieldIR] = []
            for mname in [m for m in members_csv.split(",") if m]:
                mval = kvs.get(f"struct.{k}.{mname}", "")
                parts = mval.rsplit(",", 2)
                if len(parts) == 3:
                    mtype, moff, msize = parts[0], _parse_int(parts[1]), _parse_int(parts[2])
                    members.append(StructFieldIR(name=mname, field_type=mtype, offset=moff, size=msize))
            ir.structs[k] = StructTypeIR(name=k, members=members)
        elif kind == "union":
            members_csv = kvs.get(f"union.{k}", "")
            members = []
            for mname in [m for m in members_csv.split(",") if m]:
                mval = kvs.get(f"union.{k}.{mname}", "")
                parts = mval.rsplit(",", 2)
                if len(parts) == 3:
                    mtype, moff, msize = parts[0], _parse_int(parts[1]), _parse_int(parts[2])
                    members.append(StructFieldIR(name=mname, field_type=mtype, offset=moff, size=msize))
            ir.unions[k] = UnionTypeIR(name=k, members=members)
        elif kind == "enum":
            cases_csv = kvs.get(f"enum.{k}", "")
            cases: List[EnumCaseIR] = []
            for cname in [c for c in cases_csv.split(",") if c]:
                cval = kvs.get(f"enum.{k}.{cname}")
                if cval is not None:
                    cases.append(EnumCaseIR(name=cname, val=_parse_int(cval)))
            underlying = kvs.get(f"enum.{k}.@type")
            ir.enums[k] = EnumTypeIR(name=k, cases=cases, underlying_type=underlying)
        elif kind == "typedef":
            target = kvs.get(f"typedef.{k}")
            if target:
                ir.typedefs[k] = TypedefIR(name=k, target_type=target)


def _load_callables(callables_ns: Optional[SdbNode], ir: ProjectIR) -> None:
    if not callables_ns:
        return
    kvs = callables_ns.kvs
    for k, v in kvs.items():
        if v != "func" or "." in k:
            continue
        argc = _parse_int(kvs.get(f"func.{k}.args", "0"))
        args: List[CallableArgIR] = []
        for i in range(argc):
            aval = kvs.get(f"func.{k}.arg.{i}", "")
            if "," in aval:
                atype, aname = aval.rsplit(",", 1)
                args.append(CallableArgIR(name=aname, arg_type=atype))
        ret_type = kvs.get(f"func.{k}.ret")
        cc = kvs.get(f"func.{k}.cc")
        noret = kvs.get(f"func.{k}.noreturn", "").lower() in ("true", "1")
        ir.callables[k] = CallableIR(name=k, ret_type=ret_type, args=args, cc=cc, noret=noret)


def _load_global_vars(vars_ns: Optional[SdbNode], ir: ProjectIR) -> None:
    if not vars_ns:
        return
    for k, v in vars_ns.kvs.items():
        addr = _parse_int(k, -1)
        if addr < 0:
            continue
        data = json.loads(v)
        if isinstance(data, dict) and "name" in data and "type" in data:
            ir.global_vars[addr] = GlobalVarIR(
                addr=_parse_int(data.get("addr", addr), addr),
                name=str(data["name"]),
                var_type=str(data["type"]),
            )


def _load_flags(flags_ns: Optional[SdbNode], ir: ProjectIR) -> None:
    if not flags_ns:
        return
    sub = flags_ns.ns("flags")
    if not sub:
        return
    for k, v in sub.kvs.items():
        data = json.loads(v)
        if not isinstance(data, dict) or "offset" not in data:
            continue
        ir.flags.append(
            FlagIR(
                name=k,
                offset=int(data["offset"]),
                size=int(data.get("size", 1)),
                realname=data.get("realname"),
                demangled=bool(data.get("demangled", False)),
                space=data.get("space"),
                color=data.get("color"),
                comment=data.get("comment"),
                alias=data.get("alias"),
            )
        )


def _load_marks(marks_ns: Optional[SdbNode], ir: ProjectIR) -> None:
    if not marks_ns:
        return
    sub = marks_ns.ns("marks")
    if not sub:
        return
    for k, v in sub.kvs.items():
        data = json.loads(v)
        if not isinstance(data, dict) or "from" not in data or "to" not in data:
            continue
        ir.marks.append(
            MarkIR(
                name=k,
                from_addr=int(data["from"]),
                to_addr=int(data["to"]),
                realname=data.get("realname"),
                color=data.get("color"),
                comment=data.get("comment"),
            )
        )


def _load_breakpoints(bp_ns: Optional[SdbNode], ir: ProjectIR) -> None:
    if not bp_ns:
        return
    for k, v in bp_ns.kvs.items():
        addr = _parse_int(k, -1)
        if addr < 0:
            continue
        data = json.loads(v)
        if not isinstance(data, dict):
            continue
        ir.breakpoints[addr] = BreakpointIR(
            addr=addr,
            size=int(data.get("size", 1)),
            enabled=int(data.get("enabled", 1)),
            hw=int(data.get("hw", 0)),
            perm=int(data.get("perm", 1)),
            name=data.get("name"),
            cond=data.get("cond"),
            expr=data.get("expr"),
            data=data.get("data"),
            delta=int(data.get("delta", 0)),
            hits=int(data.get("hits", 0)),
            internal=int(data.get("internal", 0)),
            module_delta=int(data.get("module_delta", 0)),
            module_name=data.get("module_name"),
            swstep=bool(data.get("swstep", False)),
            togglehits=int(data.get("togglehits", 0)),
            trace=int(data.get("trace", 0)),
        )


def load_rzdb(path: Path | str) -> ProjectIR:
    """Loads a Rizin .rzdb project file into a ProjectIR instance."""
    root = load_sdb_file(path)
    ptype = root.get("type")
    if ptype != RZ_PROJECT_TYPE:
        raise ValueError(f"Invalid Rizin project type: {ptype!r}")
    version = _parse_int(root.get("version", "26"), 26)
    ir = ProjectIR(version=version)

    core = root.ns("core")
    if not core:
        return ir

    ir.core_offset = _parse_int(core.get("offset", "0"), 0)
    ir.core_blocksize = _parse_int(core.get("blocksize", "0x100"), 0x100)

    file_ns = core.ns("file")
    if file_ns:
        ir.binary_raw_path = file_ns.get("raw", "") or ""
        ir.binary_abs_path = file_ns.get("absolute", "") or ""
        ir.binary_rel_path = file_ns.get("relative", "") or ""

    cfg_ns = core.ns("config")
    if cfg_ns:
        ir.arch = cfg_ns.get("asm.arch")
        bits_s = cfg_ns.get("asm.bits")
        if bits_s:
            ir.bits = _parse_int(bits_s, 64)
        baddr_s = cfg_ns.get("bin.baddr")
        if baddr_s:
            baddr = _parse_int(baddr_s, 0)
            if baddr and baddr != 0xFFFFFFFFFFFFFFFF:
                ir.base_addr = baddr

    analysis = core.ns("analysis")
    if analysis:
        _load_blocks(analysis.ns("blocks"), ir)
        _load_functions(analysis.ns("functions"), analysis.ns("noreturn"), ir)
        _load_xrefs(analysis.ns("xrefs"), ir)
        _load_meta(analysis.ns("meta"), ir)
        _load_types(analysis.ns("types"), ir)
        _load_callables(analysis.ns("callables"), ir)
        _load_global_vars(analysis.ns("vars"), ir)

    _load_flags(core.ns("flags"), ir)
    _load_marks(core.ns("marks"), ir)
    dbg = core.ns("debug")
    if dbg:
        _load_breakpoints(dbg.ns("breakpoints"), ir)

    return ir


def _ensure_skeleton(root: SdbNode, ir: ProjectIR, out_path: Path) -> None:
    """Populates all mandatory Rizin v26 SDB namespaces and keys so `Po` never fails."""
    root.set("type", RZ_PROJECT_TYPE)
    root.set("version", str(RZ_PROJECT_VERSION))

    core = root.ns("core", create=True)
    assert core is not None
    core.set("offset", _hex(ir.core_offset))
    core.set("blocksize", _hex(ir.core_blocksize or 0x100))

    file_ns = core.ns("file", create=True)
    assert file_ns is not None
    if ir.binary_abs_path or ir.binary_raw_path:
        abs_p = ir.binary_abs_path or str(Path(ir.binary_raw_path).resolve())
        raw_p = ir.binary_raw_path or abs_p
        file_ns.set("raw", raw_p)
        file_ns.set("absolute", abs_p)
        try:
            rel_p = os.path.relpath(abs_p, str(out_path.resolve().parent))
            file_ns.set("relative", rel_p.replace(os.sep, "/"))
        except ValueError:
            if ir.binary_rel_path:
                file_ns.set("relative", ir.binary_rel_path)

    cfg_ns = core.ns("config", create=True)
    assert cfg_ns is not None
    if ir.arch and "asm.arch" not in cfg_ns.kvs:
        cfg_ns.set("asm.arch", ir.arch)
    if ir.bits and "asm.bits" not in cfg_ns.kvs:
        cfg_ns.set("asm.bits", str(ir.bits))

    # Flags skeleton
    flags_ns = core.ns("flags", create=True)
    assert flags_ns is not None
    if "realnames" not in flags_ns.kvs:
        flags_ns.set("realnames", "1")
    fspaces = flags_ns.ns("spaces", create=True)
    assert fspaces is not None
    if "name" not in fspaces.kvs:
        fspaces.set("name", "fs")
    if "spacestack" not in fspaces.kvs:
        fspaces.set("spacestack", '["*"]')
    # Workaround for Rizin <= 0.10.0 bug (https://github.com/rizinorg/rizin/pull/6890):
    # `m` / `m+` (`mark_add_flag`) left `/core/flags/spaces/current` stuck on `"marks"`
    # when saved from an interactive Rizin session where `*` was previously selected.
    if fspaces.get("current") == "marks":
        fspaces.kvs.pop("current", None)
    fspaces_sub = fspaces.ns("spaces", create=True)
    assert fspaces_sub is not None
    for f in ir.flags:
        if f.space:
            fspaces_sub.set(f.space, "s")
    if ir.marks:
        fspaces_sub.set("marks", "s")
    for default_sp in ("functions", "symbols", "strings", "sections", "segments", "imports"):
        fspaces_sub.set(default_sp, "s")
    flags_ns.ns("tags", create=True)
    flags_ns.ns("zones", create=True)
    flags_ns.ns("flags", create=True)

    # Marks skeleton
    marks_ns = core.ns("marks", create=True)
    assert marks_ns is not None
    marks_ns.ns("marks", create=True)

    # Analysis skeleton
    analysis_ns = core.ns("analysis", create=True)
    assert analysis_ns is not None
    for sub_name in (
        "xrefs",
        "blocks",
        "classes",
        "types",
        "callables",
        "functions",
        "noreturn",
        "meta",
        "hints",
        "imports",
        "cc",
        "vars",
    ):
        analysis_ns.ns(sub_name, create=True)
    classes_ns = analysis_ns.ns("classes", create=True)
    assert classes_ns is not None
    classes_ns.ns("attrs", create=True)
    meta_ns = analysis_ns.ns("meta", create=True)
    assert meta_ns is not None
    mspaces = meta_ns.ns("spaces", create=True)
    assert mspaces is not None
    mspaces.set("name", "CS")
    if "spacestack" not in mspaces.kvs:
        mspaces.set("spacestack", '["*"]')
    mspaces_sub = mspaces.ns("spaces", create=True)
    assert mspaces_sub is not None
    for m in ir.meta:
        if m.space:
            mspaces_sub.set(m.space, "s")

    # Debug skeleton
    dbg_ns = core.ns("debug", create=True)
    assert dbg_ns is not None
    dbg_ns.ns("breakpoints", create=True)

    # Seek skeleton
    seek_ns = core.ns("seek", create=True)
    assert seek_ns is not None
    if not seek_ns.kvs:
        seek_ns.set(
            "0",
            json.dumps({"offset": ir.core_offset, "cursor": 0, "current": True}, separators=(",", ":")),
        )


def save_rzdb(
    ir: ProjectIR,
    path: Path | str,
    template_rzdb: Optional[Path | str] = None,
    compress: bool = True,
) -> None:
    """Serializes a ProjectIR into a Rizin v26 .rzdb file."""
    out_path = Path(path)
    root = load_sdb_file(template_rzdb) if template_rzdb and Path(template_rzdb).exists() else SdbNode()
    _ensure_skeleton(root, ir, out_path)

    core = root.ns("core", create=True)
    assert core is not None
    analysis = core.ns("analysis", create=True)
    assert analysis is not None

    # 1. Blocks & Functions (enforce Rizin invariant: every saved block is referenced by >=1 function)
    blocks_ns = analysis.ns("blocks", create=True)
    funcs_ns = analysis.ns("functions", create=True)
    noret_ns = analysis.ns("noreturn", create=True)
    assert blocks_ns is not None and funcs_ns is not None and noret_ns is not None
    blocks_ns.kvs.clear()
    funcs_ns.kvs.clear()

    referenced_bbs: set[int] = set()
    for fcn in ir.functions.values():
        if not fcn.bbs:
            # Ensure function has at least an entry basic block if IDA or user defined one
            if fcn.addr in ir.blocks:
                fcn.bbs = [fcn.addr]
        for bb_addr in fcn.bbs:
            if bb_addr in ir.blocks:
                referenced_bbs.add(bb_addr)

    for bb_addr in sorted(referenced_bbs):
        blk = ir.blocks[bb_addr]
        bobj: Dict[str, Any] = {"size": max(1, blk.size)}
        if blk.jump is not None:
            bobj["jump"] = blk.jump
        if blk.fail is not None:
            bobj["fail"] = blk.fail
        if blk.traced:
            bobj["traced"] = True
        if blk.colorize:
            bobj["colorize"] = blk.colorize
        if blk.switch_op is not None:
            bobj["switch_op"] = {
                "addr": blk.switch_op.addr,
                "min": blk.switch_op.min_val,
                "max": blk.switch_op.max_val,
                "def": blk.switch_op.def_val,
                "cases": [
                    {"addr": c.addr, "jump": c.jump, "value": c.value} for c in blk.switch_op.cases
                ],
            }
        # Rizin invariant (serialize_analysis.c:359): if op_pos is present, len(op_pos) MUST equal ninstr - 1
        if blk.op_pos and len(blk.op_pos) == blk.ninstr - 1 and blk.ninstr > 1:
            bobj["ninstr"] = blk.ninstr
            bobj["op_pos"] = blk.op_pos
        else:
            bobj["ninstr"] = 1
        if blk.sp_entry is not None:
            bobj["sp"] = -blk.sp_entry
        if blk.sp_delta and len(blk.sp_delta) <= bobj["ninstr"]:
            bobj["sp_delta"] = [-d for d in blk.sp_delta]
        if blk.cmpval is not None:
            bobj["cmpval"] = blk.cmpval
        if blk.cmpreg:
            bobj["cmpreg"] = blk.cmpreg
        blocks_ns.set(_hex(bb_addr), json.dumps(bobj, separators=(",", ":")))

    for faddr in sorted(ir.functions.keys()):
        fcn = ir.functions[faddr]
        valid_bbs = [b for b in fcn.bbs if b in referenced_bbs]
        fobj: Dict[str, Any] = {
            "name": fcn.name,
            "type": fcn.fcn_type,
            "stack": fcn.stack,
            "maxstack": fcn.maxstack,
            "ninstr": max(fcn.ninstr, len(valid_bbs)),
            "bbs": valid_bbs,
        }
        if fcn.bits:
            fobj["bits"] = fcn.bits
        if fcn.cc:
            fobj["cc"] = fcn.cc
        if fcn.bp_frame:
            fobj["bp_frame"] = True
        if fcn.bp_off:
            fobj["bp_off"] = fcn.bp_off
        if fcn.pure:
            fobj["pure"] = True
        if fcn.noreturn:
            fobj["noreturn"] = True
            noret_ns.set(f"addr.{faddr:x}.noreturn", "true")
            clean_name = fcn.name.removeprefix("sym.imp.").removeprefix("sym.")
            noret_ns.set(f"func.{clean_name}.noreturn", "true")
        if fcn.imports:
            fobj["imports"] = fcn.imports
        if fcn.vars:
            vars_arr: List[Dict[str, Any]] = []
            for v in fcn.vars:
                vdict: Dict[str, Any] = {
                    "name": v.name,
                    "type": v.var_type,
                    "kind": v.kind,
                }
                if v.storage_type == "reg" and v.reg_name:
                    vdict["storage"] = {"type": "reg", "reg": v.reg_name}
                else:
                    vdict["storage"] = {"type": "stack", "stack": int(v.stack_off or 0)}
                if v.comment:
                    vdict["cmt"] = v.comment
                if v.accesses:
                    vdict["accs"] = [
                        {
                            "off": a.offset,
                            "type": a.access_type,
                            **({"sp": a.sp_addend} if a.sp_addend else {}),
                            "reg": a.reg,
                        }
                        for a in v.accesses
                    ]
                vars_arr.append(vdict)
            fobj["vars"] = vars_arr
        if fcn.labels:
            fobj["labels"] = fcn.labels
        funcs_ns.set(_hex(faddr), json.dumps(fobj, separators=(",", ":")))

    for nr_addr in ir.noreturn_addrs:
        noret_ns.set(f"addr.{nr_addr:x}.noreturn", "true")
    for nr_fn in ir.noreturn_funcs:
        noret_ns.set(f"func.{nr_fn}.noreturn", "true")

    # 2. Xrefs
    xrefs_ns = analysis.ns("xrefs", create=True)
    assert xrefs_ns is not None
    xrefs_ns.kvs.clear()
    by_from: Dict[int, List[Dict[str, Any]]] = {}
    for x in ir.xrefs:
        entry: Dict[str, Any] = {"to": x.to_addr}
        if x.xref_type and x.xref_type != "\x00":
            entry["type"] = x.xref_type[0]
        by_from.setdefault(x.from_addr, []).append(entry)
    for from_addr in sorted(by_from.keys()):
        xrefs_ns.set(_hex(from_addr), json.dumps(by_from[from_addr], separators=(",", ":")))

    # 3. Meta (comments, strings, data)
    meta_ns = analysis.ns("meta", create=True)
    assert meta_ns is not None
    meta_ns.kvs.clear()
    by_addr: Dict[int, List[Dict[str, Any]]] = {}
    for m in ir.meta:
        mobj: Dict[str, Any] = {}
        if m.size != 1:
            mobj["size"] = max(1, m.size)
        mobj["type"] = m.meta_type[0]
        if m.subtype:
            mobj["subtype"] = m.subtype
        if m.str_val is not None:
            mobj["str"] = m.str_val
        if m.space:
            mobj["space"] = m.space
        by_addr.setdefault(m.addr, []).append(mobj)
    for addr in sorted(by_addr.keys()):
        meta_ns.set(_hex(addr), json.dumps(by_addr[addr], separators=(",", ":")))

    # 4. C Types (structs, unions, enums, typedefs)
    types_ns = analysis.ns("types", create=True)
    assert types_ns is not None
    for st in ir.structs.values():
        types_ns.set(st.name, "struct")
        types_ns.set(f"struct.{st.name}", ",".join(m.name for m in st.members))
        for m in st.members:
            types_ns.set(f"struct.{st.name}.{m.name}", f"{m.field_type},{m.offset},{m.size}")
    for un in ir.unions.values():
        types_ns.set(un.name, "union")
        types_ns.set(f"union.{un.name}", ",".join(m.name for m in un.members))
        for m in un.members:
            types_ns.set(f"union.{un.name}.{m.name}", f"{m.field_type},{m.offset},{m.size}")
    for en in ir.enums.values():
        types_ns.set(en.name, "enum")
        types_ns.set(f"enum.{en.name}", ",".join(c.name for c in en.cases))
        for c in en.cases:
            types_ns.set(f"enum.{en.name}.{c.name}", _hex(c.val))
            types_ns.set(f"enum.{en.name}.{_hex(c.val)}", c.name)
        if en.underlying_type:
            types_ns.set(f"enum.{en.name}.@type", en.underlying_type)
    for td in ir.typedefs.values():
        types_ns.set(td.name, "typedef")
        types_ns.set(f"typedef.{td.name}", td.target_type)

    # 5. Callables (function prototypes)
    callables_ns = analysis.ns("callables", create=True)
    assert callables_ns is not None
    for cal in ir.callables.values():
        callables_ns.set(cal.name, "func")
        callables_ns.set(f"func.{cal.name}.args", str(len(cal.args)))
        for idx, arg in enumerate(cal.args):
            callables_ns.set(f"func.{cal.name}.arg.{idx}", f"{arg.arg_type},{arg.name}")
        if cal.ret_type:
            callables_ns.set(f"func.{cal.name}.ret", cal.ret_type)
        if cal.cc:
            callables_ns.set(f"func.{cal.name}.cc", cal.cc)
        if cal.noret:
            callables_ns.set(f"func.{cal.name}.noreturn", "true")

    # 6. Global variables
    gvars_ns = analysis.ns("vars", create=True)
    assert gvars_ns is not None
    gvars_ns.kvs.clear()
    for addr in sorted(ir.global_vars.keys()):
        gv = ir.global_vars[addr]
        a_str = _hex(gv.addr)
        gvars_ns.set(
            a_str,
            json.dumps({"name": gv.name, "addr": a_str, "type": gv.var_type}, separators=(",", ":")),
        )

    # 7. Flags
    flags_sub = core.ns("flags/flags", create=True)
    assert flags_sub is not None
    flags_sub.kvs.clear()
    for fl in ir.flags:
        fl_obj: Dict[str, Any] = {}
        if fl.realname:
            fl_obj["realname"] = fl.realname
        fl_obj["demangled"] = fl.demangled
        fl_obj["offset"] = fl.offset
        fl_obj["size"] = fl.size
        if fl.space:
            fl_obj["space"] = fl.space
        if fl.color:
            fl_obj["color"] = fl.color
        if fl.comment:
            fl_obj["comment"] = fl.comment
        if fl.alias:
            fl_obj["alias"] = fl.alias
        flags_sub.set(fl.name, json.dumps(fl_obj, separators=(",", ":")))
    for bm in ir.marks:
        if bm.name not in flags_sub.kvs:
            bm_flag_obj: Dict[str, Any] = {
                "realname": bm.realname or bm.name,
                "demangled": False,
                "offset": bm.from_addr,
                "size": max(0, bm.to_addr - bm.from_addr),
                "space": "marks",
            }
            flags_sub.set(bm.name, json.dumps(bm_flag_obj, separators=(",", ":")))

    # 8. Marks (bookmarks)
    marks_sub = core.ns("marks/marks", create=True)
    assert marks_sub is not None
    marks_sub.kvs.clear()
    for bm in ir.marks:
        bm_obj: Dict[str, Any] = {}
        if bm.realname:
            bm_obj["realname"] = bm.realname
        bm_obj["from"] = bm.from_addr
        bm_obj["to"] = bm.to_addr
        if bm.color:
            bm_obj["color"] = bm.color
        if bm.comment:
            bm_obj["comment"] = bm.comment
        marks_sub.set(bm.name, json.dumps(bm_obj, separators=(",", ":")))

    # 9. Breakpoints
    bp_sub = core.ns("debug/breakpoints", create=True)
    assert bp_sub is not None
    bp_sub.kvs.clear()
    for addr in sorted(ir.breakpoints.keys()):
        bp = ir.breakpoints[addr]
        bp_obj: Dict[str, Any] = {}
        if bp.cond:
            bp_obj["cond"] = bp.cond
        if bp.data:
            bp_obj["data"] = bp.data
        bp_obj["delta"] = bp.delta
        bp_obj["enabled"] = bp.enabled
        if bp.expr:
            bp_obj["expr"] = bp.expr
        bp_obj["hits"] = bp.hits
        bp_obj["hw"] = bp.hw
        bp_obj["internal"] = bp.internal
        bp_obj["module_delta"] = bp.module_delta
        if bp.module_name:
            bp_obj["module_name"] = bp.module_name
        if bp.name:
            bp_obj["name"] = bp.name
        bp_obj["perm"] = bp.perm
        bp_obj["pids"] = [0] * 10
        bp_obj["size"] = max(1, bp.size)
        bp_obj["swstep"] = bp.swstep
        bp_obj["togglehits"] = bp.togglehits
        bp_obj["trace"] = bp.trace
        bp_sub.set(_hex(addr), json.dumps(bp_obj, separators=(",", ":")))

    save_sdb_file(root, out_path, compress=compress, sort=True)
