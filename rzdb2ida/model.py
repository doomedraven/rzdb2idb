# SPDX-License-Identifier: LGPL-3.0-only
"""Canonical Intermediate Representation (ProjectIR) for .rzdb <-> .idb/.i64 translation."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List, Optional


@dataclass
class SwitchCaseIR:
    addr: int
    jump: int
    value: int


@dataclass
class SwitchOpIR:
    addr: int
    min_val: int
    max_val: int
    def_val: int
    cases: List[SwitchCaseIR] = field(default_factory=list)


@dataclass
class BasicBlockIR:
    addr: int
    size: int
    jump: Optional[int] = None
    fail: Optional[int] = None
    traced: bool = False
    colorize: int = 0
    ninstr: int = 1
    op_pos: List[int] = field(default_factory=list)
    sp_entry: Optional[int] = None
    sp_delta: List[int] = field(default_factory=list)
    cmpval: Optional[int] = None
    cmpreg: Optional[str] = None
    switch_op: Optional[SwitchOpIR] = None


@dataclass
class VarAccessIR:
    offset: int  # Offset relative to function start
    access_type: str  # "r", "w", or "rw"
    reg: str
    sp_addend: int = 0


@dataclass
class FunctionVarIR:
    name: str
    var_type: str
    storage_type: str  # "stack" or "reg"
    stack_off: Optional[int] = None
    reg_name: Optional[str] = None
    kind: str = "v"  # "v" (local/var), "a" (arg), "r" (reg)
    comment: Optional[str] = None
    accesses: List[VarAccessIR] = field(default_factory=list)


@dataclass
class FunctionIR:
    addr: int
    name: str
    bits: int = 0
    fcn_type: int = 0
    cc: Optional[str] = None
    stack: int = 0
    maxstack: int = 0
    ninstr: int = 0
    bp_frame: bool = True
    bp_off: int = 0
    pure: bool = False
    noreturn: bool = False
    bbs: List[int] = field(default_factory=list)
    imports: List[str] = field(default_factory=list)
    vars: List[FunctionVarIR] = field(default_factory=list)
    labels: Dict[str, int] = field(default_factory=dict)


@dataclass
class XrefIR:
    from_addr: int
    to_addr: int
    xref_type: str = "c"  # "C" (call), "c" (code), "d" (data read), "w" (data write), "s" (string)


@dataclass
class MetaItemIR:
    addr: int
    meta_type: str  # "C" (comment), "s" (string), "d" (data), "c" (code), "t" (vartype), "H" (highlight)
    size: int = 1
    str_val: Optional[str] = None
    subtype: int = 0
    space: Optional[str] = None


@dataclass
class FlagIR:
    name: str
    offset: int
    size: int = 1
    realname: Optional[str] = None
    demangled: bool = False
    space: Optional[str] = None
    color: Optional[str] = None
    comment: Optional[str] = None
    alias: Optional[str] = None


@dataclass
class MarkIR:
    name: str
    from_addr: int
    to_addr: int
    realname: Optional[str] = None
    color: Optional[str] = None
    comment: Optional[str] = None


@dataclass
class BreakpointIR:
    addr: int
    size: int = 1
    enabled: int = 1
    hw: int = 0
    perm: int = 1
    name: Optional[str] = None
    cond: Optional[str] = None
    expr: Optional[str] = None
    data: Optional[str] = None
    delta: int = 0
    hits: int = 0
    internal: int = 0
    module_delta: int = 0
    module_name: Optional[str] = None
    swstep: bool = False
    togglehits: int = 0
    trace: int = 0


@dataclass
class StructFieldIR:
    name: str
    field_type: str
    offset: int  # Byte offset
    size: int = 0  # Bit size (0 for normal byte-aligned fields in Rizin SDB)


@dataclass
class StructTypeIR:
    name: str
    members: List[StructFieldIR] = field(default_factory=list)


@dataclass
class UnionTypeIR:
    name: str
    members: List[StructFieldIR] = field(default_factory=list)


@dataclass
class EnumCaseIR:
    name: str
    val: int


@dataclass
class EnumTypeIR:
    name: str
    cases: List[EnumCaseIR] = field(default_factory=list)
    underlying_type: Optional[str] = None


@dataclass
class TypedefIR:
    name: str
    target_type: str


@dataclass
class CallableArgIR:
    name: str
    arg_type: str


@dataclass
class CallableIR:
    name: str
    ret_type: Optional[str] = None
    args: List[CallableArgIR] = field(default_factory=list)
    cc: Optional[str] = None
    noret: bool = False


@dataclass
class GlobalVarIR:
    addr: int
    name: str
    var_type: str


@dataclass
class ProjectIR:
    version: int = 26
    binary_raw_path: str = ""
    binary_abs_path: str = ""
    binary_rel_path: str = ""
    core_offset: int = 0
    core_blocksize: int = 0x100
    arch: Optional[str] = None
    bits: Optional[int] = None
    base_addr: Optional[int] = None

    blocks: Dict[int, BasicBlockIR] = field(default_factory=dict)
    functions: Dict[int, FunctionIR] = field(default_factory=dict)
    noreturn_addrs: List[int] = field(default_factory=list)
    noreturn_funcs: List[str] = field(default_factory=list)
    xrefs: List[XrefIR] = field(default_factory=list)
    meta: List[MetaItemIR] = field(default_factory=list)
    flags: List[FlagIR] = field(default_factory=list)
    marks: List[MarkIR] = field(default_factory=list)
    breakpoints: Dict[int, BreakpointIR] = field(default_factory=dict)

    structs: Dict[str, StructTypeIR] = field(default_factory=dict)
    unions: Dict[str, UnionTypeIR] = field(default_factory=dict)
    enums: Dict[str, EnumTypeIR] = field(default_factory=dict)
    typedefs: Dict[str, TypedefIR] = field(default_factory=dict)
    callables: Dict[str, CallableIR] = field(default_factory=dict)
    global_vars: Dict[int, GlobalVarIR] = field(default_factory=dict)

    def apply_rebase(self, delta: int) -> None:
        """Shifts all virtual addresses in the IR by delta."""
        if delta == 0:
            return
        if self.core_offset:
            self.core_offset += delta
        if self.base_addr is not None:
            self.base_addr += delta

        new_blocks: Dict[int, BasicBlockIR] = {}
        for addr, blk in self.blocks.items():
            blk.addr = addr + delta
            if blk.jump is not None:
                blk.jump += delta
            if blk.fail is not None:
                blk.fail += delta
            if blk.switch_op is not None:
                blk.switch_op.addr += delta
                if blk.switch_op.def_val:
                    blk.switch_op.def_val += delta
                for c in blk.switch_op.cases:
                    c.addr += delta
                    c.jump += delta
            new_blocks[blk.addr] = blk
        self.blocks = new_blocks

        new_funcs: Dict[int, FunctionIR] = {}
        for addr, fcn in self.functions.items():
            fcn.addr = addr + delta
            fcn.bbs = [bb + delta for bb in fcn.bbs]
            fcn.labels = {k: v + delta for k, v in fcn.labels.items()}
            new_funcs[fcn.addr] = fcn
        self.functions = new_funcs

        self.noreturn_addrs = [a + delta for a in self.noreturn_addrs]
        for x in self.xrefs:
            x.from_addr += delta
            x.to_addr += delta
        for m in self.meta:
            m.addr += delta
        for f in self.flags:
            f.offset += delta
        for bm in self.marks:
            bm.from_addr += delta
            bm.to_addr += delta

        new_bps: Dict[int, BreakpointIR] = {}
        for addr, bp in self.breakpoints.items():
            bp.addr = addr + delta
            new_bps[bp.addr] = bp
        self.breakpoints = new_bps

        new_gvars: Dict[int, GlobalVarIR] = {}
        for addr, gv in self.global_vars.items():
            gv.addr = addr + delta
            new_gvars[gv.addr] = gv
        self.global_vars = new_gvars
