# `rzdb2idb` — Bidirectional Rizin (`.rzdb`) ⟷ IDA Pro (`.i64`/`.idb`) Translator *(Experimental)*

> [!WARNING]
> **Experimental Feature**: `rzdb2idb` / `idb2rzdb` is currently an **experimental feature** targeting Rizin project format `v26` (`.rzdb`) and headless IDA Pro 9.x (`idapro` / `idalib`). Always keep backups of your original `.rzdb` and `.i64`/`.idb` databases before translating or merging.

Translates analysis databases between **Rizin** (`.rzdb`, v26) and **IDA Pro** (`.i64` / `.idb`) so you can inspect Rizin analysis results directly in the IDA Pro GUI (and vice versa).

## Supported Metadata

- **Functions & Basic Blocks**: Function boundaries, basic blocks, `noreturn` flags, and basic block colors.
- **Function Prototypes & Variables**: Calling conventions, argument/return types (`callables`), stack frame variables, and register variables (`regvar_t`).
- **C Types**: `struct`, `union`, `enum`, and `typedef` definitions between Rizin's `RzTypeDB` (`/core/analysis/types`) and IDA's local type library (`idati`).
- **Comments, Flags/Labels & Strings**: Regular and repeatable comments (`CCu` / `CClj`), symbol flags (`f+` / `flj`), item colors, string literals, and typed global variables (`avga` / `avglj`).
- **Marks / Bookmarks *(Experimental)***: Rizin range marks (`m+` / `mlj` in `/core/marks/marks`) mapped to IDA bookmarks and `[RZ_MARK ...]` repeatable tags. Marked experimental due to the upstream Rizin `<= 0.10.0` flagspace restoration bug in `m` / `m+` / `mm` (see [`rizinorg/rizin#6890`](https://github.com/rizinorg/rizin/pull/6890)); `rzdb2idb` automatically sanitizes `/core/flags/spaces/current=marks` during conversion.
- **Cross-References & Breakpoints**: User-defined code/data xrefs (`axc`, `axC`, `axd`, `axs` / `axlj` ↔ `XREF_USER`) and software/hardware debugger breakpoints (`db @ <addr>` / `dblj` ↔ `bpt_t`).

## CLI Usage

```bash
# 1. Convert a Rizin .rzdb project + binary -> IDA Pro .i64 database
python3 -m rzdb2ida.cli --rzdb project.rzdb --bin sample.bin --out sample.i64
# Or after `pip install -e .`:
rzdb2idb --rzdb project.rzdb --bin sample.bin --out sample.i64

# 2. Convert an IDA Pro .i64/.idb database -> Rizin .rzdb project
idb2rzdb --idb sample.i64 --bin sample.bin --out roundtrip.rzdb

# 3. Inspect a .rzdb file without launching Rizin
rzdb-inspect project.rzdb
```
