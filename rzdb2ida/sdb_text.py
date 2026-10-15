# SPDX-License-Identifier: LGPL-3.0-only
"""Lossless SDB plaintext + gzip parser and writer matching librz/util/sdb/src/text.c."""

from __future__ import annotations

import gzip
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional

GZIP_MAGIC = b"\x1f\x8b\x08"


@dataclass
class SdbNode:
    """Represents a single SDB namespace containing key-value pairs and child namespaces."""

    kvs: Dict[str, str] = field(default_factory=dict)
    subns: Dict[str, SdbNode] = field(default_factory=dict)

    def ns(self, path: str, create: bool = False) -> Optional[SdbNode]:
        """Navigates a '/' separated relative or absolute namespace path."""
        tokens = [t for t in path.strip("/").split("/") if t]
        cur: SdbNode = self
        for tok in tokens:
            nxt = cur.subns.get(tok)
            if nxt is None:
                if not create:
                    return None
                nxt = SdbNode()
                cur.subns[tok] = nxt
            cur = nxt
        return cur

    def get(self, key: str, default: Optional[str] = None) -> Optional[str]:
        return self.kvs.get(key, default)

    def set(self, key: str, val: str) -> None:
        self.kvs[key] = val


def _unescape_char(c: str) -> str:
    if c == "n":
        return "\n"
    if c == "r":
        return "\r"
    if c == "t":
        return "\t"
    return c


def _parse_path_line(line: str) -> List[str]:
    """Parses a leading-'/' SDB path line into unescaped namespace tokens."""
    # line starts with '/'
    body = line[1:]
    if not body:
        return []
    tokens: List[str] = []
    cur: List[str] = []
    unescape = False
    for ch in body:
        if unescape:
            cur.append(_unescape_char(ch))
            unescape = False
        elif ch == "\\":
            unescape = True
        elif ch == "/":
            tokens.append("".join(cur))
            cur = []
        else:
            cur.append(ch)
    tokens.append("".join(cur))
    return [t for t in tokens if t]


def _parse_kv_line(line: str) -> Optional[tuple[str, str]]:
    """Parses a 'key=value' line according to SDB text escaping rules."""
    key_chars: List[str] = []
    val_chars: List[str] = []
    in_value = False
    unescape = False

    for ch in line:
        if unescape:
            target = val_chars if in_value else key_chars
            target.append(_unescape_char(ch))
            unescape = False
        elif ch == "\\":
            unescape = True
        elif not in_value and ch == "=":
            in_value = True
        else:
            target = val_chars if in_value else key_chars
            target.append(ch)

    if not in_value:
        return None
    key = "".join(key_chars)
    val = "".join(val_chars)
    if not key or not val:
        return None
    return key, val


def parse_sdb_text(text: str) -> SdbNode:
    """Parses an SDB plaintext document into an SdbNode tree."""
    root = SdbNode()
    cur_db = root

    for raw_line in text.splitlines():
        if not raw_line:
            continue
        if raw_line.startswith("/"):
            tokens = _parse_path_line(raw_line)
            cur_db = root
            for tok in tokens:
                cur_db = cur_db.ns(tok, create=True)  # type: ignore[assignment]
        else:
            kv = _parse_kv_line(raw_line)
            if kv is not None:
                cur_db.set(kv[0], kv[1])

    return root


def _escape_path_token(token: str) -> str:
    out: List[str] = []
    for ch in token:
        if ch == "\\":
            out.append("\\\\")
        elif ch == "/":
            out.append("\\/")
        elif ch == "\n":
            out.append("\\n")
        elif ch == "\r":
            out.append("\\r")
        else:
            out.append(ch)
    return "".join(out)


def _escape_key(key: str) -> str:
    out: List[str] = []
    if key.startswith("/"):
        out.append("\\")
    for ch in key:
        if ch == "\\":
            out.append("\\\\")
        elif ch == "=":
            out.append("\\=")
        elif ch == "\n":
            out.append("\\n")
        elif ch == "\r":
            out.append("\\r")
        else:
            out.append(ch)
    return "".join(out)


def _escape_value(val: str) -> str:
    out: List[str] = []
    for ch in val:
        if ch == "\\":
            out.append("\\\\")
        elif ch == "\n":
            out.append("\\n")
        elif ch == "\r":
            out.append("\\r")
        else:
            out.append(ch)
    return "".join(out)


def serialize_sdb_text(root: SdbNode, sort: bool = True) -> str:
    """Serializes an SdbNode tree into Rizin SDB plaintext format."""
    chunks: List[str] = []

    def _walk(node: SdbNode, path: List[str]) -> None:
        if not path:
            chunks.append("/\n")
        else:
            escaped_tokens = "/".join(_escape_path_token(t) for t in path)
            chunks.append(f"/{escaped_tokens}\n")

        items = sorted(node.kvs.items(), key=lambda x: x[0]) if sort else list(node.kvs.items())
        for k, v in items:
            if not k or v == "":
                continue
            chunks.append(f"{_escape_key(k)}={_escape_value(v)}\n")

        sub_items = sorted(node.subns.items(), key=lambda x: x[0]) if sort else list(node.subns.items())
        for sub_name, sub_node in sub_items:
            chunks.append("\n")
            path.append(sub_name)
            _walk(sub_node, path)
            path.pop()

    _walk(root, [])
    return "".join(chunks)


def load_sdb_file(path: Path | str) -> SdbNode:
    """Loads an .rzdb file (either gzip-compressed or raw SDB text)."""
    p = Path(path)
    raw = p.read_bytes()
    if raw[:3] == GZIP_MAGIC:
        raw = gzip.decompress(raw)
    text = raw.decode("utf-8", errors="replace")
    return parse_sdb_text(text)


def save_sdb_file(root: SdbNode, path: Path | str, compress: bool = True, sort: bool = True) -> None:
    """Saves an SdbNode tree to an .rzdb file (gzip-compressed by default)."""
    p = Path(path)
    text = serialize_sdb_text(root, sort=sort)
    data = text.encode("utf-8")
    if compress:
        # Use mtime=0 for deterministic output
        data = gzip.compress(data, compresslevel=9, mtime=0)
    p.write_bytes(data)
