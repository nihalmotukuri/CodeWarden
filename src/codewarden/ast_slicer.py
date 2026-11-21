from __future__ import annotations

from pathlib import Path

import tree_sitter_cpp as tscpp
import tree_sitter_python as tspython
import tree_sitter_typescript as tstypescript
from tree_sitter import Language, Node, Parser

from codewarden.models import DiffHunk, FunctionSlice

PY_LANG = Language(tspython.language())
TS_LANG = Language(tstypescript.language_typescript())
TSX_LANG = Language(tstypescript.language_tsx())
CPP_LANG = Language(tscpp.language())

EXT_TO_LANG: dict[str, tuple[str, Language]] = {
    ".py": ("python", PY_LANG),
    ".ts": ("typescript", TS_LANG),
    ".js": ("tsx", TSX_LANG),
    ".jsx": ("tsx", TSX_LANG),
    ".mjs": ("tsx", TSX_LANG),
    ".cjs": ("tsx", TSX_LANG),
    ".tsx": ("tsx", TSX_LANG),
    ".cpp": ("cpp", CPP_LANG),
    ".cc": ("cpp", CPP_LANG),
    ".cxx": ("cpp", CPP_LANG),
    ".h": ("cpp", CPP_LANG),
    ".hpp": ("cpp", CPP_LANG),
}

FUNCTION_NODE_TYPES: dict[str, set[str]] = {
    "python": {"function_definition", "async_function_definition"},
    "typescript": {"function_declaration", "method_definition", "arrow_function"},
    "tsx": {"function_declaration", "method_definition", "arrow_function"},
    "cpp": {"function_definition"},
}

IMPORT_NODE_TYPES: dict[str, set[str]] = {
    "python": {"import_statement", "import_from_statement"},
    "typescript": {"import_statement"},
    "tsx": {"import_statement"},
    "cpp": {"preproc_include"},
}


def _extract_symbol_name(node: Node, source_bytes: bytes) -> str:
    name_node = node.child_by_field_name("name")
    if name_node is not None:
        return source_bytes[name_node.start_byte : name_node.end_byte].decode("utf-8", errors="replace")

    declarator = node.child_by_field_name("declarator")
    while declarator is not None:
        inner = declarator.child_by_field_name("declarator")
        if inner is None:
            text = source_bytes[declarator.start_byte : declarator.end_byte].decode("utf-8", errors="replace")
            return text.split("(")[0].strip()
        declarator = inner

    if node.type == "arrow_function" and node.parent is not None and node.parent.type == "variable_declarator":
        var_name = node.parent.child_by_field_name("name")
        if var_name is not None:
            return source_bytes[var_name.start_byte : var_name.end_byte].decode("utf-8", errors="replace")

    return "<anonymous>"


def slice_hunk(repo_path: Path, hunk: DiffHunk) -> list[FunctionSlice]:
    full_path = repo_path / hunk.file_path
    if not full_path.is_file():
        return []

    lang_entry = EXT_TO_LANG.get(full_path.suffix.lower())
    if lang_entry is None:
        return []

    lang_name, language = lang_entry
    source_bytes = full_path.read_bytes()
    source_lines = source_bytes.decode("utf-8", errors="replace").splitlines()
    max_line = max(1, len(source_lines))

    parser = Parser(language)
    tree = parser.parse(source_bytes)

    imports: list[str] = []
    import_types = IMPORT_NODE_TYPES[lang_name]
    for child in tree.root_node.children:
        if child.type in import_types:
            imports.append(source_bytes[child.start_byte : child.end_byte].decode("utf-8", errors="replace").strip())

    target_lines = set(hunk.added_lines) | {min(ln, max_line) for ln in hunk.deletion_anchors}
    if not target_lines:
        return []

    fn_types = FUNCTION_NODE_TYPES[lang_name]
    matched_nodes: dict[tuple[int, int], tuple[Node, list[int]]] = {}

    def _walk(node: Node) -> None:
        start_1 = node.start_point.row + 1
        end_1 = node.end_point.row + 1
        overlapping = sorted(ln for ln in target_lines if start_1 <= ln <= end_1)
        if not overlapping:
            return

        if node.type in fn_types:
            matched_nodes[(start_1, end_1)] = (node, overlapping)

        for child in node.children:
            _walk(child)

    _walk(tree.root_node)

    outer_ranges = [
        (s, e)
        for (s, e) in matched_nodes
        if not any(os <= s and e <= oe and (os, oe) != (s, e) for (os, oe) in matched_nodes)
    ]

    slices: list[FunctionSlice] = []
    for start_1, end_1 in sorted(outer_ranges):
        node, overlapping = matched_nodes[(start_1, end_1)]
        snippet = "\n".join(source_lines[start_1 - 1 : end_1])
        slices.append(
            FunctionSlice(
                file_path=hunk.file_path,
                language=lang_name,
                symbol_name=_extract_symbol_name(node, source_bytes),
                node_type=node.type,
                start_line=start_1,
                end_line=end_1,
                changed_lines=overlapping,
                imports=imports,
                raw_patch=hunk.raw_patch,
                source_code=snippet,
            )
        )

    return slices
