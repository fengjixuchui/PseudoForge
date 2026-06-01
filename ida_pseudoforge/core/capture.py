from __future__ import annotations

import re

from ida_pseudoforge.core.normalize import (
    extract_calls,
    extract_function_name,
    extract_function_signature,
    strip_ida_tags,
)
from ida_pseudoforge.core.plan_schema import FunctionCapture, LocalVariable


DECL_RE = re.compile(
    r"^\s*(?P<type>(?:const\s+)?[A-Za-z_][A-Za-z0-9_:\s\*\&<>]*?)\s+"
    r"(?P<ptr>[\*\&]\s*)?"
    r"(?P<name>[A-Za-z_][A-Za-z0-9_]*)\s*(?:;|=|,|\[)"
)


def capture_from_pseudocode(
    pseudocode: str,
    name: str = "",
    ea: int = 0,
    source_path: str = "",
) -> FunctionCapture:
    clean_text = strip_ida_tags(pseudocode)
    signature = extract_function_signature(clean_text)
    function_name = name or extract_function_name(signature)
    lvars = _extract_declared_lvars(clean_text)
    calls = extract_calls(clean_text)
    return FunctionCapture(
        ea=ea,
        name=function_name,
        prototype=signature,
        pseudocode=clean_text,
        lvars=lvars,
        calls=calls,
        source_path=source_path,
    )


def _extract_declared_lvars(pseudocode: str) -> list[LocalVariable]:
    lvars = []
    seen = set()
    in_body = False
    for line in (pseudocode or "").splitlines():
        stripped = line.strip()
        if stripped == "{":
            in_body = True
            continue
        if not in_body:
            continue
        if not stripped or stripped.startswith("//"):
            continue
        if stripped.startswith(("if ", "if(", "return", "switch", "for ", "while", "do ")):
            continue
        match = DECL_RE.match(line)
        if not match:
            if lvars and not stripped.startswith(("__", "_", "P", "K", "U", "H", "int", "char", "void", "struct")):
                break
            continue
        var_name = match.group("name")
        if var_name in seen:
            continue
        seen.add(var_name)
        var_type = match.group("type").strip()
        ptr = (match.group("ptr") or "").strip()
        if ptr:
            var_type = f"{var_type} {ptr}"
        lvars.append(LocalVariable(name=var_name, type=var_type))
    return lvars
