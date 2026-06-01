from __future__ import annotations

import re

from ida_pseudoforge.core.normalize import extract_parameters_from_signature
from ida_pseudoforge.core.plan_schema import FunctionCapture, RenameSuggestion


def pattern_renames(capture: FunctionCapture) -> list[RenameSuggestion]:
    text = capture.pseudocode
    suggestions = []
    patterns = [
        (
            r"\b(?P<dst>[A-Za-z_][A-Za-z0-9_]*)\s*=\s*\(unsigned\s+int\)\s*a3\b",
            "inputLength",
            0.93,
            "local is a 32-bit copy of SystemInformationLength",
        ),
        (
            r"\b(?P<dst>[A-Za-z_][A-Za-z0-9_]*)\s*=\s*a2\b",
            "systemInfo128",
            0.90,
            "local aliases SystemInformation as a vector-sized pointer",
        ),
        (
            r"\b(?P<dst>[A-Za-z_][A-Za-z0-9_]*)\s*=\s*\(int\)\s*a1\b",
            "infoClass",
            0.97,
            "local is the integer dispatcher copied from SystemInformationClass",
        ),
        (
            r"\b(?P<dst>[A-Za-z_][A-Za-z0-9_]*)\s*=\s*KeGetCurrentThread\(\)->PreviousMode\b",
            "previousMode",
            0.99,
            "local captures current thread PreviousMode",
        ),
        (
            r"\b(?P<dst>[A-Za-z_][A-Za-z0-9_]*)\s*=\s*KeGetCurrentThread\(\)->ApcState\.Process\b",
            "currentProcess",
            0.94,
            "local captures current thread process object",
        ),
    ]
    for pattern, new_name, confidence, evidence in patterns:
        match = re.search(pattern, text)
        if not match:
            continue
        old_name = match.group("dst")
        if new_name == "systemInfo128":
            alias_kind = _m128_pointer_alias_kind(capture, old_name, "a2")
            if not alias_kind:
                continue
            if alias_kind == "reused":
                new_name = "infoBuffer128"
                confidence = min(confidence, 0.86)
                evidence = "typed m128 buffer pointer is reused after the original parameter alias"
        if old_name == new_name:
            continue
        suggestions.append(
            RenameSuggestion(
                kind="lvar",
                old=old_name,
                new=new_name,
                confidence=confidence,
                source="pattern",
                evidence=evidence,
            )
        )
    suggestions.extend(_saved_previous_mode_renames(capture))
    suggestions.extend(_same_named_field_local_renames(capture))
    suggestions.extend(_cpu_set_mask_renames(text))
    suggestions.extend(_pool_allocation_renames(text))
    return suggestions


def _cpu_set_mask_renames(text: str) -> list[RenameSuggestion]:
    suggestions = []
    suggestions.extend(_cpu_set_modify_mask_renames(text))
    suggestions.extend(_cpu_set_tag_mask_renames(text))
    suggestions.extend(_cpu_set_allowed_mask_renames(text))
    return suggestions


def _cpu_set_modify_mask_renames(text: str) -> list[RenameSuggestion]:
    suggestions = []
    for match in re.finditer(
        r"\bmemmove\(\s*(?P<dst>[A-Za-z_][A-Za-z0-9_]*)\s*,\s*&[A-Za-z_][A-Za-z0-9_]*->m128i_u64\[1\]\s*,\s*(?:\([^)]+\)\s*)?(?P<size>[A-Za-z_][A-Za-z0-9_]*)\s*\);",
        text,
    ):
        old_name = match.group("dst")
        size_name = match.group("size")
        tail = text[match.end() : match.end() + 800]
        if _first_cpu_set_callee(tail) != "KeModifySystemAllowedCpuSets":
            continue
        if old_name != "cpuSetMaskStackBuffer":
            suggestions.append(
                RenameSuggestion(
                    kind="lvar",
                    old=old_name,
                    new="cpuSetMaskStackBuffer",
                    confidence=0.90,
                    source="pattern",
                    evidence="stack buffer receives CPU set mask entries before KeModifySystemAllowedCpuSets",
                )
            )
        if size_name != "cpuSetMaskBytes":
            suggestions.append(
                RenameSuggestion(
                    kind="lvar",
                    old=size_name,
                    new="cpuSetMaskBytes",
                    confidence=0.88,
                    source="pattern",
                    evidence="byte count for CPU set mask stack buffer",
                )
            )
        _append_cpu_set_count_renames(suggestions, tail, size_name)
        _append_cpu_set_buffer_alias_renames(suggestions, tail, old_name)
        _append_cpu_set_operation_renames(suggestions, text, tail, match.start())
    return suggestions


def _append_cpu_set_count_renames(
    suggestions: list[RenameSuggestion],
    tail: str,
    size_name: str,
) -> None:
    count_match = re.search(
        r"\b(?P<count>[A-Za-z_][A-Za-z0-9_]*)\s*=\s*%s\s*>>\s*3\s*;" % re.escape(size_name),
        tail,
    )
    if count_match and count_match.group("count") != "cpuSetCount":
        suggestions.append(
            RenameSuggestion(
                kind="lvar",
                old=count_match.group("count"),
                new="cpuSetCount",
                confidence=0.86,
                source="pattern",
                evidence="CPU set mask byte count converted to element count",
            )
        )


def _append_cpu_set_buffer_alias_renames(
    suggestions: list[RenameSuggestion],
    tail: str,
    old_name: str,
) -> None:
    buffer_match = re.search(
        r"\b(?P<buffer>[A-Za-z_][A-Za-z0-9_]*)\s*=\s*%s\s*;" % re.escape(old_name),
        tail,
    )
    if buffer_match and buffer_match.group("buffer") != "cpuSetMaskBuffer":
        suggestions.append(
            RenameSuggestion(
                kind="lvar",
                old=buffer_match.group("buffer"),
                new="cpuSetMaskBuffer",
                confidence=0.86,
                source="pattern",
                evidence="pointer aliases CPU set mask stack buffer",
            )
        )


def _append_cpu_set_operation_renames(
    suggestions: list[RenameSuggestion],
    text: str,
    tail: str,
    match_start: int,
) -> None:
    prefix = text[max(0, match_start - 500) : match_start]
    operation_matches = list(
        re.finditer(
            r"\b(?P<operation>[A-Za-z_][A-Za-z0-9_]*)\s*=\s*"
            r"[A-Za-z_][A-Za-z0-9_]*->m128i_i64\[0\]\s*;",
            prefix,
        )
    )
    if not operation_matches:
        return
    operation_name = operation_matches[-1].group("operation")
    if not _looks_like_cpu_set_operation_use(tail, operation_name):
        return
    if operation_name != "cpuSetOperation":
        suggestions.append(
            RenameSuggestion(
                kind="lvar",
                old=operation_name,
                new="cpuSetOperation",
                confidence=0.86,
                source="pattern",
                evidence="operation selector read from the CPU set request header",
            )
        )
    operation32_match = re.search(
        r"\b(?P<operation32>[A-Za-z_][A-Za-z0-9_]*)\s*=\s*%s\s*;" % re.escape(operation_name),
        tail,
    )
    if operation32_match and operation32_match.group("operation32") != "cpuSetOperation32":
        suggestions.append(
            RenameSuggestion(
                kind="lvar",
                old=operation32_match.group("operation32"),
                new="cpuSetOperation32",
                confidence=0.82,
                source="pattern",
                evidence="32-bit operation selector passed to KeModifySystemAllowedCpuSets",
            )
        )


def _cpu_set_tag_mask_renames(text: str) -> list[RenameSuggestion]:
    suggestions = []
    for match in re.finditer(
        r"\bmemmove\(\s*(?P<dst>[A-Za-z_][A-Za-z0-9_]*)\s*,\s*&[A-Za-z_][A-Za-z0-9_]*->m128i_u64\[1\]\s*,\s*(?:\([^)]+\)\s*)?(?P<size>[A-Za-z_][A-Za-z0-9_]*)\s*\);",
        text,
    ):
        old_name = match.group("dst")
        size_name = match.group("size")
        tail = text[match.end() : match.end() + 800]
        if _first_cpu_set_callee(tail) != "KeSetTagCpuSets":
            continue
        if old_name != "cpuSetTagMaskStackBuffer":
            suggestions.append(
                RenameSuggestion(
                    kind="lvar",
                    old=old_name,
                    new="cpuSetTagMaskStackBuffer",
                    confidence=0.88,
                    source="pattern",
                    evidence="stack buffer receives CPU set tag mask entries before KeSetTagCpuSets",
                )
            )
        if size_name != "cpuSetTagMaskBytes":
            suggestions.append(
                RenameSuggestion(
                    kind="lvar",
                    old=size_name,
                    new="cpuSetTagMaskBytes",
                    confidence=0.86,
                    source="pattern",
                    evidence="byte count for CPU set tag mask stack buffer",
                )
            )
    return suggestions


def _cpu_set_allowed_mask_renames(text: str) -> list[RenameSuggestion]:
    suggestions = []
    for match in re.finditer(
        r"\bmemmove\(\s*(?P<dst>[A-Za-z_][A-Za-z0-9_]*)\s*,\s*(?!&)(?P<src>[A-Za-z_][A-Za-z0-9_]*)\s*,\s*(?:\([^)]+\)\s*)?(?P<size>[A-Za-z_][A-Za-z0-9_]*)\s*\);",
        text,
    ):
        old_name = match.group("dst")
        tail = text[match.end() : match.end() + 800]
        if _first_cpu_set_callee(tail) != "KeModifySystemAllowedCpuSets":
            continue
        if old_name != "cpuSetAllowedMaskStackBuffer":
            suggestions.append(
                RenameSuggestion(
                    kind="lvar",
                    old=old_name,
                    new="cpuSetAllowedMaskStackBuffer",
                    confidence=0.86,
                    source="pattern",
                    evidence="stack buffer receives direct CPU set mask before KeModifySystemAllowedCpuSets",
                )
            )
    return suggestions


def _pool_allocation_renames(text: str) -> list[RenameSuggestion]:
    suggestions = []
    for match in re.finditer(
        r"\b(?P<dst>[A-Za-z_][A-Za-z0-9_]*)\s*=\s*\(void\s*\*\)\s*ExAllocatePool2\s*\(",
        text,
    ):
        old_name = match.group("dst")
        if old_name != "allocatedBuffer":
            suggestions.append(
                RenameSuggestion(
                    kind="lvar",
                    old=old_name,
                    new="allocatedBuffer",
                    confidence=0.88,
                    source="pattern",
                    evidence="local receives an ExAllocatePool2 allocation result",
                )
            )
    return suggestions


def _saved_previous_mode_renames(capture: FunctionCapture) -> list[RenameSuggestion]:
    text = capture.pseudocode
    type_by_name = {var.name: var.type for var in capture.lvars}
    previous_mode_sources = {
        match.group("dst")
        for match in re.finditer(
            r"\b(?P<dst>[A-Za-z_][A-Za-z0-9_]*)\s*=\s*KeGetCurrentThread\(\)->PreviousMode\b",
            text,
        )
    }
    suggestions = []
    for source in previous_mode_sources:
        for match in re.finditer(
            r"\b(?P<dst>[A-Za-z_][A-Za-z0-9_]*)\s*=\s*%s\s*;" % re.escape(source),
            text,
        ):
            old_name = match.group("dst")
            if old_name == source:
                continue
            type_text = type_by_name.get(old_name, "")
            if type_text and "KPROCESSOR_MODE" not in type_text:
                continue
            suggestions.append(
                RenameSuggestion(
                    kind="lvar",
                    old=old_name,
                    new="savedPreviousMode",
                    confidence=0.88,
                    source="pattern",
                    evidence="local stores a saved copy of PreviousMode",
                )
            )
    return suggestions


def _same_named_field_local_renames(capture: FunctionCapture) -> list[RenameSuggestion]:
    local_names = {var.name for var in capture.lvars if var.name}
    if not local_names:
        return []

    suggestions = []
    existing_names = set(local_names)
    for match in re.finditer(
        r"\b(?P<dst>[A-Za-z_][A-Za-z0-9_]*)\s*=\s*[^;\n]*?(?:->|\.)\s*(?P=dst)\s*;",
        capture.pseudocode,
    ):
        old_name = match.group("dst")
        if old_name not in local_names:
            continue
        new_name = _lower_camel_from_pascal(old_name)
        if not new_name or new_name == old_name or new_name in existing_names:
            continue
        suggestions.append(
            RenameSuggestion(
                kind="lvar",
                old=old_name,
                new=new_name,
                confidence=0.84,
                source="field-fallback",
                evidence="local shadows a same-named structure field",
            )
        )
    return suggestions


def _lower_camel_from_pascal(name: str) -> str:
    if not name or not re.match(r"^[A-Z][A-Za-z0-9_]*$", name):
        return ""
    if name.upper() == name:
        return ""

    prefix_len = 1
    while prefix_len < len(name) and name[prefix_len].isupper():
        next_index = prefix_len + 1
        if next_index < len(name) and name[next_index].islower():
            break
        prefix_len += 1

    return name[:prefix_len].lower() + name[prefix_len:]


def _m128_pointer_alias_kind(capture: FunctionCapture, local_name: str, parameter_name: str) -> str:
    for name, type_text in extract_parameters_from_signature(capture.prototype):
        if name == parameter_name and "__m128i" in type_text:
            return "reused" if _local_alias_reassigned(capture.pseudocode, local_name, parameter_name) else "stable"

    names = "%s|%s" % (re.escape(local_name), re.escape(parameter_name))
    if not (
        re.search(r"\b(?:%s)->m128i_" % names, capture.pseudocode)
        or re.search(r"\b(?:%s)\s*\[[^\]]+\]\s*\.m128i_" % names, capture.pseudocode)
    ):
        return ""
    if _local_alias_reassigned(capture.pseudocode, local_name, parameter_name):
        return "reused"
    return "stable"


def _local_alias_reassigned(text: str, local_name: str, parameter_name: str) -> bool:
    pattern = re.compile(r"\b%s\s*=\s*(?P<expr>[^;\n]+);" % re.escape(local_name))
    for match in pattern.finditer(text):
        if _assignment_rhs_is_parameter_alias(match.group("expr"), parameter_name):
            continue
        return True
    return False


def _assignment_rhs_is_parameter_alias(expr: str, parameter_name: str) -> bool:
    value = re.sub(r"\s+", "", expr or "")
    if value == parameter_name:
        return True
    while value.startswith("("):
        close_index = value.find(")")
        if close_index < 0:
            return False
        cast_text = value[1:close_index]
        if not cast_text or parameter_name in cast_text:
            return False
        value = value[close_index + 1 :]
        if value == parameter_name:
            return True
    return False


def _first_cpu_set_callee(text: str) -> str:
    match = re.search(r"\b(?P<callee>KeModifySystemAllowedCpuSets|KeSetTagCpuSets)\s*\(", text)
    if not match:
        return ""
    return match.group("callee")


def _looks_like_cpu_set_operation_use(text: str, operation_name: str) -> bool:
    escaped = re.escape(operation_name)
    return bool(
        re.search(r"\bif\s*\(\s*%s\s*>?=\s*2\s*\)" % escaped, text)
        or re.search(r"\b[A-Za-z_][A-Za-z0-9_]*\s*=\s*%s\s*;" % escaped, text)
    )
