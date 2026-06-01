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
    suggestions.extend(_runtime_memory_parameter_renames(capture))
    suggestions.extend(_output_buffer_contract_parameter_renames(capture))
    suggestions.extend(_structure_base_parameter_renames(capture))
    suggestions.extend(_list_entry_head_parameter_renames(capture))
    suggestions.extend(_list_entry_head_local_renames(capture))
    suggestions.extend(_lookaside_entry_allocation_renames(capture))
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


def _structure_base_parameter_renames(capture: FunctionCapture) -> list[RenameSuggestion]:
    candidates = []
    for old_name, _type_text in extract_parameters_from_signature(capture.prototype):
        if not re.fullmatch(r"a\d+", old_name or ""):
            continue
        offsets = _constant_pointer_offset_uses(capture.pseudocode, old_name)
        if len(offsets) >= 3:
            candidates.append(old_name)
    if len(candidates) != 1:
        return []
    old_name = candidates[0]
    return [
        RenameSuggestion(
            kind="arg",
            old=old_name,
            new="context",
            confidence=0.86,
            source="structure-base",
            evidence="parameter is repeatedly used as a constant-offset structure base",
        )
    ]


def _runtime_memory_parameter_renames(capture: FunctionCapture) -> list[RenameSuggestion]:
    params = extract_parameters_from_signature(capture.prototype)
    if len(params) != 3:
        return []
    destination_name, destination_type = params[0]
    source_or_fill_name, source_or_fill_type = params[1]
    byte_count_name, byte_count_type = params[2]
    if not _is_pointer_type(destination_type) or not _is_integer_size_type(byte_count_type):
        return []
    text = capture.pseudocode
    if _looks_like_memmove_body(text, destination_name, source_or_fill_name, byte_count_name, source_or_fill_type):
        return _parameter_rename_suggestions(
            [
                (destination_name, "destination", 0.92, "first pointer parameter is returned and used as the memory copy destination"),
                (source_or_fill_name, "source", 0.92, "second pointer parameter is used as the memory copy source"),
                (byte_count_name, "byteCount", 0.90, "third integer parameter controls the memory copy byte count"),
            ],
            source="runtime-memory",
        )
    if _looks_like_memset_body(text, destination_name, source_or_fill_name, byte_count_name, source_or_fill_type):
        return _parameter_rename_suggestions(
            [
                (destination_name, "destination", 0.92, "first pointer parameter is returned and used as the memory fill destination"),
                (source_or_fill_name, "fillByte", 0.91, "second byte-sized parameter is expanded into a repeated fill pattern"),
                (byte_count_name, "byteCount", 0.90, "third integer parameter controls the memory fill byte count"),
            ],
            source="runtime-memory",
        )
    return []


def _parameter_rename_suggestions(
    entries: list[tuple[str, str, float, str]],
    *,
    source: str,
) -> list[RenameSuggestion]:
    suggestions = []
    for old_name, new_name, confidence, evidence in entries:
        if old_name == new_name:
            continue
        suggestions.append(
            RenameSuggestion(
                kind="arg",
                old=old_name,
                new=new_name,
                confidence=confidence,
                source=source,
                evidence=evidence,
            )
        )
    return suggestions


def _output_buffer_contract_parameter_renames(capture: FunctionCapture) -> list[RenameSuggestion]:
    params = extract_parameters_from_signature(capture.prototype)
    if len(params) != 4:
        return []
    output_name, output_type = params[1]
    length_name, length_type = params[2]
    return_length_name, return_length_type = params[3]
    if not _is_pointer_type(output_type):
        return []
    if not _is_integer_size_type(length_type):
        return []
    if not _is_pointer_type(return_length_type):
        return []
    text = capture.pseudocode
    if not _looks_like_output_buffer_contract(text, output_name, length_name, return_length_name):
        return []
    return _parameter_rename_suggestions(
        [
            (output_name, "outputBuffer", 0.88, "pointer parameter receives structured output writes"),
            (length_name, "outputBufferLength", 0.88, "integer parameter bounds the structured output buffer"),
            (return_length_name, "returnLength", 0.88, "pointer parameter receives required or written output length"),
        ],
        source="buffer-contract",
    )


def _looks_like_output_buffer_contract(
    text: str,
    output_name: str,
    length_name: str,
    return_length_name: str,
) -> bool:
    output = re.escape(output_name)
    length = re.escape(length_name)
    return_length = re.escape(return_length_name)
    has_length_guard = re.search(r"\b%s\s*<\s*(?:0x[0-9A-Fa-f]+|\d+)\b" % length, text)
    has_output_header_store = re.search(r"\*\s*%s\s*=|%s\s*\[\s*(?:0|1|2|3|4|5)\s*\]\s*=" % (output, output), text)
    has_indexed_output_store = re.search(r"\b%s\s*\[[^;\n]+\]\s*=|&\s*%s\s*\[[^;\n]+\]" % (output, output), text)
    has_return_length_store = re.search(r"\*\s*%s\s*=" % return_length, text)
    return bool(has_length_guard and has_output_header_store and has_indexed_output_store and has_return_length_store)


def _looks_like_memmove_body(
    text: str,
    destination_name: str,
    source_name: str,
    byte_count_name: str,
    source_type: str,
) -> bool:
    if not _is_pointer_type(source_type):
        return False
    if not _returns_first_parameter(text, destination_name):
        return False
    destination = re.escape(destination_name)
    source = re.escape(source_name)
    byte_count = re.escape(byte_count_name)
    has_overlap_branch = re.search(r"\b%s\s*<\s*%s\b|\b%s\s*<\s*%s\b" % (source, destination, destination, source), text)
    has_pointer_delta = re.search(r"\b%s\s*-\s*%s\b|\b%s\s*-\s*%s\b" % (source, destination, destination, source), text)
    has_byte_count_guard = re.search(
        r"\b%s\s*(?:<|>|<=|>=|==|!=)\s*(?:0x[0-9A-Fa-f]+|\d+)|\b(?:if|while)\s*\(\s*%s\s*\)"
        % (byte_count, byte_count),
        text,
    )
    has_sized_access = re.search(
        r"\b%s\s*\[\s*%s\b|\b%s\s*\[\s*%s\b|&\s*%s\s*\[\s*%s\b|&\s*%s\s*\[\s*%s\b"
        % (destination, byte_count, source, byte_count, destination, byte_count, source, byte_count),
        text,
    )
    return bool(has_overlap_branch and has_pointer_delta and has_byte_count_guard and has_sized_access)


def _looks_like_memset_body(
    text: str,
    destination_name: str,
    fill_name: str,
    byte_count_name: str,
    fill_type: str,
) -> bool:
    if _is_pointer_type(fill_type):
        return False
    if not _returns_first_parameter(text, destination_name):
        return False
    destination = re.escape(destination_name)
    fill = re.escape(fill_name)
    byte_count = re.escape(byte_count_name)
    has_fill_expansion = re.search(
        r"(?:0x0?101010101010101(?:LL|uLL|ULL)?\s*\*\s*%s|%s\s*\*\s*0x0?101010101010101(?:LL|uLL|ULL)?)"
        % (fill, fill),
        text,
    )
    has_byte_count_guard = re.search(r"\b%s\s*(?:<|>|<=|>=|==|!=)\s*(?:0x[0-9A-Fa-f]+|\d+)" % byte_count, text)
    has_destination_store = re.search(r"\*\s*\([^;\n)]*\*\s*\)\s*%s\s*=" % destination, text) or re.search(
        r"\*\s*%s\s*=" % destination,
        text,
    )
    has_sized_destination_access = re.search(r"\b%s\s*\[\s*%s\b|&\s*%s\s*\[\s*%s\b" % (destination, byte_count, destination, byte_count), text)
    return bool(has_fill_expansion and has_byte_count_guard and (has_destination_store or has_sized_destination_access))


def _returns_first_parameter(text: str, name: str) -> bool:
    escaped = re.escape(name)
    direct_return = re.search(r"\breturn\s+(?:\([^)]+\)\s*)?%s\s*;" % escaped, text)
    if direct_return:
        return True
    alias_pattern = re.compile(
        r"\b(?P<alias>[A-Za-z_][A-Za-z0-9_]*)\s*=\s*(?:\([^)]+\)\s*)?%s\s*;" % escaped
    )
    for match in alias_pattern.finditer(text):
        alias_name = match.group("alias")
        if _alias_is_returned_without_reassignment(text, alias_name, match.end()):
            return True
    return False


def _alias_is_returned_without_reassignment(text: str, alias_name: str, start_index: int) -> bool:
    escaped = re.escape(alias_name)
    tail = text[start_index:]
    return_match = re.search(r"\breturn\s+%s\s*;" % escaped, tail)
    if not return_match:
        return False
    before_return = tail[: return_match.start()]
    mutation_match = re.search(
        r"(?m)^\s*%s\s*(?:[-+*/%%&|^]?=|\+\+|--)|^\s*(?:\+\+|--)\s*%s\b"
        % (escaped, escaped),
        before_return,
    )
    return mutation_match is None


def _is_pointer_type(type_text: str) -> bool:
    return "*" in (type_text or "") or "&" in (type_text or "")


def _is_integer_size_type(type_text: str) -> bool:
    text = type_text or ""
    if _is_pointer_type(text):
        return False
    return bool(re.search(r"\b(?:size_t|SIZE_T|__int64|int64|ULONG|DWORD|int|char|unsigned|signed)\b", text))


def _constant_pointer_offset_uses(text: str, name: str) -> set[str]:
    offsets: set[str] = set()
    escaped = re.escape(name)
    for line in (text or "").splitlines():
        if not re.search(r"\b%s\s*\+" % escaped, line):
            continue
        if not _line_has_pointer_offset_evidence(line, name):
            continue
        for match in re.finditer(r"\b%s\s*\+\s*(?P<offset>0x[0-9A-Fa-f]+|\d+)\b" % escaped, line):
            offsets.add(match.group("offset").lower())
    return offsets


def _line_has_pointer_offset_evidence(line: str, name: str) -> bool:
    escaped = re.escape(name)
    return bool(
        re.search(r"\*\s*\([^;\n)]*\*\s*\)\s*\(\s*%s\s*\+" % escaped, line)
        or re.search(r"\(\s*(?:P[A-Z0-9_]+|struct\s+[A-Za-z_][A-Za-z0-9_]*\s*\*[\*\s]*|[A-Za-z_][A-Za-z0-9_\s]*\*[\*\s]*)\)\s*\(\s*%s\s*\+" % escaped, line)
    )


def _list_entry_head_parameter_renames(capture: FunctionCapture) -> list[RenameSuggestion]:
    candidates = []
    for old_name, type_text in extract_parameters_from_signature(capture.prototype):
        if "*" not in type_text:
            continue
        if _looks_like_list_entry_head_parameter(capture.pseudocode, old_name):
            candidates.append(old_name)
    if len(candidates) != 1:
        return []
    old_name = candidates[0]
    if old_name == "listHead":
        return []
    return [
        RenameSuggestion(
            kind="arg",
            old=old_name,
            new="listHead",
            confidence=0.90,
            source="kernel-list",
            evidence="pointer parameter is used as a self-referential LIST_ENTRY head",
        )
    ]


def _list_entry_head_local_renames(capture: FunctionCapture) -> list[RenameSuggestion]:
    candidates = []
    for local in capture.lvars:
        if "*" not in (local.type or ""):
            continue
        if _looks_like_list_entry_head_local(capture.pseudocode, local.name):
            candidates.append(local.name)
    if len(candidates) != 1:
        return []
    old_name = candidates[0]
    if old_name == "listHead":
        return []
    return [
        RenameSuggestion(
            kind="lvar",
            old=old_name,
            new="listHead",
            confidence=0.88,
            source="kernel-list",
            evidence="local pointer is used as a self-referential LIST_ENTRY head",
        )
    ]


def _lookaside_entry_allocation_renames(capture: FunctionCapture) -> list[RenameSuggestion]:
    candidates = []
    for match in re.finditer(
        r"\b(?P<dst>[A-Za-z_][A-Za-z0-9_]*)\s*=\s*(?:\([^)]+\)\s*)?"
        r"ExAllocateFromNPagedLookasideList\s*\(",
        capture.pseudocode,
    ):
        old_name = match.group("dst")
        if _looks_like_generic_temporary(old_name):
            candidates.append(old_name)
    candidates = _unique_preserve_order(candidates)
    if len(candidates) != 1:
        return []
    old_name = candidates[0]
    if old_name == "lookasideEntry":
        return []
    return [
        RenameSuggestion(
            kind="lvar",
            old=old_name,
            new="lookasideEntry",
            confidence=0.86,
            source="kernel-list",
            evidence="local receives a single lookaside-list allocation result",
        )
    ]


def _looks_like_list_entry_head_parameter(text: str, name: str) -> bool:
    escaped = re.escape(name)
    self_flink_patterns = (
        r"\(\s*[^)]*\*\s*\)\s*\*\s*%s\s*==\s*%s\b" % (escaped, escaped),
        r"\*\s*%s\s*==\s*%s\b" % (escaped, escaped),
        r"\b%s\s*==\s*\(\s*[^)]*\*\s*\)\s*\*\s*%s\b" % (escaped, escaped),
    )
    has_self_flink = any(re.search(pattern, text) for pattern in self_flink_patterns)
    if not has_self_flink:
        return False
    has_blink_use = bool(re.search(r"\b%s\s*\[\s*1\s*\]" % escaped, text))
    has_neighbor_check = bool(
        re.search(r"\*\s*[A-Za-z_][A-Za-z0-9_]*\s*!=\s*%s\b" % escaped, text)
        or re.search(r"\b[A-Za-z_][A-Za-z0-9_]*\s*==\s*%s\b" % escaped, text)
    )
    return has_blink_use or has_neighbor_check


def _looks_like_list_entry_head_local(text: str, name: str) -> bool:
    if not _looks_like_generic_temporary(name):
        return False
    escaped = re.escape(name)
    has_self_deref_check = bool(
        re.search(r"\*\s*%s\s*==\s*%s\b" % (escaped, escaped), text)
        or re.search(r"%s\s*==\s*\*\s*%s\b" % (escaped, escaped), text)
    )
    if not has_self_deref_check:
        return False
    has_neighbor_integrity = bool(
        re.search(r"\[\s*1\s*\]\s*!=\s*%s\b" % escaped, text)
        or re.search(r"\*\s*[A-Za-z_][A-Za-z0-9_]*\s*!=\s*%s\b" % escaped, text)
        or re.search(r"\[\s*1\s*\]\s*=\s*%s\b" % escaped, text)
        or re.search(r"=\s*%s\s*;" % escaped, text)
    )
    return has_neighbor_integrity


def _looks_like_generic_temporary(name: str) -> bool:
    return bool(re.fullmatch(r"v\d+", name or ""))


def _unique_preserve_order(values: list[str]) -> list[str]:
    result = []
    seen = set()
    for value in values:
        if value in seen:
            continue
        seen.add(value)
        result.append(value)
    return result


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
