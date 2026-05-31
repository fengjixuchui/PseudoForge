from __future__ import annotations

import re
from typing import Callable

from ida_pseudoforge.core.render_style import strip_outer_parentheses
from ida_pseudoforge.profiles.loader import (
    get_process_information_class_name,
    get_system_information_class_name,
    get_system_information_class_value,
)

_SYSTEM_INFORMATION_CLASS_DELTA_MAX_LINE_GAP = 24
_C_INTEGER_SUFFIX_PATTERN = r"(?i:ui64|i64|u?ll|llu|ul|lu|u|l)"
_C_UNSIGNED_INTEGER_LITERAL_PATTERN = r"(?:0x[0-9A-Fa-f]+|\d+)(?:%s)?" % _C_INTEGER_SUFFIX_PATTERN
_C_INTEGER_LITERAL_PATTERN = r"-?%s" % _C_UNSIGNED_INTEGER_LITERAL_PATTERN


def rewrite_system_information_class_literals(text: str) -> str:
    if "systemInformationClass" not in text and "infoClass" not in text:
        return text

    def replace_compare(match: re.Match[str]) -> str:
        value = _parse_c_integer_literal(match.group("value"))
        if value is None:
            return match.group(0)
        name = _system_information_class_name(value)
        if not name:
            return match.group(0)
        return "%s%s%s" % (match.group("lhs"), name, match.group("rhs"))

    compare_pattern = re.compile(
        r"(?P<lhs>(?:\(\s*_DWORD\s*\)\s*)?(?:systemInformationClass|infoClass)\s*(?:==|!=|>=|<=|>|<)\s*)"
        rf"(?P<value>{_C_UNSIGNED_INTEGER_LITERAL_PATTERN})"
        r"(?P<rhs>\b)"
    )
    text = compare_pattern.sub(replace_compare, text)

    subtract_patterns = [
        re.compile(
            r"(?P<lhs>(?:\(\s*(?:unsigned\s+int|int|ULONG|__int64)\s*\)\s*\(\s*(?:systemInformationClass|infoClass)\s*-\s*))"
            rf"(?P<value>{_C_UNSIGNED_INTEGER_LITERAL_PATTERN})"
            r"(?P<rhs>\s*\))"
        ),
        re.compile(
            r"(?P<lhs>(?:systemInformationClass|infoClass)\s*-\s*)"
            rf"(?P<value>{_C_UNSIGNED_INTEGER_LITERAL_PATTERN})"
            r"(?P<rhs>\b)"
        ),
    ]
    for pattern in subtract_patterns:
        text = pattern.sub(_replace_system_information_class_subtract, text)
    return _rewrite_system_information_class_delta_chains(text)


def rewrite_process_information_class_literals(text: str) -> str:
    if "processInformationClass" not in text:
        return text

    def replace_compare(match: re.Match[str]) -> str:
        value = _parse_c_integer_literal(match.group("value"))
        if value is None:
            return match.group(0)
        name = _process_information_class_name(value)
        if not name:
            return match.group(0)
        return "%s%s%s" % (match.group("lhs"), name, match.group("rhs"))

    compare_pattern = re.compile(
        r"(?P<lhs>(?:\(\s*_DWORD\s*\)\s*)?processInformationClass\s*(?:==|!=|>=|<=|>|<)\s*)"
        rf"(?P<value>{_C_UNSIGNED_INTEGER_LITERAL_PATTERN})"
        r"(?P<rhs>\b)"
    )
    text = compare_pattern.sub(replace_compare, text)

    subtract_patterns = [
        re.compile(
            r"(?P<lhs>(?:\(\s*(?:unsigned\s+int|int|ULONG|__int64)\s*\)\s*\(\s*processInformationClass\s*-\s*))"
            rf"(?P<value>{_C_UNSIGNED_INTEGER_LITERAL_PATTERN})"
            r"(?P<rhs>\s*\))"
        ),
        re.compile(
            r"(?P<lhs>processInformationClass\s*-\s*)"
            rf"(?P<value>{_C_UNSIGNED_INTEGER_LITERAL_PATTERN})"
            r"(?P<rhs>\b)"
        ),
    ]
    for pattern in subtract_patterns:
        text = pattern.sub(_replace_process_information_class_subtract, text)
    return _rewrite_enum_switch_cases(text, {"processInformationClass"}, _process_information_class_name)


def replace_char_literal_cases(text: str) -> str:
    def repl(match: re.Match[str]) -> str:
        value = match.group("value")
        if len(value) != 1:
            return match.group(0)
        return "%scase %d:" % (match.group("indent"), ord(value))

    return re.sub(
        r"(?m)^(?P<indent>\s*)case '(?P<value>[^'\\])':",
        repl,
        text,
    )


def _replace_system_information_class_subtract(match: re.Match[str]) -> str:
    value = _parse_c_integer_literal(match.group("value"))
    if value is None:
        return match.group(0)
    name = _system_information_class_name(value)
    if not name:
        return match.group(0)
    return "%s%s%s" % (match.group("lhs"), name, match.group("rhs"))


def _rewrite_system_information_class_delta_chains(text: str) -> str:
    delta_expressions: dict[str, tuple[str, int, int]] = {}
    lines = []
    for line_index, line in enumerate(text.splitlines()):
        updated = _rewrite_system_information_class_delta_condition(line, line_index, delta_expressions)
        updated = _rewrite_system_information_class_delta_assignment(updated, line_index, delta_expressions)
        lines.append(updated)
    return "\n".join(lines)


def _rewrite_system_information_class_delta_assignment(
    line: str,
    line_index: int,
    delta_expressions: dict[str, tuple[str, int, int]],
) -> str:
    match = re.match(
        r"(?P<indent>\s*)(?P<target>[A-Za-z_][A-Za-z0-9_]*)\s*=\s*(?P<expr>[^;\n]+)\s*;$",
        line,
    )
    if match is None:
        return line

    target = match.group("target")
    parsed = _parse_system_information_class_delta_expression(match.group("expr"), line_index, delta_expressions)
    if parsed is None:
        delta_expressions.pop(target, None)
        return line

    dispatcher, value = parsed
    delta_expressions[target] = (dispatcher, value, line_index)
    name = _system_information_class_name(value)
    if not name:
        return line
    return "%s%s = %s - %s;" % (match.group("indent"), target, dispatcher, name)


def _rewrite_system_information_class_delta_condition(
    line: str,
    line_index: int,
    delta_expressions: dict[str, tuple[str, int, int]],
) -> str:
    match = re.match(
        r"(?P<indent>\s*)if\s*\(\s*(?P<var>[A-Za-z_][A-Za-z0-9_]*)\s*"
        rf"(?P<op>==|!=)\s*(?P<value>{_C_INTEGER_LITERAL_PATTERN})\s*\)\s*$",
        line,
    )
    if match is not None:
        offset = _parse_c_integer_literal(match.group("value"))
        if offset is not None and offset != 0:
            replacement = _format_system_information_class_delta_offset(
                delta_expressions,
                match.group("var"),
                offset,
                line_index,
            )
            if replacement:
                return "%sif ( %s %s %s )" % (
                    match.group("indent"),
                    match.group("var"),
                    match.group("op"),
                    replacement,
                )

    match = re.match(
        rf"(?P<indent>\s*)if\s*\(\s*(?P<value>{_C_INTEGER_LITERAL_PATTERN})\s*"
        r"(?P<op>==|!=)\s*(?P<var>[A-Za-z_][A-Za-z0-9_]*)\s*\)\s*$",
        line,
    )
    if match is not None:
        offset = _parse_c_integer_literal(match.group("value"))
        if offset is not None and offset != 0:
            replacement = _format_system_information_class_delta_offset(
                delta_expressions,
                match.group("var"),
                offset,
                line_index,
            )
            if replacement:
                return "%sif ( %s %s %s )" % (
                    match.group("indent"),
                    match.group("var"),
                    match.group("op"),
                    replacement,
                )

    return line


def _format_system_information_class_delta_offset(
    delta_expressions: dict[str, tuple[str, int, int]],
    variable: str,
    offset: int,
    line_index: int,
) -> str:
    expression = delta_expressions.get(variable)
    if expression is None:
        return ""
    if not _system_information_class_delta_is_fresh(expression, line_index):
        return ""
    _dispatcher, base_value, _defined_at = expression
    base_name = _system_information_class_name(base_value)
    target_name = _system_information_class_name(base_value + offset)
    if not base_name or not target_name:
        return ""
    return "%s - %s" % (target_name, base_name)


def _parse_system_information_class_delta_expression(
    expression: str,
    line_index: int,
    delta_expressions: dict[str, tuple[str, int, int]],
) -> tuple[str, int] | None:
    normalized = _strip_cast_and_outer_parentheses(expression)
    direct = re.match(
        r"^(?P<dispatcher>systemInformationClass|infoClass)\s*-\s*"
        rf"(?P<base>[A-Za-z_][A-Za-z0-9_]*|{_C_UNSIGNED_INTEGER_LITERAL_PATTERN})$",
        normalized,
    )
    if direct is not None:
        value = _system_information_class_token_value(direct.group("base"))
        if value is None:
            return None
        return direct.group("dispatcher"), value

    chained = re.match(
        r"^(?P<source>[A-Za-z_][A-Za-z0-9_]*)\s*(?P<op>[+-])\s*"
        rf"(?P<offset>{_C_INTEGER_LITERAL_PATTERN})$",
        normalized,
    )
    if chained is None:
        return None
    source = delta_expressions.get(chained.group("source"))
    if source is None:
        return None
    offset = _parse_c_integer_literal(chained.group("offset"))
    if offset is None:
        return None
    dispatcher, base_value, _defined_at = source
    if chained.group("op") == "-":
        return dispatcher, base_value + offset
    return dispatcher, base_value - offset


def _system_information_class_delta_is_fresh(expression: tuple[str, int, int], line_index: int) -> bool:
    defined_at = expression[2]
    if line_index < defined_at:
        return False
    return line_index - defined_at <= _SYSTEM_INFORMATION_CLASS_DELTA_MAX_LINE_GAP


def _strip_cast_and_outer_parentheses(expression: str) -> str:
    value = expression.strip()
    value = re.sub(
        r"^\(\s*(?:unsigned\s+int|int|ULONG|LONG|DWORD|_DWORD|__int64|unsigned\s+__int64)\s*\)\s*",
        "",
        value,
    )
    return strip_outer_parentheses(value)


def _system_information_class_token_value(token: str) -> int | None:
    if re.fullmatch(_C_UNSIGNED_INTEGER_LITERAL_PATTERN, token):
        return _parse_c_integer_literal(token)
    return get_system_information_class_value(token)


def _system_information_class_name(value: int) -> str:
    name = get_system_information_class_name(value)
    if not name or name == "MaxSystemInfoClass":
        return ""
    return name


def _replace_process_information_class_subtract(match: re.Match[str]) -> str:
    value = _parse_c_integer_literal(match.group("value"))
    if value is None:
        return match.group(0)
    name = _process_information_class_name(value)
    if not name:
        return match.group(0)
    return "%s%s%s" % (match.group("lhs"), name, match.group("rhs"))


def _process_information_class_name(value: int) -> str:
    name = get_process_information_class_name(value)
    if not name or name == "MaxProcessInfoClass":
        return ""
    return name


def _rewrite_enum_switch_cases(
    text: str,
    dispatcher_names: set[str],
    enum_name_for_value: Callable[[int], str],
) -> str:
    lines = text.splitlines()
    result = []
    in_target_switch = False
    seen_open = False
    depth = 0
    dispatcher_pattern = "|".join(re.escape(name) for name in sorted(dispatcher_names))
    switch_pattern = re.compile(
        r"\bswitch\s*\(\s*(?:\(\s*[^()]+\s*\)\s*)*\b(?:%s)\b[^)]*\)" % dispatcher_pattern
    )
    case_pattern = re.compile(
        r"(?P<indent>\s*)case\s+(?P<value>0x[0-9A-Fa-f]+|\d+|'[^'\\]')(?P<suffix>\s*:.*)$"
    )

    for line in lines:
        if not in_target_switch and switch_pattern.search(line):
            in_target_switch = True
            seen_open = False
            depth = 0

        updated = line
        if in_target_switch:
            updated = case_pattern.sub(
                lambda match: _replace_enum_case_label(match, enum_name_for_value),
                updated,
            )
            stripped = updated.strip()
            opens = stripped.count("{")
            closes = stripped.count("}")
            if opens:
                depth += opens
                seen_open = True
            if closes:
                depth -= closes
                if seen_open and depth <= 0:
                    in_target_switch = False
                    seen_open = False
                    depth = 0
        result.append(updated)

    return "\n".join(result)


def _replace_enum_case_label(match: re.Match[str], enum_name_for_value: Callable[[int], str]) -> str:
    value = _parse_case_label_literal(match.group("value"))
    if value is None:
        return match.group(0)
    name = enum_name_for_value(value)
    if not name:
        return match.group(0)
    return "%scase %s%s" % (match.group("indent"), name, match.group("suffix"))


def _parse_case_label_literal(literal: str) -> int | None:
    token = (literal or "").strip()
    if token.startswith("'") and token.endswith("'") and len(token) == 3:
        return ord(token[1])
    return _parse_c_integer_literal(token)


def _parse_c_integer_literal(value_text: str) -> int | None:
    value = re.sub(r"%s$" % _C_INTEGER_SUFFIX_PATTERN, "", value_text.strip()).strip()
    try:
        return int(value, 0)
    except ValueError:
        return None
