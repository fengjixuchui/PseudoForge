from __future__ import annotations

import unittest

from ida_pseudoforge.core.capture import capture_from_pseudocode
from ida_pseudoforge.core.deterministic.context import build_rule_context
from ida_pseudoforge.core.plan_schema import LocalVariable


class RuleContextTests(unittest.TestCase):
    def test_rule_context_call_site_facts_include_arguments_and_spans(self) -> None:
        capture = capture_from_pseudocode(
            """
__int64 __fastcall RuleContextCallSample(void *inputBuffer)
{
  ProbeForRead(inputBuffer, sizeof("a,b"), MmGetSystemRoutineAddress(&name));
  BrokenCall(inputBuffer, 8;
  return 0;
}
"""
        )

        context = build_rule_context(capture)

        probe = next(item for item in context.call_sites if item.name == "ProbeForRead")
        self.assertIn("ProbeForRead", context.lines[probe.line_index])
        self.assertEqual(
            ["inputBuffer", 'sizeof("a,b")', "MmGetSystemRoutineAddress(&name)"],
            probe.arguments,
        )
        self.assertEqual(
            [capture.pseudocode[start:end] for start, end in probe.argument_spans],
            probe.arguments,
        )
        self.assertEqual(capture.pseudocode[probe.span[0]:probe.span[1]].split("(", 1)[0], "ProbeForRead")

        broken = next(item for item in context.call_sites if item.name == "BrokenCall")
        self.assertEqual([], broken.arguments)
        self.assertEqual([], broken.argument_spans)

    def test_rule_context_assignment_facts_include_rhs_details(self) -> None:
        capture = capture_from_pseudocode(
            """
__int64 __fastcall RuleContextAssignmentSample(void *inputBuffer)
{
  int status;
  int flags;
  int mixed;
  const wchar_t *wide;

  status = ProbeForRead(inputBuffer, sizeof("a123,b456"), 1);
  flags = status | 0x10;
  mixed = ProbeForRead(inputBuffer, 8, 1) + 1;
  wide = L"unused789";
  return status + flags + mixed;
}
"""
        )

        context = build_rule_context(capture)
        assignments = {item.target: item for item in context.assignments}

        status = assignments["status"]
        self.assertEqual("ProbeForRead(inputBuffer, sizeof(\"a123,b456\"), 1)", status.expression)
        self.assertEqual("ProbeForRead", status.rhs_call_name)
        self.assertEqual(["inputBuffer", 'sizeof("a123,b456")', "1"], status.rhs_call_arguments)
        self.assertIn("ProbeForRead", status.rhs_identifiers)
        self.assertIn("inputBuffer", status.rhs_identifiers)
        self.assertNotIn("a123", status.rhs_identifiers)
        self.assertNotIn("b456", status.rhs_identifiers)
        self.assertEqual(["1"], status.rhs_literals)

        flags = assignments["flags"]
        self.assertEqual("", flags.rhs_call_name)
        self.assertEqual([], flags.rhs_call_arguments)
        self.assertIn("status", flags.rhs_identifiers)
        self.assertEqual(["0x10"], flags.rhs_literals)

        mixed = assignments["mixed"]
        self.assertEqual("", mixed.rhs_call_name)
        self.assertEqual([], mixed.rhs_call_arguments)
        self.assertEqual(["8", "1", "1"], mixed.rhs_literals)

        wide = assignments["wide"]
        self.assertEqual([], wide.rhs_identifiers)
        self.assertEqual([], wide.rhs_literals)

    def test_rule_context_lvar_facts_include_type_and_identity_metadata(self) -> None:
        capture = capture_from_pseudocode(
            """
__int64 __fastcall RuleContextLvarSample(void *inputBuffer)
{
  int status;
  char *buffer;

  return 0;
}
"""
        )
        capture.lvars = [
            LocalVariable("inputBuffer", "void *", True, 0, "arg:0", "arg-id"),
            LocalVariable("status", "NTSTATUS", False, 1, "stack:-4", "status-id"),
            LocalVariable("scratch", "", False, 2, "stack:-8", "scratch-id"),
        ]

        context = build_rule_context(capture)
        lvars = {item.name: item for item in context.lvar_facts}

        self.assertEqual({"inputBuffer", "status", "scratch"}, context.lvar_names)
        self.assertEqual({"inputBuffer"}, context.arg_names)
        self.assertEqual({"inputBuffer": "void *", "status": "NTSTATUS"}, context.lvar_types)
        self.assertEqual("void *", lvars["inputBuffer"].type)
        self.assertTrue(lvars["inputBuffer"].is_arg)
        self.assertEqual(0, lvars["inputBuffer"].index)
        self.assertEqual("arg:0", lvars["inputBuffer"].location)
        self.assertEqual("arg-id", lvars["inputBuffer"].identity)
        self.assertEqual("NTSTATUS", lvars["status"].type)
        self.assertFalse(lvars["status"].is_arg)
        self.assertEqual("scratch-id", lvars["scratch"].identity)

    def test_rule_context_profile_function_facts_include_metadata(self) -> None:
        capture = capture_from_pseudocode(
            """
__int64 __fastcall RuleContextProfileSample(void *inputBuffer)
{
  ProbeForRead(inputBuffer, 8, 1);
  UnknownHelper(inputBuffer);
  return 0;
}
"""
        )

        def lookup(name: str):
            if name == "ProbeForRead":
                return {
                    "header": "wdm.h",
                    "return_type": "VOID",
                    "params": [
                        {"name": "Address", "type": "PVOID", "kind": "value"},
                        {"name": "Length", "type": "SIZE_T", "kind": "size"},
                        {"name": "Alignment", "type": "ULONG", "kind": "flags", "enum": "PROBE_FLAGS"},
                    ],
                    "profile_alias_of": "ProbeForRead",
                    "profile_alias_kind": "explicit",
                }
            if name == "UnknownHelper":
                raise RuntimeError("profile lookup failed")
            return {}

        context = build_rule_context(capture, profile_function_lookup=lookup)

        self.assertEqual(["ProbeForRead"], list(context.profile_functions))
        probe = context.profile_functions["ProbeForRead"]
        self.assertEqual("wdm.h", probe.header)
        self.assertEqual("VOID", probe.return_type)
        self.assertEqual(3, probe.param_count)
        self.assertEqual(["Address", "Length", "Alignment"], probe.parameter_names)
        self.assertEqual(["PVOID", "SIZE_T", "ULONG"], probe.parameter_types)
        self.assertEqual(["value", "size", "flags"], probe.parameter_kinds)
        self.assertEqual(["", "", "PROBE_FLAGS"], probe.parameter_enums)
        self.assertEqual("ProbeForRead", probe.alias_of)
        self.assertEqual("explicit", probe.alias_kind)


if __name__ == "__main__":
    unittest.main()
