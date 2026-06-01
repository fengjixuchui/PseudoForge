from __future__ import annotations

import json
import unittest

from ida_pseudoforge.core.capture import capture_from_pseudocode
from ida_pseudoforge.core.lvar_analysis import build_clean_plan
from ida_pseudoforge.core.plan_schema import LocalVariable
from ida_pseudoforge.core.render import render_cleaned_pseudocode
from ida_pseudoforge.ida.decompiler import merge_lvars_from_text_and_cfunc


MEMBER_RENAME_SAMPLE = r"""
__int64 __fastcall MemberRenameSample(int a1)
{
  KPROCESSOR_MODE PreviousMode;
  _KPROCESS *Process;
  ULONG ActiveProcessorCount;
  ULONG updated;

  PreviousMode = KeGetCurrentThread()->PreviousMode;
  Process = KeGetCurrentThread()->ApcState.Process;
  ActiveProcessorCount = KeQueryActiveProcessorCountEx(0xFFFFu);
  updated = 0;
  return updated + ActiveProcessorCount;
}
"""


POOL_ALLOCATION_SAMPLE = r"""
__int64 __fastcall PoolAllocationSample()
{
  void *Pool2;

  Pool2 = (void *)ExAllocatePool2(0x101uLL, 64, 0x50535845u);
  if ( Pool2 )
  {
    return 1;
  }
  return 0;
}
"""


CPU_SET_MASK_SAMPLE = r"""
__int64 __fastcall NtSetSystemInformation(char *a1, __m128i *a2, __int64 a3)
{
  __m128i *v4;
  int v5;
  KPROCESSOR_MODE PreviousMode;
  ULONG updated;
  unsigned int v110;
  unsigned __int64 v111;
  unsigned int v98;
  int v99;
  _BYTE *v100;
  unsigned int v101;
  __int64 v102;
  _BYTE v151[256];
  _BYTE v152[256];
  _BYTE v153[256];

  v4 = a2;
  v5 = (int)a1;
  PreviousMode = KeGetCurrentThread()->PreviousMode;
  updated = 0;
  v110 = a3 - 8;
  v111 = a2->m128i_i64[0];
  memmove(v153, &a2->m128i_u64[1], v110);
  if ( v111 >= 2 )
    return 3221225485LL;
  v98 = v110 >> 3;
  v99 = v111;
  v100 = v153;
  memmove(v151, a2, (unsigned int)a3);
  KeModifySystemAllowedCpuSets((unsigned int)a3 >> 3, (_DWORD)v151, 0, 0);
  v101 = a3 - 8;
  v102 = a2->m128i_i64[0];
  memmove(v152, &a2->m128i_u64[1], v101);
  KeSetTagCpuSets(v101 >> 3, v152, v102);
  return (unsigned int)KeModifySystemAllowedCpuSets(v98, (_DWORD)v100, 0, v99);
}
"""


PREVIOUS_MODE_COPY_SAMPLE = r"""
__int64 __fastcall PreviousModeCopySample()
{
  KPROCESSOR_MODE PreviousMode;
  KPROCESSOR_MODE v119;

  PreviousMode = KeGetCurrentThread()->PreviousMode;
  v119 = PreviousMode;
  return v119;
}
"""


SAME_NAMED_FIELD_LOCAL_SAMPLE = r"""
__int64 __fastcall SameNamedFieldLocalSample(struct _GENERIC_OBJECT *object)
{
  PVOID MappedSystemVa;
  PVOID mappedSystemVaCandidate;

  MappedSystemVa = object->MappedSystemVa;
  mappedSystemVaCandidate = MappedSystemVa;
  return (__int64)mappedSystemVaCandidate;
}
"""


SAME_NAMED_FIELD_CONFLICT_SAMPLE = r"""
__int64 __fastcall SameNamedFieldConflictSample(struct _GENERIC_OBJECT *object)
{
  PVOID MappedSystemVa;
  PVOID mappedSystemVa;

  MappedSystemVa = object->MappedSystemVa;
  mappedSystemVa = MappedSystemVa;
  return (__int64)mappedSystemVa;
}
"""


class RenameHeuristicTests(unittest.TestCase):
    def test_identifier_renames_do_not_touch_struct_members(self) -> None:
        class FakeProvider:
            def suggest_renames(self, capture):
                return json.dumps(
                    {
                        "renames": [
                            {
                                "old": "Process",
                                "new": "targetProcess",
                                "confidence": 0.95,
                                "reason": "local holds current process",
                            }
                        ]
                    }
                )

        capture = capture_from_pseudocode(MEMBER_RENAME_SAMPLE)
        plan = build_clean_plan(capture, rename_provider=FakeProvider())
        rendered = render_cleaned_pseudocode(capture, plan)

        self.assertIn("previousMode = KeGetCurrentThread()->PreviousMode;", rendered)
        self.assertIn("currentProcess = KeGetCurrentThread()->ApcState.Process;", rendered)
        self.assertIn("activeProcessorCount = KeQueryActiveProcessorCountEx(0xFFFFu);", rendered)
        self.assertNotIn("KeGetCurrentThread()->previousMode", rendered)
        self.assertNotIn("ApcState.targetProcess", rendered)
        self.assertNotIn("ULONG ActiveProcessorCount;", rendered)

    def test_pool_allocation_result_gets_stable_pattern_name(self) -> None:
        capture = capture_from_pseudocode(POOL_ALLOCATION_SAMPLE)
        plan = build_clean_plan(capture)
        rename_map = {item.old: item.new for item in plan.renames if item.apply}
        rendered = render_cleaned_pseudocode(capture, plan)

        self.assertEqual(rename_map["Pool2"], "allocatedBuffer")
        self.assertIn("void *allocatedBuffer;", rendered)
        self.assertIn("allocatedBuffer = (void *)ExAllocatePool2(", rendered)
        self.assertNotIn("void *Pool2;", rendered)
        self.assertNotIn("Pool2 = (void *)", rendered)

    def test_text_lvars_survive_cfunc_lvar_merge(self) -> None:
        sample = r"""
__int64 __fastcall TextLvarMergeSample()
{
  ULONG ActiveProcessorCount;
  void *Pool2;

  ActiveProcessorCount = KeQueryActiveProcessorCountEx(0xFFFFu);
  Pool2 = (void *)ExAllocatePool2(0x101uLL, 64, 0x50535845u);
  if ( Pool2 )
  {
    return ActiveProcessorCount;
  }
  return 0;
}
"""
        capture = capture_from_pseudocode(sample)
        capture.lvars = merge_lvars_from_text_and_cfunc(
            capture.lvars,
            [
                LocalVariable(name="v13", type="__int64 *", index=0),
                LocalVariable(name="v14", type="__int64", index=1),
            ],
        )
        plan = build_clean_plan(capture)
        rename_map = {item.old: item.new for item in plan.renames if item.apply}
        rendered = render_cleaned_pseudocode(capture, plan)

        self.assertEqual(rename_map["ActiveProcessorCount"], "activeProcessorCount")
        self.assertEqual(rename_map["Pool2"], "allocatedBuffer")
        self.assertIn("activeProcessorCount = KeQueryActiveProcessorCountEx(0xFFFFu);", rendered)
        self.assertIn("allocatedBuffer = (void *)ExAllocatePool2(", rendered)

    def test_cpu_set_mask_stack_buffer_pattern_beats_vague_llm_name(self) -> None:
        class FakeProvider:
            def suggest_renames(self, capture):
                return json.dumps(
                    {
                        "renames": [
                            {
                                "old": "v153",
                                "new": "localInputCopy",
                                "confidence": 0.95,
                                "reason": "local stack copy",
                            },
                        ]
                    }
                )

        capture = capture_from_pseudocode(CPU_SET_MASK_SAMPLE)
        plan = build_clean_plan(capture, rename_provider=FakeProvider())
        rename_map = {item.old: item.new for item in plan.renames if item.apply}
        rendered = render_cleaned_pseudocode(capture, plan)

        self.assertEqual(rename_map["v153"], "cpuSetMaskStackBuffer")
        self.assertEqual(rename_map["v151"], "cpuSetAllowedMaskStackBuffer")
        self.assertEqual(rename_map["v152"], "cpuSetTagMaskStackBuffer")
        self.assertEqual(rename_map["v101"], "cpuSetTagMaskBytes")
        self.assertEqual(rename_map["v111"], "cpuSetOperation")
        self.assertEqual(rename_map["v99"], "cpuSetOperation32")
        self.assertIn("_BYTE cpuSetMaskStackBuffer[256];", rendered)
        self.assertIn("_BYTE cpuSetAllowedMaskStackBuffer[256];", rendered)
        self.assertIn("_BYTE cpuSetTagMaskStackBuffer[256];", rendered)
        self.assertIn("memmove(cpuSetMaskStackBuffer, &systemInfo128->m128i_u64[1], cpuSetMaskBytes);", rendered)
        self.assertIn(
            "memmove(cpuSetAllowedMaskStackBuffer, systemInformation, (unsigned int)systemInformationLength);",
            rendered,
        )
        self.assertIn("memmove(cpuSetTagMaskStackBuffer, &systemInfo128->m128i_u64[1], cpuSetTagMaskBytes);", rendered)
        self.assertIn("if ( cpuSetOperation >= 2 )", rendered)
        self.assertIn("cpuSetOperation32 = cpuSetOperation;", rendered)
        self.assertIn("cpuSetMaskBuffer = cpuSetMaskStackBuffer;", rendered)
        self.assertNotIn("localInputCopy", rendered)

    def test_previous_mode_copy_pattern_beats_captured_llm_name(self) -> None:
        class FakeProvider:
            def suggest_renames(self, capture):
                return json.dumps(
                    {
                        "renames": [
                            {
                                "old": "v119",
                                "new": "capturedPreviousMode",
                                "confidence": 0.95,
                                "reason": "copy of previous mode",
                            }
                        ]
                    }
                )

        capture = capture_from_pseudocode(PREVIOUS_MODE_COPY_SAMPLE)
        plan = build_clean_plan(capture, rename_provider=FakeProvider())
        rename_map = {item.old: item.new for item in plan.renames if item.apply}
        rendered = render_cleaned_pseudocode(capture, plan)

        self.assertEqual(rename_map["v119"], "savedPreviousMode")
        self.assertIn("savedPreviousMode = previousMode;", rendered)
        self.assertNotIn("capturedPreviousMode", rendered)

    def test_same_named_field_local_gets_lower_camel_name(self) -> None:
        capture = capture_from_pseudocode(SAME_NAMED_FIELD_LOCAL_SAMPLE)
        plan = build_clean_plan(capture)
        rename_map = {item.old: item.new for item in plan.renames if item.apply}
        rendered = render_cleaned_pseudocode(capture, plan)

        self.assertEqual(rename_map["MappedSystemVa"], "mappedSystemVa")
        self.assertIn("PVOID mappedSystemVa;", rendered)
        self.assertIn("mappedSystemVa = object->MappedSystemVa;", rendered)
        self.assertIn("return (__int64)mappedSystemVa;", rendered)
        self.assertNotIn("mappedSystemVaCandidate", rendered)
        self.assertNotIn("object->mappedSystemVa", rendered)

    def test_same_named_field_local_skips_existing_target_name(self) -> None:
        capture = capture_from_pseudocode(SAME_NAMED_FIELD_CONFLICT_SAMPLE)
        plan = build_clean_plan(capture)
        rename_map = {item.old: item.new for item in plan.renames if item.apply}
        rendered = render_cleaned_pseudocode(capture, plan)

        self.assertNotIn("MappedSystemVa", rename_map)
        self.assertIn("PVOID MappedSystemVa;", rendered)
        self.assertIn("MappedSystemVa = object->MappedSystemVa;", rendered)

    def test_same_named_field_local_yields_to_stronger_suggestion(self) -> None:
        class FakeProvider:
            def suggest_renames(self, capture):
                return json.dumps(
                    {
                        "renames": [
                            {"old": "MappedSystemVa", "new": "mappedAddress", "confidence": 0.90},
                        ]
                    }
                )

        capture = capture_from_pseudocode(SAME_NAMED_FIELD_LOCAL_SAMPLE)
        plan = build_clean_plan(capture, rename_provider=FakeProvider())
        rename_map = {item.old: item.new for item in plan.renames if item.apply}
        rendered = render_cleaned_pseudocode(capture, plan)

        self.assertEqual(rename_map["MappedSystemVa"], "mappedAddress")
        self.assertIn("mappedAddress = object->MappedSystemVa;", rendered)
        self.assertNotIn("object->mappedAddress", rendered)


if __name__ == "__main__":
    unittest.main()
