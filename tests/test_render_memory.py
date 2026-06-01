from __future__ import annotations

import unittest

from ida_pseudoforge.core.capture import capture_from_pseudocode
from ida_pseudoforge.core.lvar_analysis import build_clean_plan
from ida_pseudoforge.core.render import render_cleaned_pseudocode


MEMORY_MANAGER_PROBE_SAMPLE = r"""
void sub_1400047F0()
{
  BOOLEAN IsAddressValid; // al
  __int64 v1; // rax
  PVOID VirtualAddress; // [rsp+30h] [rbp-118h]
  PVOID VirtualAddressa; // [rsp+30h] [rbp-118h]
  PMDL MemoryDescriptorList; // [rsp+38h] [rbp-110h]
  PVOID BaseAddress; // [rsp+40h] [rbp-108h]
  __int64 v6; // [rsp+48h] [rbp-100h] BYREF
  PVOID SystemRoutineAddress; // [rsp+50h] [rbp-F8h]
  PHYSICAL_ADDRESS PhysicalAddress; // [rsp+58h] [rbp-F0h]
  PVOID v10; // [rsp+68h] [rbp-E0h]
  PHYSICAL_ADDRESS BoundaryAddressMultiple; // [rsp+70h] [rbp-D8h]
  PHYSICAL_ADDRESS HighestAcceptableAddress; // [rsp+78h] [rbp-D0h]
  PHYSICAL_ADDRESS LowestAcceptableAddress; // [rsp+80h] [rbp-C8h]
  struct _UNICODE_STRING DestinationString; // [rsp+88h] [rbp-C0h] BYREF
  _BYTE v15[64]; // [rsp+A0h] [rbp-A8h] BYREF
  _BYTE v16[64]; // [rsp+E0h] [rbp-68h] BYREF

  v6 = 0LL;
  memset(v15, 0, sizeof(v15));
  memset(v16, 0, sizeof(v16));
  RtlInitUnicodeString(&DestinationString, L"ZwClose");
  SystemRoutineAddress = MmGetSystemRoutineAddress(&DestinationString);
  sub_140003DB0(SystemRoutineAddress);
  VirtualAddress = (PVOID)ExAllocatePool2(0x40uLL, 64LL, 0x744B4650u);
  sub_140003DB0(VirtualAddress);
  if ( VirtualAddress )
  {
    qmemcpy(VirtualAddress, v15, 0x40uLL);
    IsAddressValid = MmIsAddressValid(VirtualAddress);
    sub_140003DB0(IsAddressValid);
    PhysicalAddress = MmGetPhysicalAddress(VirtualAddress);
    sub_140003DB0(PhysicalAddress.QuadPart);
    v10 = VirtualAddress;
    MmCopyMemory(v16, VirtualAddress, 64LL, 2LL, &v6);
    sub_140003DB0(v6);
    MemoryDescriptorList = IoAllocateMdl(VirtualAddress, 0x40u, 0, 0, 0LL);
    sub_140003DB0(MemoryDescriptorList);
    if ( MemoryDescriptorList )
    {
      MmBuildMdlForNonPagedPool(MemoryDescriptorList);
      v1 = sub_140004AB0(MemoryDescriptorList, 16LL);
      sub_140003DB0(v1);
      sub_140003DB0(MemoryDescriptorList->ByteCount);
      sub_140003DB0(MemoryDescriptorList->ByteOffset);
      IoFreeMdl(MemoryDescriptorList);
    }
    ExFreePoolWithTag(VirtualAddress, 0x744B4650u);
  }
  BaseAddress = MmAllocateNonCachedMemory(0x40uLL);
  sub_140003DB0(BaseAddress);
  if ( BaseAddress )
  {
    MmFreeNonCachedMemory(BaseAddress, 0x40uLL);
  }
  LowestAcceptableAddress.QuadPart = 0LL;
  HighestAcceptableAddress.QuadPart = 0x7FFFFFFFFFFFFFFFLL;
  BoundaryAddressMultiple.QuadPart = 0LL;
  VirtualAddressa = MmAllocateContiguousMemorySpecifyCache(
                      0x1000uLL,
                      0LL,
                      (PHYSICAL_ADDRESS)0x7FFFFFFFFFFFFFFFLL,
                      0LL,
                      MmCached);
  sub_140003DB0(VirtualAddressa);
  if ( VirtualAddressa )
  {
    MmFreeContiguousMemory(VirtualAddressa);
  }
}
"""


MEMORY_MANAGER_REUSED_PROBE_SINK_SAMPLE = r"""
void sub_1400030F4()
{
  _OWORD *Pool2; // rax
  void *v1; // rsi
  __int128 v2; // xmm1
  __int128 v3; // xmm0
  __int128 v4; // xmm1
  struct _MDL *Mdl; // rax
  struct _MDL *v6; // rdi
  PVOID MappedSystemVa; // rax
  PVOID NonCachedMemory; // rax
  PVOID ContiguousMemorySpecifyCache; // rax
  ULONG BugCheckOnFailure[2]; // [rsp+38h] [rbp-59h] BYREF
  struct _UNICODE_STRING DestinationString; // [rsp+40h] [rbp-51h] BYREF
  _OWORD v12[4]; // [rsp+58h] [rbp-39h] BYREF
  _BYTE v13[64]; // [rsp+98h] [rbp+7h] BYREF

  *(_QWORD *)BugCheckOnFailure = 0LL;
  sub_1400045C0(v12, 0LL, 64LL);
  sub_1400045C0(v13, 0LL, 64LL);
  RtlInitUnicodeString(&DestinationString, L"ZwClose");
  qword_1400060A0 = (__int64)MmGetSystemRoutineAddress(&DestinationString);
  Pool2 = (_OWORD *)ExAllocatePool2(0x40uLL, 64LL, 0x744B4650u);
  qword_1400060A0 = (__int64)Pool2;
  v1 = Pool2;
  if ( Pool2 )
  {
    v2 = v12[1];
    *Pool2 = v12[0];
    v3 = v12[2];
    Pool2[1] = v2;
    v4 = v12[3];
    Pool2[2] = v3;
    Pool2[3] = v4;
    qword_1400060A0 = MmIsAddressValid(Pool2);
    qword_1400060A0 = MmGetPhysicalAddress(v1).QuadPart;
    MmCopyMemory(v13, v1, 64LL, 2LL, BugCheckOnFailure);
    qword_1400060A0 = *(_QWORD *)BugCheckOnFailure;
    Mdl = IoAllocateMdl(v1, 0x40u, 0, 0, 0LL);
    qword_1400060A0 = (__int64)Mdl;
    v6 = Mdl;
    if ( Mdl )
    {
      MmBuildMdlForNonPagedPool(Mdl);
      if ( (v6->MdlFlags & 5) != 0 )
      {
        MappedSystemVa = v6->MappedSystemVa;
      }
      else
      {
        MappedSystemVa = MmMapLockedPagesSpecifyCache(v6, 0, MmCached, 0LL, 0, 0x10u);
      }
      qword_1400060A0 = (__int64)MappedSystemVa;
      qword_1400060A0 = v6->ByteCount;
      IoFreeMdl(v6);
    }
    ExFreePoolWithTag(v1, 0x744B4650u);
  }
  NonCachedMemory = MmAllocateNonCachedMemory(0x40uLL);
  qword_1400060A0 = (__int64)NonCachedMemory;
  if ( NonCachedMemory )
  {
    MmFreeNonCachedMemory(NonCachedMemory, 0x40uLL);
  }
  ContiguousMemorySpecifyCache = MmAllocateContiguousMemorySpecifyCache(
                                   0x1000uLL,
                                   0LL,
                                   (PHYSICAL_ADDRESS)0x7FFFFFFFFFFFFFFFLL,
                                   0LL,
                                   MmCached);
  qword_1400060A0 = (__int64)ContiguousMemorySpecifyCache;
  if ( ContiguousMemorySpecifyCache )
  {
    MmFreeContiguousMemory(ContiguousMemorySpecifyCache);
  }
}
"""


class RenderMemoryTests(unittest.TestCase):
    def test_memory_manager_probe_gets_mm_semantics(self):
        capture = capture_from_pseudocode(MEMORY_MANAGER_PROBE_SAMPLE)
        plan = build_clean_plan(capture)
        rename_map = {item.old: item.new for item in plan.renames if item.apply}
        rendered = render_cleaned_pseudocode(capture, plan)

        self.assertEqual(rename_map["DestinationString"], "systemRoutineName")
        self.assertEqual(rename_map["SystemRoutineAddress"], "systemRoutineAddress")
        self.assertEqual(rename_map["VirtualAddress"], "poolBuffer")
        self.assertEqual(rename_map["VirtualAddressa"], "contiguousMemory")
        self.assertEqual(rename_map["MemoryDescriptorList"], "mdl")
        self.assertEqual(rename_map["BaseAddress"], "nonCachedMemory")
        self.assertEqual(rename_map["v6"], "bytesCopied")
        self.assertEqual(rename_map["v15"], "sourceBuffer")
        self.assertEqual(rename_map["v16"], "copyBuffer")
        self.assertEqual(rename_map["IsAddressValid"], "isAddressValid")
        self.assertEqual(rename_map["PhysicalAddress"], "physicalAddress")
        self.assertEqual(rename_map["LowestAcceptableAddress"], "lowestAcceptableAddress")
        self.assertEqual(rename_map["HighestAcceptableAddress"], "highestAcceptableAddress")
        self.assertEqual(rename_map["BoundaryAddressMultiple"], "boundaryAddressMultiple")
        self.assertIn("memory_manager_probe", rendered)
        self.assertIn("RtlInitUnicodeString(&systemRoutineName, L\"ZwClose\");", rendered)
        self.assertIn("systemRoutineAddress = MmGetSystemRoutineAddress(&systemRoutineName);", rendered)
        self.assertIn("poolBuffer = (PVOID)ExAllocatePool2(POOL_FLAG_NON_PAGED, 64LL, POOL_TAG('P', 'F', 'K', 't'));", rendered)
        self.assertIn("qmemcpy(poolBuffer, sourceBuffer, 0x40uLL);", rendered)
        self.assertIn("isAddressValid = MmIsAddressValid(poolBuffer);", rendered)
        self.assertIn("physicalAddress = MmGetPhysicalAddress(poolBuffer);", rendered)
        self.assertIn("MmCopyMemory(copyBuffer, poolBuffer, 64LL, MM_COPY_MEMORY_VIRTUAL, &bytesCopied);", rendered)
        self.assertIn("mdl = IoAllocateMdl(poolBuffer, 0x40u, FALSE, FALSE, 0LL);", rendered)
        self.assertIn("MmBuildMdlForNonPagedPool(mdl);", rendered)
        self.assertIn("IoFreeMdl(mdl);", rendered)
        self.assertIn("ExFreePoolWithTag(poolBuffer, POOL_TAG('P', 'F', 'K', 't'));", rendered)
        self.assertIn("nonCachedMemory = MmAllocateNonCachedMemory(0x40uLL);", rendered)
        self.assertIn("MmFreeNonCachedMemory(nonCachedMemory, 0x40uLL);", rendered)
        self.assertIn("contiguousMemory = MmAllocateContiguousMemorySpecifyCache", rendered)
        self.assertIn("MmFreeContiguousMemory(contiguousMemory);", rendered)
        self.assertNotIn("MmCopyMemory(copyBuffer, poolBuffer, 64LL, 2LL", rendered)
        self.assertNotIn("VirtualAddress", rendered.rsplit("*/", 1)[-1])

        partial_sample = MEMORY_MANAGER_PROBE_SAMPLE.replace(
            "    MmCopyMemory(v16, VirtualAddress, 64LL, 2LL, &v6);\n",
            "",
        )
        partial_plan = build_clean_plan(capture_from_pseudocode(partial_sample))
        self.assertFalse(any(comment.get("kind") == "memory_manager_probe" for comment in partial_plan.comments))

    def test_memory_manager_probe_uses_neutral_name_for_reused_probe_sink(self):
        capture = capture_from_pseudocode(MEMORY_MANAGER_REUSED_PROBE_SINK_SAMPLE)
        plan = build_clean_plan(capture)
        rename_map = {item.old: item.new for item in plan.renames if item.apply}
        rendered = render_cleaned_pseudocode(capture, plan)

        self.assertEqual(rename_map["qword_1400060A0"], "probeSinkValue")
        self.assertEqual(rename_map["BugCheckOnFailure"], "bytesCopied")
        self.assertEqual(rename_map["DestinationString"], "systemRoutineName")
        self.assertEqual(rename_map["Pool2"], "poolBuffer")
        self.assertEqual(rename_map["Mdl"], "mdl")
        self.assertEqual(rename_map["MappedSystemVa"], "mappedSystemVa")
        self.assertEqual(rename_map["v12"], "sourceBuffer")
        self.assertNotEqual(rename_map["qword_1400060A0"], "systemRoutineAddress")
        self.assertIn("SIZE_T bytesCopied; // [rsp+38h] [rbp-59h] BYREF", rendered)
        self.assertIn("bytesCopied = 0LL;", rendered)
        self.assertIn("sub_1400045C0(sourceBuffer, 0LL, 64LL);", rendered)
        self.assertIn("sub_1400045C0(copyBuffer, 0LL, 64LL);", rendered)
        self.assertIn("(void)MmGetSystemRoutineAddress(&systemRoutineName);", rendered)
        self.assertIn("qmemcpy(poolBuffer, sourceBuffer, sizeof(sourceBuffer));", rendered)
        self.assertIn("(void)MmIsAddressValid(poolBuffer);", rendered)
        self.assertIn("(void)MmGetPhysicalAddress(poolBuffer);", rendered)
        self.assertIn("MmCopyMemory(copyBuffer, poolBuffer, 64LL, MM_COPY_MEMORY_VIRTUAL, &bytesCopied);", rendered)
        self.assertIn("mdl = IoAllocateMdl(poolBuffer, 0x40u, FALSE, FALSE, 0LL);", rendered)
        self.assertIn("if ( (mdl->MdlFlags & 5) == 0 )", rendered)
        self.assertIn("(void)MmMapLockedPagesSpecifyCache(mdl, 0, MmCached, 0LL, 0, 0x10u);", rendered)
        self.assertIn("IoFreeMdl(mdl);", rendered)
        self.assertNotIn("systemRoutineAddress = (__int64)MmGetSystemRoutineAddress", rendered)
        self.assertNotIn("probeSinkValue", rendered.rsplit("*/", 1)[-1])
        self.assertNotIn("void *v1;", rendered)
        self.assertNotIn("struct _MDL *v6;", rendered)
        self.assertNotIn("PVOID MappedSystemVa;", rendered)
        self.assertNotIn("PVOID mappedSystemVa;", rendered)
        self.assertNotIn("mappedSystemVa", rendered.rsplit("*/", 1)[-1])
        self.assertNotIn("mdl->MappedSystemVa", rendered.rsplit("*/", 1)[-1])
        self.assertNotIn("__int128 v2;", rendered)
        self.assertNotIn("__int128 v3;", rendered)
        self.assertNotIn("__int128 v4;", rendered)
        self.assertNotIn("poolBuffer[1]", rendered)
        self.assertNotIn("v2 = sourceBuffer", rendered)
        self.assertNotIn("v1", rendered.rsplit("*/", 1)[-1])
        self.assertNotIn("v6", rendered.rsplit("*/", 1)[-1])
        self.assertNotIn("BugCheckOnFailure", rendered.rsplit("*/", 1)[-1])


if __name__ == "__main__":
    unittest.main()
