from __future__ import annotations

import unittest

from ida_pseudoforge.core.render_dispatcher import (
    replace_char_literal_cases,
    rewrite_process_information_class_literals,
    rewrite_system_information_class_literals,
)


class RenderDispatcherTests(unittest.TestCase):
    def test_system_information_class_literals_and_delta_chain(self) -> None:
        rendered = rewrite_system_information_class_literals(
            "  if ( infoClass == 9 )\n"
            "    return 0;\n"
            "  v115 = infoClass - 235;\n"
            "  if ( v115 == 8 )\n"
            "    return 1;\n"
        )

        self.assertIn("infoClass == SystemFlagsInformation", rendered)
        self.assertIn("v115 = infoClass - SystemHypervisorBootPagesInformation;", rendered)
        self.assertIn(
            "v115 == SystemTrustedAppsRuntimeInformation - SystemHypervisorBootPagesInformation",
            rendered,
        )

    def test_process_information_class_cases_and_comparisons(self) -> None:
        rendered = rewrite_process_information_class_literals(
            "  switch ( (int)processInformationClass )\n"
            "  {\n"
            "    case 113:\n"
            "      return 0;\n"
            "  }\n"
            "  if ( (_DWORD)processInformationClass == 96 )\n"
            "    return 1;\n"
        )

        self.assertIn("case ProcessSlistRollbackInformation:", rendered)
        self.assertIn("processInformationClass == ProcessEnableLogging", rendered)

    def test_char_literal_case_labels_become_numeric_cases(self) -> None:
        rendered = replace_char_literal_cases(
            "  switch ( code )\n"
            "  {\n"
            "    case 'K':\n"
            "      return 1;\n"
            "  }\n"
        )

        self.assertIn("case 75:", rendered)
        self.assertNotIn("case 'K':", rendered)


if __name__ == "__main__":
    unittest.main()
