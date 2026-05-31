from __future__ import annotations

import os
import unittest

from ida_pseudoforge.ida import ui_preview as ui_preview_module
from ida_pseudoforge.ida.ui_preview import (
    _MAX_HIGHLIGHT_LINES,
    _highlight_preview_lines,
    _syntax_highlight_lines,
)


class UiPreviewTests(unittest.TestCase):
    def test_preview_syntax_highlighting_marks_cpp_tokens(self) -> None:
        lines = [
            "if ( status == STATUS_SUCCESS )",
            "  return ExAllocatePool2(POOL_FLAG_PAGED, 0x28uLL, POOL_TAG('A', 'R', 'F', 'T'));",
            "  // comment",
            "name = \"http://example//not-comment\"; /* block */",
        ]

        def colorize(text: str, role: str) -> str:
            return "<%s>%s</%s>" % (role, text, role)

        rendered = "\n".join(_syntax_highlight_lines(lines, colorize))

        self.assertIn("<keyword>if</keyword>", rendered)
        self.assertIn("<constant>STATUS_SUCCESS</constant>", rendered)
        self.assertIn("<keyword>return</keyword>", rendered)
        self.assertIn("<function>ExAllocatePool2</function>", rendered)
        self.assertIn("<constant>POOL_FLAG_PAGED</constant>", rendered)
        self.assertIn("<number>0x28uLL</number>", rendered)
        self.assertIn("<char>'A'</char>", rendered)
        self.assertIn("<comment>// comment</comment>", rendered)
        self.assertIn("<string>\"http://example//not-comment\"</string>", rendered)
        self.assertIn("<comment>/* block */</comment>", rendered)

    def test_preview_syntax_highlighting_falls_back_for_large_views(self) -> None:
        lines = ["if ( status == STATUS_SUCCESS )"] * (_MAX_HIGHLIGHT_LINES + 1)

        self.assertEqual(_highlight_preview_lines(lines), lines)

    def test_preview_syntax_highlighting_can_be_disabled(self) -> None:
        old_value = os.environ.get("PSEUDOFORGE_DISABLE_PREVIEW_HIGHLIGHT")
        os.environ["PSEUDOFORGE_DISABLE_PREVIEW_HIGHLIGHT"] = "1"
        try:
            self.assertEqual(_highlight_preview_lines(["if ( STATUS_SUCCESS )"]), ["if ( STATUS_SUCCESS )"])
        finally:
            if old_value is None:
                os.environ.pop("PSEUDOFORGE_DISABLE_PREVIEW_HIGHLIGHT", None)
            else:
                os.environ["PSEUDOFORGE_DISABLE_PREVIEW_HIGHLIGHT"] = old_value

    def test_preview_syntax_highlighting_accepts_ida_color_tags(self) -> None:
        class FakeIdaLines:
            SCOLOR_KEYWORD = "\x01"
            SCOLOR_REGCMT = "\x02"
            SCOLOR_STRING = "\x03"
            SCOLOR_CHAR = "\x04"
            SCOLOR_DNUM = "\x05"
            SCOLOR_MACRO = "\x06"
            SCOLOR_CNAME = "\x07"
            SCOLOR_TYPE = "\x08"

            @staticmethod
            def COLSTR(text, color):
                return "<%s>%s</>" % (repr(color), text)

        old_ida_lines = ui_preview_module.ida_lines
        ui_preview_module.ida_lines = FakeIdaLines
        try:
            highlighted = ui_preview_module._highlight_preview_lines(["if ( STATUS_SUCCESS ) // comment"])
        finally:
            ui_preview_module.ida_lines = old_ida_lines

        self.assertIn("<'\\x01'>if</>", highlighted[0])
        self.assertIn("<'\\x06'>STATUS_SUCCESS</>", highlighted[0])
        self.assertIn("<'\\x02'>// comment</>", highlighted[0])


if __name__ == "__main__":
    unittest.main()
