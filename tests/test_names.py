"""Names recovered from assertion strings.

The matcher is pure Python, so it is tested without a JVM: these are exactly the
strings that appear in a stripped C++ binary, including the ones that must *not*
be mistaken for a name.
"""

import unittest

from ghlab.session import _assert_name


class AssertNameTest(unittest.TestCase):
    def test_plain_assertion(self):
        self.assertEqual(
            _assert_name("TableLineUpdater::update : failure"), "TableLineUpdater::update"
        )

    def test_takes_the_first_name_when_the_text_chats(self):
        got = _assert_name("Solver::solve: invalid state, Solver::reset failed")
        self.assertEqual(got, "Solver::solve")

    def test_case_is_irrelevant_for_the_failure_word(self):
        self.assertEqual(
            _assert_name("PartitionModifier::split FAILED"), "PartitionModifier::split"
        )

    def test_template_arguments_stay_in_the_name(self):
        got = _assert_name("TypoMemObj<TypoLayoutPage<DocDataTraits>>::ctor : assertion")
        self.assertEqual(got, "TypoMemObj<TypoLayoutPage<DocDataTraits>>::ctor")

    def test_rejects_strings_without_a_failure_word(self):
        self.assertIsNone(_assert_name("Software\\Microsoft\\Notepad"))
        self.assertIsNone(_assert_name("http://example.com/a::b"))

    def test_rejects_strings_without_a_qualified_name(self):
        self.assertIsNone(_assert_name("assertion failed"))
        self.assertIsNone(_assert_name("something : failure"))

    def test_rejects_short_runs(self):
        self.assertIsNone(_assert_name("A::b"))


if __name__ == "__main__":
    unittest.main()
