"""The command list in `--help` is data, so it can be checked like data."""

from __future__ import annotations

import unittest

from ghlab import cli


def _parser():
    return cli.build_parser()


def _subparsers(parser):
    for action in parser._actions:
        if action.__class__.__name__ == "_SubParsersAction":
            return action
    raise AssertionError("no subparsers")


class HelpTest(unittest.TestCase):
    def test_every_command_appears_in_exactly_one_group(self):
        sub = _subparsers(_parser())
        canonical = {p.prog.split()[-1] for p in sub.choices.values()}
        listed = [name for _title, group in cli._HELP_GROUPS for name in group]
        self.assertEqual(len(listed), len(set(listed)), "a command is listed twice")
        self.assertEqual(set(listed), canonical)

    def test_no_group_is_empty(self):
        for title, group in cli._HELP_GROUPS:
            with self.subTest(group=title):
                self.assertTrue(group)

    def test_the_listing_quotes_the_subparser_help(self):
        parser = _parser()
        helps = parser.command_help
        listing = parser.epilog
        for name in (n for _t, group in cli._HELP_GROUPS for n in group):
            want = helps.get(name)
            if not want:  # pragma: no cover - every command has help today
                continue
            with self.subTest(command=name):
                self.assertIn(want.split("(")[0].strip()[:24], listing)

    def test_the_listing_has_examples_and_the_json_hint(self):
        listing = _parser().epilog
        self.assertIn("examples:", listing)
        self.assertIn("--json", listing)
        self.assertIn("ghlab use", listing)

    def test_help_hides_the_flat_list_and_keeps_the_usage_line(self):
        text = _parser().format_help()
        self.assertIn("<command> ...", text)
        self.assertIn("commands by what they are for:", text)
        self.assertIn("questions (read-only)", text)
        self.assertLess(len(text.splitlines()), 140)


class ReachabilityTest(unittest.TestCase):
    def test_strings_has_a_command(self):
        args = _parser().parse_args(["strings", "a.exe", "-q", "crypt", "--refs"])
        self.assertEqual(args.binary, "a.exe")
        self.assertTrue(args.refs)
        self.assertTrue(callable(args.func))

    def test_the_underscore_spellings_also_work(self):
        for argv in (["set_type", "a.exe", "f", "int f(void)"], ["cross_xref", "needle"]):
            with self.subTest(argv=argv):
                self.assertTrue(callable(_parser().parse_args(argv).func))

    def test_both_spellings_reach_the_daemon_with_the_daemon_name(self):
        seen: list[str] = []
        original = cli._call

        def fake_call(_args, cmd, _params=None):
            seen.append(cmd)
            return 0

        cli._call = fake_call  # type: ignore[assignment]
        try:
            for argv in (["set_type", "a.exe", "f", "int f(void)"], ["cross_xref", "needle"]):
                ns = _parser().parse_args(argv)
                ns.func(ns)
        finally:
            cli._call = original  # type: ignore[assignment]
        self.assertEqual(seen, ["set_type", "cross_xref"])


class FilterFlagTest(unittest.TestCase):
    def test_functions_takes_q_like_strings_and_names(self):
        for flag in ("-q", "-m", "--match", "--query"):
            with self.subTest(flag=flag):
                args = _parser().parse_args(["functions", "a.exe", flag, "crypt"])
                self.assertEqual(args.match, "crypt")


class StatusUrlTest(unittest.TestCase):
    def test_status_probes_the_url_it_was_given(self):
        seen = {}

        class FakeClient:
            def __init__(self, url):
                seen["url"] = url
                self.url = url

            def call(self, _cmd):
                raise OSError("down")

        args = _parser().parse_args(["status", "--url", "http://127.0.0.1:9/"])
        restore = cli.Client
        cli.Client = FakeClient  # type: ignore[assignment]
        try:
            code = cli.cmd_status(args)
        finally:
            cli.Client = restore  # type: ignore[assignment]
        self.assertEqual(seen["url"], "http://127.0.0.1:9/")
        self.assertEqual(code, 1)

    def test_status_falls_back_to_host_and_port(self):
        seen = {}

        class FakeClient:
            def __init__(self, url):
                seen["url"] = url
                self.url = url

            def call(self, _cmd):
                raise OSError("down")

        args = _parser().parse_args(["status", "--url", "", "--host", "h", "--port", "9"])
        restore = cli.Client
        cli.Client = FakeClient  # type: ignore[assignment]
        try:
            cli.cmd_status(args)
        finally:
            cli.Client = restore  # type: ignore[assignment]
        self.assertEqual(seen["url"], "http://h:9/")


class FriendlyErrorTest(unittest.TestCase):
    def test_a_user_error_loses_the_class(self):
        self.assertEqual(cli._friendly("ValueError: unknown group 'dll'"), "unknown group 'dll'")
        self.assertEqual(cli._friendly("FileNotFoundError: pdb not found: x"), "pdb not found: x")
        self.assertEqual(cli._friendly("PermissionError: read-only"), "read-only")

    def test_keyerror_loses_its_quotes(self):
        self.assertEqual(cli._friendly('KeyError: "no function at 0x1"'), "no function at 0x1")

    def test_anything_unexpected_keeps_its_class(self):
        for message in (
            "RuntimeError: cannot save program for 'x'",
            "java.io.IOException: Unable to lock",
            "TypeError: No matching overloads found for",
            "no class prefix at all",
        ):
            with self.subTest(message=message):
                self.assertEqual(cli._friendly(message), message)

    def test_an_empty_remainder_falls_back_to_the_whole_message(self):
        self.assertEqual(cli._friendly("ValueError: "), "ValueError: ")


if __name__ == "__main__":
    unittest.main()
