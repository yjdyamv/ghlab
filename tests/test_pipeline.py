"""Script pipelines: parsing, variables, redirects, failure policy. No daemon needed."""

import io
import tempfile
import unittest
from pathlib import Path

from ghlab import pipeline


class ParseTest(unittest.TestCase):
    def test_comments_blank_lines_and_quotes(self):
        text = """
        # triage
        digest a.exe --top 4

        decompile a.exe -t entry -n 20
        """
        steps = pipeline.parse_script(text)
        self.assertEqual([s.argv[0] for s in steps], ["digest", "decompile"])
        self.assertEqual(steps[0].lineno, 3)
        self.assertEqual(steps[1].lineno, 5)

        quoted = pipeline.parse_script("""comment a.exe --text 'two words'""")
        self.assertEqual(quoted[0].argv[-1], "two words")

    def test_variables_expand_from_set(self):
        steps = pipeline.parse_script("digest $BIN --top ${N}", {"BIN": "a.exe", "N": "3"})
        self.assertEqual(steps[0].argv, ["digest", "a.exe", "--top", "3"])

    def test_undefined_variable_is_reported_with_context(self):
        with self.assertRaises(pipeline.PipelineError) as ctx:
            pipeline.parse_script("digest $MISSING")
        self.assertIn("$MISSING", str(ctx.exception))

    def test_redirect_is_split_off_and_not_passed_to_the_command(self):
        step = pipeline.parse_script("report a.exe > out/a.md")[0]
        self.assertEqual(step.argv, ["report", "a.exe"])
        self.assertEqual(step.out, "out/a.md")
        self.assertFalse(step.append)

        append = pipeline.parse_script("notes a.exe >> log.txt")[0]
        self.assertTrue(append.append)

    def test_redirect_without_target_is_an_error(self):
        with self.assertRaises(pipeline.PipelineError):
            pipeline.parse_script("report a.exe >")
        with self.assertRaises(pipeline.PipelineError):
            pipeline.parse_script("report a.exe > a.md extra")


class RunTest(unittest.TestCase):
    def test_steps_run_in_order_and_report_timings(self):
        seen = []

        def execute(argv):
            seen.append(argv)
            return 0

        steps = pipeline.parse_script("ping\nbinaries")
        summary = pipeline.run_steps(steps, execute=execute, progress=io.StringIO())
        self.assertEqual(seen, [["ping"], ["binaries"]])
        self.assertEqual(summary["ran"], 2)
        self.assertEqual(summary["failed"], 0)
        self.assertTrue(all("ms" in s for s in summary["steps"]))

    def test_failure_stops_unless_keep_going(self):
        ran = []

        def execute(argv):
            ran.append(argv[0])
            return 1 if argv[0] == "bad" else 0

        steps = pipeline.parse_script("ping\nbad\ntrailing")
        summary = pipeline.run_steps(steps, execute=execute, progress=io.StringIO())
        self.assertEqual(ran, ["ping", "bad"])
        self.assertEqual(summary["failed"], 1)
        self.assertEqual(summary["steps"][-1]["error"], "exit 1")

        ran.clear()
        summary = pipeline.run_steps(steps, execute=execute, keep_going=True, progress=io.StringIO())
        self.assertEqual(ran, ["ping", "bad", "trailing"])
        self.assertEqual(summary["ran"], 3)

    def test_exception_in_a_step_is_captured_not_raised(self):
        def execute(argv):
            raise RuntimeError("boom")

        summary = pipeline.run_steps(
            pipeline.parse_script("ping"), execute=execute, progress=io.StringIO()
        )
        self.assertIn("boom", summary["steps"][0]["error"])

    def test_dry_run_executes_nothing(self):
        def execute(argv):  # pragma: no cover - must not run
            raise AssertionError("executed")

        summary = pipeline.run_steps(
            pipeline.parse_script("ping\ndigest a.exe"), execute=execute, dry_run=True
        )
        self.assertEqual([s["status"] for s in summary["steps"]], ["skipped", "skipped"])

    def test_redirect_writes_the_step_output_to_a_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            target = Path(tmp) / "nested" / "out.md"

            def execute(argv):
                print("# report body")
                return 0

            steps = pipeline.parse_script(f"report a.exe > {target}")
            pipeline.run_steps(steps, execute=execute, progress=io.StringIO())
            self.assertEqual(target.read_text(encoding="utf-8"), "# report body\n")

    def test_run_file_round_trip(self):
        with tempfile.TemporaryDirectory() as tmp:
            script = Path(tmp) / "job.gh"
            script.write_text("# two steps\ndigest $BIN\nping\n", encoding="utf-8")
            seen = []
            summary = pipeline.run_file(
                script, {"BIN": "a.exe"}, execute=lambda argv: seen.append(argv) or 0
            )
            self.assertEqual(seen, [["digest", "a.exe"], ["ping"]])
            self.assertEqual(summary["script"], str(script))


if __name__ == "__main__":
    unittest.main()
