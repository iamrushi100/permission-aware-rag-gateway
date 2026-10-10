"""Tests for the local CLI demonstration and its safe visible output."""

import io
import unittest
from contextlib import redirect_stdout

from authorization_boundary import Outcome
from demo import (
    main,
    run_authorized_scenario,
    run_denied_scenario,
    run_dependency_failure_scenario,
)


class DemoTests(unittest.TestCase):
    def test_authorized_scenario_invokes_model_once(self):
        run = run_authorized_scenario()

        self.assertIs(run.result.outcome, Outcome.ALLOWED)
        self.assertEqual(len(run.model.inputs), 1)
        self.assertEqual(run.dependencies.content_calls, ["authorized-doc"])

    def test_denied_scenario_does_not_load_content_or_invoke_model(self):
        run = run_denied_scenario()

        self.assertIs(run.result.outcome, Outcome.DENIED)
        self.assertEqual(run.dependencies.content_calls, [])
        self.assertEqual(run.model.inputs, [])

    def test_dependency_failure_loads_no_candidate_content_or_model_input(self):
        run = run_dependency_failure_scenario()

        self.assertIs(run.result.outcome, Outcome.DEPENDENCY_FAILURE)
        self.assertEqual(run.dependencies.document_calls, ["authorized-doc", "failure-doc"])
        self.assertEqual(run.dependencies.content_calls, [])
        self.assertEqual(run.model.inputs, [])
        self.assertNotIn("SIMULATED PRIVATE LOOKUP DETAIL", repr(run.result))
        self.assertNotIn("FICTIONAL", repr(run.result))

    def test_scenarios_use_fresh_dependencies_and_models(self):
        authorized = run_authorized_scenario()
        denied = run_denied_scenario()
        failed = run_dependency_failure_scenario()

        self.assertIsNot(authorized.dependencies, denied.dependencies)
        self.assertIsNot(authorized.dependencies, failed.dependencies)
        self.assertIsNot(denied.dependencies, failed.dependencies)
        self.assertIsNot(authorized.model, denied.model)
        self.assertIsNot(authorized.model, failed.model)
        self.assertIsNot(denied.model, failed.model)

    def test_main_prints_safe_scenario_summaries(self):
        output = io.StringIO()

        with redirect_stdout(output):
            exit_code = main()

        displayed = output.getvalue()
        self.assertEqual(exit_code, 0)
        self.assertIn("Authorized request: ALLOWED; model invoked: yes", displayed)
        self.assertIn("Denied request: DENIED; model invoked: no", displayed)
        self.assertIn(
            "Dependency failure: DEPENDENCY_FAILURE; model invoked: no", displayed
        )
        for secret in (
            "FICTIONAL AUTHORIZED DOCUMENT CONTENT",
            "FICTIONAL DENIED DOCUMENT CONTENT",
            "FICTIONAL FAILURE SCENARIO CONTENT",
            "demo-credential",
            "SIMULATED PRIVATE LOOKUP DETAIL",
        ):
            self.assertNotIn(secret, displayed)


if __name__ == "__main__":
    unittest.main()
