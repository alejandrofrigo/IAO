import unittest

from omega.control import STATES, TRANSITIONS, InvalidTransition, transition


class StateMachineTests(unittest.TestCase):
    def test_no_skipping_created_to_running(self) -> None:
        with self.assertRaises(InvalidTransition):
            transition("CREATED", "RUNNING")

    def test_happy_path(self) -> None:
        s = "CREATED"
        for n in ("AUTHENTICATED", "COMPILED", "POLICY_CHECKED", "AUTHORIZED", "RUNNING", "VERIFYING", "SUCCEEDED"):
            s = transition(s, n)

    def test_terminal_states_have_no_exits(self) -> None:
        for t in ("SUCCEEDED", "FAILED", "DENIED", "NEEDS_CLARIFICATION", "CANCELLED", "EXPIRED"):
            self.assertFalse(TRANSITIONS[t])

    def test_exhaustive_table(self) -> None:  # every pair not in the table is rejected
        for a in STATES:
            for b in STATES:
                if b in TRANSITIONS[a]:
                    self.assertEqual(transition(a, b), b)
                else:
                    with self.assertRaises(InvalidTransition):
                        transition(a, b)
