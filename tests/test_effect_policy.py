import unittest

from omega.effect_policy import authorize_effect


class EffectPolicyTests(unittest.TestCase):
    def test_read_only_is_allowed_only_when_policy_grants_it(self):
        self.assertTrue(authorize_effect("READ_ONLY").allowed)
        self.assertFalse(authorize_effect("READ_ONLY", approved_effects=set()).allowed)

    def test_every_non_read_only_effect_is_denied_without_request_bound_approval(self):
        for effect in ("REVERSIBLE", "EXTERNAL", "IRREVERSIBLE", "WRITE", "DESTRUCTIVE"):
            with self.subTest(effect=effect):
                self.assertFalse(authorize_effect(effect).allowed)

    def test_non_read_only_effect_requires_both_explicit_grant_and_binding(self):
        self.assertFalse(authorize_effect(
            "REVERSIBLE", approved_effects={"REVERSIBLE"}
        ).allowed)
        self.assertFalse(authorize_effect(
            "REVERSIBLE", approval_bound_to_request=True
        ).allowed)
        self.assertTrue(authorize_effect(
            "REVERSIBLE",
            approved_effects={"REVERSIBLE"},
            approval_bound_to_request=True,
        ).allowed)

    def test_unknown_effect_class_fails_closed(self):
        decision = authorize_effect("UNRESTRICTED", approval_bound_to_request=True)
        self.assertFalse(decision.allowed)
        self.assertEqual(decision.reason, "UNKNOWN_EFFECT_CLASS")


if __name__ == "__main__":
    unittest.main()
