import unittest

from omega.policy import authorize


class PolicyTests(unittest.TestCase):
    def test_denies_unauthenticated_request(self) -> None:
        r = authorize("knowledge.search", authenticated=False, approved_capabilities={"knowledge.search"})
        self.assertFalse(r.allowed)
        self.assertEqual(r.reason, "AUTHENTICATION_REQUIRED")

    def test_denies_ungranted_capability(self) -> None:
        r = authorize("shell.execute", authenticated=True, approved_capabilities={"knowledge.search"})
        self.assertFalse(r.allowed)
        self.assertEqual(r.reason, "CAPABILITY_NOT_GRANTED")

    def test_allows_granted_capability(self) -> None:
        r = authorize("knowledge.search", authenticated=True, approved_capabilities={"knowledge.search"})
        self.assertTrue(r.allowed)

    def test_default_deny_with_empty_grants(self) -> None:
        r = authorize("anything", authenticated=True, approved_capabilities=set())
        self.assertFalse(r.allowed)
