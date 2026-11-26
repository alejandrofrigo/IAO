import unittest

from omega.federation_open_policy import evaluate_peer


class FederationOpenPolicyTests(unittest.TestCase):

    def test_unsecure_peer_gets_no_access(self):
        r = evaluate_peer(
            transport_secure=False,
            audit_available=True,
            identity_verified=True,
            challenge_verified=True,
            requested_capabilities=["knowledge.search"],
        )
        self.assertEqual(r["level"], 0)
        self.assertEqual(r["granted_capabilities"], [])

    def test_unknown_peer_can_make_provisional_contact(self):
        r = evaluate_peer(
            transport_secure=True,
            audit_available=True,
            identity_verified=False,
            challenge_verified=False,
        )
        self.assertEqual(r["level"], 2)
        self.assertEqual(r["status"], "LIMITED_COLLABORATION")
        self.assertFalse(r["manual_approval_required"])

    def test_missing_audit_blocks_collaboration_permissions(self):
        r = evaluate_peer(
            transport_secure=True,
            audit_available=False,
            identity_verified=True,
            challenge_verified=True,
            requested_capabilities=["knowledge.search"],
        )
        self.assertEqual(r["level"], 1)
        self.assertEqual(r["granted_capabilities"], [])

    def test_verified_peer_gets_automatic_scoped_permissions(self):
        r = evaluate_peer(
            transport_secure=True,
            audit_available=True,
            identity_verified=True,
            challenge_verified=True,
            requested_capabilities=[
                "knowledge.search",
                "capabilities.exchange",
                "artifact.test",
            ],
        )
        self.assertEqual(r["level"], 4)
        self.assertEqual(
            set(r["granted_capabilities"]),
            {"knowledge.search", "capabilities.exchange", "artifact.test"},
        )
        self.assertFalse(r["manual_approval_required"])

    def test_admin_and_secret_access_are_never_auto_granted(self):
        r = evaluate_peer(
            transport_secure=True,
            audit_available=True,
            identity_verified=True,
            challenge_verified=True,
            requested_capabilities=[
                "knowledge.search",
                "admin",
                "credentials.read",
                "host.shell",
            ],
        )
        self.assertEqual(r["granted_capabilities"], ["knowledge.search"])
        self.assertEqual(
            set(r["denied_capabilities"]),
            {"admin", "credentials.read", "host.shell"},
        )

    def test_unrecognized_capability_is_denied(self):
        r = evaluate_peer(
            transport_secure=True,
            audit_available=True,
            identity_verified=True,
            challenge_verified=True,
            requested_capabilities=["unknown.capability"],
        )
        self.assertEqual(r["granted_capabilities"], [])
        self.assertEqual(r["denied_capabilities"], ["unknown.capability"])

    def test_identity_without_challenge_is_not_verified(self):
        r = evaluate_peer(
            transport_secure=True,
            audit_available=True,
            identity_verified=True,
            challenge_verified=False,
            requested_capabilities=["knowledge.search"],
        )
        self.assertEqual(r["level"], 2)
        self.assertEqual(r["granted_capabilities"], [])


if __name__ == "__main__":
    unittest.main()
