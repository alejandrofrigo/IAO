import sqlite3
import tempfile
import unittest
from pathlib import Path

from omega.store import Store


class AuditStatusTests(unittest.TestCase):
    def test_reports_valid_chain_and_event_count(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            store = Store(Path(tmp) / "audit.db", audit_key=b"test-audit-key-0123456789abcdef")
            try:
                store.audit("alice", "TEST_ONE", "subject")
                store.audit("alice", "TEST_TWO", "subject")
                self.assertEqual(
                    store.audit_status(),
                    {
                        "valid": True,
                        "authenticated": True,
                        "event_count": 2,
                        "first_invalid_index": None,
                        "first_invalid_event_id": None,
                    },
                )
                self.assertEqual(store.verify_audit(), (True, None))
            finally:
                store.close()

    def test_reports_first_invalid_index_and_database_id(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            db_path = Path(tmp) / "audit.db"
            store = Store(db_path, audit_key=b"test-audit-key-0123456789abcdef")
            try:
                store.audit("alice", "TEST_ONE", "subject")
                store.audit("alice", "TEST_TWO", "subject")
                store.audit("alice", "TEST_THREE", "subject")
                store.db.execute(
                    "UPDATE audit_event_v2 SET details=? WHERE id=2",
                    ('{"actor":"tampered"}',),
                )
                status = store.audit_status()
                self.assertFalse(status["valid"])
                self.assertEqual(status["event_count"], 3)
                self.assertEqual(status["first_invalid_index"], 1)
                self.assertEqual(status["first_invalid_event_id"], 2)
                self.assertEqual(store.verify_audit(), (False, 1))
            finally:
                store.close()


if __name__ == "__main__":
    unittest.main()
