import tempfile
import unittest
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from omega.jobs import JobStore, idempotency_key


class JobTests(unittest.TestCase):  # T-02 / T-07 / AT-BOOT-02/03
    def test_same_document_does_not_duplicate(self) -> None:
        with tempfile.TemporaryDirectory() as d:
            s = JobStore(Path(d))
            k = idempotency_key("SO-OMEGA-PRIME", "3.0", "abc")
            with ThreadPoolExecutor(8) as ex:
                res = list(ex.map(lambda _: s.create_or_resume(k, {}), range(16)))
            self.assertEqual(sum(1 for _, created in res if created), 1)

    def test_new_hash_new_job(self) -> None:
        self.assertNotEqual(idempotency_key("p", "3.0", "a"), idempotency_key("p", "3.0", "b"))

    def test_resume_after_restart_from_checkpoint(self) -> None:
        with tempfile.TemporaryDirectory() as d:
            k = idempotency_key("p", "3.0", "h")
            JobStore(Path(d)).create_or_resume(k, {})
            JobStore(Path(d)).checkpoint(k, "BUILDING", {"step": 4})
            job, created = JobStore(Path(d)).create_or_resume(k, {})  # "restarted" process
            self.assertFalse(created)
            self.assertEqual((job["state"], job["checkpoint"]["step"]), ("BUILDING", 4))
