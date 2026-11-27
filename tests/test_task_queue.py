from __future__ import annotations

import sqlite3
import tempfile
import threading
import unittest
from pathlib import Path

from omega.store import Store


AUDIT_KEY = b"task-queue-test-key-0123456789abcdef"


class DurableTaskQueueTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.db_path = Path(self.tmp.name) / "omega.db"
        self.store = Store(self.db_path, AUDIT_KEY)

    def tearDown(self) -> None:
        self.store.close()
        self.tmp.cleanup()

    def _queue_one(self, task_id: str = "task-1") -> None:
        task, created = self.store.create_task(
            task_id,
            "owner-a",
            {"goal": "read-only test", "allowed_capabilities": ["knowledge.search"]},
            None,
        )
        self.assertTrue(created)
        self.store.set_task_state(task["id"], "AUTHORIZED")
        self.assertTrue(self.store.queue_task(task["id"]))
        self.assertFalse(self.store.queue_task(task["id"]))

    def test_two_database_connections_cannot_claim_the_same_task(self) -> None:
        self._queue_one()
        second = Store(self.db_path, AUDIT_KEY)
        barrier = threading.Barrier(2)

        results: list[dict | None] = []

        def claim(store: Store, worker: str) -> None:
            barrier.wait(timeout=5)
            results.append(store.claim_next_task(worker, lease_seconds=60))

        try:
            first_thread = threading.Thread(
                target=claim, args=(self.store, "worker-a")
            )
            second_thread = threading.Thread(
                target=claim, args=(second, "worker-b")
            )
            first_thread.start()
            second_thread.start()
            first_thread.join(timeout=10)
            second_thread.join(timeout=10)
            self.assertFalse(first_thread.is_alive())
            self.assertFalse(second_thread.is_alive())

            self.assertEqual(len(results), 2)
            self.assertEqual(sum(result is not None for result in results), 1)
            self.assertIsNone(self.store.claim_next_task("worker-c"))
            row = self.store.get_task("task-1", "owner-a")
            self.assertEqual(row["state"], "RUNNING")
            self.assertIn(row["lease_owner"], {"worker-a", "worker-b"})
            self.assertEqual(row["attempt_count"], 1)
        finally:
            second.close()

    def test_live_lease_is_preserved_but_expired_work_fails_closed(self) -> None:
        self._queue_one()
        claimed = self.store.claim_next_task(
            "worker-a",
            lease_seconds=30,
            now="2026-11-26T12:00:00+00:00",
        )
        self.assertIsNotNone(claimed)

        live = self.store.recover_interrupted_tasks(
            now="2026-11-26T12:00:10+00:00"
        )
        self.assertEqual(live, [])
        still_running = self.store.get_task("task-1", "owner-a")
        self.assertEqual(still_running["state"], "RUNNING")
        self.assertEqual(still_running["lease_owner"], "worker-a")

        recovered = self.store.recover_interrupted_tasks(
            now="2026-11-26T12:01:00+00:00"
        )
        self.assertEqual(recovered, [{"id": "task-1", "owner": "owner-a"}])
        failed = self.store.get_task("task-1", "owner-a")
        self.assertEqual(failed["state"], "FAILED")
        self.assertIsNone(failed["lease_owner"])
        self.assertIsNone(failed["lease_until"])
        self.assertEqual(self.store.claim_next_task("worker-b"), None)

    def test_interrupted_verifying_task_fails_closed_and_is_not_requeued(self) -> None:
        self._queue_one()
        claimed = self.store.claim_next_task(
            "worker-a",
            lease_seconds=30,
        )
        self.assertIsNotNone(claimed)
        self.assertTrue(
            self.store.update_claimed_task(
                "task-1", "worker-a", "VERIFYING",
                lease_generation=claimed["lease_generation"],
            )
        )

        recovered = self.store.recover_interrupted_tasks(
            now="2999-01-01T00:00:00+00:00"
        )

        self.assertEqual(recovered, [{"id": "task-1", "owner": "owner-a"}])
        failed = self.store.get_task("task-1", "owner-a")
        self.assertEqual(failed["state"], "FAILED")
        self.assertEqual(
            failed["result_json"],
            '{"decision": "INTERRUPTED", "error": "PROCESS_INTERRUPTED"}',
        )
        self.assertIsNone(failed["lease_owner"])
        self.assertIsNone(failed["lease_until"])
        self.assertIsNone(self.store.claim_next_task("worker-b"))

    def test_only_current_unexpired_lease_owner_can_finish(self) -> None:
        self._queue_one()
        claimed = self.store.claim_next_task("worker-a", lease_seconds=300)
        self.assertIsNotNone(claimed)
        self.assertFalse(
            self.store.update_claimed_task(
                "task-1", "worker-b", "SUCCEEDED", {"result": "forged"},
                release=True, lease_generation=claimed["lease_generation"],
            )
        )
        self.assertTrue(
            self.store.update_claimed_task(
                "task-1", "worker-a", "VERIFYING",
                lease_generation=claimed["lease_generation"],
            )
        )
        self.assertTrue(
            self.store.update_claimed_task(
                "task-1", "worker-a", "SUCCEEDED", {"result": "verified"},
                release=True, lease_generation=claimed["lease_generation"],
            )
        )
        final = self.store.get_task("task-1", "owner-a")
        self.assertEqual(final["state"], "SUCCEEDED")
        self.assertEqual(final["result_json"], '{"result": "verified"}')
        self.assertIsNone(final["lease_owner"])

    def test_expired_lease_cannot_complete_even_before_recovery(self) -> None:
        self._queue_one()
        self.store.claim_next_task(
            "worker-a", lease_seconds=1,
            now="2000-01-01T00:00:00+00:00",
        )
        # The real clock is later than the fixed historical lease above.
        self.assertFalse(
            self.store.update_claimed_task(
                "task-1", "worker-a", "SUCCEEDED", {"result": "late"},
                release=True, lease_generation=1,
            )
        )

    def test_recovery_is_atomic_across_database_connections(self) -> None:
        self._queue_one()
        self.store.set_task_state("task-1", "RUNNING")
        second = Store(self.db_path, AUDIT_KEY)
        barrier = threading.Barrier(2)
        results: list[list[dict[str, str]]] = []

        def recover(store: Store) -> None:
            barrier.wait(timeout=5)
            results.append(store.recover_interrupted_tasks(
                now="2026-11-27T12:00:00+00:00"
            ))

        try:
            workers = [
                threading.Thread(target=recover, args=(self.store,)),
                threading.Thread(target=recover, args=(second,)),
            ]
            for worker in workers:
                worker.start()
            for worker in workers:
                worker.join(timeout=10)
                self.assertFalse(worker.is_alive())
            self.assertEqual(len(results), 2)
            self.assertEqual(sum(len(result) for result in results), 1)
            final = self.store.get_task("task-1", "owner-a")
            self.assertEqual(final["state"], "FAILED")
            self.assertIsNone(final["lease_owner"])
        finally:
            second.close()

    def test_stale_lease_generation_cannot_update_reclaimed_task(self) -> None:
        self._queue_one()
        first = self.store.claim_next_task("worker-a", lease_seconds=300)
        self.assertIsNotNone(first)
        first_generation = first["lease_generation"]
        # Recovery is fail-closed; an explicit operator requeue is required.
        self.store.recover_interrupted_tasks(now="2999-01-01T00:00:00+00:00")
        with self.store.lock:
            self.store.db.execute(
                "UPDATE task SET state='QUEUED' WHERE id='task-1' AND state='FAILED'"
            )
        second = self.store.claim_next_task("worker-a", lease_seconds=300)
        self.assertIsNotNone(second)
        self.assertEqual(second["lease_generation"], first_generation + 1)
        self.assertFalse(self.store.update_claimed_task(
            "task-1", "worker-a", "SUCCEEDED", {"result": "stale"},
            release=True, lease_generation=first_generation,
        ))
        self.assertTrue(self.store.update_claimed_task(
            "task-1", "worker-a", "SUCCEEDED", {"result": "current"},
            release=True, lease_generation=second["lease_generation"],
        ))

    def test_task_budget_ledger_charges_limits_and_requires_live_lease(self) -> None:
        intent = {
            "goal": "budget test",
            "allowed_capabilities": ["knowledge.search"],
            "budget": {
                "max_model_calls": 0,
                "max_tool_calls": 1,
                "max_input_bytes": 16,
                "max_output_bytes": 16,
                "timeout_seconds": 5,
            },
        }
        task, created = self.store.create_task(
            "budget-task", "owner-a", intent, None,
        )
        self.assertTrue(created)
        self.store.set_task_state(task["id"], "AUTHORIZED")
        self.assertTrue(self.store.queue_task(task["id"]))
        claimed = self.store.claim_next_task("budget-worker", lease_seconds=60)
        self.assertIsNotNone(claimed)
        generation = claimed["lease_generation"]

        self.assertFalse(self.store.consume_task_budget(
            task["id"], "budget-worker", generation, "model_calls", 1,
        ))
        self.assertTrue(self.store.consume_task_budget(
            task["id"], "budget-worker", generation, "tool_calls", 1,
        ))
        self.assertFalse(self.store.consume_task_budget(
            task["id"], "budget-worker", generation, "tool_calls", 1,
        ))
        self.assertTrue(self.store.consume_task_budget(
            task["id"], "budget-worker", generation, "input_bytes", 16,
        ))
        self.assertFalse(self.store.consume_task_budget(
            task["id"], "budget-worker", generation, "input_bytes", 1,
        ))
        self.assertTrue(self.store.consume_task_budget(
            task["id"], "budget-worker", generation, "output_bytes", 16,
        ))
        self.assertFalse(self.store.consume_task_budget(
            task["id"], "budget-worker", generation, "output_bytes", 1,
        ))
        self.assertFalse(self.store.consume_task_budget(
            task["id"], "stale-worker", generation, "tool_calls", 1,
        ))
        usage = self.store.task_budget_status(task["id"], "owner-a")
        self.assertEqual(usage["used_tool_calls"], 1)
        self.assertEqual(usage["used_input_bytes"], 16)
        self.assertEqual(usage["used_output_bytes"], 16)
        self.assertIsNone(self.store.task_budget_status(task["id"], "other-owner"))

    def test_state_transition_uses_compare_and_swap(self) -> None:
        self._queue_one()
        self.store.set_task_state("task-1", "CREATED")
        self.assertTrue(self.store.transition_task_state(
            "task-1", "CREATED", "AUTHENTICATED"
        ))
        self.assertFalse(self.store.transition_task_state(
            "task-1", "CREATED", "AUTHENTICATED"
        ))
        row = self.store.get_task("task-1", "owner-a")
        self.assertEqual(row["state"], "AUTHENTICATED")

    def test_state_transition_rejects_illegal_edges(self) -> None:
        self._queue_one()
        self.store.set_task_state("task-1", "CREATED")
        with self.assertRaisesRegex(ValueError, "INVALID_TASK_STATE_TRANSITION"):
            self.store.transition_task_state("task-1", "CREATED", "SUCCEEDED")
        row = self.store.get_task("task-1", "owner-a")
        self.assertEqual(row["state"], "CREATED")

    def test_existing_task_table_receives_additive_lease_migration(self) -> None:
        self.store.close()
        connection = sqlite3.connect(self.db_path)
        connection.execute("DROP TABLE task")
        connection.execute(
            "CREATE TABLE task("
            "id TEXT PRIMARY KEY, owner TEXT NOT NULL, state TEXT NOT NULL, "
            "intent_json TEXT NOT NULL, result_json TEXT, idem_key TEXT, "
            "created_at TEXT NOT NULL, updated_at TEXT NOT NULL, "
            "UNIQUE(owner, idem_key))"
        )
        connection.execute("DELETE FROM schema_migrations WHERE version >= 2")
        connection.commit()
        connection.close()

        migrated = Store(self.db_path, AUDIT_KEY)
        try:
            columns = {
                row["name"]
                for row in migrated.db.execute("PRAGMA table_info(task)").fetchall()
            }
            self.assertTrue(
                {"lease_owner", "lease_until", "attempt_count", "lease_generation", "cancel_requested_at"}.issubset(columns)
            )
        finally:
            migrated.close()


    def test_queued_task_can_be_cancelled_atomically(self) -> None:
        self._queue_one()
        self.assertEqual(self.store.request_task_cancel("task-1", "owner-a"), "CANCELLED")
        row = self.store.get_task("task-1", "owner-a")
        self.assertEqual(row["state"], "CANCELLED")
        self.assertIsNone(row["lease_owner"])
        self.assertEqual(self.store.request_task_cancel("task-1", "owner-a"), "TERMINAL")

    def test_running_task_cancellation_is_cooperative_and_owner_scoped(self) -> None:
        self._queue_one()
        claimed = self.store.claim_next_task("worker-a", lease_seconds=300)
        self.assertIsNotNone(claimed)
        self.assertEqual(self.store.request_task_cancel("task-1", "other-owner"), "NOT_FOUND")
        self.assertEqual(self.store.request_task_cancel("task-1", "owner-a"), "REQUESTED")
        self.assertTrue(self.store.task_cancel_requested(
            "task-1", "worker-a", claimed["lease_generation"]
        ))
        self.assertFalse(self.store.update_claimed_task(
            "task-1", "worker-a", "SUCCEEDED", {"result": "late"},
            release=True, lease_generation=claimed["lease_generation"],
        ))
        self.assertTrue(self.store.update_claimed_task(
            "task-1", "worker-a", "CANCELLED", {"decision": "CANCELLED"},
            release=True, lease_generation=claimed["lease_generation"],
        ))

    def test_cancel_requested_on_expired_lease_cannot_be_observed_by_stale_worker(self) -> None:
        self._queue_one()
        claimed = self.store.claim_next_task("worker-a", lease_seconds=1,
            now="2000-01-01T00:00:00+00:00")
        self.assertIsNotNone(claimed)
        self.assertEqual(self.store.request_task_cancel("task-1", "owner-a"), "REQUESTED")
        self.assertFalse(self.store.task_cancel_requested(
            "task-1", "worker-a", claimed["lease_generation"]
        ))


    def test_live_lease_renewal_is_generation_fenced_and_stops_on_cancel(self) -> None:
        self._queue_one()
        claimed = self.store.claim_next_task("worker-a", lease_seconds=30)
        self.assertIsNotNone(claimed)
        before = self.store.get_task("task-1", "owner-a")["lease_until"]
        self.assertTrue(self.store.renew_task_lease(
            "task-1", "worker-a", claimed["lease_generation"], 120
        ))
        after = self.store.get_task("task-1", "owner-a")["lease_until"]
        self.assertGreater(after, before)
        self.assertFalse(self.store.renew_task_lease(
            "task-1", "worker-a", claimed["lease_generation"] + 1, 120
        ))
        self.assertEqual(self.store.request_task_cancel("task-1", "owner-a"), "REQUESTED")
        self.assertFalse(self.store.renew_task_lease(
            "task-1", "worker-a", claimed["lease_generation"], 120
        ))


if __name__ == "__main__":
    unittest.main()
