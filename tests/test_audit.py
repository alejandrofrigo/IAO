import copy
import unittest

from omega.audit import GENESIS_HASH, make_event, verify_chain


def build(n: int, key: bytes | None = None) -> list[dict]:  # type: ignore[type-arg]
    evs, prev = [], GENESIS_HASH
    for i in range(n):
        ev = make_event("TEST", f"s{i}", {"i": i}, prev, key)
        evs.append(ev)
        prev = ev["event_hash"]
    return evs


class AuditChainTests(unittest.TestCase):  # AUD-01
    def test_valid_chain(self) -> None:
        self.assertEqual(verify_chain(build(5)), (True, None))

    def test_detects_modified_event(self) -> None:
        evs = build(5)
        evs[2]["details"]["i"] = 999
        self.assertEqual(verify_chain(evs), (False, 2))

    def test_detects_deleted_event(self) -> None:
        evs = build(5)
        del evs[1]
        self.assertFalse(verify_chain(evs)[0])

    def test_detects_reordered_events(self) -> None:
        evs = build(4)
        evs[1], evs[2] = evs[2], evs[1]
        self.assertFalse(verify_chain(evs)[0])

    def test_hmac_requires_correct_key(self) -> None:
        evs = build(3, key=b"k1")
        self.assertTrue(verify_chain(evs, key=b"k1")[0])
        self.assertFalse(verify_chain(evs, key=b"wrong")[0])

    def test_rehash_without_key_is_detected(self) -> None:
        evs = build(3, key=b"k1")
        forged = copy.deepcopy(evs)
        self.assertFalse(verify_chain(forged)[0])
