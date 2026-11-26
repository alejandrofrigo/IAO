from omega.architecture import (
    ARCHITECTURE_ID,
    SUBSYSTEMS,
    inspect_architecture,
)


def test_architecture_has_all_target_subsystems():
    expected = {
        "iao_core", "padge", "global_discovery", "node_assimilation",
        "federated_identity", "distributed_intelligence",
        "distributed_memory", "replication", "self_healing",
        "resource_orchestration", "network_intelligence", "continuity",
    }
    assert set(SUBSYSTEMS) == expected


def test_architecture_inspection_is_truthful_and_read_only():
    report = inspect_architecture()
    assert report["architecture_id"] == ARCHITECTURE_ID
    assert report["mode"] == "READ_ONLY_CONTRACT_INSPECTION"
    assert report["summary"]["subsystem_count"] == 12
    assert report["summary"]["external_nodes_confirmed"] == 0
    assert report["summary"]["external_replicas_confirmed"] == 0
    assert report["summary"]["global_autonomy_confirmed"] is False


def test_each_subsystem_has_a_purpose_and_contracts():
    for name, spec in SUBSYSTEMS.items():
        assert spec["purpose"]
        assert spec["components"]
