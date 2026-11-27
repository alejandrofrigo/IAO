import json

from tools import iao_five_motor_supervisor as supervisor


def test_new_supervisor_config_enables_only_quarantined_p2p_discovery(tmp_path, monkeypatch):
    config = tmp_path / "adapters.json"
    monkeypatch.setattr(supervisor, "CONFIG", config)
    motors = supervisor.adapters()
    node = motors["NODE_NETWORK"]
    assert node["enabled"] is True
    assert node["command"][-2:] == ["tools/iao_libp2p_discovery.py", "--run"]
    assert "PADGE" in motors
    assert motors["GUARDIAN"]["enabled"] is False
    assert motors["DISTRIBUTED_INTELLIGENCE"]["enabled"] is False


def test_existing_operator_node_network_setting_is_preserved(tmp_path, monkeypatch):
    config = tmp_path / "adapters.json"
    config.write_text(json.dumps({
        "motors": {
            "NODE_NETWORK": {
                "command": ["custom", "operator-command"],
                "enabled": False,
                "group": "operator-defined",
            },
            "PADGE": {"command": [], "enabled": False},
        }
    }))
    monkeypatch.setattr(supervisor, "CONFIG", config)
    motors = supervisor.adapters()
    assert motors["NODE_NETWORK"]["enabled"] is False
    assert motors["NODE_NETWORK"]["command"] == ["custom", "operator-command"]
