import json

from omega.infrastructure_assimilator import (
    InfrastructureAssimilator,
    classify_url,
    safe_url,
)


def test_documentation_not_server():
    assert classify_url(
        "https://learn.microsoft.com/en-us/windows/server"
    ) == "DOCUMENTATION"


def test_repository_not_server():
    assert classify_url(
        "https://github.com/example/project"
    ) == "REPOSITORY"


def test_api_only_candidate():
    assert classify_url(
        "https://api.example.com/v1/status"
    ) == "ENDPOINT_CANDIDATE"


def test_generic_page_unclassified():
    assert classify_url(
        "https://example.com/about"
    ) == "UNCLASSIFIED_WEB_RESOURCE"


def test_private_and_http_rejected():
    for url in (
        "http://example.com",
        "https://127.0.0.1",
        "https://192.168.1.1",
        "https://localhost",
        "https://10.0.0.1",
        "https://[::1]",
    ):
        assert not safe_url(url)


def test_credentials_and_nonstandard_ports_rejected():
    assert not safe_url("https://user:pass@example.com")
    assert not safe_url("https://example.com:8443")


def test_generic_probe_disabled():
    assert InfrastructureAssimilator().test_server(
        "https://example.com"
    ) is False


def test_persistence_without_operational_claim(tmp_path, monkeypatch):
    import omega.infrastructure_assimilator as module

    monkeypatch.setattr(module, "STATE", tmp_path / "inventory.json")

    obj = InfrastructureAssimilator()
    obj.search_web = lambda query: [
        "https://api.example.com/v1/status",
        "https://learn.microsoft.com/en-us/server",
        "https://github.com/example/repo",
        "http://example.net/private",
    ]

    obj.assimilate()

    data = json.loads((tmp_path / "inventory.json").read_text())
    resources = data["resources"]

    assert len(resources) == 3

    for item in resources.values():
        assert item["stage"] == "DISCOVERED"
        assert item["operational"] is False
        assert item["checks"]["reachable"] is False
        assert item["checks"]["protocol_verified"] is False
        assert item["checks"]["identity_verified"] is False
        assert item["checks"]["real_exchange_confirmed"] is False

    assert resources["https://learn.microsoft.com/en-us/server"]["category"] == "DOCUMENTATION"
    assert resources["https://github.com/example/repo"]["category"] == "REPOSITORY"

    monkeypatch.setattr(module, "STATE", tmp_path / "inventory.json")
    reloaded = InfrastructureAssimilator()
    assert len(reloaded.inventory["resources"]) == 3
