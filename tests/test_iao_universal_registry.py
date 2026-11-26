import argparse
import json

import tools.iao_universal_registry as registry


def isolated_registry(monkeypatch, tmp_path):
    state = tmp_path / "state"
    monkeypatch.setattr(registry, "STATE", state)
    monkeypatch.setattr(registry, "REGISTRY", state / "registry.json")


def resource_args(name="Recurso de prueba", url="https://example.com"):
    return argparse.Namespace(
        kind="api",
        name=name,
        url=url,
        adapter=registry.ADAPTERS["api"][0],
        capabilities=["chat"],
        permission="public_service",
        notes="Prueba aislada; sin conexión externa",
    )


def test_validate_url_accepts_https(monkeypatch, tmp_path):
    isolated_registry(monkeypatch, tmp_path)
    assert registry.validate_url("https://example.com/api") == (
        "https://example.com/api"
    )


def test_validate_url_rejects_http(monkeypatch, tmp_path):
    isolated_registry(monkeypatch, tmp_path)
    try:
        registry.validate_url("http://example.com")
    except ValueError:
        return
    raise AssertionError("Se aceptó una URL HTTP")


def test_validate_url_rejects_embedded_credentials(monkeypatch, tmp_path):
    isolated_registry(monkeypatch, tmp_path)
    try:
        registry.validate_url("https://usuario:clave@example.com")
    except ValueError:
        return
    raise AssertionError("Se aceptó una URL con credenciales")


def test_empty_url_is_allowed_for_resource_without_endpoint(
    monkeypatch, tmp_path
):
    isolated_registry(monkeypatch, tmp_path)
    assert registry.validate_url(None) is None
    assert registry.validate_url("") is None


def test_registration_stays_discovered_and_unverified(
    monkeypatch, tmp_path
):
    isolated_registry(monkeypatch, tmp_path)

    registry.add_resource(resource_args())

    data = json.loads(registry.REGISTRY.read_text(encoding="utf-8"))
    assert len(data["resources"]) == 1

    item = data["resources"][0]
    assert item["stage"] == "DISCOVERED"
    assert item["checks"]["identity_verified"] is False
    assert item["checks"]["permission_verified"] is False
    assert item["checks"]["adapter_tested"] is False
    assert item["checks"]["real_exchange_confirmed"] is False


def test_duplicate_registration_does_not_create_second_resource(
    monkeypatch, tmp_path
):
    isolated_registry(monkeypatch, tmp_path)

    registry.add_resource(resource_args())
    registry.add_resource(resource_args())

    data = json.loads(registry.REGISTRY.read_text(encoding="utf-8"))
    assert len(data["resources"]) == 1


def test_save_and_load_round_trip(monkeypatch, tmp_path):
    isolated_registry(monkeypatch, tmp_path)

    data = registry.load()
    data["test_marker"] = "isolated-round-trip"
    registry.save(data)

    loaded = registry.load()
    assert loaded["test_marker"] == "isolated-round-trip"


def test_validate_url_rejects_private_and_special_ip_literals(
    monkeypatch, tmp_path
):
    isolated_registry(monkeypatch, tmp_path)
    for url in (
        "https://127.0.0.1",
        "https://10.0.0.8",
        "https://192.168.1.2",
        "https://169.254.169.254",
        "https://[::1]",
        "https://[fc00::1]",
    ):
        try:
            registry.validate_url(url)
        except ValueError:
            continue
        raise AssertionError(f"Se aceptó IP no pública: {url}")


def test_validate_url_rejects_local_hostnames(monkeypatch, tmp_path):
    isolated_registry(monkeypatch, tmp_path)
    for url in (
        "https://localhost",
        "https://printer.local",
        "https://service.internal",
        "https://router.home.arpa",
    ):
        try:
            registry.validate_url(url)
        except ValueError:
            continue
        raise AssertionError(f"Se aceptó host local: {url}")


def test_validate_url_rejects_control_characters(monkeypatch, tmp_path):
    isolated_registry(monkeypatch, tmp_path)
    for url in (
        "https://example.com/\nadmin",
        "https://example.com/\tadmin",
        "https://example.com /path",
    ):
        try:
            registry.validate_url(url)
        except ValueError:
            continue
        raise AssertionError("Se aceptó URL con caracteres inválidos")


def test_validate_public_dns_rejects_private_resolution():
    def fake_resolver(host, port, type=None):
        return [(None, None, None, None, ("127.0.0.1", 443))]

    try:
        registry.validate_public_dns("example.com", fake_resolver)
    except ValueError:
        return
    raise AssertionError("Se aceptó una resolución DNS privada")


def test_validate_public_dns_accepts_public_resolution():
    def fake_resolver(host, port, type=None):
        return [(None, None, None, None, ("8.8.8.8", 443))]

    assert registry.validate_public_dns(
        "example.com", fake_resolver
    ) == ("8.8.8.8",)
