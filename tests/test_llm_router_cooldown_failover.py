import time

import omega.llm_router as router


def test_all_cooling_providers_are_probed_until_one_succeeds(monkeypatch):
    providers = [
        {
            "id": "provider-first",
            "url": "https://first.example",
            "model": "model-first",
            "priority": 10,
        },
        {
            "id": "provider-second",
            "url": "https://second.example",
            "model": "model-second",
            "priority": 20,
        },
    ]

    now = time.time()
    states = {
        "provider-first": {
            "failures": 2,
            "retry_after": now + 30,
        },
        "provider-second": {
            "failures": 1,
            "retry_after": now + 60,
        },
    }

    calls = []

    def fake_request(provider, messages, timeout):
        calls.append(provider["id"])
        if provider["id"] == "provider-first":
            raise TimeoutError("simulated timeout")
        return "respuesta válida", "model-second-upstream"

    monkeypatch.setattr(router, "providers", lambda: providers)
    monkeypatch.setattr(router, "health", lambda: states)
    monkeypatch.setattr(router, "_request", fake_request)
    monkeypatch.setattr(router, "_write_json", lambda path, data: None)

    result = router.chat_with_metadata(
        [{"role": "user", "content": "prueba"}],
        timeout=1,
    )

    assert calls == ["provider-first", "provider-second"]
    assert result["reply"] == "respuesta válida"
    assert result["model_identity"]["provider_id"] == "provider-second"
    assert result["model_identity"]["upstream_model"] == "model-second-upstream"
    assert states["provider-first"]["failures"] == 3
    assert states["provider-second"]["failures"] == 0
