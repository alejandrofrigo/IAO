"""Provider diagnostics must not echo URLs, queries, or exception text."""
from omega import deepseek_web


def test_external_provider_failures_log_only_exception_class(monkeypatch, capsys):
    def fail(*_args, **_kwargs):
        raise RuntimeError("private-error-message-marker")

    monkeypatch.setattr(deepseek_web.urllib.request, "urlopen", fail)

    assert deepseek_web._buscar_tavily("private-query-marker") == ""
    assert deepseek_web._buscar_duckduckgo("private-query-marker") == ""
    assert deepseek_web._redactar_gratis("private-query-marker", "") == ""

    output = capsys.readouterr().out
    assert "RuntimeError" in output
    assert "private-error-message-marker" not in output
    assert "private-query-marker" not in output
