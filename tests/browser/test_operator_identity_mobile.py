"""Real Chromium mobile-emulation test for the browser operator identity flow.

The test starts an isolated FastAPI service and a local static web origin. It
never contacts the configured public tunnel and uses disposable test secrets.
"""
from __future__ import annotations

import os
import shutil
import socket
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request
from pathlib import Path

import pytest

sync_playwright = pytest.importorskip("playwright.sync_api").sync_playwright


ROOT = Path(__file__).resolve().parents[2]


def free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


def wait_for_http(url: str, process: subprocess.Popen, timeout: float = 40.0) -> None:
    deadline = time.monotonic() + timeout
    last_error: Exception | None = None
    while time.monotonic() < deadline:
        if process.poll() is not None:
            raise RuntimeError(f"test server exited early: {process.returncode}")
        try:
            with urllib.request.urlopen(url, timeout=2) as response:
                if response.status == 200:
                    return
        except (OSError, urllib.error.URLError) as exc:
            last_error = exc
        time.sleep(0.25)
    raise TimeoutError(f"server did not become ready: {url}: {last_error}")


def test_mobile_chromium_bootstrap_login_and_read_only_device_binding() -> None:
    with tempfile.TemporaryDirectory(prefix="iao-mobile-e2e-") as temporary:
        state = Path(temporary)
        api_port, web_port = free_port(), free_port()
        api_origin = f"http://127.0.0.1:{api_port}"
        web_origin = f"http://127.0.0.1:{web_port}"
        web_root = state / "web"
        shutil.copytree(ROOT / "web", web_root)
        (web_root / "api-config.js").write_text(
            "window.IAO_API_BASE = " + repr(api_origin) + ";\n"
            "window.iaoApiUrl = path => new URL(String(path).replace(/^\\/+/, ''), "
            "window.IAO_API_BASE + '/').toString();\n",
            encoding="utf-8",
        )

        (state / "state").mkdir()
        (state / "corpus").mkdir()
        bootstrap_code = "browser-e2e-bootstrap-" + "b" * 48
        environment = os.environ.copy()
        environment.update({
            "OMEGA_DEV_TOKEN_KEY": "browser-e2e-token-" + "t" * 48,
            "AUDIT_HMAC_KEY": "browser-e2e-audit-" + "a" * 48,
            "IAO_STATE_DIR": str(state / "state"),
            "IAO_CORPUS_DIR": str(state / "corpus"),
            "IAO_CORS_ORIGINS": web_origin,
            "IAO_OPERATOR_BOOTSTRAP_CODE": bootstrap_code,
            "IAO_OPERATOR_BOOTSTRAP_EXPIRES_AT": str(time.time() + 1800),
            "IAO_DEVICE_ENROLLMENT_CODE": "browser-e2e-device-" + "d" * 40,
            "MODEL_ADAPTER": "disabled",
        })
        api = subprocess.Popen(
            [
                sys.executable, "-m", "uvicorn", "apps.api.main:app",
                "--host", "127.0.0.1", "--port", str(api_port),
            ],
            cwd=ROOT, env=environment,
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        )
        web = subprocess.Popen(
            [
                sys.executable, "-m", "http.server", str(web_port),
                "--bind", "127.0.0.1", "--directory", str(web_root),
            ],
            cwd=ROOT, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        )
        try:
            wait_for_http(api_origin + "/health/live", api)
            wait_for_http(web_origin + "/api-config.js", web)
            with sync_playwright() as playwright:
                browser = playwright.chromium.launch(headless=True)
                context = browser.new_context(
                    **playwright.devices["Pixel 7"],
                    service_workers="block",
                )
                page = context.new_page()
                page_errors: list[str] = []
                page.on("pageerror", lambda error: page_errors.append(str(error)))
                page.goto(web_origin, wait_until="networkidle")

                page.get_by_role("button", name="Entrar al chat").click()
                page.get_by_text(
                    "Conectado como visitante. Solo chat; sin mando ni tareas en cola.",
                    exact=False,
                ).wait_for(timeout=15000)
                panel = page.locator("#iao-operator-identity-panel")
                associate = panel.get_by_role("button", name="Asociar sesión autenticada")
                bind = panel.get_by_role("button", name="Vincular dispositivo primario")
                assert associate.is_disabled()
                assert bind.is_disabled()

                page.get_by_placeholder("Código de bootstrap fuera de banda").fill(bootstrap_code)
                page.get_by_placeholder(
                    "Crear código de recuperación offline (mínimo 32 caracteres)"
                ).fill("browser-e2e-recovery-" + "r" * 48)
                panel.get_by_role("button", name="Registrar identidad raíz").click()
                page.get_by_text("IDENTIDAD RAÍZ REGISTRADA", exact=False).wait_for(timeout=20000)

                panel.get_by_role("button", name="Iniciar sesión de operador").click()
                page.get_by_text(
                    "SESIÓN DE OPERADOR AUTENTICADA", exact=False
                ).wait_for(timeout=20000)
                page.get_by_text(
                    "Sesión de operador autenticada. Solo lectura; sin permisos de mando.",
                    exact=False,
                ).wait_for(timeout=15000)
                bind.wait_for(state="visible")
                assert not bind.is_disabled()
                bind.click()
                page.get_by_text("DISPOSITIVO VINCULADO", exact=False).wait_for(timeout=15000)

                session = page.evaluate(
                    """async () => {
                      const token = window.iaoGetSessionToken();
                      const response = await fetch(window.iaoApiUrl('/v1/me'), {
                        headers: {Authorization: 'Bearer ' + token},
                        credentials: 'omit',
                        cache: 'no-store'
                      });
                      return {status: response.status, body: await response.json()};
                    }"""
                )
                assert session["status"] == 200
                assert session["body"]["scopes"] == []
                assert session["body"]["subject"].startswith("operator:")
                assert not page_errors, page_errors
                context.close()
                browser.close()
        finally:
            for process in (web, api):
                process.terminate()
                try:
                    process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(timeout=5)
