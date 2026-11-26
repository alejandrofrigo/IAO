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
                page.add_init_script(
                    """(() => {
                      window.__iaoIdbWrites = [];
                      const originalPut = IDBObjectStore.prototype.put;
                      IDBObjectStore.prototype.put = function(value, key) {
                        window.__iaoIdbWrites.push({
                          database: this.transaction.db.name,
                          store: this.name,
                          key: key === undefined ? null : String(key)
                        });
                        return originalPut.apply(this, arguments);
                      };
                    })();"""
                )
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
                page.wait_for_function(
                    """() => {
                      const panel = document.querySelector('#iao-operator-identity-panel pre');
                      return panel && (
                        panel.textContent.includes('IDENTIDAD RAÍZ REGISTRADA') ||
                        panel.textContent.startsWith('ERROR:')
                      );
                    }""",
                    timeout=20000,
                )
                bootstrap_output = panel.locator("pre").inner_text()
                assert "IDENTIDAD RAÍZ REGISTRADA" in bootstrap_output, bootstrap_output
                local_identity = page.evaluate(
                    """async () => {
                      const databases = await indexedDB.databases();
                      const request = indexedDB.open('iao-operator-root', 1);
                      const db = await new Promise((resolve, reject) => {
                        request.onerror = () => reject(request.error);
                        request.onsuccess = () => resolve(request.result);
                      });
                      const stores = Array.from(db.objectStoreNames);
                      const tx = db.transaction('identity', 'readonly');
                      const store = tx.objectStore('identity');
                      const keys = await new Promise((resolve, reject) => {
                        const get = store.getAllKeys();
                        get.onerror = () => reject(get.error);
                        get.onsuccess = () => resolve(get.result);
                      });
                      const value = await new Promise((resolve, reject) => {
                        const get = store.get('root');
                        get.onerror = () => reject(get.error);
                        get.onsuccess = () => resolve(get.result || null);
                      });
                      db.close();
                      return {
                        databases: databases.map(item => ({name: item.name, version: item.version})),
                        writes: window.__iaoIdbWrites,
                        stores, keys,
                        present: Boolean(value),
                        keyVersion: value && value.keyVersion,
                        privateKey: Boolean(value && value.privateKey),
                        extractable: value && value.privateKey ? value.privateKey.extractable : null
                      };
                    }"""
                )
                assert local_identity["present"], f"IndexedDB state: {local_identity}"
                assert local_identity["keyVersion"] == 1, local_identity
                assert local_identity["privateKey"], local_identity
                assert local_identity["extractable"] is False, local_identity

                panel.get_by_role("button", name="Iniciar sesión de operador").click()
                output = panel.locator("pre")
                page.wait_for_function(
                    """() => {
                      const panel = document.querySelector('#iao-operator-identity-panel pre');
                      return panel && (
                        panel.textContent.includes('SESIÓN DE OPERADOR AUTENTICADA') ||
                        panel.textContent.startsWith('ERROR:')
                      );
                    }""",
                    timeout=20000,
                )
                assert "SESIÓN DE OPERADOR AUTENTICADA" in output.inner_text(), output.inner_text()
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

                # A browser reload must preserve non-exportable identity keys,
                # but must not resurrect the short-lived operator bearer session.
                page.reload(wait_until="networkidle")
                page.get_by_role("button", name="Entrar al chat").click()
                page.get_by_text(
                    "Conectado como visitante. Solo chat; sin mando ni tareas en cola.",
                    exact=False,
                ).wait_for(timeout=15000)
                after_reload = page.evaluate(
                    """async () => {
                      const rootDb = await new Promise((resolve, reject) => {
                        const request = indexedDB.open('iao-operator-root', 1);
                        request.onerror = () => reject(request.error);
                        request.onsuccess = () => resolve(request.result);
                      });
                      const root = await new Promise((resolve, reject) => {
                        const request = rootDb.transaction('identity', 'readonly')
                          .objectStore('identity').get('root');
                        request.onerror = () => reject(request.error);
                        request.onsuccess = () => resolve(request.result || null);
                      });
                      rootDb.close();
                      const devicePublicKey = await window.IAODeviceAuthority.publicKeyPem();
                      const response = await fetch(window.iaoApiUrl('/v1/me'), {
                        headers: {Authorization: 'Bearer ' + window.iaoGetSessionToken()},
                        credentials: 'omit',
                        cache: 'no-store'
                      });
                      return {
                        rootPresent: Boolean(root && root.privateKey && root.keyVersion === 1),
                        rootPrivateKeyExtractable: root && root.privateKey
                          ? root.privateKey.extractable : null,
                        deviceKeyPresent: typeof devicePublicKey === 'string' &&
                          devicePublicKey.includes('BEGIN PUBLIC KEY'),
                        sessionStatus: response.status,
                        session: await response.json()
                      };
                    }"""
                )
                assert after_reload["rootPresent"], after_reload
                assert after_reload["rootPrivateKeyExtractable"] is False, after_reload
                assert after_reload["deviceKeyPresent"], after_reload
                assert after_reload["sessionStatus"] == 200, after_reload
                assert after_reload["session"]["subject"].startswith("guest:"), after_reload
                assert after_reload["session"]["scopes"] == [], after_reload

                queued_denial = page.evaluate(
                    """async () => {
                      try {
                        await window.IAODeviceAuthority.submitQueuedTask({
                          goal: 'must remain denied after operator session loss',
                          capability: 'knowledge.search',
                          input: {query: 'authorization boundary'},
                          execution_mode: 'queued'
                        });
                        return {denied: false};
                      } catch (error) {
                        return {denied: true, error: String(error.message || error)};
                      }
                    }"""
                )
                assert queued_denial["denied"], queued_denial
                assert queued_denial["error"] in {
                    "DEVICE_OWNER_MISMATCH", "HTTP_403", "OPERATOR_SESSION_REQUIRED"
                }, queued_denial
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
