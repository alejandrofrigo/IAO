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
        initial_recovery_code = "browser-e2e-recovery-" + "r" * 48
        rotated_recovery_code = "browser-e2e-recovery-rotated-" + "n" * 48
        third_recovery_code = "browser-e2e-recovery-third-" + "q" * 48
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
                ).fill(initial_recovery_code)
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
                        extractable: value && value.privateKey ? value.privateKey.extractable : null,
                        publicKeyPem: value && value.publicKeyPem
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
                        devicePublicKeyPem: devicePublicKey,
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

                # Simulate a lost HTTP response after the server commits recovery.
                # Retry must reconcile durable state instead of replaying the challenge.
                page.get_by_placeholder("Código de recuperación offline actual").fill(
                    initial_recovery_code
                )
                page.get_by_placeholder(
                    "Nuevo código de recuperación offline (mínimo 32 caracteres)"
                ).fill(rotated_recovery_code)
                recovery_button = panel.get_by_role(
                    "button", name="Recuperar identidad y sustituir dispositivo"
                )
                recovery_path = "**/v1/operator/recovery/complete"
                recovery_intercepted = {"count": 0}

                def drop_committed_recovery_response(route):
                    response = route.fetch()
                    assert response.status == 200, response.text()
                    recovery_intercepted["count"] += 1
                    route.abort("failed")

                page.route(recovery_path, drop_committed_recovery_response)
                recovery_button.click()
                page.wait_for_function(
                    """() => {
                      const output = document.querySelector('#iao-operator-identity-panel pre');
                      return output && output.textContent.startsWith('ERROR:');
                    }""",
                    timeout=20000,
                )
                assert recovery_intercepted["count"] == 1
                page.unroute(recovery_path, drop_committed_recovery_response)

                # Pending keys and the new recovery code survive the lost response.
                # The second attempt must complete through /recovery/status.
                recovery_button.click()
                page.wait_for_function(
                    """() => {
                      const output = document.querySelector('#iao-operator-identity-panel pre');
                      return output && output.textContent.includes('IDENTIDAD RECUPERADA');
                    }""",
                    timeout=20000,
                )
                recovery_output = panel.locator("pre").inner_text()
                assert "Versión de clave: 2" in recovery_output, recovery_output
                assert rotated_recovery_code in recovery_output, recovery_output

                recovered_identity = page.evaluate(
                    """async ({oldRootPem, oldDevicePem}) => {
                      const db = await new Promise((resolve, reject) => {
                        const request = indexedDB.open('iao-operator-root', 1);
                        request.onerror = () => reject(request.error);
                        request.onsuccess = () => resolve(request.result);
                      });
                      const root = await new Promise((resolve, reject) => {
                        const request = db.transaction('identity', 'readonly')
                          .objectStore('identity').get('root');
                        request.onerror = () => reject(request.error);
                        request.onsuccess = () => resolve(request.result || null);
                      });
                      db.close();
                      const devicePublicKeyPem = await window.IAODeviceAuthority.publicKeyPem();
                      return {
                        keyVersion: root && root.keyVersion,
                        rootKeyChanged: Boolean(root && root.publicKeyPem &&
                          root.publicKeyPem !== oldRootPem),
                        rootPrivateKeyExtractable: root && root.privateKey
                          ? root.privateKey.extractable : null,
                        deviceKeyChanged: devicePublicKeyPem !== oldDevicePem,
                        devicePublicKeyPem
                      };
                    }""",
                    {
                        "oldRootPem": local_identity["publicKeyPem"],
                        "oldDevicePem": after_reload["devicePublicKeyPem"],
                    },
                )
                assert recovered_identity["keyVersion"] == 2, recovered_identity
                assert recovered_identity["rootKeyChanged"], recovered_identity
                assert recovered_identity["rootPrivateKeyExtractable"] is False, recovered_identity
                assert recovered_identity["deviceKeyChanged"], recovered_identity

                # The recovered root/device pair authenticates, still read-only.
                panel.get_by_role("button", name="Iniciar sesión de operador").click()
                page.wait_for_function(
                    """() => {
                      const output = document.querySelector('#iao-operator-identity-panel pre');
                      return output && (
                        output.textContent.includes('SESIÓN DE OPERADOR AUTENTICADA') ||
                        output.textContent.startsWith('ERROR:')
                      );
                    }""",
                    timeout=20000,
                )
                assert "SESIÓN DE OPERADOR AUTENTICADA" in panel.locator("pre").inner_text()
                recovered_session = page.evaluate(
                    """async () => {
                      const response = await fetch(window.iaoApiUrl('/v1/me'), {
                        headers: {Authorization: 'Bearer ' + window.iaoGetSessionToken()},
                        credentials: 'omit', cache: 'no-store'
                      });
                      return {status: response.status, body: await response.json()};
                    }"""
                )
                assert recovered_session["status"] == 200, recovered_session
                assert recovered_session["body"]["subject"].startswith("operator:"), recovered_session
                assert recovered_session["body"]["scopes"] == [], recovered_session

                # Exercise the ordinary successful completion path as well.
                # This catches local activation errors that reconciliation can mask.
                page.get_by_placeholder("Código de recuperación offline actual").fill(
                    rotated_recovery_code
                )
                page.get_by_placeholder(
                    "Nuevo código de recuperación offline (mínimo 32 caracteres)"
                ).fill(third_recovery_code)
                recovery_button.click()
                page.wait_for_function(
                    """() => {
                      const output = document.querySelector('#iao-operator-identity-panel pre');
                      return output && (
                        output.textContent.includes('IDENTIDAD RECUPERADA') ||
                        output.textContent.startsWith('ERROR:')
                      );
                    }""",
                    timeout=20000,
                )
                second_recovery_output = panel.locator("pre").inner_text()
                assert "IDENTIDAD RECUPERADA" in second_recovery_output, second_recovery_output
                assert "Versión de clave: 3" in second_recovery_output, second_recovery_output
                assert third_recovery_code in second_recovery_output, second_recovery_output

                second_recovered_identity = page.evaluate(
                    """async (previousDevicePem) => {
                      const db = await new Promise((resolve, reject) => {
                        const request = indexedDB.open('iao-operator-root', 1);
                        request.onerror = () => reject(request.error);
                        request.onsuccess = () => resolve(request.result);
                      });
                      const root = await new Promise((resolve, reject) => {
                        const request = db.transaction('identity', 'readonly')
                          .objectStore('identity').get('root');
                        request.onerror = () => reject(request.error);
                        request.onsuccess = () => resolve(request.result || null);
                      });
                      db.close();
                      const devicePublicKeyPem = await window.IAODeviceAuthority.publicKeyPem();
                      return {
                        keyVersion: root && root.keyVersion,
                        privateKeyExtractable: root && root.privateKey
                          ? root.privateKey.extractable : null,
                        deviceKeyChanged: devicePublicKeyPem !== previousDevicePem
                      };
                    }""",
                    recovered_identity["devicePublicKeyPem"],
                )
                assert second_recovered_identity["keyVersion"] == 3, second_recovered_identity
                assert second_recovered_identity["privateKeyExtractable"] is False, second_recovered_identity
                assert second_recovered_identity["deviceKeyChanged"], second_recovered_identity

                panel.get_by_role("button", name="Iniciar sesión de operador").click()
                page.wait_for_function(
                    """() => {
                      const output = document.querySelector('#iao-operator-identity-panel pre');
                      return output && (
                        output.textContent.includes('SESIÓN DE OPERADOR AUTENTICADA') ||
                        output.textContent.startsWith('ERROR:')
                      );
                    }""",
                    timeout=20000,
                )
                assert "SESIÓN DE OPERADOR AUTENTICADA" in panel.locator("pre").inner_text()

                # Revocation must clear local root material and invalidate the
                # already-issued bearer session at the API boundary.
                revocation_token = page.evaluate("() => window.iaoGetSessionToken()")
                page.once("dialog", lambda dialog: dialog.accept())
                panel.get_by_role(
                    "button", name="Revocar identidad y dispositivo"
                ).click()
                page.wait_for_function(
                    """() => {
                      const output = document.querySelector('#iao-operator-identity-panel pre');
                      return output && output.textContent.includes('IDENTIDAD REVOCADA');
                    }""",
                    timeout=20000,
                )
                revoked_state = page.evaluate(
                    """async (token) => {
                      const db = await new Promise((resolve, reject) => {
                        const request = indexedDB.open('iao-operator-root', 1);
                        request.onerror = () => reject(request.error);
                        request.onsuccess = () => resolve(request.result);
                      });
                      const root = await new Promise((resolve, reject) => {
                        const request = db.transaction('identity', 'readonly')
                          .objectStore('identity').get('root');
                        request.onerror = () => reject(request.error);
                        request.onsuccess = () => resolve(request.result || null);
                      });
                      db.close();
                      const meResponse = await fetch(window.iaoApiUrl('/v1/me'), {
                        headers: {Authorization: 'Bearer ' + token},
                        credentials: 'omit', cache: 'no-store'
                      });
                      const pem = await window.IAODeviceAuthority.publicKeyPem();
                      const encoded = pem.replace(/-----[^-]+-----/g, '').replace(/\s/g, '');
                      const der = Uint8Array.from(atob(encoded), char => char.charCodeAt(0));
                      const digest = await crypto.subtle.digest('SHA-256', der);
                      const deviceId = Array.from(new Uint8Array(digest),
                        byte => byte.toString(16).padStart(2, '0')).join('');
                      const challengeResponse = await fetch(
                        window.iaoApiUrl('/v1/device/challenge'), {
                          method: 'POST',
                          headers: {
                            Authorization: 'Bearer ' + token,
                            'Content-Type': 'application/json'
                          },
                          body: JSON.stringify({device_id: deviceId}),
                          credentials: 'omit', cache: 'no-store'
                        }
                      );
                      return {
                        rootPresent: Boolean(root),
                        meStatus: meResponse.status,
                        meBody: await meResponse.json(),
                        challengeStatus: challengeResponse.status,
                        challengeBody: await challengeResponse.json()
                      };
                    }""",
                    revocation_token,
                )
                assert not revoked_state["rootPresent"], revoked_state
                assert revoked_state["meStatus"] == 401, revoked_state
                assert revoked_state["meBody"]["error"] == "OPERATOR_SESSION_REVOKED", revoked_state
                assert revoked_state["challengeStatus"] == 401, revoked_state
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
