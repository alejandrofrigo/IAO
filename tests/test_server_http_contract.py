import http.client
import os
import tempfile
import threading
import unittest
from pathlib import Path
from unittest.mock import patch
from http.server import ThreadingHTTPServer

from omega.server import build_service, make_handler


class StdlibHttpContractTests(unittest.TestCase):
    def test_wrong_method_has_same_405_allow_and_correlation_contract(self):
        with tempfile.TemporaryDirectory() as tmp:
            with patch.dict(os.environ, {
                "AUDIT_HMAC_KEY": "stdlib-http-audit-key-" + "a" * 40,
                "MODEL_ADAPTER": "disabled",
            }):
                service = build_service(
                    Path(tmp) / "state",
                    "stdlib-http-auth-key-" + "b" * 40,
                    Path(__file__).resolve().parent.parent / "docs" / "corpus",
                )
            httpd = ThreadingHTTPServer(("127.0.0.1", 0), make_handler(service))
            thread = threading.Thread(target=httpd.serve_forever, daemon=True)
            thread.start()
            connection = http.client.HTTPConnection("127.0.0.1", httpd.server_port, timeout=5)
            try:
                connection.request("GET", "/v1/chat")
                response = connection.getresponse()
                payload = response.read()
                self.assertEqual(response.status, 405)
                self.assertEqual(response.getheader("Allow"), "POST")
                self.assertTrue(response.getheader("X-Correlation-ID"))
                self.assertEqual(response.getheader("Cache-Control"), "no-store")
                self.assertIn(b"METHOD_NOT_ALLOWED", payload)
            finally:
                connection.close()
                httpd.shutdown()
                httpd.server_close()
                thread.join(timeout=5)
                service.store.close()


if __name__ == "__main__":
    unittest.main()
