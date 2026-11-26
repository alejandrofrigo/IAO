import os
import json
import urllib.request
import urllib.parse
import urllib.error
import xml.etree.ElementTree as ET

class UniversalConnector:
    def __init__(self):
        # Aquí se cargarían las claves desde el .env en producción
        pass

    def fetch(self, url: str, method: str = "GET", headers: dict = None, data: dict = None, auth_type: str = "none", auth_key: str = None) -> dict:
        """
        Conecta con cualquier API, detectando formato y manejando autenticación.
        """
        req_headers = {"User-Agent": "IAO-Universal-Connector/1.0"}
        if headers: req_headers.update(headers)

        # Manejo de autenticación (Capa 2)
        if auth_type == "bearer" and auth_key:
            req_headers["Authorization"] = f"Bearer {auth_key}"
        elif auth_type == "apikey_header" and auth_key:
            req_headers["X-API-Key"] = auth_key
        elif auth_type == "apikey_query" and auth_key:
            url += f"?apikey={auth_key}"

        encoded_data = None
        if data:
            encoded_data = json.dumps(data).encode('utf-8')
            req_headers["Content-Type"] = "application/json"

        try:
            req = urllib.request.Request(url, data=encoded_data, headers=req_headers, method=method)
            with urllib.request.urlopen(req, timeout=10) as response:
                content_type = response.headers.get("Content-Type", "").lower()
                raw_data = response.read()

                # Detección de formato (Capa 1)
                if "application/json" in content_type:
                    return {"status": "success", "format": "json", "data": json.loads(raw_data.decode('utf-8'))}
                elif "application/xml" in content_type or "text/xml" in content_type:
                    root = ET.fromstring(raw_data.decode('utf-8'))
                    return {"status": "success", "format": "xml", "data": {child.tag: child.text for child in root}}
                elif "text/html" in content_type:
                    return {"status": "success", "format": "html", "data": raw_data.decode('utf-8')[:500]} # Scraping básico
                else:
                    return {"status": "success", "format": "text", "data": raw_data.decode('utf-8')[:500]}
        except urllib.error.HTTPError as e:
            return {"status": "error", "code": e.code, "message": e.read().decode('utf-8')}
        except Exception as e:
            return {"status": "error", "message": str(e)}

connector = UniversalConnector()
