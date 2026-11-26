"""Utilities for connectivity validation of federation candidates.

Este módulo ofrece funciones de bajo nivel para verificar que un nodo candidato
sea alcanzable mediante una conexión TCP o una petición HTTPS. Las
funcionalidades están diseñadas para ser usadas por los componentes de
orquestación y registro de candidatos sin provocar efectos secundarios
(perfiles de red, escritura en disco, etc.).

Todas las operaciones están limitadas por un tiempo de espera configurable
para evitar bloqueos de la aplicación y manejan de forma explícita los
errores esperados (tiempos de espera, errores de resolución DNS, rechazos de
TLS, etc.).
"""

from __future__ import annotations

import socket
import ssl
from typing import Tuple

__all__: Tuple[str, ...] = (
    "check_tcp_connectivity",
    "check_https_endpoint",
)


def _resolve_host(host: str) -> str:
    """Resuelve un nombre de host a su dirección IP.

    La función encapsula la llamada a ``socket.getaddrinfo`` y devuelve la
    primera dirección IPv4 disponible. Si la resolución falla, se lanza una
    ``OSError`` con un mensaje claro.
    """
    try:
        infos = socket.getaddrinfo(host, None, family=socket.AF_INET)
        if not infos:
            raise OSError(f"No IPv4 address found for host '{host}'.")
        return infos[0][4][0]
    except socket.gaierror as exc:
        raise OSError(f"Error resolving host '{host}': {exc}") from exc


def check_tcp_connectivity(host: str, port: int, timeout: float = 2.0) -> bool:
    """Comprueba la conectividad TCP a *host*: *port*.

    Parameters
    ----------
    host: str
        Nombre de dominio o dirección IP del nodo candidato.
    port: int
        Puerto TCP al que intentar conectar.
    timeout: float, optional
        Tiempo máximo en segundos para la operación (por defecto 2.0).

    Returns
    -------
    bool
        ``True`` si la conexión se establece correctamente, ``False`` en caso
        de cualquier error (timeout, rechazo de conexión, resolución DNS,
        etc.).
    """
    try:
        ip = _resolve_host(host)
        with socket.create_connection((ip, port), timeout=timeout):
            return True
    except Exception:
        return False


def check_https_endpoint(url: str, timeout: float = 5.0) -> bool:
    """Valida que un endpoint HTTPS sea accesible y presente un certificado válido.

    Esta función abre una conexión TLS al *url* especificado y verifica que el
    handshake se complete sin errores. No se descarga el cuerpo de la respuesta;
    sólo se realiza el ``HEAD`` para minimizar el tráfico y el impacto.

    Parameters
    ----------
    url: str
        URL completa del endpoint (por ejemplo, ``https://example.com/api``).
    timeout: float, optional
        Tiempo máximo en segundos para establecer la conexión y recibir los
        encabezados (por defecto 5.0).

    Returns
    -------
    bool
        ``True`` si el endpoint responde exitosamente con código 2xx o 3xx,
        ``False`` en caso de fallos de red, TLS o códigos HTTP inesperados.
    """
    from urllib.parse import urlparse
    import http.client

    parsed = urlparse(url)
    if parsed.scheme != "https":
        raise ValueError("Only HTTPS URLs are supported for connectivity checks.")

    host = parsed.hostname
    port = parsed.port or 443
    path = parsed.path or "/"
    if parsed.query:
        path += f"?{parsed.query}"

    try:
        ip = _resolve_host(host)
        context = ssl.create_default_context()
        conn = http.client.HTTPSConnection(host=ip, port=port, timeout=timeout, context=context)
        conn.request("HEAD", path)
        response = conn.getresponse()
        # Considéranse exitosos los códigos de respuesta 2xx y 3xx.
        success = 200 <= response.status < 400
        conn.close()
        return success
    except Exception:
        return False
