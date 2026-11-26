"""omega.federation_dns_ip_check
================================

Módulo de utilidades que proporciona una verificación ligera de conectividad
DNS e IP para endpoints de candidatos federados.

La función principal, :func:`check_dns_ip_connectivity`, valida que el nombre
de host de un endpoint sea resoluble y que el puerto especificado acepte
conexiones TCP dentro de un tiempo de espera configurable.

Esta verificación se ejecuta **antes** de cualquier comprobación HTTPS para
evitar esperas largas o errores inesperados cuando el host no es alcanzable
ni siquiera a nivel de red.

Uso típico::

    from omega.federation_dns_ip_check import check_dns_ip_connectivity

    if check_dns_ip_connectivity("https://example.org:443"):
        # proceder con la verificación HTTPS
        ...
    else:
        # rechazar o re‑intentar el candidato
        ...

La implementación es deliberadamente sencilla y no depende de bibliotecas de
terceros, garantizando que funcione en entornos restringidos y bajo el
control de las políticas de PADGE.
"""

from __future__ import annotations

import socket
import ssl
from urllib.parse import urlparse
from typing import Tuple

__all__: Tuple[str, ...] = ("check_dns_ip_connectivity",)


def _parse_endpoint(endpoint: str) -> Tuple[str, int]:
    """Parsea *endpoint* y devuelve una tupla ``(hostname, port)``.

    El *endpoint* puede ser una URL completa (p.ej. ``https://example.org:443``)
    o simplemente ``example.org`` (en cuyo caso se asume el puerto 443).
    La función lanza ``ValueError`` si no puede determinar un puerto válido.
    """
    # Si el endpoint parece una URL, usar urlparse para extraer host y puerto.
    if "//" not in endpoint:
        # No contiene esquema, asumir https por defecto.
        endpoint = f"https://{endpoint}"
    parsed = urlparse(endpoint)
    hostname = parsed.hostname
    port = parsed.port
    if hostname is None:
        raise ValueError(f"No se pudo extraer el hostname del endpoint: {endpoint}")
    if port is None:
        # Asumimos 443 para HTTPS y 80 para HTTP según el esquema.
        if parsed.scheme == "https":
            port = 443
        elif parsed.scheme == "http":
            port = 80
        else:
            raise ValueError(f"No se especificó puerto y el esquema no es http/https: {endpoint}")
    return hostname, port


def check_dns_ip_connectivity(endpoint: str, timeout: float = 3.0) -> bool:
    """Comprueba que *endpoint* es resoluble mediante DNS y que el puerto está
    abierto para conexiones TCP.

    Parameters
    ----------
    endpoint: str
        URL o host que se desea validar. Puede incluir esquema y puerto.
    timeout: float, optional
        Tiempo máximo (en segundos) para la resolución DNS y para intentar la
        conexión TCP. El valor por defecto es 3 s.

    Returns
    -------
    bool
        ``True`` si la resolución DNS tiene éxito y se establece una conexión
        TCP al puerto indicado antes de que expire el *timeout*; ``False`` en
        cualquier otro caso (error de resolución, puerto cerrado, tiempo de
        espera agotado, etc.).

    Notas
    -----
    * La conexión TCP se cierra inmediatamente después de comprobar que se
      ha establecido; no se envía ningún dato.
    * Para HTTPS se realiza un *handshake* TLS opcional opcionalmente, pero
      no es necesario para la simple verificación de conectividad.
    """
    try:
        hostname, port = _parse_endpoint(endpoint)
    except ValueError:
        return False

    try:
        # getaddrinfo devuelve una lista de tuples (family, type, proto, canonname, sockaddr)
        addr_info = socket.getaddrinfo(hostname, port, type=socket.SOCK_STREAM)
    except socket.gaierror:
        # DNS resolution failed
        return False

    for family, socktype, proto, _, sockaddr in addr_info:
        try:
            with socket.socket(family, socktype, proto) as sock:
                sock.settimeout(timeout)
                sock.connect(sockaddr)
                # Si el esquema es HTTPS, opcionalmente podemos intentar un handshake TLS
                # sin validar certificados (solo para confirmar que el servidor habla TLS).
                # Esto es extra, pero no se considera un fallo si ocurre una excepción.
                try:
                    if endpoint.startswith("https://"):
                        context = ssl.create_default_context()
                        # No verificamos el certificado aquí; la verificación completa
                        # se realizará en la capa HTTPS posterior.
                        with context.wrap_socket(sock, server_hostname=hostname):
                            pass
                except Exception:
                    # Fallo en TLS no implica falta de conectividad TCP.
                    pass
                return True
        except (socket.timeout, ConnectionRefusedError, OSError):
            # Intentar la siguiente dirección si la actual falla.
            continue
    return False
