'''omega/federation_candidate_validator.py

Módulo de validación y verificación de conectividad para candidatos federados.

Este módulo provee una clase ``CandidateValidator`` que permite:

* Validar la estructura mínima requerida de un diccionario de candidato.
* Verificar que la URL declarada sea sintácticamente correcta.
* Resolver el nombre de host mediante DNS.
* Comprobar la conectividad TCP básica al puerto indicado (por defecto 443).

Las funciones están diseñadas para ser usadas en entornos de pruebas y
producción sin generar efectos secundarios: no se realizan intercambios de
datos más allá de la apertura de un socket TCP con timeout configurable.
''' 

import socket
import ssl
import urllib.parse
from typing import Mapping, Any, Tuple


class CandidateValidationError(RuntimeError):
    """Excepción lanzada cuando la validación estructural del candidato falla."""


class ConnectivityError(RuntimeError):
    """Excepción lanzada cuando no es posible establecer conectividad con el candidato."""


class CandidateValidator:
    """Validador de candidatos federados.

    El validador no mantiene estado interno; todos los métodos son ``@staticmethod``
    para permitir su uso directo sin necesidad de instanciar la clase.
    """

    # Campos obligatorios que debe contener el diccionario del candidato.
    _required_fields = {"id", "url", "public_key"}

    @staticmethod
    def validate_structure(candidate: Mapping[str, Any]) -> None:
        """Valida que el candidato contenga los campos mínimos y que ``url`` sea
        una URL válida con esquema ``https``.

        Lanza ``CandidateValidationError`` si la validación falla.
        """
        missing = CandidateValidator._required_fields - candidate.keys()
        if missing:
            raise CandidateValidationError(
                f"Campos obligatorios ausentes en el candidato: {', '.join(sorted(missing))}"
            )

        url = candidate["url"]
        parsed = urllib.parse.urlparse(url)
        if parsed.scheme.lower() != "https":
            raise CandidateValidationError(
                f"La URL del candidato debe usar esquema 'https', se encontró: '{parsed.scheme}'"
            )
        if not parsed.hostname:
            raise CandidateValidationError("La URL del candidato no contiene un hostname válido.")

        # Opcional: verificar que el puerto sea un entero válido o asignar 443 por defecto.
        port = parsed.port or 443
        if not (0 < port < 65536):
            raise CandidateValidationError(f"Puerto fuera de rango en la URL del candidato: {port}")

    @staticmethod
    def _resolve_hostname(hostname: str) -> Tuple[str, ...]:
        """Resuelve el hostname a una lista de direcciones IP.

        Lanza ``ConnectivityError`` si la resolución falla.
        """
        try:
            infos = socket.getaddrinfo(hostname, None, family=socket.AF_UNSPEC, type=socket.SOCK_STREAM)
            # ``getaddrinfo`` devuelve una lista de tuples; el segundo elemento es la dirección.
            addresses = tuple(info[4][0] for info in infos)
            if not addresses:
                raise ConnectivityError(f"No se encontraron direcciones IP para el hostname '{hostname}'.")
            return addresses
        except socket.gaierror as exc:
            raise ConnectivityError(f"Error de resolución DNS para '{hostname}': {exc}") from exc

    @staticmethod
    def check_connectivity(candidate: Mapping[str, Any], timeout: float = 3.0) -> None:
        """Comprueba la conectividad TCP a la URL del candidato.

        1. Se valida la estructura (para asegurar que la URL es válida).
        2. Se resuelve el hostname.
        3. Se intenta abrir una conexión TCP al puerto (TLS opcional).

        Si cualquier paso falla, se lanza ``ConnectivityError`` con un mensaje
        descriptivo.
        """
        # Paso 1: validación estructural mínima.
        CandidateValidator.validate_structure(candidate)

        url = candidate["url"]
        parsed = urllib.parse.urlparse(url)
        hostname = parsed.hostname
        port = parsed.port or 443

        # Paso 2: resolución DNS.
        addresses = CandidateValidator._resolve_hostname(hostname)

        last_err: Exception | None = None
        for addr in addresses:
            try:
                # Se abre un socket TCP; si el puerto es 443, se envuelve en TLS para validar el handshake.
                sock = socket.create_connection((addr, port), timeout=timeout)
                if port == 443:
                    # Realizamos un handshake TLS sencillo sin validar certificados (las pruebas pueden usar mocks).
                    context = ssl.create_default_context()
                    with context.wrap_socket(sock, server_hostname=hostname) as tls_sock:
                        # Sólo verificamos que el handshake haya ocurrido sin excepción.
                        _ = tls_sock.version()
                else:
                    sock.close()
                # Conexión exitosa, retornamos sin error.
                return
            except Exception as exc:
                last_err = exc
                continue
        # Si llegamos aquí, todas las direcciones fallaron.
        raise ConnectivityError(
            f"No se pudo establecer conectividad TCP/TLS a {hostname}:{port}. Último error: {last_err}"
        )
