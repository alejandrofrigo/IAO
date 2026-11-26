"""Puente cognitivo configurable para IAO. Solo biblioteca estándar."""
import json
import os
import urllib.request
import urllib.error


class CognitionError(RuntimeError):
    pass


def complete(messages, *, temperature=0.2, max_tokens=1200, timeout=45):
    """
    messages: lista de {"role": "system|user|assistant", "content": "..."}.
    Configuración:
      IAO_API_BASE=https://proveedor.example/v1
      IAO_MODEL=nombre-del-modelo
      IAO_API_KEY=... (opcional para endpoints sin autenticación)

    No ejecuta herramientas ni aplica cambios de código.
    """
    base = os.environ.get("IAO_API_BASE", "").strip().rstrip("/")
    model = os.environ.get("IAO_MODEL", "").strip()
    key = os.environ.get("IAO_API_KEY", "").strip()

    if not base or not model:
        raise CognitionError(
            "Falta configurar IAO_API_BASE e IAO_MODEL. "
            "No se ha enviado ninguna petición."
        )

    if not base.startswith(("https://", "http://")):
        raise CognitionError("IAO_API_BASE debe ser una URL HTTP(S).")

    if not isinstance(messages, list) or not messages:
        raise CognitionError("messages debe ser una lista no vacía.")

    safe_messages = []
    for item in messages:
        if not isinstance(item, dict):
            raise CognitionError("Formato de mensaje no válido.")
        role, content = item.get("role"), item.get("content")
        if role not in ("system", "user", "assistant"):
            raise CognitionError("Rol de mensaje no permitido.")
        if not isinstance(content, str):
            raise CognitionError("El contenido del mensaje debe ser texto.")
        safe_messages.append({"role": role, "content": content})

    payload = json.dumps({
        "model": model,
        "messages": safe_messages,
        "temperature": max(0.0, min(float(temperature), 1.0)),
        "max_tokens": max(1, min(int(max_tokens), 4096)),
        "stream": False,
    }).encode("utf-8")

    headers = {"Content-Type": "application/json"}
    if key:
        headers["Authorization"] = "Bearer " + key

    request = urllib.request.Request(
        base + "/chat/completions",
        data=payload,
        headers=headers,
        method="POST",
    )

    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            if response.status != 200:
                raise CognitionError(
                    "El proveedor devolvió HTTP " + str(response.status)
                )
            data = json.loads(response.read(2_000_000).decode("utf-8"))
    except urllib.error.HTTPError as exc:
        raise CognitionError(
            "Error HTTP del proveedor: " + str(exc.code)
        ) from None
    except (urllib.error.URLError, TimeoutError, OSError):
        raise CognitionError(
            "Proveedor inaccesible o conexión agotada."
        ) from None
    except (ValueError, UnicodeError):
        raise CognitionError(
            "Respuesta del proveedor no válida."
        ) from None

    try:
        result = data["choices"][0]["message"]["content"]
    except (KeyError, IndexError, TypeError):
        raise CognitionError(
            "La respuesta no contiene choices[0].message.content."
        ) from None

    if not isinstance(result, str) or not result.strip():
        raise CognitionError("El proveedor devolvió contenido vacío.")

    return result.strip()


if __name__ == "__main__":
    import sys
    if "--check" in sys.argv:
        print("PASS: puente cognitivo importable.")
        print("Proveedor configurado:",
              "sí" if os.environ.get("IAO_API_BASE") else "no")
        print("Modelo configurado:",
              "sí" if os.environ.get("IAO_MODEL") else "no")
    else:
        print("Este módulo se importa desde el código de IAO.")
        print("No se realiza ninguna petición sin configuración explícita.")
