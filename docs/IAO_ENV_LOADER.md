# Carga de variables de entorno con `load_env`

## Propósito

`omega.iao_router.load_env` es la función responsable de leer archivos de configuración **`.env`** y **`~/.iao-runtime.env`** y poblar el entorno del proceso con las variables definidas.  Su diseño garantiza:

1. **Determinismo** – El mismo conjunto de archivos siempre produce el mismo `os.environ`.
2. **Seguridad** – No sobrescribe variables que ya existen en el entorno del proceso.
3. **Compatibilidad** – Maneja valores sin comillas, entre comillas simples o dobles y secuencias de escape al estilo POSIX.
4. **Robustez** – Ignora líneas vacías o comentarios y reporta de forma controlada los errores de sintaxis.

## Reglas de análisis (implementadas en el código)

| Patrón | Descripción |
|--------|-------------|
| `KEY=VALUE` | Asigna `VALUE` a `KEY`.  Si `VALUE` está entre comillas simples (`'`) o dobles (`"`), se eliminan las comillas exteriores y se interpretan las secuencias de escape (`\n`, `\t`, `\\`, `\"`, `\'`). |
| `# comentario` | Línea ignorada. |
| líneas sin `=` o con una clave vacía | Se descartan y se registra una advertencia en el log interno (no se lanza excepción). |

## Uso típico

```python
from omega.iao_router import load_env

# Carga de variables del proyecto y del runtime del usuario
load_env()  # Busca automáticamente .env y ~/.iao-runtime.env

# Después de la llamada, las variables están disponibles vía os.getenv / os.environ
api_key = os.getenv("IAO_API_KEY")
```

### Parámetros opcionales

- `paths: list[str] | None` – Lista de archivos a cargar en orden.  Si se omite, se usan los valores por defecto `[".env", os.path.expanduser("~/.iao-runtime.env")]`.
- `override: bool = False` – Cuando se define como `True`, la función sobrescribe variables existentes; el comportamiento por defecto mantiene los valores preexistentes.

## Buenas prácticas

1. **No incluir secretos en el repositorio** – Utilice `.env` local o `~/.iao-runtime.env` para credenciales.
2. **Mantenga los archivos fuera de control de versiones** – Añada `.env` al `.gitignore`.
3. **Valide la presencia de variables críticas** después de la carga:
   ```python
   required = ["IAO_API_BASE", "IAO_MODEL"]
   missing = [k for k in required if not os.getenv(k)]
   if missing:
       raise RuntimeError(f"Variables de entorno faltantes: {', '.join(missing)}")
   ```
4. **Utilice comillas** cuando el valor contenga espacios o caracteres especiales.

## Ejemplo de archivo `.env`

```
# Configuración de la API de IAO
IAO_API_BASE=https://api.ejemplo.com/v1
IAO_MODEL=gpt-4o-mini
IAO_API_KEY="sk-xxxxxxxxxxxxxxxxxxxx"
# Comentario adicional
TIMEOUT=30
```

## Registro interno

La función escribe mensajes de depuración mediante el módulo `logging`.  Para habilitar la salida en la consola durante el desarrollo:

```python
import logging
logging.basicConfig(level=logging.DEBUG)
```

---

*Este documento forma parte del repositorio y será incluido en la generación automática de la documentación del proyecto.*