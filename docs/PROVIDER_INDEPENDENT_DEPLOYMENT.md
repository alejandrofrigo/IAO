# Despliegue independiente del proveedor

## Decisión

Cloudflare no es una dependencia arquitectónica de IAO. La interfaz estática se publica mediante GitHub Pages y el backend es una aplicación Python empaquetada en Docker. La construcción del sitio y la ejecución de la API son planos separados.

## Interfaz pública

- Workflow: `.github/workflows/pages.yml`.
- Fuente: `web/`.
- Publicación: GitHub Pages, sin Workers, Functions ni túneles temporales.
- El workflow lee la variable de repositorio `IAO_API_BASE_URL` y la inyecta en `api-config.js` durante la construcción.
- El valor debe ser un origen HTTPS exacto, sin credenciales, ruta, query ni fragmento. Configurar además ese origen de Pages en `IAO_CORS_ORIGINS` del backend.
- Si la variable no existe, el sitio se publica en modo seguro sin backend: la interfaz no intenta enviar sesiones ni mensajes a un host arbitrario y muestra el error `IAO_API_ENDPOINT_NOT_CONFIGURED` al intentar conectar.

No se debe almacenar en el repositorio una URL Quick Tunnel, una dirección IP doméstica, credenciales o una URL temporal. No se debe usar una URL recibida por query string para decidir el destino de tokens de sesión.

## Backend: alternativa autocontrolada

El backend se puede construir y ejecutar desde `deploy/Dockerfile` en infraestructura que controle el operador: un ordenador Linux siempre encendido, un servidor doméstico o un dispositivo Android con Termux compatible con Python. Esto evita depender de Cloudflare Workers y de un proveedor serverless.

Requisitos mínimos del backend:
- proceso API persistente y accesible por HTTPS desde el navegador;
- volumen persistente y respaldado para `IAO_STATE_DIR` (base de datos, identidad de nodo, claves y auditoría);
- secretos persistentes inyectados fuera del repositorio;
- TLS, proxy inverso y CORS limitado al origen real de Pages;
- monitorización, copias de seguridad y restauración probada.

Un dispositivo móvil puede servir como entorno de desarrollo/autohospedaje, pero suspensión Android, ahorro de batería, cambios de red y CGNAT impiden prometer disponibilidad pública 24/7. No se debe exponer directamente un servidor HTTP de desarrollo a Internet. Para publicar un backend desde una red doméstica hace falta una ruta entrante segura y TLS; el soporte Tor onion/I2P debe añadirse y probarse como transporte separado, no fingirse mediante HTTPS directo.

## Coste y alternativas

| Opción | Uso apropiado | Límite |
|---|---|---|
| GitHub Pages | Interfaz estática pública | No ejecuta la API ni workers |
| Equipo propio / Termux | Backend autocontrolado y desarrollo | Depende de energía, conectividad y disponibilidad del equipo |
| Servidor propio ya disponible | Backend persistente | Requiere administración, TLS y almacenamiento |
| Cloud Run u otro servicio administrado | Alternativa opcional si ya existe cuota/crédito | No se presume gratuito ni se activa sin comprobar facturación y límites |

GitHub Actions es CI efímera, no un servidor persistente. No se debe desplegar automáticamente en un servicio de pago ni activar una cuenta de proveedor para eludir un fallo de Cloudflare.

## Estado de producción

La existencia del Dockerfile o de un workflow verde no certifica el backend. El contrato de producción de IAO mantiene el worker bloqueado hasta satisfacer los controles de identidad, aislamiento, persistencia y validación E2E. La API actual también debe superar su propia cualificación de producción antes de exponerse públicamente.

## Cambio de proveedor

Para cambiar el host de API, se actualiza la variable de repositorio `IAO_API_BASE_URL`, se configura exactamente el mismo origen de Pages en `IAO_CORS_ORIGINS` del backend y se vuelve a ejecutar el workflow de Pages. No se modifican rutas del chat ni la lógica de autenticación.
