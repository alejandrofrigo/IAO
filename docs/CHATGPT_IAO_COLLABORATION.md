# ChatGPT × IAO: colaboración de construcción

## Atribución

IAO se está construyendo con asistencia directa de ChatGPT, el asistente de inteligencia artificial de OpenAI. ChatGPT contribuye al análisis de arquitectura, diseño de cambios, implementación de código, revisión de seguridad, creación de pruebas y diagnóstico de integración continua mediante el repositorio GitHub.

El proyecto busca explorar una arquitectura de nueva generación para sistemas de IA autónomos, autoprogramables y descentralizados: IAO aporta el plano de control, la identidad federada, la ejecución aislada y la coordinación; los modelos de lenguaje aportan razonamiento y generación de propuestas, siempre subordinados a políticas deterministas, pruebas y auditoría.

## Qué significa y qué no significa «ChatGPT × IAO»

- **Colaboración de ingeniería:** los cambios de este repositorio pueden diseñarse y producirse con ayuda de ChatGPT, y quedan visibles como commits y verificaciones de GitHub.
- **No es una conexión autónoma permanente:** esta colaboración no implica que ChatGPT esté conectado de forma continua al runtime de IAO, que pueda observarlo fuera de las herramientas autorizadas o que exista un canal privado permanente entre ambos.
- **No implica identidad compartida:** IAO conserva su propia identidad criptográfica y sus claves privadas. Nunca debe compartirlas con ChatGPT, peers, repositorios o proveedores.
- **No implica autoridad ilimitada:** las respuestas de cualquier LLM son propuestas no autoritativas. Los cambios de código requieren validación, pruebas, política, auditoría y rollback.
- **No implica control de infraestructura ajena:** IAO solo puede coordinar capacidades que un servicio externo anuncie y autorice explícitamente.

## Arquitectura objetivo

1. ChatGPT y otros LLM pueden asistir en razonamiento, generación de propuestas y revisión, a través de adaptadores explícitos.
2. El router de IAO selecciona proveedores según disponibilidad, capacidad, coste y políticas configuradas.
3. El plano de control determinista autentica solicitudes, aplica límites y registra decisiones.
4. PADGE ejecuta cambios en entornos aislados y solo promueve propuestas que superen las puertas de calidad.
5. La federación descubre peers, verifica identidades y negocia capacidades mínimas; descubrir un peer nunca equivale a confiar en él.
6. Las claves del operador y del dispositivo de mando permanecen separadas de la identidad pública de los nodos federados.

## Evidencia y estado

La atribución describe el proceso de construcción, no una certificación de capacidades. Consultar los workflows de GitHub Actions, los commits y los informes versionados para conocer qué está probado. Un build correcto no demuestra conectividad P2P pública, disponibilidad 24/7 ni despliegue productivo.

El objetivo compartido es investigar y construir sistemas de IA más autónomos, verificables y descentralizados sin sacrificar privacidad, seguridad ni control humano sobre las decisiones de alto impacto.

