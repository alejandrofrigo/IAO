# IAO — Registro de continuidad

Actualizado: 2026-10-31T15:05:33-04:00

## Objetivo permanente
Construir IAO como sistema inteligente integrado, verificable y con autonomía operativa controlada.

## Reglas de continuidad
1. Recuperar este registro al comenzar cada sesión.
2. Verificar el estado real antes de continuar.
3. Preservar modificaciones, archivos nuevos y respaldos.
4. Toda reparación debe incluir respaldo, validación y reversión.
5. No considerar una capacidad terminada sin pruebas.
6. Registrar resultados y siguiente acción.

## Estado del repositorio
```
 M .gitignore
 M artifacts/MANIFEST.sha256
 M artifacts/backup-restore-report.json
 M artifacts/network-connectivity.json
 M artifacts/runtime-report.json
 M artifacts/runtime.log
 M omega/egress.py
 M omega/evolution.py
 M omega/federation.py
 M omega/iao_router.py
 M omega/llm_router.py
 M omega/server.py
 M omega/service.py
 M tests/test_egress.py
 M tests/test_federation.py
 M tools/iao_autonomy.py
 M tools/iao_autonomy_cycle.py
 M tools/iao_boot.py
 M tools/iao_continuity.py
 M tools/iao_federation_agent.py
 M tools/iao_federation_contract.py
 M tools/iao_guardian.py
 M tools/iao_watchdog.py
 M web/api-config.js
 M web/index.html
?? -sb
?? .iao_http405_backup_20261028T111535Z/
?? IAO_HTTP405_DIAGNOSTICO.txt
?? IAO_REPARACION_DESPLIEGUE.txt
?? docs/corpus/iao-feed-ingest.txt
?? docs/corpus/iao-feed-ingest.txt.backup-20261028T044911Z
?? docs/corpus/iao-feed-ingest.txt.backup-20261028T054913Z
?? logs/
?? omega/adapters/model.py.bak
?? omega/adapters/model.py.bak-groq
?? omega/adapters/model.py.bak.20261026_142232
?? omega/adapters/model.py.bak_identity_20261025-213246
?? omega/adapters/model.py.pre_config_fix_20261024-171622.bak
?? omega/autonomous_coordinator.py
?? omega/autonomous_core.py
?? omega/config.py.pre_config_fix_20261024-171622.bak
?? omega/federation_assimilation.py
?? omega/federation_identity.py
?? omega/federation_ledger.py
?? omega/federation_proposals.py
?? omega/jobs.py.bak
?? omega/jobs.py.pre_flock.bak
?? omega/llm_router.py.bak-20261026-083509
?? omega/server.py.before_adapter_precedence_20261028_121050.bak
?? omega/server.py.before_persistent_audit_key.bak
?? omega/server.py.pre_cors_repair_20261029T151909Z.bak
?? omega/server.py.pre_public_chat.bak
?? omega/server.py.pre_web.bak
?? omega/service.py.bak-router-fix-20261028-115408
?? omega/service.py.pre_adapter_precedence_20261027_104642.bak
?? omega/service.py.pre_public_chat.bak
?? omega_body.tmp
?? omega_headers.tmp
?? tests/test_autonomous_core.py
?? tests/test_federation_assimilation_security.py
?? tests/test_federation_proposals.py
?? tests/test_service.py.before_model_test_fix.bak
?? tools/iao_autonomous_core.py
?? tools/iao_autonomy_cycle.py.pre_syntax_fix_20261027_103358.bak
?? tools/iao_autonomy_daemon.py
?? tools/iao_control_plane.py
?? tools/iao_control_plane_local.py
?? tools/iao_federation_autonomy.py
?? tools/iao_federation_binding.py
?? tools/iao_federation_candidate_verify.py
?? tools/iao_federation_discover.py
?? tools/iao_federation_identity.py
?? tools/iao_federation_worker.py
?? tools/iao_flow.py.bak_opener_20261028_000819
?? tools/iao_github_discovery.py
?? tools/iao_probe_documented_apis.py
?? tools/iao_universal_cycle.py
?? tools/iao_universal_enablement.py
?? tools/iao_universal_evaluate.py
?? tools/iao_universal_integrator.py
?? tools/iao_universal_registry.py
?? tools/iao_universal_sync.py
?? web/index.html.bak_405_20261028_061654
?? web/index.html.pre_http405_20261028T112210Z.bak
```

Rama: iao-repair-http405-20261028T113227Z
Commit: a79b6d9f50ea90b00b1e361ab909b8c073c7c0a4

## Estado de servicios
Puerto 8080: LIBRE
Puerto 8765: LIBRE
Puerto 8766: LIBRE

## Próximas prioridades
1. Arranque y salud del supervisor.
2. Continuidad persistente y recuperación de tareas.
3. Autonomía controlada: observar, planificar, ejecutar y validar.
4. Conexión funcional del chat público.
5. Federación segura de nodos.

## Limitación
Este registro conserva el estado; no ejecuta tareas en segundo plano ni inicia sesiones automáticamente.
