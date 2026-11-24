# Seguimiento de incidentes repetidos

Desde **Alerts → Incident #** en la consola o **Live → seleccionar alerta → Incident # · History** se puede asignar un responsable, reconocer el caso, ver las mediciones y comprobar cómo terminó. Una lectura que vuelve a disparar la misma regla después de la recuperación crea otro incidente. **Previous incident** abre el anterior.

## Caso de aceptación

La prueba usa dos organizaciones locales que tienen una máquina llamada `rack-01`. Los valores de esta tabla son datos de prueba.

| Observación o acción en la primera organización | Resultado |
|---|---|
| RAM al 96 % | Abre el caso 1 con una señal. |
| Se asigna el caso a `oncall` y llega otra lectura al 96 % | El caso 1 tiene dos señales y conserva el responsable. |
| `first-admin` reconoce el caso y llega una lectura al 97 % | El caso 1 queda reconocido, con tres señales. El estado de salud del equipo sigue siendo crítico. |
| Llega un latido que solo informa la memoria total | La recuperación sigue pendiente. |
| RAM al 72 % | El sistema cierra el caso 1. El historial conserva las tres lecturas altas, el reconocimiento, el responsable y la medición de recuperación. |
| RAM al 96 % otra vez | Abre el caso 2 con una señal y un enlace al caso 1. Queda disponible para asignar y reconocer. |

En cada organización los IDs son locales. La segunda puede tener su propio caso 1 para la misma regla y el mismo nombre de máquina. El historial y los candidatos a responsable pertenecen a la organización de la sesión.

## Qué queda registrado

- Se mantiene un solo caso `OPEN` o `ACKED` por organización, `host_id` y `rule_code`. La escritura de la señal, el contador y su historial se confirma en una transacción. El contador suma observaciones recibidas que disparan la regla. El protocolo de latidos actual carece de un ID de muestra que permita distinguir un reenvío del observador de una nueva lectura idéntica.
- Asignar y reconocer son acciones independientes. Si el caso todavía está sin asignar, el primer reconocimiento lo asigna a quien lo hizo. Una repetición conserva responsable, primer reconocimiento y fecha. Se puede reasignar o dejar sin asignar mientras siga activo. Una baja posterior del usuario conserva el nombre en la historia.
- RAM, CPU, RSS y cantidad de procesos se recuperan con una medición válida bajo el umbral correspondiente. Un latido recibido cierra la alerta de latido ausente. Los refrescos de pantalla no agregan señales para la misma interrupción. Las reglas de bucle, cuota y exposición de secretos requieren que un operador confirme la recuperación. La confirmación manual queda identificada por separado y registra quién la hizo.
- Cada señal conserva valores de medición y, si existe, el último paso registrado por el diario en esa máquina al observarla. La resolución también registra el paso disponible en ese momento. El detalle muestra agente, sesión, acción, herramienta y archivos relativos confirmados. La proximidad temporal no demuestra qué agente causó el incidente. Un evento genérico, una mención de archivo o un campo ausente no aportan esa evidencia. Cuando falta un paso, la consola lo indica.
- Los casos guardan estos datos en la base de recursos hasta que se archive la instancia. El resumen conservado puede sobrevivir a la rotación del diario de siete días. La proyección excluye argumentos de comandos, conversaciones, contenido de archivos y mensajes crudos del error.

## API

| Ruta | Uso |
|---|---|
| `GET /api/v1/alerts?status=ACTIVE` | Últimos 100 casos abiertos o reconocidos. También admite `ALL`, `OPEN`, `ACKED` y `RESOLVED`. El valor predeterminado del cliente legado sigue siendo `OPEN`. |
| `GET /api/v1/alerts/<id>` | Devuelve `organization`, `alert`, `history` y `next_before`. Los historiales se recorren de a 50 movimientos, del más reciente al más antiguo, con `?before=<next_before>`. |
| `POST /api/v1/alerts/<id>/owner` | `{"owner_id": 42}` asigna un miembro operador o administrador del espacio. `{"owner_id": null}` lo deja sin asignar. El detalle incluye `assignees` para quienes pueden gestionar un caso activo. |
| `POST /api/v1/alerts/<id>/ack` | Acepta `{}`. Conserva la respuesta anterior `ok`, `alert_id` y `host_status` y agrega el caso actualizado. |
| `POST /api/v1/alerts/<id>/resolve` | `{"reason":"operator_verified"}` confirma que alguien verificó la recuperación. Repetir el mismo cierre conserva actor y fecha. |

`alert` incluye `occurrence_count`, `count_is_minimum`, `owner`, `created_at`, `last_seen_at`, `updated_at`, `acked_by`, `acked_at`, `resolved_by`, `resolved_at`, `resolution`, `last_step`, `previous_id` y `evidence`. Los tiempos son segundos Unix. `last_seen_at` corresponde a la última señal de fallo. El movimiento `resolved` guarda la evidencia de la recuperación. Tanto el flujo incremental como el histórico usan el ID canónico del caso.

Pueden leer los miembros del espacio y los tokens de lectura. Las escrituras requieren sesión de operador o administrador. El servidor toma la identidad de esa sesión. La interfaz envía además `organization_id` en las mutaciones y en la lectura del detalle. Si la organización activa ya cambió, responde `409`. Las mutaciones que intenten modificar un caso cerrado también responden `409`, salvo la repetición de una resolución válida.

## Migración y recuperación

El servidor migra al esquema de recursos 2 al abrir cada base de organización. La creación de tablas, la conversión y el registro de versión ocurren en una transacción por base. Se mantienen las rutas del agente, la base legada y las bases hermanas de otros espacios. Un diario anterior puede continuar enviando pasos con el formato anterior. La marca de procedencia que habilita el contexto de incidentes se escribe a partir de la actualización del diario o de la ingesta remota.

De las filas de alertas legadas con la misma regla y máquina, se consolidan las que carecen de una recuperación registrada entre ellas. El caso conserva el primer ID. Consultar o reconocer cualquiera de sus antiguos IDs apunta al mismo caso. Una recuperación documentada establece el límite con el siguiente episodio. Las filas originales quedan en `incident_v1_snapshots` para revisión local. La API publica la proyección depurada y los hashes de auditoría existentes se conservan.

La versión anterior sobrescribía mediciones y no registraba asignaciones independientes. Por eso el contador migrado se muestra como **At least**, el primer reconocimiento humano conocido aporta el responsable inicial y la evidencia que no consta permanece desconocida.

Para una reversión operativa, hacer una copia de la instancia completa con los escritores detenidos antes de migrar. Restaurar esa copia en un directorio nuevo para usar el servidor anterior. Las escrituras posteriores al momento de la copia solo están en la instancia migrada. La herramienta incluye la base principal y sus bases de organización. [Guía de copia y restauración](self-host.md)

El primer comando imprime la ruta de la copia. Usar esa ruta como `SNAPSHOT_DIR` y un destino nuevo como `RESTORE_DIR` al ensayar la restauración.

```bash
python3 deploy/backup.py snapshot "$STATE_DIR" "$BACKUP_DIR"
python3 deploy/backup.py restore "$SNAPSHOT_DIR" "$RESTORE_DIR"
```

## Reproducir

Desde la raíz del repositorio, con el Chromium de pruebas instalado, este comando levanta consolas temporales de loopback y ejecuta el caso HTTP, las pruebas de migración y concurrencia y el recorrido en escritorio y móvil emulado.

```bash
python3 -m unittest discover -s tests -p 'test_incidents.py' -v
```

`SWARMCONTROL_BROWSER_ARTIFACTS` permite indicar un directorio para guardar la captura del incidente resuelto. La prueba usa cuentas y datos sintéticos y limpia las bases temporales al terminar.
