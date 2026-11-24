# Colaboración local de OpenBot

En la candidata, `GET /api/v1/work-board` incorpora `collaboration.changes`. Cada cambio representa una tarea raíz que ya tiene al menos una asignación hija en el mismo canal. La raíz figura también en `tasks` con `parent_id: null`, para identificar quién coordina. Los demás `parent_id` conservan la relación registrada. Dos tareas con objetivos parecidos pueden pertenecer a cambios diferentes.

## Activación en el servidor de Control

Configurá `SWARMCONTROL_OPENBOT_CHANNEL_ID` con el identificador exacto de **un canal**. Esa variable habilita únicamente la lectura de colaboración. `SWARMCONTROL_OPENBOT_CONFIG` puede señalar el directorio que contiene `openbot.db` (por defecto, `~/.config/OpenBot` del proceso de Control). El servicio necesita lectura del SQLite y, si OpenBot usa WAL, de sus archivos auxiliares. Para una instalación en contenedor usá un montaje local de solo lectura que también permita leer la vista WAL actual.

La organización legada **1** recibe los cambios del canal elegido. Los lectores autorizados del tablero de esa organización, incluidos sus tokens de lectura, comparten ese alcance. El navegador y los observadores remotos no eligen el canal. Las demás organizaciones reciben `{"changes":[]}`, incluso si tienen un administrador o un token con el mismo nombre. Dejar la variable vacía desactiva la función. No hace falta habilitar la inspección de carpetas, configurar GitHub ni instalar OpenBot en las máquinas observadas.

## Contrato y evidencia

El campo aparece también al pedir `?include=activity`. Una instalación sin OpenBot, un canal vacío o una fuente inaccesible devuelven una colección vacía y se conservan los demás campos del tablero.

| Campo | Significado |
| --- | --- |
| `changes[].id`, `tasks[].id` | Identificadores de tareas de OpenBot. El del cambio es el de su tarea raíz. |
| `title` | Objetivo breve del cambio o trabajo asignado a la persona o agente responsable. |
| `status` | Estado registrado de esa tarea. El del cambio es el de la raíz, sin deducirlo de los hijos. |
| `tasks[].agent` | Nombre registrado del agente. Ante un perfil no disponible se muestra una etiqueta genérica. |
| `tasks[].parent_id` | Tarea que hizo la asignación. Un nieto conserva su padre inmediato. |
| `tasks[].result` | Resumen breve de la entrega formal vigente. Cadena vacía mientras no haya una entrega atribuible. |
| `updated_at` | Segundos Unix UTC de la evidencia asociada más reciente. En el cambio incluye los hijos. Un valor nulo significa que falta una fecha válida. |

## Qué se comparte

El lector abre una transacción SQLite con `mode=ro` y `query_only`. Solo usa las proyecciones locales de tareas, asignaciones, mensajes del canal seleccionado y los nombres de sus responsables. Al cambiar de organización, la API resuelve primero la membresía o el token de Control. Para otra organización ni siquiera abre la fuente. Cada consulta lee los datos vigentes en una instantánea consistente. Control no los copia a su base, no conserva una caché del canal y responde con `Cache-Control: no-store`.

El título proviene de la instrucción de la tarea o de su objetivo esperado. El resultado requiere una entrega formal del mismo agente, tarea, canal y revisión. Una entrega reemplazada queda fuera. La actividad ordinaria aporta como máximo su fecha. El texto de conversaciones, planes de chat, adjuntos, archivos y registros de herramientas queda fuera de la consulta de contenido.

El resumen toma una frase de hasta 160 caracteres para la asignación y 180 para la entrega. El filtro descarta material técnico que identifica como privado, entre ello rutas, enlaces, instrucciones de consola, bloques de código y credenciales reconocibles. Si no encuentra una frase adecuada, conserva la evidencia de la asignación o entrega con una etiqueta genérica. Los objetivos y nombres son información compartida con los lectores de la organización. Un filtro de patrones no puede identificar un dato confidencial escrito como prosa corriente.

## Alcance y verificación

Aparecen hasta 12 cambios y 48 tareas por cambio. Se priorizan las raíces abiertas y las solicitudes más recientes. Solo se incluyen descendientes que pueden conectarse con su raíz. Para fechar cada tarea se consideran la solicitud, la entrega formal, la fecha propia si la fuente la ofrece y los metadatos de los últimos 512 mensajes del canal. La hora representa la última evidencia disponible y puede ser anterior a una transición de estado sin fecha. Una fuente bloqueada, dañada o con un esquema incompatible deja disponible el resto del tablero.

Estos comandos ejecutan las pruebas del lector y de aceptación HTTP desde la raíz del proyecto.

```bash
python3 -m unittest discover -s tests -p test_work_collaboration.py -v
python3 -m unittest discover -s tests -p test_collaboration_acceptance.py -v
```
