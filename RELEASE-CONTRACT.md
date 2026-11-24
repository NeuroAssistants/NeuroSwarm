# Verificar una entrega de la consola

Desde la raíz del paquete que se va a publicar, ejecutá este comando antes y después del cambio de versión.

```sh
python3 deploy/check_release.py https://console.example.org --candidate .
```

El comando devuelve **0** si coinciden el manifiesto, las dos páginas y los seis archivos JavaScript y CSS, y pasan los siete controles del servicio. Una diferencia, un recurso ausente o un error de conexión o de certificado devuelve un código distinto de cero. Cada recurso se descarga completo hasta su tamaño previsto más un byte. La comparación utiliza la representación descomprimida y la URL con versión que carga el navegador. El verificador solo visita el origen indicado y utiliza las rutas de la candidata local.

La opción `--candidate` también acepta la ruta a otro paquete extraído. Por defecto se usa el paquete que contiene el verificador. Para una instancia temporal en la misma máquina se admite HTTP en loopback. Para un dominio se exige HTTPS con un certificado de confianza. Se puede usar `SSL_CERT_FILE` para indicar la CA privada de una instalación.

## Contrato público

`GET /api/v1/version` devuelve JSON sin autenticación, con `Cache-Control: no-store`. `HEAD` entrega las mismas cabeceras. `GET /health` indica dónde consultar el manifiesto mediante `version_url`.

| Campo | Contenido |
| --- | --- |
| `schema_version` | Entero `1`, la versión de este contrato. |
| `version` | Identificador de la entrega, con prefijo `sha256:` y los 64 dígitos hexadecimales de la huella. |
| `runtime_sha256` | Huella agregada de los módulos Python de `backend/*.py`, `backend/adapters/*.py` y `agent/*.py` del paquete al arrancar el servidor. |
| `assets` | Mapa con las rutas públicas de los seis JS y CSS. Cada entrada contiene `sha256` y `bytes`. La URL de navegador agrega `?v=` y los primeros 12 dígitos de la huella. |
| `pages` | Mapa con `/` y `/live`. Los mismos campos describen el HTML servido después de insertar las URLs versionadas. `/index.html` es un alias de `/`. |

La entrada para `runtime_sha256` es un objeto que asocia cada ruta relativa del paquete con el SHA-256 de sus bytes. Para calcular `version` se toman los cuatro campos restantes del manifiesto. En ambos casos se aplica SHA-256 al JSON con claves ordenadas, separadores compactos `,` y `:` y escape ASCII. Dos extracciones del mismo código producen el mismo identificador independientemente de su directorio, fechas o disponibilidad de Git.

La identidad de Python corresponde al arranque del proceso. El manifiesto lee la interfaz que se sirve en ese momento, lo que permite cambiar los recursos estáticos en caliente. Durante un cambio de archivos, dos peticiones pueden ver versiones distintas y el verificador lo señala. El identificador pertenece al paquete de consola. Los observadores ya instalados en cada máquina informan su propia versión.

## Alcance de la comprobación

El verificador contrasta los bytes públicos de la interfaz y la identidad de Python declarada por el servidor. Los instaladores generados por origen conservan su control de disponibilidad. La consulta es anónima y el manifiesto solo contiene metadatos del paquete. La comprobación de una sesión y una edición reales necesita acceso de operador.

Al publicar, registrá en `CHANGELOG.md` la fecha, el identificador que pasó por HTTPS y el resultado de la comprobación con sesión. Para verificar una reversión, repetí el comando apuntando a la extracción de la versión restaurada.
