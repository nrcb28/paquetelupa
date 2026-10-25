# PaqueteLupa 0.2.0

Revisa localmente un ZIP de soporte antes de compartirlo o extraerlo. Busca posibles credenciales en texto, nombres de entradas y comentarios ZIP, y señala rutas peligrosas, colisiones, enlaces y estructuras sospechosas. Genera informes sin valores capturados ni fragmentos de archivos. Por defecto también omite nombres; `--show-paths` los incluye y puede revelar secretos presentes en ellos.

**Un resultado sin coincidencias no certifica que el paquete sea seguro.** La herramienta no es un antivirus ni anonimiza el ZIP. El original se abre solo para lectura; no se extrae ni se ejecuta su contenido y no se hacen peticiones de red.

## Empezar

Requiere **Python 3.11 o posterior**, con su biblioteca estándar. No requiere instalar paquetes de terceros. Abre una terminal en esta carpeta:

```console
python -m paquetelupa archivo.zip --html informe.html --json informe.json
```

La terminal muestra el resumen. El HTML se puede abrir directamente en un navegador y no utiliza JavaScript ni recursos externos. El JSON permite automatizar la revisión. Las salidas se crean de forma exclusiva: si un destino ya existe, el comando falla para evitar sobrescribirlo. Elige nombres nuevos para cada ejecución.

```console
python -m paquetelupa --help
python -m paquetelupa archivo.zip
```

Por privacidad, los informes identifican cada entrada como `entrada-00001`, siguiendo el orden del directorio central del ZIP. No reflejan el nombre del ZIP de entrada ni el de los archivos de informe. Si necesitas ver las rutas internas, añádelas expresamente:

```console
python -m paquetelupa archivo.zip --show-paths --html informe-con-rutas.html
```

**`--show-paths` expone nombres que pueden ser sensibles o contener secretos.** Conserva ese informe con el mismo cuidado que el ZIP. La revisión de nombres se realiza también cuando se omiten del informe.

## Localizar un hallazgo sin revelar todos los nombres

Desde la versión 0.2.0 puedes consultar una sola entrada del ZIP:

```console
python -m paquetelupa archivo.zip --locate entrada-00002
python -m paquetelupa archivo.zip --locate entrada-00002 --json ubicacion.json
```

El resultado es JSON en la terminal y, si lo pides, en un archivo nuevo. Contiene **solo el nombre seleccionado**, su ID, tamaños y la identidad del ZIP; ese nombre puede ser sensible. Los controles y caracteres especiales se representan con escapes JSON. Esta operación no inspecciona ni descomprime el contenido de la entrada, no extrae archivos y no equivale a un análisis de seguridad. `--locate` es incompatible con `--html` y `--show-paths`.

Los informes de análisis incluyen una huella en `archive.sha256` cuando se pudo leer el ZIP dentro del presupuesto. También aparece en el HTML y en el texto. Para relacionar el ID de un informe anterior con exactamente los mismos bytes, añade `--expect-sha256` al comando de localización o al análisis. Sustituye el marcador del ejemplo por los 64 caracteres hexadecimales de la huella:

```console
python -m paquetelupa archivo.zip --locate entrada-00002 --expect-sha256 "HUELLA_HEXADECIMAL_DEL_INFORME"
```

Si no coincide, el comando falla antes de revelar nombres. Sin esa opción, el ID se interpreta sobre el archivo suministrado en esa ejecución. **SHA-256 identifica bytes; no es una firma ni prueba autenticidad o seguridad.**

## Interpretar el resultado

| Código | Estado | Qué hacer |
| --- | --- | --- |
| `0` | `no_findings` | No se registraron coincidencias dentro del alcance. Comprueba las limitaciones antes de compartir. |
| `1` | `review` | Hay hallazgos que requieren revisión manual. |
| `2` | `incomplete` | Parte del análisis no se completó: contenido omitido, estructura no admitida o límite alcanzado. Puede haber además hallazgos. |
| `3` | Error operativo | No se pudo ejecutar o guardar correctamente la revisión. Corrige el problema y repite. |

En modo `--locate`, `0` significa que se localizó la entrada solicitada; el JSON lleva `operation: "locate"` y no contiene un estado de análisis. Un ID que no existe o una huella diferente devuelve `3`.

Los argumentos inválidos también devuelven `2`, mediante el parser de la CLI, sin generar un informe de análisis. Si automatizas el comando, comprueba que se haya creado el JSON esperado antes de interpretar su estado.

El estado incompleto tiene prioridad sobre los hallazgos. `complete: true` solo expresa cobertura del alcance admitido; no significa que se hayan buscado todos los tipos de secretos ni inspeccionado todos los bytes del contenedor.

Si aparece una credencial potencial:

1. Localiza la entrada por su ID mediante `--locate` y conserva la huella con `--expect-sha256`; después revisa la línea indicada, cuando exista, en un entorno adecuado. Si necesitas todas las rutas, genera un nuevo informe privado con `--show-paths`.
2. Confirma manualmente si el valor es sensible. Hay falsos positivos y falsos negativos; la herramienta no verifica credenciales con sus proveedores.
3. Retira el valor del paquete de soporte o genera otro paquete con los datos necesarios. PaqueteLupa no modifica ni limpia archivos.
4. Si una credencial real ya se compartió, revócala o rótala en su proveedor y revisa su uso. No basta con borrar el valor del siguiente ZIP.
5. Repite el análisis sobre el paquete nuevo y revisa también todo el contenido omitido.

## Alcance y límites

Se admite un subconjunto conservador de **ZIP clásico con STORE o DEFLATE**. Se comprueban cabeceras, tamaños y CRC de las entradas leídas; el CRC detecta incoherencias, pero no prueba autenticidad ni ausencia de malware.

| Presupuesto máximo | Valor |
| --- | --- |
| Tamaño físico del ZIP | 64 MiB |
| Directorio central | 2 MiB |
| Entradas | 2.000 |
| Nombre de entrada | 1.024 bytes |
| Profundidad de ruta | 64 separadores |
| Datos descomprimidos por entrada | 8 MiB |
| Datos descomprimidos totales | 32 MiB |
| Relación declarada de descompresión | 100:1 |
| Hallazgos registrados | 500 |
| Tiempo del analizador | 20 segundos, mediante comprobaciones cooperativas |

La CLI ejecuta la operación en un proceso supervisado. El plazo es `--timeout` más 2 segundos de margen, hasta 22 segundos por defecto, y cubre también la recepción completa del resultado. La limpieza de recursos puede añadir hasta 5 segundos. `--timeout` permite reducir el tiempo de análisis. Estos controles **no constituyen un límite duro de memoria ni un sandbox del sistema operativo**. Los límites máximos no se pueden elevar mediante la API de esta versión; se pueden reducir.

- ZIP64, multidisco, prefijos autoextraíbles, huecos entre registros y nombres/comentarios Unicode alternativos en campos extra quedan fuera del formato admitido. Variantes de flags, cifrado y otros métodos de compresión se marcan como incompletos.
- No se inspeccionan recursivamente archivos anidados. Los binarios y codificaciones no admitidas se señalan como contenido sin revisar. El texto admitido es UTF-8 y UTF-16 con BOM.
- Los comentarios globales del ZIP y de cada entrada se buscan también en el detector; se interpreta texto UTF-8/UTF-16 con BOM y se usa CP437 como alternativa. Se reconocen campos extra de fechas extendidas, fechas NTFS y UID/GID Unix v1, validados estructuralmente. Las fechas extendidas se validan según sus flags y su ubicación en cabecera local o directorio central. Los demás campos extra dejan cobertura incompleta; no se buscan secretos en sus bytes.
- La detección usa ocho reglas heurísticas: cabeceras de claves privadas, incluidos PEM cifrados; identificadores AWS; tokens GitHub; claves Stripe de producción; asignaciones de contraseñas/tokens, incluidas frases entre comillas y nombres como `DB_PASSWORD`; cabeceras HTTP de autenticación; contraseñas en URL de servicios; y cadenas con estructura JWT.
- Se consideran separadores de línea CR/LF y Unicode, algunos códigos ANSI y hasta dos capas de escapes habituales. Hay normalización limitada de caracteres Unicode compatibles con ASCII. Son vistas adicionales para buscar patrones, no un decodificador universal: quedan fuera otras codificaciones, ofuscación arbitraria y muchos proveedores y datos personales.
- Los informes omiten valores, líneas fuente, huellas de secretos y fragmentos de evidencia. Aun así, el informe revela metadatos como tamaños, reglas y números de línea; trátalo como información interna.

Más detalles en [SECURITY.md](SECURITY.md). La motivación y los productos existentes se documentan en [RESEARCH.md](RESEARCH.md).

En Windows se rechazan rutas de entrada y salida con flujos alternativos ADS, dispositivos o nombres reservados, recursos UNC, rutas relativas a una unidad y nombres ambiguos. Guarda los informes en carpetas de confianza. En POSIX las salidas nuevas se crean con modo `0600`; en Windows se heredan las ACL de la carpeta.

Si dispones del archivo portable de esta entrega, puedes ejecutarlo con Python usando su ruta, por ejemplo `python "C:\ruta\PaqueteLupa-0.2.0.pyz" archivo.zip`. No necesita instalar el módulo. Los cambios de versión están en [CHANGELOG.md](CHANGELOG.md).

## Uso en CI y comprobaciones

En un trabajo que ya tenga disponible esta carpeta y Python, el código de salida permite bloquear una entrega cuando hay hallazgos, cobertura incompleta o errores:

```yaml
- name: Revisar el paquete de soporte
  run: python -m paquetelupa soporte.zip --json revision.json --html revision.html
```

Usa destinos nuevos en cada ejecución. Revisa las reglas de conservación y acceso antes de publicar los informes como artefactos de CI, especialmente si incluyes rutas.

Ejecuta la suite desde esta carpeta:

```console
python -m unittest discover -s tests -v
```

Las pruebas emplean datos sintéticos; no requieren credenciales reales ni acceso a servicios externos.
