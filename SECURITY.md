# Modelo de seguridad

PaqueteLupa revisa ZIP de soporte no confiables y produce información para una decisión humana. **No certifica seguridad, no detecta malware, no anonimiza archivos y no comprueba si una credencial funciona.** La ausencia de hallazgos puede ser un falso negativo.

## Fronteras de confianza

Los nombres, metadatos y bytes del ZIP se consideran no confiables. El analizador abre un archivo regular para lectura y conserva un descriptor durante la revisión. Rechaza enlaces/puntos de reanálisis en la entrada cuando puede detectarlos y comprueba cambios observables durante la lectura. El usuario debe mantener el archivo y su carpeta estables mientras se analiza; estas comprobaciones no sustituyen el aislamiento frente a un proceso local hostil.

El descriptor se lee sin caché de `BufferedReader`. Se calcula SHA-256 antes y después de inspeccionar o localizar, además de comparar metadatos, para detectar reescrituras persistentes del mismo tamaño aunque se restaure `mtime` o `ctime` represente creación en Windows. Es una comprobación de estabilidad; no es una instantánea inmutable ni protege frente a cambios posteriores o a un proceso hostil que restaure bytes entre lecturas.

No se extraen miembros del ZIP al sistema de archivos, no se ejecutan programas del paquete y no se envían datos por red. No se siguen destinos de enlaces del archivo. Las rutas peligrosas se notifican para prevenir un uso posterior inseguro del paquete; la herramienta no convierte un ZIP peligroso en uno apto para extraer.

La salida contiene solo metadatos y consejos constantes. Los IDs ordinales permiten relacionar hallazgos con el orden central sin publicar nombres. `--show-paths` incluye todos los nombres internos por solicitud del usuario; `--locate` revela solo el nombre seleccionado. Ambos pueden revelar personas, proyectos o credenciales. Ni el nombre del ZIP de entrada ni los de los archivos de informe se insertan automáticamente como título del reporte.

En Windows se rechazan tanto para entrada como para salida los flujos alternativos ADS, dispositivos, nombres reservados, recursos UNC, rutas relativas a una unidad y nombres ambiguos. La comprobación de rutas y archivos regulares no aísla el acceso frente a carpetas padre, junctions o enlaces controlados por un proceso local hostil. Utiliza carpetas de confianza.

## Identidad del ZIP y localización privada

La versión 0.2.0 calcula SHA-256 del ZIP dentro del presupuesto de lectura y la incluye en `archive.sha256`, en el HTML y en el texto cuando está disponible. `--expect-sha256` compara los bytes actuales con la huella esperada antes de devolver nombres. La comparación evita aplicar un ID ordinal a un ZIP diferente del informe anterior; la huella por sí sola no autentica al autor, no detecta malware y no es una firma.

`--locate entrada-00002` devuelve JSON con la entrada seleccionada y la identidad del ZIP. No incluye la lista de nombres ni el contenido de las entradas. La salida de terminal utiliza escapes JSON para neutralizar controles; `--json` permite conservar la misma información en un archivo nuevo. No admite `--html` ni `--show-paths`. La operación lee los bytes del contenedor para calcular su huella y valida la estructura necesaria para localizar el ID, pero no descomprime, interpreta ni comprueba el CRC del contenido de la entrada: su éxito no es un análisis completo ni un resultado sin hallazgos.

## Controles de recursos y formato

El perímetro máximo es 64 MiB físicos, 2 MiB de directorio central, 2.000 entradas, nombres de hasta 1.024 bytes y rutas de hasta 64 separadores, 8 MiB descomprimidos por entrada, 32 MiB totales, relación 100:1 y 500 hallazgos. Las lecturas y la descompresión aplican presupuestos; no se confía únicamente en los tamaños declarados.

El analizador comprueba cooperativamente un plazo de hasta 20 segundos, también durante la detección. La CLI utiliza además un proceso supervisado: el plazo de la operación es `--timeout` más 2 segundos de margen, hasta 22 segundos por defecto. Cubre la recepción completa del resultado, para que una transmisión IPC parcial no deje la espera sin plazo. La limpieza del proceso y del receptor puede añadir hasta 5 segundos. La API directa solo dispone de las comprobaciones cooperativas. **No hay cuota dura de memoria, contenedor de seguridad ni garantía frente a vulnerabilidades de Python, zlib o del sistema operativo.** Mantén actualizado el intérprete; para entradas deliberadamente hostiles, utiliza además aislamiento y cuotas del sistema operativo.

Solo se admite un subconjunto de ZIP clásico STORE/DEFLATE con coherencia entre cabeceras y directorio central. ZIP64, multidisco, autoextraíbles, huecos y campos extra de nombres/comentarios Unicode alternativos se rechazan. Cifrado, flags u otros formatos no admitidos dejan el análisis incompleto. Se revisan CRC y longitudes de datos leídos; **CRC no es una firma ni un control de malware**.

## Cobertura que no debe confundirse con seguridad

- Los binarios y archivos anidados no se analizan en busca de secretos. Se documentan como contenido sin revisar.
- UTF-8 y UTF-16 con BOM son las codificaciones de texto admitidas. Otros textos pueden quedar fuera.
- Los comentarios globales y por entrada se revisan con las reglas de secretos; se intenta interpretar UTF-8/UTF-16 con BOM y se recurre a CP437 como alternativa. Fechas extendidas, fechas NTFS y UID/GID Unix v1 se validan estructuralmente. Las longitudes de fechas extendidas deben corresponder a sus flags y al contexto local o central. Otros campos extra se señalan como cobertura incompleta; no se buscan secretos en ellos.
- Las ocho reglas detectan determinados formatos o contextos. Incluyen cabeceras PEM cifradas, frases entre comillas y aliases como `DB_PASSWORD`. Se conservan ubicaciones para CR/LF y separadores Unicode, y se añade una vista con eliminación limitada de ANSI, hasta dos capas de escapes y compatibilidad Unicode hacia ASCII. Esto no cubre todas las credenciales, formatos codificados, confusables Unicode, datos personales ni claves fragmentadas. Puede haber falsos positivos.
- La herramienta no descarga listas de firmas ni pregunta a proveedores si un token es válido. Esta decisión conserva el funcionamiento sin red y evita utilizar credenciales encontradas.
- `complete: true` significa que se completó el alcance admitido y configurado; no es una garantía sobre el contenedor completo. Los límites alcanzados y el contenido omitido requieren seguimiento manual.

## Informes y archivos de salida

HTML y texto no incluyen valores capturados por los detectores, líneas fuente ni huellas derivadas de esos valores; SHA-256 corresponde al ZIP completo. Por defecto omiten también los nombres; con `--show-paths`, los nombres originales sí pueden contener credenciales. El HTML escapa los datos, no usa JavaScript ni recursos externos y declara una política CSP restrictiva. El texto neutraliza controles de terminal y caracteres de dirección que podrían falsear su visualización. Los campos y filas de presentación están acotados; el JSON conserva el detalle del informe generado por el analizador.

Las salidas se crean exclusivamente y deben ser archivos regulares nuevos, sin sobrescribir destinos existentes. Se usa modo `0600` en POSIX, restringido por cualquier umask más estricta; en Windows se heredan las ACL de la carpeta y no se impone una ACL privada adicional. La suite incluye una comprobación de permisos POSIX, omitida al ejecutarse en Windows; no debe interpretarse una ejecución Windows como validación de ese control en POSIX.

Un fallo de escritura puede dejar un informe parcial: comprueba el código de salida y no interpretes ese archivo como una ejecución completa. Guarda las salidas en una carpeta de confianza; la herramienta no protege frente a modificaciones posteriores por otros procesos locales.

## Si se confirma una exposición

Detén el envío del paquete. Revisa el archivo original en un entorno apropiado, prepara una copia sin el dato sensible y vuelve a analizarla. Si el secreto ya se compartió, revócalo o rótalo en su proveedor y revisa los registros de acceso. Borrar una cadena de un ZIP no invalida una credencial expuesta.

Para investigar un fallo de la herramienta, conserva primero un caso mínimo con datos sintéticos. Incluye la versión de Python, el código de salida y cómo reproducirlo. No adjuntes ZIP de producción, credenciales ni informes con rutas sensibles a un canal público.
