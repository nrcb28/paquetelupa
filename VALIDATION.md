# Validación de PaqueteLupa 0.2.0

Fecha: 25 de octubre de 2026. Entorno local: Python 3.12.14, Windows. La matriz de GitHub Actions ejecuta además Windows y Ubuntu con Python 3.11, 3.12 y 3.13. Consulta el resultado del commit utilizado en [GitHub Actions](https://github.com/nrcb28/paquetelupa/actions).

## Pruebas y revisión

- Suite unittest local: **208 pruebas, 206 superadas y 2 omitidas**: creación de symlinks sin privilegios Windows y permisos POSIX no disponibles en Windows. Las pruebas de enlaces almacenados dentro del ZIP sí se ejecutan.
- Cobertura: STORE/DEFLATE, ZIP vacío y streaming, descriptores con/sin firma, CRC y tamaños reales, cabeceras divergentes, ZIP64, solapamientos, datos sobrantes, rutas Windows/POSIX, colisiones y directorios ambiguos; límites exactos y excedidos; comentarios/metadatos opacos; credenciales y privacidad; HTML/terminal; procesos, cancelación y salidas exclusivas.
- Revisión del código por agentes independientes de la implementación inicial. Los defectos encontrados se reprodujeron antes de corregirse. Esto no es una auditoría externa ni una demostración formal.
- Pruebas de llamadas comunes de red bloqueadas durante el worker, ausencia de extracción y preservación de las entradas sintéticas. El código de ejecución no utiliza clientes de red.

La evidencia actual y los hashes SHA-256 de los módulos comprobados están en `examples/validation-0.2.0.json`. `examples/validation.json` conserva la evidencia anterior de 0.1.0.

Se añadieron regresiones para ADS/dispositivos Windows, permisos de salida, recepción IPC incompleta, campos de fecha con bytes no declarados, normalizaciones acotadas de logs, identificadores de credenciales habituales y localización de una entrada con identidad SHA-256. El empaquetador usa un manifiesto explícito; se prueba que informes y ZIP ajenos al manifiesto no entren en la entrega. El workflow de GitHub configura la suite en Windows y Ubuntu con Python 3.11, 3.12 y 3.13; el resultado de CI debe consultarse en cada commit.

La primera ejecución de CI descubrió que `ctime` no detectaba de forma portable una reescritura con `mtime` restaurado. Se corrigió mediante segunda lectura SHA-256 sin buffering y se añadieron dos regresiones con metadatos simulados idénticos. Se mantienen las limitaciones frente a procesos locales hostiles que alteren y restauren bytes deliberadamente entre comprobaciones.

## Mutaciones y recursos

El harness reproducible usa entradas pequeñas sintéticas, mutaciones de bytes/estructuras y 100 ZIP válidos por ejecución. Verifica ausencia de excepciones inesperadas, coherencia de estados, entrada intacta, ausencia de extracción en la carpeta de pruebas y ausencia de secretos centinela en JSON por defecto.

| Evidencia | Semilla | Mutaciones | Total de casos | Resultado |
| --- | --- | ---: | ---: | --- |
| `examples/fuzz-0.2.0-stability-20261025.json` | 20261029 | 1.000 | 1.104, incluidos benchmarks | Aprobado tras corrección de estabilidad |
| `examples/fuzz-0.2.0-final-20261025.json` | 20261028 | 5.000 | 5.104, incluidos benchmarks | Aprobado, versión 0.2.0 |
| `examples/fuzz-0.2.0-20261025.json` | 20261027 | 5.000 | 5.104, incluidos benchmarks | Aprobado, revisión previa de 0.2.0 |
| `examples/fuzz-20261025.json` | 20261025 | 5.000 | 5.104, incluidos benchmarks | Aprobado |
| `examples/fuzz-final-20261025.json` | 20261025 | 5.000 | 5.102 | Aprobado |
| `examples/fuzz-final-pathfix-20261025.json` | 20261026 | 5.000 | 5.102 | Aprobado |

La semilla 20261025 se repitió en 0.1.0; las repeticiones no representan 10.000 mutaciones independientes. Las tres primeras filas corresponden a esta revisión de seguridad; las demás conservan evidencia histórica.

Benchmarks sintéticos STORE de la revisión final de 0.2.0, en este equipo: 8 MiB descomprimidos en aproximadamente 4,2 segundos; 32 MiB en aproximadamente 15,2 segundos, dentro del plazo predeterminado. La medición histórica con tracemalloc de 0.1.0 observó picos de asignaciones Python de aproximadamente 16 y 32 MiB respectivamente; no se presenta como medición de 0.2.0. **No mide RSS, memoria nativa ni consumo total del proceso y no implica una cuota dura de memoria.**

El harness también verificó que su informe no sobrescribe destinos existentes y que su supervisor responde al timeout. La CLI dispone de pruebas separadas de timeout, cierre de pipes, terminate/join/kill y cancelación.

Reproducir desde esta carpeta:

```console
python -m unittest discover -s tests -v
python tools/fuzz_smoke.py --seed 20261026 --cases 5000 --json nueva-validacion.json
python tools/fuzz_smoke.py --cases 5000 --benchmark --tracemalloc
```

## Presentación y empaquetado

El HTML estático dispone de pruebas de escape frente a XSS, CSP restrictiva y ausencia de recursos externos. El texto neutraliza controles y caracteres de dirección. **No se completó una inspección visual en navegador:** su política bloqueó la URL local `file:`. No se intentó eludir ese bloqueo.

La entrega incluye código fuente y una aplicación ZIP de Python (`.pyz`). El generador usa `.release-manifest.json` y fija orden, fechas y metadatos del ZIP; se comprueba reproducibilidad en este entorno y ejecución del `.pyz`. El manifiesto debe revisarse cuando se incorporan archivos de entrega. `PaqueteLupa-0.2.0-SHA256SUMS.txt`, en la carpeta superior, permite comprobar ambos paquetes; `SHA256SUMS.txt` conserva también las versiones anteriores. Los hashes no son una firma de autor ni un certificado de seguridad.

Las pruebas no cubren todos los ZIP ni todos los secretos posibles. Binarios, archivos anidados, formatos excluidos y límites alcanzados aparecen como cobertura incompleta. Los campos reconocidos de fechas/UID/GID se validan estructuralmente sin buscar secretos en sus valores numéricos. Con `--show-paths`, los nombres incluidos pueden contener información sensible.
