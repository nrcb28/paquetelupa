# Probar PaqueteLupa 0.2.0

Requiere Python 3.11 o posterior. No instala dependencias. En Windows, `py -3` puede sustituir a `python` si usas el lanzador de Python.

Abre `examples/demo-soporte.html` en un navegador para ver un informe con datos inventados: credenciales de ejemplo, una ruta peligrosa, una colisión y contenido sin revisar.

Para analizar un ZIP propio desde la carpeta del proyecto:

```console
python -m paquetelupa "C:\ruta\soporte.zip" --html mi-informe.html --json mi-informe.json
```

Si tienes el archivo portable de esta entrega, utiliza su ruta en lugar del módulo:

```console
python "C:\ruta\PaqueteLupa-0.2.0.pyz" "C:\ruta\soporte.zip" --html mi-informe.html
```

Los destinos de informe deben ser nuevos. El ZIP original se abre solo para lectura. Si hay contenido omitido o un límite alcanzado, el resultado será incompleto. La herramienta no limpia archivos ni certifica seguridad.

Para averiguar a qué archivo corresponde un hallazgo, puedes revelar **solo un nombre**:

```console
python -m paquetelupa "C:\ruta\soporte.zip" --locate entrada-00002 --json ubicacion.json
```

El resultado JSON aparece también en la terminal. Puede contener datos sensibles del nombre seleccionado; no muestra los demás nombres y no inspecciona ni extrae el contenido. En este modo no se admiten `--html` ni `--show-paths`.

El informe anterior muestra el SHA-256 del ZIP, también disponible en `archive.sha256` del JSON. Para asegurar que el ID corresponde a los mismos bytes, añade `--expect-sha256` con esa huella de 64 caracteres hexadecimales. Una huella diferente provoca un error antes de revelar el nombre. SHA-256 no es una firma ni acredita seguridad.

Los nombres se ocultan por defecto en el análisis normal. `--show-paths` revela todos ellos y debe reservarse para informes privados. Usa una carpeta de salida de confianza; en Windows se rechazan ADS, dispositivos, UNC y rutas ambiguas.

Consulta [README.md](README.md) para interpretar códigos de salida y límites, [SECURITY.md](SECURITY.md) para el modelo de seguridad y [CHANGELOG.md](CHANGELOG.md) para los cambios.
