# Cambios

## 0.2.0 — 25 de octubre de 2026

- Añadida localización de una entrada por ID con `--locate`, revelando solo su nombre en JSON. No inspecciona el contenido ni extrae archivos; es incompatible con HTML y con la divulgación de todos los nombres.
- Añadida identidad SHA-256 del ZIP en informes y localizaciones. `--expect-sha256` rechaza archivos diferentes antes de revelar nombres. La huella no es una firma ni una garantía de seguridad.
- Se recalcula SHA-256 al finalizar sobre un descriptor sin caché de lectura, para detectar cambios persistentes que las fechas de Windows pueden ocultar. Se mantiene el requisito de conservar estables el archivo y su carpeta.
- Rechazadas rutas Windows con ADS, dispositivos, nombres reservados, UNC, referencias relativas a una unidad y formas ambiguas, tanto para entrada como para salida.
- Las salidas nuevas se crean exclusivamente y se comprueba que sean archivos regulares. Se solicita modo `0600` en POSIX; Windows conserva las ACL heredadas de la carpeta.
- El supervisor aplica un plazo también a la recepción completa por IPC; se evita una espera sin límite si el mensaje queda a medias. Se mantiene la terminación y limpieza del proceso y del receptor.
- Endurecida la validación de fechas extendidas ZIP: longitud coherente con flags y con el contexto de cabecera local o central. Los metadatos extra desconocidos siguen dejando cobertura incompleta.
- Ampliadas las heurísticas de secretos: PEM cifrado, frases entre comillas, nombres de asignación como `DB_PASSWORD`, separadores de línea adicionales y vistas limitadas de ANSI, escapes y compatibilidad Unicode hacia ASCII. La búsqueda añade comprobaciones cooperativas de tiempo y continúa sin verificar credenciales con proveedores.
- Los errores de argumentos evitan reflejar valores suministrados. Los informes mantienen valores capturados y fragmentos de contenido fuera de la salida.
- Actualizadas las guías portables y el modelo de seguridad. Las pruebas usan datos sintéticos; los controles específicos de un sistema operativo pueden omitirse en otro.
- El empaquetador utiliza un manifiesto explícito para excluir informes, ZIP y módulos locales no revisados. Se añade CI de Windows/Ubuntu y Python 3.11–3.13 con acciones fijadas por commit y permisos de solo lectura.

## 0.1.0 — 25 de octubre de 2026

- Primera versión local para revisar un subconjunto de ZIP clásico STORE/DEFLATE sin extraer ni transmitir contenido.
- Detección heurística de credenciales y revisión de rutas, colisiones, enlaces, estructura y presupuestos de descompresión.
- Informes de texto, HTML estático y JSON con nombres omitidos por defecto, cobertura explícita y salidas que no sobrescriben archivos existentes.

Los artefactos de la versión 0.1.0 se conservan como entrega anterior. Consulta el modelo de seguridad de la versión utilizada antes de interpretar sus resultados.
