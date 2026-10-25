# Investigación del nicho

**Fecha de consulta: 25 de octubre de 2026.** Propuesta: revisión local de ZIP de soporte antes de compartirlos o extraerlos, dirigida inicialmente a equipos pequeños de desarrollo y soporte. Esta es una hipótesis de utilidad y de producto; no representa validación con clientes, ventas ni una estimación demostrada del mercado.

## Necesidad documentada

[Atlassian: Create a Support Zip](https://confluence.atlassian.com/support/create-a-support-zip-790796819.html) explica que los ZIP de soporte reúnen logs, configuración y diagnóstico para investigar problemas. También indica que eliminar usuarios y contraseñas encontrados en configuración no elimina necesariamente el contenido sensible de los logs. Esto aporta un caso de uso concreto para una revisión previa al envío.

[Atlassian: Redacting data in support zip](https://confluence.atlassian.com/support/redacting-data-in-support-zip-1754464515.html) describe redacción por patrones y sus límites: las coincidencias no son exhaustivas y los binarios, heap dumps y grabaciones JFR se incluyen sin redactar. La inferencia para este proyecto es que una utilidad debe mostrar también lo que no revisó, en lugar de limitarse a un contador de hallazgos.

[OWASP: File Upload Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/File_Upload_Cheat_Sheet.html) documenta riesgos de archivos subidos, incluyendo bombas de descompresión, agotamiento de recursos, sobrescritura y contenido activo. Recomienda límites de tamaño y validación del contenido. Para PaqueteLupa, esto justifica inspeccionar sin extraer y limitar metadatos, entradas y descompresión.

## Productos existentes y diferencia propuesta

[Gitleaks, documentación oficial](https://github.com/gitleaks/gitleaks), ya ofrece detección de secretos, redacción, informes y revisión de archivos comprimidos/anidados mediante `--max-archive-depth`. [Truffle Security: Secret Scanning Encoded and Archived Data](https://trufflesecurity.com/blog/secret-scanning-encoded-and-archived-data) también documenta soporte de archivos comprimidos en TruffleHog. Por tanto, **buscar secretos dentro de ZIP no es una novedad de PaqueteLupa** y esta versión no pretende superar su amplitud de detectores.

La diferencia propuesta es un flujo pequeño y explicable para un paquete de soporte: controles estructurales conservadores, detección básica sin red, IDs en lugar de nombres por defecto e informes locales que explican cobertura incompleta y pasos manuales. Su posible valor es reducir fricción para una revisión puntual; esta ventaja todavía requiere comprobarse con usuarios.

## Decisiones derivadas

| Evidencia o restricción | Decisión del prototipo |
| --- | --- |
| Los paquetes pueden contener configuración y logs sensibles. | Analizar texto y nombres; omitir valores y fragmentos en los informes. |
| La redacción por patrones es incompleta. | Presentar hallazgos como indicios y explicar alcance, falsos negativos y omitidos. |
| Los archivos comprimidos pueden agotar recursos. | Límites estrictos y formato admitido reducido; no extraer ni hacer recursión. |
| Ya existen detectores generalistas maduros. | Priorizar un flujo de soporte sencillo y privado; no competir en cantidad de firmas. |

[Python: documentación de zipfile](https://docs.python.org/3/library/zipfile.html) describe fallos por formato/CRC, limitaciones del sistema de archivos, agotamiento de recursos y sobrescritura al extraer. PaqueteLupa evita la extracción y valida un subconjunto estrecho del formato; esto reduce superficie, pero no demuestra ausencia de vulnerabilidades.

## Validación pendiente

La investigación confirma que el problema existe y que hay soluciones previas. No prueba que otro producto sea comercialmente necesario. Antes de invertir en una versión de pago, habría que observar revisiones reales con equipos de soporte, medir tiempo ahorrado y ruido de las reglas, y comprobar si prefieren esta utilidad o configurar Gitleaks/TruffleHog. El prototipo tampoco sustituye una auditoría independiente de seguridad ni una evaluación sobre un corpus representativo de paquetes reales.
