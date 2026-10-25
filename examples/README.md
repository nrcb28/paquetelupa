# Ejemplos sintéticos

- `demo-soporte.html`: abre este informe para ver el funcionamiento y los límites. No contiene credenciales reales.
- `demo-texto.html`: informe de un pequeño ZIP de texto sin coincidencias.
- Los JSON equivalentes sirven para integraciones.
- Los ZIP sirven como entradas reproducibles para PaqueteLupa. **No extraigas `demo-soporte.zip`: contiene deliberadamente una ruta `../` y nombres en colisión para demostrar su detección.** No es necesario extraer ninguno de los ejemplos.
- `fuzz-*.json`: evidencia de pruebas automáticas sintéticas. No certifica seguridad de otros ZIP.

Para recrear los ejemplos desde la carpeta del proyecto:

```console
python tools/create_demo.py
```

Este generador escribe los ejemplos propios de esta carpeta, sustituyendo versiones anteriores. No debe usarse con archivos de producción.
