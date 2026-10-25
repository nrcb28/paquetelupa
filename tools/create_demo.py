"""Generate harmless synthetic archives and reports. No usable credentials."""
from pathlib import Path
import json
import sys
import zipfile
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from paquetelupa.scanner import scan_file
from paquetelupa.reports import render_html


def main():
    folder = Path(__file__).resolve().parents[1] / "examples"
    folder.mkdir(exist_ok=True)
    with zipfile.ZipFile(folder / "demo-soporte.zip", "w") as archive:
        archive.writestr("logs/application.log", "Servicio iniciado\nAuthorization: Bearer " + "DEMO" * 12 + "\n")
        archive.writestr("config/.env", "password=SoloDemostracionSinValorReal123!\n")
        archive.writestr("../ruta-peligrosa.txt", "Archivo sintético: no extraer.\n")
        archive.writestr("logs/SERVICIO.txt", "Nombre en mayúsculas\n")
        archive.writestr("logs/servicio.txt", "Colisión en Windows\n")
        archive.writestr("diagnostico.bin", b"\x00\xff\x03\x04BINARIO")
    with zipfile.ZipFile(folder / "demo-texto.zip", "w", compression=zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("estado.log", "Servicio iniciado. Solicitudes procesadas: 12.\n")
    for stem in ("demo-soporte", "demo-texto"):
        report = scan_file(folder / (stem + ".zip"))
        (folder / (stem + ".json")).write_text(json.dumps(report, ensure_ascii=True, indent=2) + "\n", encoding="utf-8")
        (folder / (stem + ".html")).write_text(render_html(report), encoding="utf-8")
    print("Ejemplos sintéticos creados.")


if __name__ == "__main__":
    main()
