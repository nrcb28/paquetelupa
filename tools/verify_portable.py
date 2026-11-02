"""Exercise the built ZIP app outside the source tree using synthetic inputs."""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile
import zipfile


ROOT = Path(__file__).resolve().parents[1]
VERSION_PATTERN = re.compile(r'__version__ = "([0-9.]+)"')
SENTINEL = "AKIA" + "ABCDEFGHIJKLMNOP"


class VerificationError(Exception):
    pass


def _version(source):
    match = VERSION_PATTERN.search(source)
    if match is None:
        raise VerificationError("No se encontró la versión del paquete.")
    return match.group(1)


def _check(condition, message):
    if not condition:
        raise VerificationError(message)


def _json(text, label):
    try:
        result = json.loads(text)
    except (ValueError, UnicodeError) as error:
        raise VerificationError(label + ": no produjo un único documento JSON válido.") from error
    _check(isinstance(result, dict), label + ": el resultado JSON debe ser un objeto.")
    return result


def verify(app, *, check_json_stdout=True):
    """Verify only the copied artifact; never import the source package."""
    app = Path(app).resolve()
    with zipfile.ZipFile(app) as archive:
        version = _version(archive.read("paquetelupa/__init__.py").decode("utf-8"))
    with tempfile.TemporaryDirectory(prefix="PaqueteLupa portable ") as temporary:
        root = Path(temporary)
        artifact_dir = root / "artefacto con espacios"
        working_dir = root / "ejecucion fuera del repositorio"
        artifact_dir.mkdir()
        working_dir.mkdir()
        isolated_app = artifact_dir / "Paquete Lupa.pyz"
        shutil.copyfile(app, isolated_app)

        def invoke(label, expected_code, *arguments):
            # -I excludes PYTHONPATH and the working directory; -S also removes
            # installed packages as a fallback for modules missing from the app.
            result = subprocess.run(
                [sys.executable, "-I", "-S", str(isolated_app), *map(str, arguments)],
                cwd=working_dir, capture_output=True, text=True, encoding="utf-8",
                errors="replace", timeout=20,
            )
            _check(result.returncode == expected_code,
                   f"{label}: código {result.returncode}, se esperaba {expected_code}. "
                   f"Salida: {result.stdout[:1000]!r}; error: {result.stderr[:1000]!r}")
            _check("Traceback" not in result.stderr, label + ": apareció un traceback.")
            _check(SENTINEL not in result.stdout + result.stderr,
                   label + ": se divulgó el valor sintético detectado.")
            if expected_code != 3:
                _check(not result.stderr, label + ": stderr debería estar vacío.")
            print("OK: " + label)
            return result

        def create_zip(name, content):
            path = working_dir / name
            with zipfile.ZipFile(path, "w", compression=zipfile.ZIP_DEFLATED) as archive:
                archive.writestr("nota sintetica.txt", content)
            return path

        clean = create_zip("paquete limpio.zip", "Small ordinary diagnostic note.\n")
        credential = create_zip("paquete con credencial.zip", "aws_access_key_id=" + SENTINEL + "\n")
        incomplete = working_dir / "paquete incompleto.zip"
        incomplete.write_bytes(b"SYNTHETIC INVALID ZIP")
        missing = working_dir / "archivo inexistente.zip"
        expected_hash = hashlib.sha256(clean.read_bytes()).hexdigest()

        result = invoke("versión portable", 0, "--version")
        _check(result.stdout.strip() == "PaqueteLupa " + version,
               "La versión de la CLI no coincide con la del artefacto.")

        cases = (("limpio", clean, 0, "no_findings", True),
                 ("credencial", credential, 1, "review", True),
                 ("incompleto", incomplete, 2, "incomplete", False))
        for label, source, code, status, complete in cases:
            destination = working_dir / (label + " informe.json")
            arguments = [source, "--timeout", "5", "--json", destination]
            html_path = working_dir / "informe limpio.html"
            if label == "limpio":
                arguments.extend(("--html", html_path))
            result = invoke("análisis portable " + label, code, *arguments)
            _check("PAQUETELUPA" in result.stdout, label + ": falta el informe de texto.")
            report = _json(destination.read_text(encoding="utf-8"), label)
            _check(report.get("status") == status and report.get("complete") is complete,
                   label + ": estado o cobertura incorrectos.")
            _check(report.get("tool", {}).get("version") == version,
                   label + ": versión de informe incorrecta.")
            _check(SENTINEL not in destination.read_text(encoding="utf-8"),
                   label + ": el JSON contiene el secreto sintético.")
            _check(all("path" not in entry for entry in report.get("entries", [])),
                   label + ": se incluyeron nombres sin solicitud expresa.")
            if label == "limpio":
                _check(report.get("archive", {}).get("sha256") == expected_hash,
                       "El informe portable no identifica los bytes analizados.")
                _check("<!doctype html>" in html_path.read_text(encoding="utf-8").lower(),
                       "No se generó el informe HTML portable.")

        invoke("error operativo portable", 3, missing, "--timeout", "5")
        result = invoke("localización portable con identidad", 0, clean,
                        "--locate", "entrada-00001", "--expect-sha256", expected_hash,
                        "--timeout", "5")
        location = _json(result.stdout, "localización")
        _check(location.get("operation") == "locate"
               and location.get("entry", {}).get("id") == "entrada-00001"
               and location.get("entry", {}).get("path") == "nota sintetica.txt"
               and location.get("archive", {}).get("sha256") == expected_hash,
               "La localización portable no corresponde al ZIP y a la entrada esperados.")
        result = invoke("rechazo portable de identidad diferente", 3, clean,
                        "--locate", "entrada-00001", "--expect-sha256", "0" * 64,
                        "--timeout", "5")
        _check("nota sintetica.txt" not in result.stdout + result.stderr,
               "La localización reveló el nombre con una identidad diferente.")

        if check_json_stdout:
            for label, source, code, status, complete in cases:
                result = invoke("JSON por stdout portable " + label, code, source,
                                "--format", "json", "--timeout", "5")
                report = _json(result.stdout, "stdout " + label)
                _check(report.get("status") == status and report.get("complete") is complete,
                       label + ": estado o cobertura de stdout incorrectos.")
                _check(report.get("tool", {}).get("version") == version,
                       label + ": versión de stdout incorrecta.")
            result = invoke("error operativo con stdout JSON", 3, missing,
                            "--format", "json", "--timeout", "5")
            _check(not result.stdout, "Un error operativo no debe producir un informe JSON.")
            result = invoke("localización con stdout JSON", 0, clean,
                            "--format", "json", "--locate", "entrada-00001",
                            "--expect-sha256", expected_hash, "--timeout", "5")
            _check(_json(result.stdout, "stdout localización") == location,
                   "--format json alteró el resultado de localización.")
        _check(hashlib.sha256(clean.read_bytes()).hexdigest() == expected_hash,
               "El artefacto modificó el ZIP original.")
    print("Artefacto portable verificado fuera del árbol fuente.")


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("app", nargs="?", type=Path, help="ruta del .pyz construido")
    args = parser.parse_args(argv)
    try:
        app = args.app
        if app is None:
            version = _version((ROOT / "paquetelupa" / "__init__.py").read_text(encoding="utf-8"))
            app = ROOT.parent / f"PaqueteLupa-{version}.pyz"
        verify(app)
    except (VerificationError, OSError, ValueError, KeyError, zipfile.BadZipFile,
            subprocess.TimeoutExpired) as error:
        print("ERROR: " + str(error), file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
