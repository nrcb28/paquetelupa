"""Offline CLI with a supervised worker and exclusive report destinations."""
from __future__ import annotations

import argparse
from contextlib import ExitStack
from dataclasses import asdict, replace
import json
import multiprocessing
import os
import re
from pathlib import Path
import sys
import threading

from . import __version__
from .reports import render_html, render_text
from .runtime import worker as _worker
from .scanner import Limits
from .files import validate_local_path, open_private_output


def supervised_scan(path, limits, show_paths=False, *, locate_id=None, expected_sha256=None):
    context = multiprocessing.get_context("spawn")
    reader, writer = context.Pipe(duplex=False)
    worker = context.Process(target=_worker, args=(writer, str(path), limits, show_paths, locate_id, expected_sha256), daemon=True)
    receiver = None
    completed = threading.Event()
    received = {}
    budget = limits.seconds + 2
    def receive():
        try:
            if not reader.poll(budget):
                received["result"] = {"report": _timeout_report(limits)}
            else:
                result = json.loads(reader.recv_bytes(16 * 1024 * 1024))
                if not isinstance(result, dict) or len(result) != 1 or not set(result) <= {"report", "location", "error"}:
                    raise ValueError("Invalid worker envelope")
                received["result"] = result
        except KeyboardInterrupt:
            received["interrupt"] = True
        except Exception:
            received["result"] = {"error": "El proceso de análisis terminó sin un informe válido."}
        finally:
            completed.set()
    try:
        worker.start()
        writer.close()
        receiver = threading.Thread(target=receive, daemon=True)
        receiver.start()
        if not completed.wait(budget):
            return {"report": _timeout_report(limits)}
        if received.get("interrupt"):
            raise KeyboardInterrupt()
        return received["result"]
    finally:
        writer.close()
        if worker.pid is not None:
            if worker.is_alive():
                worker.terminate()
            worker.join(timeout=2)
            if worker.is_alive():
                worker.kill()
                worker.join(timeout=2)
        reader.close()
        if receiver is not None:
            receiver.join(timeout=1)


def _timeout_report(limits):
    return dict(schema_version="1.0", tool=dict(name="PaqueteLupa", version=__version__),
                status="incomplete", complete=False, limits=asdict(limits), entries=[],
                summary=dict(entries=0, scanned_text_files=0, skipped_files=0, bytes_read=0, findings=1),
                findings=[dict(rule="runtime.timeout", severity="high", entry=None, line=None,
                               message="El proceso excedió el tiempo permitido y fue detenido.",
                               remediation="Reduce el paquete o revísalo en un entorno aislado.")],
                notes=["No hay cobertura disponible: el proceso terminó por tiempo.",
                       "El supervisor añade hasta dos segundos para el arranque del proceso.",
                       "El informe no es un certificado de seguridad."])


class ReportDestinationError(OSError):
    """Only constant, non-sensitive output validation messages are allowed."""


def validate_report_destinations(source, json_path=None, html_path=None):
    """Reject predictable output errors before scanning, without creating files.

    This is an early usability check, not a reservation. Exclusive creation and
    path validation are still required when the reports are actually written.
    """
    paths = [Path(path) for path in (json_path, html_path) if path]
    if not paths:
        return
    try:
        # Reject Windows UNC/device inputs before resolve() can touch them.
        validate_local_path(Path(source))
        for path in paths:
            validate_local_path(path)
        resolved = [os.path.normcase(str(path.resolve())) for path in paths]
        source_resolved = os.path.normcase(str(Path(source).resolve()))
    except (OSError, ValueError, RuntimeError):
        raise ReportDestinationError("La entrada o un destino no es una ruta local válida y accesible.") from None
    if len(set(resolved)) != len(resolved) or source_resolved in resolved:
        raise ReportDestinationError("Los destinos deben ser distintos entre sí y de la entrada.")
    for path in paths:
        try:
            path.lstat()
        except FileNotFoundError:
            pass
        except NotADirectoryError:
            raise ReportDestinationError("La carpeta de un destino no existe o no es un directorio.") from None
        else:
            raise ReportDestinationError("Un destino de informe ya existe; elige un nombre nuevo.")
        if not path.parent.is_dir():
            raise ReportDestinationError("La carpeta de un destino no existe o no es un directorio.")


def write_reports(report, source, json_path=None, html_path=None):
    validate_report_destinations(source, json_path, html_path)
    destinations = []
    if json_path:
        destinations.append((Path(json_path), json.dumps(report, ensure_ascii=True, indent=2) + "\n"))
    if html_path:
        destinations.append((Path(html_path), render_html(report)))
    # Reserve every destination before writing. 'x' never overwrites a file or link.
    opened = []
    try:
        with ExitStack() as stack:
            streams = []
            for path, data in destinations:
                try:
                    stream = stack.enter_context(open_private_output(path))
                except FileExistsError:
                    raise ReportDestinationError("Un destino de informe ya existe; elige un nombre nuevo.") from None
                opened.append((path, os.fstat(stream.fileno())))
                streams.append(stream)
            for stream, (_, data) in zip(streams, destinations):
                stream.write(data)
    except (OSError, KeyboardInterrupt):
        _remove_owned_empty(opened)
        raise


def _remove_owned_empty(opened):
    for path, identity in opened:
        try:
            current = path.lstat()
            if (current.st_dev, current.st_ino, current.st_size) == (identity.st_dev, identity.st_ino, 0):
                path.unlink()
        except OSError:
            pass


_SAFE_ARGUMENT_ERRORS = frozenset({
    "--timeout debe ser positivo, finito y no mayor que 20",
    "La localización no admite HTML ni mostrar todos los nombres.",
    "Identificador inválido. Usa el formato entrada-00001.",
    "Huella inválida. Usa 64 caracteres hexadecimales para SHA-256.",
})


class _PrivateParser(argparse.ArgumentParser):
    def error(self, message):
        # argparse normally echoes invalid values (possibly filenames or secrets).
        self.print_usage(sys.stderr)
        detail = (message if message in _SAFE_ARGUMENT_ERRORS
                  else "Argumentos inválidos. Consulta --help; usa -- antes de un nombre que empiece por guion.")
        self.exit(2, "Error: " + detail + "\n")


def _parser():
    parser = _PrivateParser(prog="paquetelupa", description="Revisa ZIP de soporte localmente, sin extraer ni enviar contenidos.")
    parser.add_argument("archive", help="archivo ZIP que quieres revisar")
    parser.add_argument("--json", dest="json_path", metavar="INFORME.json", help="crear informe JSON; el destino no debe existir")
    parser.add_argument("--html", dest="html_path", metavar="INFORME.html", help="crear informe HTML local; el destino no debe existir")
    parser.add_argument("--format", dest="output_format", choices=("text", "json"), default="text",
                        help="formato de salida estándar del análisis (por defecto: text); --locate siempre devuelve JSON")
    parser.add_argument("--show-paths", action="store_true", help="incluir nombres originales: pueden revelar información sensible")
    parser.add_argument("--locate", metavar="ENTRADA", help="localizar un único ID, p. ej. entrada-00001; revela solo ese nombre, sin extraer")
    parser.add_argument("--expect-sha256", metavar="HUELLA", help="comprobar que el ZIP coincide con el SHA-256 de un informe anterior")
    parser.add_argument("--timeout", type=float, default=20, metavar="SEGUNDOS", help="reducir tiempo de análisis (0 < segundos <= 20)")
    parser.add_argument("--version", action="version", version="PaqueteLupa " + __version__)
    return parser


def main(argv=None):
    for stream in (sys.stdout, sys.stderr):
        if hasattr(stream, "reconfigure"):
            stream.reconfigure(encoding="utf-8", errors="backslashreplace")
    parser = _parser()
    args = parser.parse_args(argv)
    if args.locate and (args.show_paths or args.html_path):
        parser.error("La localización no admite HTML ni mostrar todos los nombres.")
    if args.locate and not re.fullmatch(r"entrada-[0-9]{5}", args.locate):
        parser.error("Identificador inválido. Usa el formato entrada-00001.")
    if args.expect_sha256 and not re.fullmatch(r"[0-9a-fA-F]{64}", args.expect_sha256):
        parser.error("Huella inválida. Usa 64 caracteres hexadecimales para SHA-256.")
    try:
        limits = replace(Limits(), seconds=args.timeout)
    except ValueError:
        parser.error("--timeout debe ser positivo, finito y no mayor que 20")
    try:
        validate_report_destinations(args.archive, args.json_path, args.html_path)
        result = supervised_scan(args.archive, limits, args.show_paths, locate_id=args.locate, expected_sha256=args.expect_sha256)
        if "error" in result:
            print("Error: " + result["error"], file=sys.stderr)
            return 3
        if "location" in result:
            location = result["location"]
            write_reports(location, args.archive, args.json_path)
            print(json.dumps(location, ensure_ascii=True, indent=2))
            return 0
        report = result["report"]
        write_reports(report, args.archive, args.json_path, args.html_path)
        if args.output_format == "json":
            print(json.dumps(report, ensure_ascii=True, indent=2))
        else:
            print(render_text(report))
        return {"no_findings": 0, "review": 1, "incomplete": 2}[report["status"]]
    except KeyboardInterrupt:
        print("Análisis cancelado.", file=sys.stderr)
        return 3
    except ReportDestinationError as error:
        print("Error: " + str(error), file=sys.stderr)
        return 3
    except (OSError, ValueError):
        print("Error: no se pudo crear el informe o iniciar el análisis. Los destinos deben ser nuevos y accesibles.", file=sys.stderr)
        return 3


if __name__ == "__main__":
    multiprocessing.freeze_support()
    raise SystemExit(main())
