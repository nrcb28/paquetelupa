"""Importable multiprocessing entry point (also works with Windows spawn)."""
import json
import signal

from .scanner import scan_file, locate_entry, IdentityMismatch, SelectionNotFound, Rejected


def worker(connection, path, limits, show_paths, locate_id=None, expected_sha256=None):
    # The supervisor owns cancellation; avoid a second traceback from Ctrl+C.
    signal.signal(signal.SIGINT, signal.SIG_IGN)
    try:
        if locate_id is not None:
            payload = {"location": locate_entry(path, locate_id, limits, expected_sha256=expected_sha256)}
        else:
            report = scan_file(path, limits, show_paths, expected_sha256=expected_sha256)
            payload = {"report": report}
    except IdentityMismatch:
        payload = {"error": "La huella del ZIP no coincide con la esperada; no uses los IDs de otro archivo."}
    except SelectionNotFound:
        payload = {"error": "El identificador solicitado no existe en este ZIP."}
    except Rejected:
        payload = {"error": "No se pudo localizar la entrada: ZIP no admitido, inconsistente o fuera de límites."}
    except (OSError, ValueError):
        payload = {"error": "No se pudo leer la entrada. Comprueba que sea un archivo ZIP regular y accesible."}
    except Exception:
        payload = {"error": "Fallo interno durante el análisis. No se obtuvo un resultado fiable."}
    try:
        connection.send_bytes(json.dumps(payload, ensure_ascii=True).encode("ascii"))
    finally:
        connection.close()
