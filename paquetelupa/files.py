"""Regular local inputs and exclusively-created private report files."""
from contextlib import contextmanager
import ntpath
import os
from pathlib import Path
import re
import stat
import unicodedata


WINDOWS_DEVICE = re.compile(r"^(?:con|prn|aux|nul|clock\$|conin\$|conout\$|com[1-9¹²³]|lpt[1-9¹²³]) *(?:\.|$)", re.I)


def validate_local_path(path):
    """On Windows, reject device namespaces, ADS and ambiguous DOS paths."""
    if os.name != "nt":
        return
    value = os.fspath(path)
    normalized = value.replace("/", "\\")
    if normalized.startswith("\\\\") or normalized.startswith("\\??\\"):
        raise OSError("Solo se admiten rutas locales normales, sin dispositivos ni recursos UNC.")
    drive, tail = ntpath.splitdrive(normalized)
    if drive and (not re.fullmatch(r"[A-Za-z]:", drive) or not tail.startswith("\\")):
        raise OSError("No se admiten rutas relativas a una unidad ni espacios de nombres especiales.")
    for component in tail.split("\\"):
        if component in ("", ".", ".."):
            continue
        if (any(c in '<>:"|?*' or unicodedata.category(c).startswith("C") for c in component)
                or component.endswith((" ", ".")) or WINDOWS_DEVICE.match(component)):
            raise OSError("La ruta no puede contener dispositivos, flujos alternativos ni nombres ambiguos.")


@contextmanager
def open_regular_input(path):
    input_path = Path(path)
    validate_local_path(input_path)
    initial = input_path.lstat()
    if not stat.S_ISREG(initial.st_mode) or getattr(initial, "st_file_attributes", 0) & 0x400:
        raise OSError("La entrada debe ser un archivo regular, sin enlaces ni puntos de reanálisis.")
    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
    descriptor = os.open(input_path, flags)
    try:
        # Revalidation must read fresh descriptor bytes rather than a cached
        # BufferedReader window after a same-size concurrent rewrite.
        stream = os.fdopen(descriptor, "rb", buffering=0)
    except BaseException:
        os.close(descriptor)
        raise
    with stream:
        before = os.fstat(stream.fileno())
        if not stat.S_ISREG(before.st_mode) or (before.st_dev, before.st_ino) != (initial.st_dev, initial.st_ino):
            raise OSError("La entrada cambió durante la apertura.")
        yield stream, before


def assert_unchanged(stream, before):
    after = os.fstat(stream.fileno())
    if (before.st_size, before.st_mtime_ns, before.st_ctime_ns) != (after.st_size, after.st_mtime_ns, after.st_ctime_ns):
        raise OSError("El archivo cambió durante la lectura; resultado no fiable.")


def open_private_output(path):
    validate_local_path(path)
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(path, flags, 0o600)
    try:
        if not stat.S_ISREG(os.fstat(descriptor).st_mode):
            raise OSError("El destino debe ser un archivo regular nuevo.")
        return os.fdopen(descriptor, "w", encoding="utf-8", newline="\n")
    except BaseException:
        os.close(descriptor)
        raise
