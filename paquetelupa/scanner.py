"""Read-only, bounded ZIP inspection. No archive members are ever extracted."""
from __future__ import annotations

from dataclasses import asdict, dataclass
import io
import hashlib
import math
import os
from pathlib import Path
import re
import stat
import struct
import time
import unicodedata
import zlib

from .detectors import decode_text, scan_text
from . import __version__
from .files import WINDOWS_DEVICE as _DEVICE, open_regular_input, assert_unchanged


@dataclass(frozen=True)
class Limits:
    archive_bytes: int = 64 * 1024 * 1024
    central_bytes: int = 2 * 1024 * 1024
    entries: int = 2000
    entry_bytes: int = 8 * 1024 * 1024
    total_bytes: int = 32 * 1024 * 1024
    ratio: int = 100
    seconds: float = 20
    findings: int = 500

    def __post_init__(self):
        for key, value in asdict(self).items():
            if isinstance(value, bool) or not isinstance(value, (int, float)) or not math.isfinite(value) or value <= 0:
                raise ValueError("Los límites deben ser positivos y finitos.")
            if key != "seconds" and not isinstance(value, int):
                raise ValueError("Los límites de tamaño y recuento deben ser enteros.")
        # API callers can lower limits, never remove the tested perimeter.
        ceilings = dict(archive_bytes=64*1024*1024, central_bytes=2*1024*1024,
                        entries=2000, entry_bytes=8*1024*1024, total_bytes=32*1024*1024,
                        ratio=100, seconds=20, findings=500)
        if any(value > ceilings[key] for key, value in asdict(self).items()):
            raise ValueError("Un límite supera el máximo admitido por esta versión.")


class Rejected(Exception):
    """Only constant, non-sensitive messages may be passed here."""


class IdentityMismatch(ValueError):
    """The archive is different from the expected report identity."""


class SelectionNotFound(ValueError):
    """No member with the requested opaque ID exists."""


def _fingerprint(stream, size, limits, check, expected_sha256=None):
    if size > limits.archive_bytes:
        raise Rejected("El ZIP supera el límite de tamaño físico.")
    stream.seek(0)
    digest = hashlib.sha256()
    remaining = size
    while remaining:
        check()
        data = _read_exact(stream, min(1024*1024, remaining))
        remaining -= len(data)
        digest.update(data)
    identity = dict(sha256=digest.hexdigest(), size_bytes=size)
    if expected_sha256 is not None:
        if not isinstance(expected_sha256, str) or not re.fullmatch(r"[0-9a-fA-F]{64}", expected_sha256):
            raise ValueError("La huella esperada debe ser un SHA-256 hexadecimal.")
        if identity["sha256"] != expected_sha256.lower():
            raise IdentityMismatch("La huella del ZIP no coincide con la esperada.")
    return identity


def _read_exact(stream, count):
    data = stream.read(count)
    if len(data) != count:
        raise Rejected("Estructura ZIP truncada.")
    return data


def _extras(data, *, central=False):
    cursor = 0
    opaque = False
    while cursor < len(data):
        if len(data) - cursor < 4:
            raise Rejected("Campo extra ZIP truncado.")
        kind, size = struct.unpack_from("<HH", data, cursor)
        if len(data) - cursor < 4 + size:
            raise Rejected("Longitud de campo extra inválida.")
        if kind in (0x0001, 0x7075, 0x6375):
            raise Rejected("ZIP64 o nombres Unicode alternativos no admitidos.")
        payload = data[cursor+4:cursor+4+size]
        if kind == 0x5455:  # Extended timestamp: flags + up to three uint32 times.
            if not size or payload[0] & ~7:
                raise Rejected("Campo de fecha extendida ZIP inválido.")
            expected = 1 + 4 * (bool(payload[0] & 1) if central else (payload[0] & 7).bit_count())
            if size != expected:
                raise Rejected("Campo de fecha extendida ZIP inválido.")
        elif kind == 0x000a:  # NTFS: reserved + timestamp attribute.
            if size != 32 or payload[:8] != b"\x00\x00\x00\x00\x01\x00\x18\x00":
                raise Rejected("Campo NTFS ZIP no admitido.")
        elif kind == 0x7875:  # Unix UID/GID v1, numeric values only.
            if size < 5 or payload[0] != 1 or not 1 <= payload[1] <= 8:
                raise Rejected("Campo UID/GID ZIP no admitido.")
            gid_pos = 2 + payload[1]
            if gid_pos >= size or not 1 <= payload[gid_pos] <= 8 or gid_pos+1+payload[gid_pos] != size:
                raise Rejected("Campo UID/GID ZIP inválido.")
        else:
            opaque = True
        cursor += 4 + size
    return opaque


def _directory(stream, size, limits, check):
    if size < 22:
        raise Rejected("El archivo no es un ZIP clásico válido.")
    stream.seek(max(0, size - 65557))
    tail = stream.read(65557)
    pos = tail.rfind(b"PK\x05\x06")
    if pos < 0 or len(tail) - pos < 22:
        raise Rejected("No se encuentra el directorio final ZIP.")
    _, disk, cd_disk, n_disk, count, cd_size, cd_offset, comment = struct.unpack_from("<4s4H2LH", tail, pos)
    eocd_offset = size - len(tail) + pos
    if pos + 22 + comment != len(tail):
        raise Rejected("ZIP con datos finales ambiguos o truncados.")
    if disk or cd_disk or n_disk != count:
        raise Rejected("ZIP multidisco no admitido.")
    if count == 65535 or cd_size == 0xffffffff or cd_offset == 0xffffffff:
        raise Rejected("ZIP64 no admitido.")
    if count > limits.entries or cd_size > limits.central_bytes:
        raise Rejected("El directorio ZIP supera el presupuesto de metadatos.")
    if cd_offset + cd_size != eocd_offset:
        raise Rejected("Directorio ZIP fuera de rango o estructura no admitida.")
    stream.seek(cd_offset)
    central = io.BytesIO(_read_exact(stream, cd_size))
    entries = []
    for index in range(count):
        check()
        header = _read_exact(central, 46)
        fields = struct.unpack("<4s6H3L5H2L", header)
        (signature, made, version, flags, method, _, _, crc, compressed, unpacked,
         name_len, extra_len, comment_len, disk_start, _, external, offset) = fields
        if signature != b"PK\x01\x02" or disk_start or max(offset, compressed, unpacked) == 0xffffffff:
            raise Rejected("Registro central inválido o ZIP64 no admitido.")
        if name_len > 1024:
            raise Rejected("Nombre de entrada mayor que el límite de 1024 bytes.")
        raw_name = _read_exact(central, name_len)
        opaque_extra = _extras(_read_exact(central, extra_len), central=True)
        entry_comment = _read_exact(central, comment_len)
        try:
            name = raw_name.decode("utf-8" if flags & 0x800 else "cp437", errors="strict")
        except UnicodeError:
            raise Rejected("Nombre ZIP con codificación inválida.") from None
        if name.replace("\\", "/").count("/") > 64:
            raise Rejected("Ruta con más de 64 separadores no admitida.")
        entries.append(dict(id=f"entrada-{index+1:05d}", name=name, raw_name=raw_name,
                            flags=flags, method=method, crc=crc, compressed=compressed,
                            unpacked=unpacked, external=external, made=made, offset=offset,
                            comment=entry_comment, opaque_extra=opaque_extra))
    if central.tell() != cd_size:
        raise Rejected("El recuento de entradas ZIP no coincide con el directorio.")
    if count == 0 and cd_offset != 0:
        raise Rejected("ZIP vacío con prefijo no admitido.")
    ranges = []
    for entry in entries:
        check()
        if entry["offset"] + 30 > cd_offset:
            raise Rejected("Cabecera local ZIP fuera de rango.")
        stream.seek(entry["offset"])
        local = struct.unpack("<4s5H3L2H", _read_exact(stream, 30))
        sig, _, flags, method, _, _, crc, comp, unpacked, nl, el = local
        if sig != b"PK\x03\x04" or flags != entry["flags"] or method != entry["method"]:
            raise Rejected("Cabeceras local y central incoherentes.")
        if nl != len(entry["raw_name"]) or stream.tell() + nl + el > cd_offset:
            raise Rejected("Longitud de cabecera local inválida.")
        if _read_exact(stream, nl) != entry["raw_name"]:
            raise Rejected("El nombre local difiere del nombre central.")
        entry["opaque_extra"] |= _extras(_read_exact(stream, el))
        if not flags & 8 and (crc, comp, unpacked) != (entry["crc"], entry["compressed"], entry["unpacked"]):
            raise Rejected("Tamaños o CRC local y central incoherentes.")
        if flags & 8 and any(actual not in (0, expected) for actual, expected in zip(
                (crc, comp, unpacked), (entry["crc"], entry["compressed"], entry["unpacked"]))):
            raise Rejected("Valores locales incompatibles con el descriptor ZIP.")
        entry["data_offset"] = stream.tell()
        end = stream.tell() + entry["compressed"]
        if end > cd_offset:
            raise Rejected("Datos ZIP fuera de rango.")
        if flags & 8:
            stream.seek(end)
            first = _read_exact(stream, 4)
            desc = _read_exact(stream, 12) if first == b"PK\x07\x08" else first + _read_exact(stream, 8)
            if struct.unpack("<3L", desc) != (entry["crc"], entry["compressed"], entry["unpacked"]):
                raise Rejected("Descriptor de datos ZIP incoherente.")
            end = stream.tell()
        if end > cd_offset:
            raise Rejected("Descriptor ZIP fuera de rango.")
        ranges.append((entry["offset"], end))
    previous = 0
    for start, end in sorted(ranges):
        if start != previous:
            raise Rejected("ZIP con solapamientos, prefijos o huecos no admitidos.")
        previous = end
    if previous != cd_offset:
        raise Rejected("ZIP con datos no referenciados antes del directorio.")
    return entries, tail[pos+22:]


def _path_info(name):
    normalized = name.replace("\\", "/")
    parts = normalized.rstrip("/").split("/")
    unsafe = (not name or normalized.startswith("/") or "\\" in name
              or any(unicodedata.category(c).startswith("C") for c in name)
              or any(c in '<>:"|?*' for c in name)
              or any(p in ("", ".", "..") or p.endswith((" ", ".")) or _DEVICE.match(p) for p in parts))
    key = "/".join(unicodedata.normalize("NFC", p).casefold().rstrip(" .") for p in parts)
    return bool(unsafe), key


def _payload(stream, entry, budget, check):
    stream.seek(entry["data_offset"])
    remaining = entry["compressed"]
    chunks = []
    actual = 0
    crc = 0
    decoder = zlib.decompressobj(-15) if entry["method"] == 8 else None
    while remaining:
        check()
        block = _read_exact(stream, min(65536, remaining))
        remaining -= len(block)
        if decoder:
            block = decoder.decompress(block, min(65536, budget-actual+1))
            while True:
                actual += len(block)
                if actual > budget:
                    raise Rejected("La expansión real supera el presupuesto de lectura.")
                crc = zlib.crc32(block, crc)
                chunks.append(block)
                check()
                if not decoder.unconsumed_tail:
                    break
                block = decoder.decompress(decoder.unconsumed_tail, min(65536, budget-actual+1))
            if decoder.unused_data or (decoder.eof and remaining):
                raise Rejected("Flujo DEFLATE con datos sobrantes.")
        else:
            actual += len(block)
            if actual > budget:
                raise Rejected("La lectura supera el presupuesto de bytes.")
            crc = zlib.crc32(block, crc)
            chunks.append(block)
    if decoder and not decoder.eof:
        raise Rejected("Flujo DEFLATE incompleto.")
    if actual != entry["unpacked"] or crc != entry["crc"]:
        raise Rejected("Tamaño real o CRC inválido: contenido no verificable.")
    return b"".join(chunks)


def scan_file(path: str | Path, limits: Limits | None = None, show_paths: bool = False, *, expected_sha256=None):
    """Inspect a regular local file. I/O errors are intentionally left to the CLI.

    Direct API use has cooperative time checks; CLI additionally supervises a child
    process. Names are excluded by default because they can themselves be secrets.
    """
    limits = limits or Limits()
    deadline = time.monotonic() + limits.seconds
    report = dict(schema_version="1.0", tool=dict(name="PaqueteLupa", version=__version__),
                  status="no_findings", complete=True, summary=dict(entries=0, scanned_text_files=0,
                  skipped_files=0, bytes_read=0, findings=0), limits=asdict(limits), findings=[], entries=[],
                  notes=["Inspección local: no extrae, ejecuta ni envía contenidos.",
                         "Sin hallazgos no significa seguro. Detección por patrones; no es un antivirus ni una anonimización.",
                         "Nombres omitidos por privacidad; los identificadores siguen el orden del directorio central.",
                         "Se revisan texto, nombres y comentarios ZIP. Fechas y UID/GID reconocidos se validan estructuralmente; otros campos extra dejan cobertura incompleta."])

    def check():
        if time.monotonic() > deadline:
            raise Rejected("Se ha agotado el presupuesto de tiempo.")

    def finding(rule, severity, message, entry=None, line=None, remediation="Revisar el paquete antes de compartirlo o extraerlo."):
        if len(report["findings"]) >= limits.findings:
            report["complete"] = False
            if "Se alcanzó el límite de hallazgos; la lista está truncada." not in report["notes"]:
                report["notes"].append("Se alcanzó el límite de hallazgos; la lista está truncada.")
            return
        report["findings"].append(dict(rule=rule, severity=severity, entry=entry, line=line,
                                       message=message, remediation=remediation))

    with open_regular_input(path) as (stream, before):
        try:
            report["archive"] = _fingerprint(stream, before.st_size, limits, check, expected_sha256)
            entries, archive_comment = _directory(stream, before.st_size, limits, check)
            report["summary"]["entries"] = len(entries)
            def scan_comment(data, eid):
                if data:
                    text = decode_text(data)
                    if text is None:
                        text = data.decode("cp437")
                    for hit in scan_text(text, eid, limit=limits.findings+1, check=check):
                        hit["rule"] = "comment." + hit["rule"]
                        hit["message"] = "Posible credencial en un comentario del ZIP."
                        finding(**hit)
            scan_comment(archive_comment, None)
            seen = {}
            keys = []
            for entry in entries:
                check()
                eid = entry["id"]
                name = entry["name"]
                directory = name.endswith("/")
                unsafe, key = _path_info(name)
                item = dict(id=eid, size=entry["unpacked"], compressed_size=entry["compressed"], state="pending")
                if show_paths:
                    item["path"] = name
                report["entries"].append(item)
                entry["item"] = item
                scan_comment(entry["comment"], eid)
                if entry["opaque_extra"]:
                    report["complete"] = False
                    finding("coverage.metadata", "medium", "Campo extra ZIP desconocido: no se inspecciona su contenido.", eid)
                if unsafe:
                    finding("path.unsafe", "high", "Ruta peligrosa o ambigua entre sistemas operativos.", eid)
                if key in seen:
                    finding("path.collision", "high", "Entrada duplicada o colisión de nombres normalizados.", eid)
                seen[key] = directory
                keys.append((key, directory, eid))
                mode = entry["external"] >> 16
                # Some extractors honor Unix mode bits even for other creator hosts
                # (including Darwin=19). Treat all recognizable special modes conservatively.
                kind = stat.S_IFMT(mode)
                entry["special"] = kind not in (0, stat.S_IFREG, stat.S_IFDIR)
                entry["directory_conflict"] = (
                    (kind == stat.S_IFREG and directory)
                    or ((kind == stat.S_IFDIR or entry["external"] & 0x10) and not directory)
                    or (directory and entry["unpacked"] != 0))
                if entry["special"]:
                    finding("archive.special", "high", "Enlace simbólico o archivo especial dentro del ZIP.", eid)
                if entry["directory_conflict"]:
                    finding("archive.directory_conflict", "high", "El nombre, los atributos o el contenido del directorio son incoherentes.", eid)
                basename = name.replace("\\", "/").rstrip("/").split("/")[-1].casefold()
                if basename in (".env", ".npmrc", ".pypirc", "id_rsa", "id_ed25519", "credentials", "kubeconfig") or basename.endswith((".pem", ".key", ".p12", ".pfx")):
                    finding("privacy.sensitive_name", "medium", "Nombre habitual de archivo con credenciales o claves.", eid)
                # Names themselves can leak secrets; record only constant findings.
                for hit in scan_text(name, eid, limit=limits.findings + 1, check=check):
                    finding("name."+hit["rule"], hit["severity"], "Posible credencial en el nombre de una entrada.", eid)
            for key, _, eid in keys:
                check()
                segments = key.split("/")
                if any(seen.get("/".join(segments[:i])) is False for i in range(1, len(segments))):
                    finding("path.parent_file", "high", "Un archivo ocupa el nombre de un directorio padre.", eid)
            for entry in entries:
                check()
                item, eid = entry["item"], entry["id"]
                reason = None
                allowed_flags = 0x808 | (6 if entry["method"] == 8 else 0)
                if entry["name"].endswith("/") and entry["unpacked"] == 0 and not entry["special"] and not entry["directory_conflict"] and not entry["flags"] & ~allowed_flags and entry["method"] in (0, 8):
                    if entry["compressed"] not in (0, 2):
                        reason = "Directorio con datos inesperados."
                    else:
                        # Validate directory streams too; do not hide invalid CRC or data.
                        _payload(stream, entry, limits.entry_bytes, check)
                        item["state"] = "directory"
                        continue
                if entry["special"]:
                    reason = "No se inspecciona el destino de enlaces o archivos especiales."
                elif entry["directory_conflict"]:
                    reason = "Directorio ambiguo: se omite su contenido."
                elif entry["flags"] & ~allowed_flags:
                    reason = "Entrada cifrada o con opciones ZIP no admitidas."
                elif entry["method"] not in (0, 8):
                    reason = "Método de compresión no admitido; solo STORE y DEFLATE."
                elif entry["unpacked"] > limits.entry_bytes:
                    reason = "Entrada mayor que el límite de bytes por archivo."
                elif entry["unpacked"] > max(1, entry["compressed"]) * limits.ratio:
                    reason = "Relación de compresión excesiva: posible bomba ZIP."
                elif entry["unpacked"] + report["summary"]["bytes_read"] > limits.total_bytes:
                    reason = "Se ha alcanzado el presupuesto total de bytes."
                if reason:
                    report["complete"] = False
                    item["state"] = "skipped"
                    report["summary"]["skipped_files"] += 1
                    finding("coverage.skipped", "medium", reason, eid)
                    continue
                if entry["method"] == 0 and entry["compressed"] != entry["unpacked"]:
                    raise Rejected("Entrada STORE con tamaños incoherentes.")
                budget = min(limits.entry_bytes, limits.total_bytes-report["summary"]["bytes_read"])
                data = _payload(stream, entry, budget, check)
                report["summary"]["bytes_read"] += len(data)
                if data.startswith((b"PK\x03\x04", b"PK\x05\x06", b"PK\x07\x08", b"\x1f\x8b", b"7z\xbc\xaf\x27\x1c", b"Rar!", b"BZh", b"\xfd7zXZ")) or entry["name"].casefold().endswith((".zip", ".jar", ".docx", ".xlsx", ".pptx", ".gz", ".tar", ".7z", ".rar", ".bz2", ".xz")):
                    text = None
                    reason = "Archivo anidado: no se descomprime recursivamente."
                else:
                    text = decode_text(data)
                    reason = "Contenido binario o codificación no admitida."
                if text is None:
                    item["state"] = "skipped"
                    report["complete"] = False
                    report["summary"]["skipped_files"] += 1
                    finding("coverage.content", "medium", reason, eid)
                else:
                    item["state"] = "scanned"
                    report["summary"]["scanned_text_files"] += 1
                    for hit in scan_text(text, eid, limit=limits.findings+1, check=check):
                        finding(**hit)
                check()
            after = os.fstat(stream.fileno())
            if (before.st_size, before.st_mtime_ns, before.st_ctime_ns) != (after.st_size, after.st_mtime_ns, after.st_ctime_ns):
                raise Rejected("El archivo cambió durante el análisis; resultado no fiable.")
            # st_ctime is creation time on some Windows/Python combinations;
            # do not rely on it to detect same-size rewrites with restored mtime.
            if _fingerprint(stream, before.st_size, limits, check)["sha256"] != report["archive"]["sha256"]:
                raise Rejected("Los bytes del ZIP cambiaron durante el análisis.")
            assert_unchanged(stream, before)
        except (Rejected, zlib.error, struct.error, UnicodeError) as error:
            report["complete"] = False
            message = str(error) if isinstance(error, Rejected) else "Error de estructura o descompresión ZIP."
            finding("archive.rejected", "high", message)
            for item in report["entries"]:
                if item["state"] == "pending":
                    item["state"] = "skipped"
                    report["summary"]["skipped_files"] += 1
    if show_paths:
        report["notes"][2] = "Nombres incluidos por petición: pueden revelar información sensible."
    report["summary"]["findings"] = len(report["findings"])
    report["status"] = "incomplete" if not report["complete"] else "review" if report["findings"] else "no_findings"
    return report


def locate_entry(path, entry_id, limits=None, *, expected_sha256=None):
    """Reveal one requested name without decompressing or inspecting its payload.

    The output is a locator, not a content inspection. An expected SHA-256 binds
    the ordinal from an earlier report to the same archive bytes.
    """
    if not isinstance(entry_id, str) or not re.fullmatch(r"entrada-[0-9]{5}", entry_id):
        raise ValueError("El identificador de entrada no es válido.")
    limits = limits or Limits()
    deadline = time.monotonic() + limits.seconds
    def check():
        if time.monotonic() > deadline:
            raise Rejected("Se ha agotado el presupuesto de tiempo.")
    with open_regular_input(path) as (stream, before):
        identity = _fingerprint(stream, before.st_size, limits, check, expected_sha256)
        entries, _ = _directory(stream, before.st_size, limits, check)
        selected = next((entry for entry in entries if entry["id"] == entry_id), None)
        if selected is None:
            raise SelectionNotFound("El identificador solicitado no existe en este ZIP.")
        if _fingerprint(stream, before.st_size, limits, check)["sha256"] != identity["sha256"]:
            raise OSError("Los bytes del ZIP cambiaron durante la localización.")
        assert_unchanged(stream, before)
        return dict(schema_version="1.0", tool=dict(name="PaqueteLupa", version=__version__),
                    operation="locate", archive=identity,
                    entry=dict(id=entry_id, path=selected["name"], size=selected["unpacked"],
                               compressed_size=selected["compressed"]),
                    notes=["Nombre original incluido por solicitud expresa: puede contener datos sensibles.",
                           "Solo se localiza la entrada; no se inspecciona ni extrae su contenido.",
                           "La huella identifica bytes; no prueba autenticidad ni seguridad."])
