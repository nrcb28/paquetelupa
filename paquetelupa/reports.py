"""Informes locales: sin contenido de archivos, JavaScript ni recursos externos."""

from __future__ import annotations

import html
from itertools import islice
import unicodedata
from typing import Any


MAX_ROWS = 1000
MAX_FIELD = 1200
_STATUS = {
    "review": ("Requiere revisión", "review"),
    "incomplete": ("Análisis incompleto", "incomplete"),
    "no_findings": ("Sin coincidencias en lo revisado", "no-findings"),
}
_SEVERITIES = {
    "critical": "Crítica",
    "high": "Alta",
    "medium": "Media",
    "low": "Baja",
    "info": "Información",
}


def _display(value: Any, maximum: int = MAX_FIELD) -> str:
    """Make untrusted fields single-line, bounded, and resistant to spoofing."""
    value = str(value) if value is not None else "—"
    truncated = len(value) > maximum
    value = value[:maximum]
    parts = []
    for char in value:
        code = ord(char)
        if unicodedata.category(char).startswith("C") or char in "\u2028\u2029":
            parts.append(f"\\u{code:04x}" if code <= 0xFFFF else f"\\U{code:08x}")
        else:
            parts.append(char)
    return "".join(parts) + ("… [truncado]" if truncated else "")


def _html(value: Any, maximum: int = MAX_FIELD) -> str:
    return html.escape(_display(value, maximum), quote=True)


def _mapping(value: Any) -> dict:
    return value if isinstance(value, dict) else {}


def _rows(value: Any) -> list:
    return value if isinstance(value, list) else []


def _status(report: dict) -> tuple[str, str]:
    if report.get("complete") is not True:
        return _STATUS["incomplete"]
    status = report.get("status")
    return _STATUS.get(status, _STATUS["incomplete"]) if isinstance(status, str) else _STATUS["incomplete"]


def _location(item: dict) -> str:
    entry = item.get("entry")
    line = item.get("line")
    location = _display(entry, 160) if entry is not None else "Archivo ZIP"
    if line is not None:
        location += " · línea " + _display(line, 30)
    return location


def render_text(report: dict) -> str:
    """Render a readable terminal report without executable control sequences."""
    report = _mapping(report)
    title, _ = _status(report)
    summary = _mapping(report.get("summary"))
    findings = _rows(report.get("findings"))
    entries = _rows(report.get("entries"))
    notes = _rows(report.get("notes"))
    tool = _mapping(report.get("tool"))
    lines = [
        "PAQUETELUPA · Revisión local de paquetes de soporte",
        "Versión " + _display(tool.get("version", "—"), 40),
        "Resultado: " + title,
        "Cobertura: " + ("completa dentro del alcance" if report.get("complete") is True else "incompleta"),
        "",
        "Entradas: " + _display(summary.get("entries", 0), 30),
        "Textos revisados: " + _display(summary.get("scanned_text_files", 0), 30),
        "Archivos omitidos: " + _display(summary.get("skipped_files", 0), 30),
        "Bytes leídos: " + _display(summary.get("bytes_read", 0), 30),
        "Hallazgos: " + _display(summary.get("findings", len(findings)), 30),
        "",
        "Este informe no es un certificado de seguridad.",
        "La ausencia de coincidencias no garantiza que el paquete sea seguro ni que carezca de secretos.",
        "Los valores detectados y el contenido de los archivos no se incluyen en el informe.",
        "",
        "HALLAZGOS",
    ]
    identity = _mapping(report.get("archive"))
    if identity:
        lines[4:4] = ["SHA-256 del ZIP: " + _display(identity.get("sha256"), 64),
                      "La huella identifica bytes; no prueba autenticidad ni seguridad."]
    if any(isinstance(item, dict) and "path" in item for item in entries):
        lines[0:0] = ["AVISO: solicitaste nombres originales; pueden incluir credenciales y datos sensibles.", ""]
    if not findings:
        lines.append("No se registraron coincidencias. Revisa la cobertura y los archivos omitidos.")
    for raw in findings[:MAX_ROWS]:
        item = _mapping(raw)
        severity_value = _display(item.get("severity"), 40)
        severity = _SEVERITIES.get(severity_value, severity_value)
        lines.append("- [" + severity + "] " + _display(item.get("rule"), 160))
        lines.append("  Ubicación: " + _location(item))
        lines.append("  " + _display(item.get("message")))
        lines.append("  Acción: " + _display(item.get("remediation")))
    if len(findings) > MAX_ROWS:
        lines.append("Se omiten filas del informe por el límite de presentación; consulta el JSON.")
    lines.extend(["", "COBERTURA POR ENTRADA"])
    for raw in entries[:MAX_ROWS]:
        item = _mapping(raw)
        row = "- " + _display(item.get("id"), 160) + " | " + _display(item.get("state"), 100)
        row += " | " + _display(item.get("size"), 30) + " bytes"
        if "path" in item:
            row += " | ruta: " + _display(item.get("path"), 240)
        lines.append(row)
    if not entries:
        lines.append("Sin entradas disponibles.")
    if len(entries) > MAX_ROWS:
        lines.append("Se omiten filas del informe por el límite de presentación; consulta el JSON.")
    lines.extend(["", "Los nombres de las entradas se omiten salvo solicitud expresa.", "", "LÍMITES APLICADOS"])
    limits = _mapping(report.get("limits"))
    for key, value in islice(limits.items(), 100):
        lines.append("- " + _display(key, 120) + ": " + _display(value, 160))
    if notes:
        lines.extend(["", "NOTAS"])
        lines.extend("- " + _display(note) for note in notes[:MAX_ROWS])
    return "\n".join(lines) + "\n"


def render_html(report: dict) -> str:
    """Render a standalone, inert HTML report; escape every dynamic field."""
    report = _mapping(report)
    title, status_class = _status(report)
    summary = _mapping(report.get("summary"))
    findings = _rows(report.get("findings"))
    entries = _rows(report.get("entries"))
    notes = _rows(report.get("notes"))
    tool = _mapping(report.get("tool"))
    metrics = [
        ("Entradas", summary.get("entries", 0)),
        ("Textos revisados", summary.get("scanned_text_files", 0)),
        ("Archivos omitidos", summary.get("skipped_files", 0)),
        ("Hallazgos", summary.get("findings", len(findings))),
    ]
    cards = "".join(f'<div class="metric"><strong>{_html(value, 30)}</strong><span>{label}</span></div>' for label, value in metrics)
    finding_rows = []
    for raw in findings[:MAX_ROWS]:
        item = _mapping(raw)
        severity_value = _display(item.get("severity"), 40)
        severity = _SEVERITIES.get(severity_value, severity_value)
        finding_rows.append(
            '<tr><td><span class="severity">' + _html(severity, 40) + '</span><br><code>'
            + _html(item.get("rule"), 160) + '</code></td><td>' + _html(_location(item), 240)
            + '</td><td>' + _html(item.get("message")) + '<p class="action"><strong>Acción:</strong> '
            + _html(item.get("remediation")) + '</p></td></tr>'
        )
    findings_body = ('<div class="table-wrap"><table><thead><tr><th>Prioridad / regla</th><th>Ubicación</th><th>Detalle y siguiente paso</th></tr></thead><tbody>'
                     + "".join(finding_rows) + '</tbody></table></div>') if finding_rows else (
                         '<p class="empty">No se registraron coincidencias. Comprueba la cobertura y los archivos omitidos antes de decidir si puedes compartir el paquete.</p>')
    if len(findings) > MAX_ROWS:
        findings_body += '<p class="warning">Se omiten filas por el límite de presentación. Consulta el JSON para el detalle completo.</p>'
    show_paths = any(isinstance(item, dict) and "path" in item for item in entries[:MAX_ROWS])
    path_notice = ('<p class="warning"><strong>Nombres originales incluidos por solicitud expresa: pueden revelar credenciales y datos sensibles.</strong></p>' if show_paths else '')
    entry_rows = []
    for raw in entries[:MAX_ROWS]:
        item = _mapping(raw)
        entry_rows.append('<tr><td><code>' + _html(item.get("id"), 160) + '</code></td>'
                          + ('<td class="path">' + _html(item.get("path"), 400) + '</td>' if show_paths else '')
                          + '<td>' + _html(item.get("state"), 100) + '</td><td>' + _html(item.get("size"), 30)
                          + '</td><td>' + _html(item.get("compressed_size"), 30) + '</td></tr>')
    entries_body = ('<div class="table-wrap"><table><thead><tr><th>Entrada</th>'
                    + ('<th>Ruta solicitada</th>' if show_paths else '')
                    + '<th>Estado</th><th>Bytes declarados</th><th>Bytes comprimidos</th></tr></thead><tbody>'
                    + "".join(entry_rows) + '</tbody></table></div>') if entry_rows else '<p class="empty">Sin entradas disponibles.</p>'
    if len(entries) > MAX_ROWS:
        entries_body += '<p class="warning">Se omiten filas por el límite de presentación. Consulta el JSON.</p>'
    limit_rows = "".join('<tr><th scope="row">' + _html(key, 120) + '</th><td>' + _html(value, 160) + '</td></tr>'
                         for key, value in islice(_mapping(report.get("limits")).items(), 100))
    notes_html = '<ul>' + "".join('<li>' + _html(note) + '</li>' for note in notes[:MAX_ROWS]) + '</ul>' if notes else '<p>No hay notas adicionales.</p>'
    coverage = 'Completa dentro del alcance configurado' if report.get("complete") is True else 'Incompleta: hay contenido sin revisar o se alcanzó un límite'
    identity = _mapping(report.get("archive"))
    identity_html = ('<p><strong>SHA-256 del ZIP:</strong> <code>' + _html(identity.get("sha256"), 64)
                     + '</code></p><p class="muted">La huella permite comprobar que los IDs corresponden al mismo archivo; no prueba autenticidad ni seguridad.</p>' if identity else '')
    return f'''<!doctype html>
<html lang="es">
<head>
<meta charset="utf-8">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'; form-action 'none'; img-src 'none'">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="referrer" content="no-referrer">
<title>PaqueteLupa · Informe de revisión</title>
<style>
:root{{color-scheme:light;--ink:#172b38;--muted:#526774;--line:#d8e2e7;--paper:#fff;--bg:#f2f6f7}}
*{{box-sizing:border-box}}body{{margin:0;background:var(--bg);color:var(--ink);font:16px/1.6 "Segoe UI",system-ui,sans-serif}}
main{{max-width:1180px;margin:auto;padding:48px 28px}}header{{padding:34px;border-radius:18px;background:#123442;color:#fff}}
.eyebrow{{font-size:12px;font-weight:700;letter-spacing:.14em;text-transform:uppercase;color:#a9d6d2}}
h1{{font-size:clamp(30px,5vw,46px);letter-spacing:-.04em;margin:8px 0 4px;line-height:1.15}}header p{{margin:14px 0 0;color:#dfebee;max-width:760px}}
.badge{{display:inline-block;margin-top:24px;padding:7px 13px;border-radius:7px;background:#e3eee9;color:#174d40;font-weight:700}}
.badge.review{{background:#ffe1d8;color:#7b2d1e}}.badge.incomplete{{background:#fff0c4;color:#684510}}
.metrics{{display:grid;grid-template-columns:repeat(4,1fr);gap:14px;margin:22px 0}}.metric{{background:white;border:1px solid var(--line);border-radius:12px;padding:20px;overflow-wrap:anywhere}}
.metric strong{{display:block;font-size:30px;line-height:1.2}}.metric span{{display:block;color:var(--muted);font-size:14px;margin-top:5px}}
section{{margin-top:24px;padding:26px;background:var(--paper);border:1px solid var(--line);border-radius:14px}}h2{{margin:0 0 10px;font-size:23px;letter-spacing:-.02em}}
p{{margin:9px 0}}.muted{{color:var(--muted);font-size:14px}}.notice{{padding:20px 24px;border-left:4px solid #b6732f;background:#fff9ed;border-radius:8px}}
.table-wrap{{overflow-x:auto;margin-top:18px}}table{{border-collapse:collapse;width:100%;text-align:left;font-size:14px}}th,td{{padding:13px 12px;border-bottom:1px solid var(--line);vertical-align:top;overflow-wrap:anywhere;max-width:470px}}
thead th{{background:#f1f6f7;font-size:12px;text-transform:uppercase;letter-spacing:.04em}}code{{font-family:Consolas,monospace;font-size:12px;overflow-wrap:anywhere}}.severity{{font-weight:700}}
.action{{color:var(--muted);margin:10px 0 0}}.empty{{color:var(--muted);padding:16px;background:#f6f8f9;border-radius:8px}}.warning{{color:#754b16}}
.path{{unicode-bidi:plaintext}}li{{overflow-wrap:anywhere;margin:7px 0}}footer{{margin:28px 0 0;color:var(--muted);font-size:12px}}.coverage{{font-weight:600}}
@media(max-width:700px){{main{{padding:20px 14px}}header,section{{padding:22px}}.metrics{{grid-template-columns:repeat(2,1fr)}}th,td{{padding:10px 8px}}}}
@media print{{body{{background:white}}main{{padding:0}}header{{border:1px solid #123442}}section,.metric{{break-inside:avoid}}.table-wrap{{overflow:visible}}}}
</style>
</head>
<body><main>
<header><div class="eyebrow">PaqueteLupa / Revisión local</div><h1>Antes de compartir,<br>mira dentro.</h1>
<p>Informe de revisión de un paquete ZIP de soporte. Hallazgos, límites y cobertura en un documento local.</p>
<div class="badge {status_class}">{_html(title)}</div></header>
<div class="metrics">{cards}</div>
<aside class="notice"><strong>Este informe no es un certificado de seguridad.</strong><p>La ausencia de coincidencias no garantiza que el paquete sea seguro ni que carezca de secretos. Revisa los hallazgos y el contenido que quedó fuera del análisis.</p><p class="muted">No se incluyen fragmentos del contenido de los archivos ni los valores capturados por los detectores.</p>{path_notice}</aside>
<section><h2>Hallazgos</h2><p class="muted">Cada entrada se identifica mediante un ID. La ubicación permite revisar el archivo original sin publicar su contenido.</p>{findings_body}</section>
<section><h2>Cobertura</h2><p class="coverage">{coverage}</p>{identity_html}<p class="muted">Bytes leídos: {_html(summary.get("bytes_read", 0), 30)}. Los nombres de las entradas se omiten salvo solicitud expresa.</p>{entries_body}</section>
<section><h2>Límites aplicados</h2><p class="muted">Los límites protegen los recursos del equipo. El contenido omitido requiere una revisión adicional.</p><div class="table-wrap"><table><tbody>{limit_rows}</tbody></table></div></section>
<section><h2>Notas y alcance</h2>{notes_html}</section>
<footer>PaqueteLupa {_html(tool.get("version", "—"), 40)} · Esquema {_html(report.get("schema_version", "—"), 30)} · Documento sin JavaScript ni recursos externos.</footer>
</main></body></html>'''
