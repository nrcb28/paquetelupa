"""Bounded, offline heuristics for accidental credential disclosure.

Findings contain locations and constant advice only. They deliberately never
contain captured values, source lines, token hashes, or token fragments. These
heuristics do not verify credentials and cannot establish that text is safe.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Callable
import unicodedata


@dataclass(frozen=True)
class _Rule:
    name: str
    severity: str
    pattern: re.Pattern[str]
    message: str
    remediation: str
    value_group: str | None = None


_PLACEHOLDERS = frozenset({
    "example", "examplepassword", "changeme", "change_me", "replace_me",
    "replaceme", "redacted", "[redacted]", "<redacted>", "<password>",
    "<secret>", "<token>", "<api_key>", "your_password", "your_token",
    "your_api_key", "your_secret", "dummy", "placeholder", "xxxxxxxx",
    "********", "null", "none", "true", "false", "undefined",
    "akiaiosfodnn7example",
})


def _placeholder(value: str) -> bool:
    """Suppress explicit substitution syntax, never arbitrary words like test."""
    # Quoted assignment matches retain their opening delimiter. They capture a
    # bounded prefix so long passphrases do not disappear at the capture limit.
    if value.startswith(('"', "'")):
        delimiter = value[0]
        value = value[1:]
        if value.endswith(delimiter):
            value = value[:-1]
    lower = value.casefold().rstrip(";")
    if lower in _PLACEHOLDERS:
        return True
    # Only complete variable references are placeholders. A shell default may
    # contain an actual password, and an arbitrary '<...>' can be a password.
    if re.fullmatch(r"\$\{[A-Za-z_][A-Za-z0-9_]{0,127}\}", value):
        return True
    if re.fullmatch(r"\{\{[ \t]{0,8}[A-Za-z_][A-Za-z0-9_.]{0,127}[ \t]{0,8}\}\}", value):
        return True
    if lower.startswith(("$env:", "process.env.",
                         "os.environ", "os.getenv(", "getenv(", "env(")):
        return True
    if lower.startswith("$") and re.fullmatch(r"\$[A-Za-z_][A-Za-z0-9_]*", value):
        return True
    if re.fullmatch(r"%[A-Za-z_][A-Za-z0-9_]*%", value):
        return True
    return len(value) >= 4 and set(value) <= {"*"}


_RULES = (
    _Rule(
        "private-key", "high",
        re.compile(r"-----BEGIN (?:RSA |DSA |EC |OPENSSH |PGP |ENCRYPTED )?PRIVATE KEY(?: BLOCK)?-----"),
        "Cabecera de una clave privada.",
        "Retira la clave del paquete; si se compartió, revócala o rótala.",
    ),
    _Rule(
        "aws-access-id", "high",
        re.compile(r"(?<![A-Z0-9])(?P<value>(?:AKIA|ASIA)[A-Z0-9]{16})(?![A-Z0-9])"),
        "Identificador con formato de credencial AWS.",
        "Revisa la credencial asociada y retira los datos de autenticación.", "value",
    ),
    _Rule(
        "github-token", "high",
        re.compile(r"(?<![A-Za-z0-9_])(?P<value>(?:gh[pousr]_[A-Za-z0-9]{36}|github_pat_[A-Za-z0-9_]{20,255}))(?![A-Za-z0-9_])"),
        "Cadena con formato de token de GitHub.",
        "Retira el token; si se compartió, revócalo y genera otro.", "value",
    ),
    _Rule(
        "stripe-live-secret", "high",
        re.compile(r"(?<![A-Za-z0-9_])(?P<value>sk_live_[A-Za-z0-9]{16,128})(?![A-Za-z0-9_])"),
        "Cadena con formato de clave secreta de producción de Stripe.",
        "Retira la clave; si se compartió, rótala en su proveedor.", "value",
    ),
    _Rule(
        "credential-assignment", "medium",
        re.compile(
            r'''(?i)(?<![A-Za-z0-9_])["']?(?:[A-Za-z][A-Za-z0-9_-]{0,63}[_-])?'''
            r'''(?:password|passwd|pwd|(?:api|access|secret|private)[_-]?key|access[_-]?token|auth[_-]?token|token|secret|client[_-]?secret)'''
            r'''["']?[ \t]{0,16}[:=][ \t]{0,16}'''
            r'''(?P<value>"(?:\\[^\r\n]|[^"\\\r\n]){4,256}|'(?:\\[^\r\n]|[^'\\\r\n]){4,256}|[^\s"'`,;#]{4,256})'''
        ),
        "Asignación que puede contener una contraseña, clave o token.",
        "Revisa el valor señalado y sustitúyelo por un marcador antes de compartir.", "value",
    ),
    _Rule(
        "http-authorization", "high",
        re.compile(r'''(?i)\b(?:proxy-)?authorization[ \t"']{0,8}:[ \t"']{0,8}(?:Basic[ \t]{1,16}(?P<basic>[A-Za-z0-9+/]{8,512}={0,2})|Bearer[ \t]{1,16}(?P<bearer>[A-Za-z0-9._~+/=-]{8,2048}))(?![A-Za-z0-9._~+/=-])'''),
        "Posible credencial de autenticación HTTP Basic o Bearer.",
        "Retira los datos de autenticación de cabeceras y registros.",
    ),
    _Rule(
        "database-url-password", "high",
        re.compile(r'''(?i)\b(?:postgres(?:ql)?|mysql|mariadb|mongodb(?:\+srv)?|redis|rediss|amqp|amqps)://[^\s:/@'"]{1,128}:(?P<value>[^\s/@'"]{1,256})@'''),
        "URL de servicio que incluye una contraseña.",
        "Elimina la contraseña de la URL y revisa si requiere rotación.", "value",
    ),
    _Rule(
        "jwt-shaped-value", "medium",
        re.compile(r"(?<![A-Za-z0-9_-])eyJ[A-Za-z0-9_-]{5,1024}\.[A-Za-z0-9_-]{4,4096}\.[A-Za-z0-9_-]{8,1024}(?![A-Za-z0-9_-])"),
        "Cadena con estructura de JWT; puede contener credenciales o datos privados.",
        "Revisa el uso del token y retíralo del paquete si contiene datos sensibles.",
    ),
)


_LINE_BREAK = re.compile(r"\r\n|[\n\r\x85\u2028\u2029]")
_ESCAPE = re.compile(r'''\\(?:u([0-9A-Fa-f]{4})|x([0-9A-Fa-f]{2})|(["\\/]))''')
_ANSI = re.compile(
    r"(?:\x1b\[|\x9b)[0-?]{0,32}[ -/]{0,8}[@-~]"
    r"|(?:\x1b\]|\x9d)[^\x07\x1b\r\n]{0,2048}(?:\x07|\x1b\\)"
)
_CONTROLS = re.compile(r"[\x00-\x08\x0a-\x1f\x7f-\x9f]")
_CONTROL_TRANSLATION = {value: None for value in (*range(0, 9), *range(10, 32), *range(127, 160))}


def _unescape(match: re.Match[str]) -> str:
    if match.group(1) is not None:
        return chr(int(match.group(1), 16))
    if match.group(2) is not None:
        return chr(int(match.group(2), 16))
    return match.group(3)


def _normalized_line(line: str) -> str:
    """Conservative extra view of common log formatting, never a full parser.

    Only two escaping layers are considered; arbitrary obfuscation, other
    encodings and general Unicode confusables are outside these heuristics.
    Unicode compatibility folding is limited to short ASCII replacements; this
    avoids unbounded expansion of compatibility characters such as U+FDFA. The
    caller retains the original view too, so normalization cannot erase a finding.
    """
    if "\\" in line:
        for _ in range(2):
            decoded = _ESCAPE.sub(_unescape, line)
            if decoded == line:
                break
            line = decoded
    if "\x1b" in line or "\x9b" in line or "\x9d" in line:
        line = _ANSI.sub("", line)
    if _CONTROLS.search(line):
        line = line.translate(_CONTROL_TRANSLATION)
    if not line.isascii():
        replacements = {}
        for char in line:
            if ord(char) < 128:
                continue
            if unicodedata.category(char) == "Cf":
                replacements[ord(char)] = None
            else:
                folded = unicodedata.normalize("NFKC", char)
                if folded.isascii() and len(folded) <= 4:
                    replacements[ord(char)] = folded
        # Only format controls and ASCII-compatible characters populate this
        # table. No list of the original characters is materialized.
        if replacements:
            line = line.translate(replacements)
    return line


def _lines(text: str):
    start = 0
    line_number = 1
    for match in _LINE_BREAK.finditer(text):
        yield line_number, text[start:match.start()]
        start = match.end()
        line_number += 1
    if start < len(text):
        yield line_number, text[start:]


def decode_text(data: bytes) -> str | None:
    """Decode UTF-8 or BOM-marked UTF-16; return None for binary/unsupported text.

    Binary identification is a heuristic. A None result must be represented as
    uninspected content by the caller, never as a negative credential result.
    """
    if data.startswith((b"\xff\xfe\x00\x00", b"\x00\x00\xfe\xff")):
        return None  # UTF-32 is deliberately outside the supported encodings.
    encoding = "utf-16" if data.startswith((b"\xff\xfe", b"\xfe\xff")) else "utf-8-sig"
    try:
        text = data.decode(encoding, errors="strict")
    except UnicodeError:
        return None
    if "\x00" in text:
        return None
    bad_controls = sum(ord(char) < 32 and char not in "\t\n\r\f\x1b" for char in text)
    if bad_controls > max(1, len(text) // 100):
        return None
    return text


def scan_text(text: str, entry_id: str, limit: int = 100, *,
              check: Callable[[], None] | None = None) -> list[dict]:
    """Return at most limit metadata-only findings; rule matches are heuristic.

    The caller supplies a safe, opaque entry_id. Limits from 0 to 10,000 are
    accepted. One finding per rule per line prevents repeated values from
    inflating reports. Match widths are bounded and no nested repetition is used.
    CR, LF, CRLF and Unicode line separators retain physical line locations.
    Optional check() is called per line and rule for cooperative supervision;
    exceptions raised by it propagate without capturing source text.
    """
    if not isinstance(limit, int) or isinstance(limit, bool) or not 0 <= limit <= 10_000:
        raise ValueError("limit debe ser un entero entre 0 y 10000")
    findings: list[dict] = []
    if limit == 0:
        return findings
    for line_number, line in _lines(text):
        if check is not None:
            check()
        normalized = _normalized_line(line)
        views = (line,) if normalized == line else (line, normalized)
        for rule in _RULES:
            if check is not None:
                check()
            detected = False
            for view in views:
                for match in rule.pattern.finditer(view):
                    if rule.value_group and _placeholder(match.group(rule.value_group)):
                        continue
                    if rule.name == "http-authorization":
                        if _placeholder(match.group("basic") or match.group("bearer")):
                            continue
                    detected = True
                    break
                if detected:
                    break
            if detected:
                findings.append({
                    "rule": rule.name,
                    "severity": rule.severity,
                    "entry": entry_id,
                    "line": line_number,
                    "message": rule.message,
                    "remediation": rule.remediation,
                })
                if len(findings) >= limit:
                    return findings
    return findings
