"""Build reproducible source ZIP and runnable Python ZIP app, without dependencies."""
from __future__ import annotations
import hashlib
import json
import re
from pathlib import Path, PurePosixPath
import zipfile

ROOT = Path(__file__).resolve().parents[1]
OUTPUT = ROOT.parent
STAMP = (2026, 10, 25, 0, 0, 0)
VERSION = re.search(r'__version__ = "([0-9.]+)"', (ROOT / "paquetelupa" / "__init__.py").read_text(encoding="utf-8")).group(1)


def source_files(root):
    """Ship only the reviewed manifest, never arbitrary reports or local ZIPs."""
    data = json.loads((root / ".release-manifest.json").read_text(encoding="utf-8"))
    names = data.get("files") if isinstance(data, dict) else None
    if not isinstance(names, list) or not 1 <= len(names) <= 500:
        raise ValueError("El manifiesto de entrega no es válido.")
    result = []
    seen = set()
    root = root.resolve()
    for name in names:
        if not isinstance(name, str) or len(name) > 240 or "\\" in name or ":" in name:
            raise ValueError("Ruta de manifiesto no válida.")
        relative = PurePosixPath(name)
        if relative.is_absolute() or any(part in ("", ".", "..", ".git") for part in relative.parts) or str(relative) != name:
            raise ValueError("El manifiesto debe contener rutas relativas normales.")
        key = name.casefold()
        if key in seen:
            raise ValueError("El manifiesto contiene rutas duplicadas.")
        seen.add(key)
        path = root.joinpath(*relative.parts)
        if not path.resolve().is_relative_to(root) or not path.is_file():
            raise ValueError("Un archivo del manifiesto no está dentro del proyecto.")
        for component in (path, *path.parents):
            if component == root:
                break
            if component.is_symlink() or getattr(component.lstat(), "st_file_attributes", 0) & 0x400:
                raise ValueError("La entrega no admite enlaces ni puntos de reanálisis.")
        result.append((name, path))
    return sorted(result)


def add(archive, name, data):
    info = zipfile.ZipInfo(name, STAMP)
    info.compress_type = zipfile.ZIP_DEFLATED
    info.create_system = 3
    info.external_attr = 0o100644 << 16
    archive.writestr(info, data)


def main():
    sources = source_files(ROOT)
    app_path = OUTPUT / f"PaqueteLupa-{VERSION}.pyz"
    with zipfile.ZipFile(app_path, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=9) as archive:
        add(archive, "__main__.py", b'from paquetelupa.__main__ import main\nif __name__ == "__main__":\n    raise SystemExit(main())\n')
        for name, path in sources:
            if name.startswith("paquetelupa/") and path.suffix == ".py":
                add(archive, name, path.read_bytes())
    source_path = OUTPUT / f"PaqueteLupa-{VERSION}-fuentes.zip"
    with zipfile.ZipFile(source_path, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=9) as archive:
        for name, path in sources:
            add(archive, "paquetelupa/" + name, path.read_bytes())
    sums = "".join(hashlib.sha256(path.read_bytes()).hexdigest() + "  " + path.name + "\n" for path in sorted(OUTPUT.glob("PaqueteLupa-*")) if path.suffix in (".pyz", ".zip"))
    (OUTPUT / "SHA256SUMS.txt").write_text(sums, encoding="ascii")
    version_sums = "".join(hashlib.sha256(path.read_bytes()).hexdigest() + "  " + path.name + "\n" for path in (app_path, source_path))
    (OUTPUT / f"PaqueteLupa-{VERSION}-SHA256SUMS.txt").write_text(version_sums, encoding="ascii")
    print(sums, end="")


if __name__ == "__main__":
    main()
