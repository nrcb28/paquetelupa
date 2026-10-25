"""Reproducible, supervised smoke fuzzing with synthetic ZIPs only.

This is a regression harness, not an exhaustive security assessment. It never
reads user archives. A parent process kills its worker after at most 60 seconds.
"""

from __future__ import annotations

import argparse
from contextlib import nullcontext
import io
import json
from pathlib import Path
import random
import struct
import subprocess
import sys
import tempfile
import time
import tracemalloc
import zipfile


sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from paquetelupa.scanner import scan_file  # noqa: E402


SEED = 20261025
_SENTINELS = (
    "FUZZ_CREDENTIAL_ND47Q9V7_SYNTHETIC",
    "FUZZ_FILENAME_KT82Q7V9_SYNTHETIC",
    "FUZZ_COMMENT_RM91Q8V3_SYNTHETIC",
)
_INVARIANTS = (
    "no_unexpected_exception", "status_complete_consistent", "input_unchanged",
    "no_extraction_in_fixture_directory", "no_sentinel_in_default_report",
)


def _zip(members, *, compression=zipfile.ZIP_STORED, comment=b""):
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", compression=compression) as archive:
        for name, data in members:
            archive.writestr(name, data)
        archive.comment = comment
    return buffer.getvalue()


def _fixtures():
    benign = _zip([("logs/info.txt", b"Synthetic diagnostic information.\n"),
                   ("config/readme.txt", b"No credentials are required.\n")])
    sensitive = _zip([
        ("config/settings.txt", ("password=" + _SENTINELS[0] + "\n").encode()),
        ("password=" + _SENTINELS[1] + ".txt", b"Synthetic filename fixture.\n"),
    ], compression=zipfile.ZIP_DEFLATED,
       comment=("password=" + _SENTINELS[2]).encode())
    return benign, sensitive


def _mutate(source: bytes, rng: random.Random, ordinal: int):
    """Keep each mutation short; preserve unmodified sensitive baselines too."""
    mode = ordinal % 10
    data = bytearray(source)
    if mode == 0:
        for _ in range(rng.randint(1, 8)):
            data[rng.randrange(len(data))] ^= 1 << rng.randrange(8)
        label = "bit_flips"
    elif mode == 1:
        del data[rng.randrange(len(data) + 1):]
        label = "truncate"
    elif mode == 2:
        start = rng.randrange(len(data))
        count = min(rng.randint(1, 32), len(data) - start)
        data[start:start + count] = rng.randbytes(count)
        label = "overwrite"
    elif mode == 3:
        start = rng.randrange(len(data))
        del data[start:start + rng.randint(1, 64)]
        label = "delete_span"
    elif mode == 4:
        start = rng.randrange(len(data) + 1)
        data[start:start] = rng.randbytes(rng.randint(1, 64))
        label = "insert_span"
    elif mode == 5:
        data = bytearray(rng.randbytes(rng.randint(0, 512)))
        label = "random_bytes"
    elif mode == 6:
        signature = rng.choice((b"PK\x03\x04", b"PK\x01\x02", b"PK\x05\x06"))
        start = data.find(signature)
        fields = {
            b"PK\x03\x04": ((6, 2), (8, 2), (14, 4), (18, 4), (22, 4), (26, 2), (28, 2)),
            b"PK\x01\x02": ((8, 2), (10, 2), (16, 4), (20, 4), (24, 4), (28, 2), (30, 2), (42, 4)),
            b"PK\x05\x06": ((4, 2), (6, 2), (8, 2), (10, 2), (12, 4), (16, 4), (20, 2)),
        }
        offset, width = rng.choice(fields[signature])
        value = rng.choice((0, 1, (1 << (width * 8)) - 1, rng.randrange(1 << (width * 8))))
        struct.pack_into("<H" if width == 2 else "<L", data, start + offset, value)
        label = "structural_field"
    elif mode == 7:
        data.extend(rng.randbytes(rng.randint(1, 64)))
        label = "append"
    elif mode == 8:
        start = rng.randrange(len(data))
        span = data[start:start + rng.randint(1, 64)]
        data[start:start] = span
        label = "duplicate_span"
    else:
        start = rng.randrange(len(data))
        stop = min(len(data), start + rng.randint(1, 64))
        data[start:stop] = reversed(data[start:stop])
        label = "reverse_span"
    return bytes(data), label


def _valid_zip(rng, ordinal):
    members = []
    for index in range(rng.randint(0, 5)):
        name = rng.choice(("logs", "config", "documentación", "synthetic"))
        name += f"/fixture-{ordinal:03d}-{index:02d}.txt"
        mode = rng.randrange(5)
        if mode == 0:
            contents = rng.randbytes(rng.randint(0, 256))
        elif mode == 1:
            contents = ("password=" + _SENTINELS[0]).encode("utf-16")
        elif mode == 2:
            contents = ("Información sintética.\r\n" * rng.randint(1, 10)).encode()
        elif mode == 3:
            contents = b""
        else:
            contents = ("password=" + _SENTINELS[0] + "\n").encode()
        members.append((name, contents))
    comment = ("password=" + _SENTINELS[2]).encode() if ordinal % 7 == 0 else b""
    return _zip(members, compression=rng.choice((zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED)), comment=comment)


class _InvariantFailure(Exception):
    def __init__(self, invariant, exception_type=None):
        self.invariant = invariant
        self.exception_type = exception_type


def _check(path, data, *, trace=False):
    path.write_bytes(data)
    if trace:
        tracemalloc.start()
    started = time.monotonic()
    try:
        report = scan_file(path)
    except Exception as error:
        raise _InvariantFailure("no_unexpected_exception", type(error).__name__) from None
    finally:
        elapsed = time.monotonic() - started
        if trace:
            _, peak = tracemalloc.get_traced_memory()
            tracemalloc.stop()
    if path.read_bytes() != data:
        raise _InvariantFailure("input_unchanged")
    if set(path.parent.iterdir()) != {path}:
        raise _InvariantFailure("no_extraction_in_fixture_directory")
    complete, status = report.get("complete"), report.get("status")
    expected = "incomplete" if complete is False else "review" if report.get("findings") else "no_findings"
    if type(complete) is not bool or status != expected:
        raise _InvariantFailure("status_complete_consistent")
    serialized = json.dumps(report, ensure_ascii=True)
    # Check all sentinels on every case, including cases in which mutations
    # preserve the sensitive bytes. Assertions never echo a captured value.
    if any(sentinel in serialized for sentinel in _SENTINELS):
        raise _InvariantFailure("no_sentinel_in_default_report")
    metrics = {"duration_seconds": round(elapsed, 6), "status": status, "complete": complete}
    if trace:
        metrics["peak_traced_python_bytes"] = peak
    return metrics


def _worker(config):
    started = time.monotonic()
    rng = random.Random(config["seed"])
    result = {
        "seed": config["seed"], "requested_mutations": config["cases"],
        "requested_valid_zip_cases": 100, "completed_cases": 0, "passed": True,
        "sentinel_bearing_cases": 0,
        "invariants": dict.fromkeys(_INVARIANTS, True), "benchmarks": [],
        "limitation": "Prueba reproducible con datos sintéticos; no demuestra seguridad exhaustiva.",
    }
    phase, ordinal, mutation = "baseline", 0, "none"
    try:
        # The supervising parent owns cleanup, including after killing a worker.
        with nullcontext(config["directory"]) as directory:
            path = Path(directory) / "fixture.zip"
            fixtures = _fixtures()
            for ordinal, fixture in enumerate(fixtures):
                _check(path, fixture)
                result["completed_cases"] += 1
                result["sentinel_bearing_cases"] += int(any(value.encode() in fixture for value in _SENTINELS))
            phase = "mutation"
            for ordinal in range(config["cases"]):
                data, mutation = _mutate(fixtures[rng.randrange(len(fixtures))], rng, ordinal)
                _check(path, data)
                result["completed_cases"] += 1
                result["sentinel_bearing_cases"] += int(any(value.encode() in data for value in _SENTINELS))
            phase, mutation = "valid_zip", "none"
            for ordinal in range(100):
                data = _valid_zip(rng, ordinal)
                _check(path, data)
                result["completed_cases"] += 1
                result["sentinel_bearing_cases"] += int(any(value.encode() in data for value in _SENTINELS))
            if config["benchmark"]:
                phase = "benchmark"
                # STORE avoids a compression-ratio rejection. Expanded inputs
                # are exactly 8 MiB and 32 MiB, within the scanner's perimeter.
                payload = b"Readable synthetic benchmark information. "
                payload = (payload * ((8 * 1024 * 1024 // len(payload)) + 1))[:8 * 1024 * 1024]
                for ordinal, count in enumerate((1, 4)):
                    data = _zip([(f"benchmark-{index}.txt", payload) for index in range(count)])
                    metrics = _check(path, data, trace=config["tracemalloc"])
                    metrics["expanded_bytes"] = count * len(payload)
                    metrics["archive_bytes"] = len(data)
                    result["benchmarks"].append(metrics)
                    result["completed_cases"] += 1
    except _InvariantFailure as error:
        result["passed"] = False
        result["invariants"][error.invariant] = False
        result["failure"] = {"phase": phase, "ordinal": ordinal,
                             "mutation": mutation, "invariant": error.invariant}
        if error.exception_type:
            result["failure"]["exception_type"] = error.exception_type
    result["duration_seconds"] = round(time.monotonic() - started, 6)
    return result


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--seed", type=int, default=SEED)
    parser.add_argument("--cases", type=int, default=5000, help="mutaciones, de 1 a 50000")
    parser.add_argument("--seconds", type=float, default=60, help="límite del supervisor, máximo 60 segundos")
    parser.add_argument("--benchmark", action="store_true", help="medir ZIP STORE de 8 y 32 MiB")
    parser.add_argument("--tracemalloc", action="store_true", help="memoria Python durante benchmarks; ralentiza el análisis")
    parser.add_argument("--json", type=Path, help="crear informe exclusivo; nunca sobrescribe")
    parser.add_argument("--_worker", action="store_true", help=argparse.SUPPRESS)
    args = parser.parse_args(argv)
    if args._worker:
        config = json.loads(sys.stdin.read(8192))
        # ASCII transport also works when Windows configures a legacy pipe codepage.
        print(json.dumps(_worker(config), ensure_ascii=True))
        return 0
    if not 0 <= args.seed < 2**63 or not 1 <= args.cases <= 50_000 or not 0 < args.seconds <= 60:
        parser.error("seed, cases o seconds fuera del intervalo admitido")
    config = {"seed": args.seed, "cases": args.cases, "benchmark": args.benchmark,
              "tracemalloc": args.tracemalloc}
    started = time.monotonic()
    try:
        with tempfile.TemporaryDirectory(prefix="paquetelupa-fuzz-") as directory:
            config["directory"] = directory
            process = subprocess.run([sys.executable, str(Path(__file__).resolve()), "--_worker"],
                                     input=json.dumps(config), capture_output=True, text=True,
                                     encoding="utf-8", timeout=args.seconds, check=False)
        result = json.loads(process.stdout) if process.returncode == 0 else None
        if not isinstance(result, dict):
            raise ValueError("worker failed")
    except subprocess.TimeoutExpired:
        result = {"seed": args.seed, "requested_mutations": args.cases,
                  "completed_cases": None, "passed": False, "timed_out": True,
                  "invariants": dict.fromkeys(_INVARIANTS),
                  "limitation": "El supervisor agotó su presupuesto; no se completó la prueba."}
    except (ValueError, TypeError, OSError):
        result = {"seed": args.seed, "requested_mutations": args.cases,
                  "completed_cases": None, "passed": False,
                  "failure": {"invariant": "worker_process_completed"}}
    result["supervised_duration_seconds"] = round(time.monotonic() - started, 6)
    serialized = json.dumps(result, ensure_ascii=True, indent=2) + "\n"
    if args.json is not None:
        try:
            with args.json.open("x", encoding="utf-8", newline="\n") as target:
                target.write(serialized)
        except OSError:
            print("No se pudo crear el informe JSON exclusivo.", file=sys.stderr)
            return 2
    print(serialized, end="")
    return 0 if result.get("passed") else 1


if __name__ == "__main__":
    raise SystemExit(main())
