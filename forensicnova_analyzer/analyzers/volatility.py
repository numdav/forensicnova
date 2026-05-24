"""ForensicNova — Volatility 3 subprocess wrapper.

Stage E3.1 introduces the low-level primitive `run_plugin()` that
invokes the `vol` CLI as a subprocess, parses its JSON output, and
returns a normalised result dict. The next commit (E3.2) layers
VolatilityAnalyzer on top of it to implement the fast/full/custom
preset dispatch.

Why subprocess and not Python API:

  Volatility 3 ships a `vol` CLI and a `volatility3` Python package.
  In principle the latter could be imported and driven programmatically,
  but in practice every plugin has its own dependency graph and a few
  of them (notably anything that touches the symbol downloader) crash
  with `sys.exit` on errors. A crashed Vol3 plugin invoked in-process
  would kill the Flask service. The subprocess gives us hard isolation:
  Vol3 dying just means we collect a non-zero returncode and continue
  to the next plugin. The price is fork+exec overhead per call (~100 ms),
  which is negligible compared to the multi-second analysis time of a
  4 GiB dump.

Why --renderer json:

  Vol3 supports four renderers: pretty (human-readable table), csv,
  json, and quick. JSON gives us machine-parseable rows of typed
  fields — one JSON list per plugin, each element being a record (a
  process, a network connection, a module, etc.). The output shape
  is plugin-specific but the renderer wrapper is uniform.

Environment isolation:

  - `cwd` is set to the cache directory so any temp files Vol3
    creates land in a controlled location.
  - `XDG_CACHE_HOME` points to the same cache directory so the PDB
    (Microsoft symbol) cache is dedicated to the analyzer service
    (does not pollute the user's ~/.cache).
  - Hard timeout (default 300 s) prevents a runaway plugin from
    blocking the worker thread forever. On timeout the subprocess is
    SIGTERM'd, then SIGKILL'd if it doesn't exit.

Output schema:

  Every invocation returns a dict with the same top-level keys, so
  the aggregator (VolatilityAnalyzer) can serialise an array of
  results uniformly even when some failed.

      plugin            (str)        FQN, e.g. "windows.info.Info"
      status            (str)        "ok" | "failed" | "timeout" | "parse_error"
      returncode        (int|None)   None on timeout
      duration_seconds  (float)      wall-clock time
      rows              (list[dict]) parsed JSON output, [] on failure
      row_count         (int)        len(rows)
      stderr_tail       (str)        last ~50 stderr lines (always useful)
      error_message     (str|None)   populated on non-"ok" status
"""
from __future__ import annotations

import json
import logging
import os
import subprocess
import sys
import time
from pathlib import Path
from typing import Optional

log = logging.getLogger("forensicnova_analyzer.analyzers.volatility")

# Path to the `vol` CLI binary. We derive it from sys.executable so it
# automatically points at the .venv-analyzer of the running process —
# no hardcoded /opt/stack path, no PATH lookup ambiguity.
VOL_BIN = str(Path(sys.executable).parent / "vol")

# Default per-plugin wall-clock timeout. Generous: 5 minutes is enough
# for slow plugins (netscan, malfind on a noisy dump) without letting a
# truly stuck plugin block a job indefinitely.
DEFAULT_PLUGIN_TIMEOUT = 300

# Lines of stderr we keep in the result for diagnostics. Vol3 prints
# warnings, missing-symbol hints, and progress dots on stderr; trimming
# to the tail keeps the analysis JSON small but still useful.
_STDERR_TAIL_LINES = 50


def get_volatility_version() -> str:
    """Return the Vol3 version string by invoking `vol --version`.

    Returns "unknown" if the call fails for any reason. This is
    recorded in the analysis JSON (input metadata) so the analyst can
    correlate a result with the exact Vol3 build that produced it.
    """
    try:
        proc = subprocess.run(
            [VOL_BIN, "--version"],
            capture_output=True,
            text=True,
            timeout=10,
            check=False,
        )
        out = (proc.stdout or proc.stderr or "").strip()
        return out.split("\n", 1)[0] if out else "unknown"
    except Exception as exc:  # noqa: BLE001
        log.warning("could not query vol --version: %s", exc)
        return "unknown"


def run_plugin(
    dump_path: Path,
    plugin_name: str,
    cache_dir: Path,
    timeout: int = DEFAULT_PLUGIN_TIMEOUT,
    extra_args: Optional[list[str]] = None,
) -> dict:
    """Invoke a Volatility 3 plugin via subprocess and parse its output.

    :param dump_path:    absolute path to the memory image
    :param plugin_name:  Vol3 plugin FQN (e.g. "windows.info.Info")
    :param cache_dir:    directory for XDG_CACHE_HOME + subprocess cwd
    :param timeout:      hard wall-clock timeout in seconds
    :param extra_args:   plugin-specific CLI args (e.g. ["--pid", "4"])
                         appended after the plugin name

    :returns: dict with the schema described in this module's docstring.
              Never raises on Vol3 failures; always returns a result.

    :raises FileNotFoundError: if the vol binary or dump file is missing.
    """
    dump_path = Path(dump_path)
    cache_dir = Path(cache_dir)

    if not Path(VOL_BIN).exists():
        raise FileNotFoundError(
            f"vol binary not found at {VOL_BIN!r} — check venv layout"
        )
    if not dump_path.is_file():
        raise FileNotFoundError(f"dump file not found: {dump_path}")

    cache_dir.mkdir(parents=True, exist_ok=True)

    cmd = [
        VOL_BIN,
        "-f", str(dump_path),
        "--renderer", "json",
        "-q",  # quiet: suppress per-row progress dots on stderr
        plugin_name,
    ]
    if extra_args:
        cmd.extend(extra_args)

    log.info(
        "[%s] launching: %s (timeout=%ds, cwd=%s)",
        plugin_name, " ".join(cmd), timeout, cache_dir,
    )

    # Environment: inherit parent (PATH, locale) and override only
    # XDG_CACHE_HOME so Vol3's PDB downloads land in our isolated
    # cache directory.
    env = dict(os.environ)
    env["XDG_CACHE_HOME"] = str(cache_dir)

    t0 = time.monotonic()
    try:
        proc = subprocess.run(
            cmd,
            cwd=str(cache_dir),
            env=env,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
    except subprocess.TimeoutExpired as exc:
        duration = time.monotonic() - t0
        # exc.stderr may carry partial output captured before SIGTERM.
        stderr_partial = exc.stderr or ""
        if isinstance(stderr_partial, bytes):
            stderr_partial = stderr_partial.decode("utf-8", errors="replace")
        stderr_tail = _tail(stderr_partial.strip(), _STDERR_TAIL_LINES)
        log.warning(
            "[%s] TIMEOUT after %.1fs (limit=%ds)",
            plugin_name, duration, timeout,
        )
        return {
            "plugin":           plugin_name,
            "status":           "timeout",
            "returncode":       None,
            "duration_seconds": round(duration, 3),
            "rows":             [],
            "row_count":        0,
            "stderr_tail":      stderr_tail,
            "error_message":    f"plugin exceeded {timeout}s timeout",
        }
    except FileNotFoundError:
        raise  # vol binary or dump missing — caller's fault, surface up
    except Exception as exc:  # noqa: BLE001
        duration = time.monotonic() - t0
        log.exception("[%s] subprocess error", plugin_name)
        return {
            "plugin":           plugin_name,
            "status":           "failed",
            "returncode":       None,
            "duration_seconds": round(duration, 3),
            "rows":             [],
            "row_count":        0,
            "stderr_tail":      "",
            "error_message":    f"subprocess error: {exc}",
        }

    duration = time.monotonic() - t0
    stderr_tail = _tail((proc.stderr or "").strip(), _STDERR_TAIL_LINES)

    if proc.returncode != 0:
        log.warning(
            "[%s] FAILED returncode=%d duration=%.1fs",
            plugin_name, proc.returncode, duration,
        )
        return {
            "plugin":           plugin_name,
            "status":           "failed",
            "returncode":       proc.returncode,
            "duration_seconds": round(duration, 3),
            "rows":             [],
            "row_count":        0,
            "stderr_tail":      stderr_tail,
            "error_message":    f"vol exited with returncode {proc.returncode}",
        }

    stdout = (proc.stdout or "").strip()
    if not stdout:
        log.info("[%s] OK but empty output (0 rows)", plugin_name)
        return {
            "plugin":           plugin_name,
            "status":           "ok",
            "returncode":       0,
            "duration_seconds": round(duration, 3),
            "rows":             [],
            "row_count":        0,
            "stderr_tail":      stderr_tail,
            "error_message":    None,
        }

    try:
        rows = json.loads(stdout)
    except (ValueError, TypeError) as exc:
        log.error(
            "[%s] could not parse JSON output: %s (first 200 chars: %r)",
            plugin_name, exc, stdout[:200],
        )
        return {
            "plugin":           plugin_name,
            "status":           "parse_error",
            "returncode":       0,
            "duration_seconds": round(duration, 3),
            "rows":             [],
            "row_count":        0,
            "stderr_tail":      stderr_tail,
            "error_message":    f"could not parse JSON: {exc}",
        }

    if not isinstance(rows, list):
        # Vol3 should always emit a list for --renderer json; if it
        # doesn't, wrap in a list for schema consistency.
        rows = [rows]

    log.info(
        "[%s] OK %d row(s) in %.1fs",
        plugin_name, len(rows), duration,
    )
    return {
        "plugin":           plugin_name,
        "status":           "ok",
        "returncode":       0,
        "duration_seconds": round(duration, 3),
        "rows":             rows,
        "row_count":        len(rows),
        "stderr_tail":      stderr_tail,
        "error_message":    None,
    }


def _tail(text: str, max_lines: int) -> str:
    """Return the last `max_lines` lines of `text`."""
    if not text:
        return ""
    lines = text.splitlines()
    return "\n".join(lines[-max_lines:])
