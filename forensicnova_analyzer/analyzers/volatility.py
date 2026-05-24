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

import hashlib
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
    """Return the Vol3 version string by reading it from the installed package.

    Vol3 has no working `vol --version` flag (it prints usage instead),
    so we read the version constants directly from the volatility3
    package. The import is lazy so this module can still be loaded if
    Vol3 is somehow misconfigured — we'd just report 'unknown' instead
    of failing import.

    The value is recorded in the analysis JSON as input metadata so
    the analyst can correlate a result with the exact Vol3 build that
    produced it.
    """
    try:
        from volatility3.framework import constants
        return (
            f"{constants.VERSION_MAJOR}."
            f"{constants.VERSION_MINOR}."
            f"{constants.VERSION_PATCH}"
        )
    except Exception as exc:  # noqa: BLE001
        log.warning("could not read volatility3 version: %s", exc)
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


# ===========================================================================
# VolatilityAnalyzer — high-level orchestration of preset plugin pipelines
# ===========================================================================

# Streaming read chunk for the triple-witness hash phase. Same value
# as analyzers/noop.py and swift.download_dump_with_hashes so the I/O
# profile is consistent across the whole pipeline.
_HASH_CHUNK_SIZE = 1024 * 1024  # 1 MiB

# Preset -> plugin list maps. Per-OS variants because Vol3 plugin FQNs
# are OS-specific (windows.pslist.PsList vs linux.pslist.PsList). The
# "fast" preset answers the four triage questions an analyst asks in
# the first minute of incident response:
#
#     - Who is running?       (pslist)
#     - Who spawned whom?     (pstree)   — exposes injection parents
#     - What did they launch? (cmdline)  — exposes credential dumpers
#     - Who's calling out?    (netscan)  — exposes C2 callbacks
#     - What system is this?  (info)     — kernel build, banner, DTB
#
# E4 will introduce PRESET_FULL_* covering injection detection
# (malware.malfind), driver/rootkit (modules, modscan), and credential
# artifacts (registry.hashdump).

PRESET_FAST_WINDOWS = [
    "windows.info.Info",
    "windows.pslist.PsList",
    "windows.pstree.PsTree",
    "windows.cmdline.CmdLine",
    "windows.netscan.NetScan",
]

PRESET_FAST_LINUX = [
    # Placeholder — Linux is out of scope for the thesis demo, but
    # having a non-empty map prevents accidental fallback to windows
    # plugins when a future Linux acquisition lands here.
    "linux.pslist.PsList",
    "linux.psaux.PsAux",
    "linux.lsmod.Lsmod",
    "linux.bash.Bash",
]

# "full" preset — 13 plugins covering all six SANS macro-areas of
# Windows memory forensics:
#
#   1. Identify Rogue Processes   pslist, psscan, pstree
#   2. Analyze Process Objects    cmdline, handles, dlllist
#   3. Review Network Artifacts   netscan
#   4. Look for Code Injection    malware.malfind, malware.ldrmodules,
#                                 malware.hollowprocesses
#   5. Audit Drivers/Rootkit      modules, ssdt
#   6. Metadata                   info
#
# psscan complements pslist by scanning memory for orphaned EPROCESS
# blocks (DKOM-hidden processes). malfind detects RWX regions not
# backed by a file on disk — the canonical signature for Meterpreter
# shellcode injection. hollowprocesses detects process hollowing
# (REMCOS, HijackLoader, generic T1055.012). SSDT detects kernel-level
# hooks placed by rootkits to intercept system calls.

PRESET_FULL_WINDOWS = [
    "windows.info.Info",
    "windows.pslist.PsList",
    "windows.psscan.PsScan",
    "windows.pstree.PsTree",
    "windows.cmdline.CmdLine",
    "windows.handles.Handles",
    "windows.dlllist.DllList",
    "windows.netscan.NetScan",
    "windows.malware.malfind.Malfind",
    "windows.malware.ldrmodules.LdrModules",
    "windows.malware.hollowprocesses.HollowProcesses",
    "windows.modules.Modules",
    "windows.ssdt.SSDT",
]

PRESET_FULL_LINUX = [
    # Placeholder, see PRESET_FAST_LINUX comment.
    "linux.pslist.PsList",
    "linux.psaux.PsAux",
    "linux.lsmod.Lsmod",
    "linux.bash.Bash",
    "linux.malfind.Malfind",
    "linux.check_modules.Check_modules",
    "linux.check_syscall.Check_syscall",
    "linux.check_idt.Check_idt",
]

# Custom preset whitelist — plugins that can be requested via
# preset="custom". The whitelist excludes plugins that produce
# non-JSON-friendly output (binary file dumps, megabytes of raw
# strings) which would inflate the analysis JSON beyond practical
# size limits. Adding a plugin here is a deliberate trust decision:
# the runner will accept it from API callers.
#
# Excluded from the namespace seen on the deployed Vol3 2.28.0:
#   windows.dumpfiles.DumpFiles  — writes PE/file artifacts to disk
#   windows.pedump.PEDump        — writes PE files to disk
#   windows.strings.Strings      — emits a string per byte run (huge)
#
# All other 88 plugins are accepted. The list below is the result of
# `vol --help | grep ^\s+windows\.` filtered against the exclusion
# set, snapshot taken on 2026-05-24 against Vol3 2.28.0.

PLUGIN_WHITELIST_WINDOWS = frozenset({
    "windows.amcache.Amcache",
    "windows.bigpools.BigPools",
    "windows.callbacks.Callbacks",
    "windows.cmdline.CmdLine",
    "windows.cmdscan.CmdScan",
    "windows.consoles.Consoles",
    "windows.crashinfo.Crashinfo",
    "windows.debugregisters.DebugRegisters",
    "windows.deskscan.DeskScan",
    "windows.desktops.Desktops",
    "windows.devicetree.DeviceTree",
    "windows.dlllist.DllList",
    "windows.driverirp.DriverIrp",
    "windows.drivermodule.DriverModule",
    "windows.driverscan.DriverScan",
    "windows.envars.Envars",
    "windows.etwpatch.EtwPatch",
    "windows.filescan.FileScan",
    "windows.getservicesids.GetServiceSIDs",
    "windows.getsids.GetSIDs",
    "windows.handles.Handles",
    "windows.hollowprocesses.HollowProcesses",
    "windows.iat.IAT",
    "windows.info.Info",
    "windows.joblinks.JobLinks",
    "windows.kpcrs.KPCRs",
    "windows.ldrmodules.LdrModules",
    "windows.malfind.Malfind",
    "windows.malware.drivermodule.DriverModule",
    "windows.malware.hollowprocesses.HollowProcesses",
    "windows.malware.ldrmodules.LdrModules",
    "windows.malware.malfind.Malfind",
    "windows.malware.pebmasquerade.PebMasquerade",
    "windows.malware.processghosting.ProcessGhosting",
    "windows.malware.psxview.PsXView",
    "windows.malware.skeleton_key_check.Skeleton_Key_Check",
    "windows.malware.suspicious_threads.SuspiciousThreads",
    "windows.malware.svcdiff.SvcDiff",
    "windows.malware.unhooked_system_calls.UnhookedSystemCalls",
    "windows.mbrscan.MBRScan",
    "windows.memmap.Memmap",
    "windows.modscan.ModScan",
    "windows.modules.Modules",
    "windows.mutantscan.MutantScan",
    "windows.netscan.NetScan",
    "windows.netstat.NetStat",
    "windows.orphan_kernel_threads.Threads",
    "windows.pe_symbols.PESymbols",
    "windows.poolscanner.PoolScanner",
    "windows.privileges.Privs",
    "windows.processghosting.ProcessGhosting",
    "windows.pslist.PsList",
    "windows.psscan.PsScan",
    "windows.pstree.PsTree",
    "windows.psxview.PsXView",
    "windows.registry.amcache.Amcache",
    "windows.registry.certificates.Certificates",
    "windows.registry.getcellroutine.GetCellRoutine",
    "windows.registry.hivelist.HiveList",
    "windows.registry.hivescan.HiveScan",
    "windows.registry.printkey.PrintKey",
    "windows.registry.scheduled_tasks.ScheduledTasks",
    "windows.registry.userassist.UserAssist",
    "windows.scheduled_tasks.ScheduledTasks",
    "windows.sessions.Sessions",
    "windows.shimcachemem.ShimcacheMem",
    "windows.skeleton_key_check.Skeleton_Key_Check",
    "windows.ssdt.SSDT",
    "windows.statistics.Statistics",
    "windows.suspended_threads.SuspendedThreads",
    "windows.suspicious_threads.SuspiciousThreads",
    "windows.svcdiff.SvcDiff",
    "windows.svclist.SvcList",
    "windows.svcscan.SvcScan",
    "windows.symlinkscan.SymlinkScan",
    "windows.thrdscan.ThrdScan",
    "windows.threads.Threads",
    "windows.timers.Timers",
    "windows.truecrypt.Passphrase",
    "windows.unhooked_system_calls.unhooked_system_calls",
    "windows.unloadedmodules.UnloadedModules",
    "windows.vadinfo.VadInfo",
    "windows.vadregexscan.VadRegExScan",
    "windows.vadwalk.VadWalk",
    "windows.verinfo.VerInfo",
    "windows.virtmap.VirtMap",
    "windows.windows.Windows",
    "windows.windowstations.WindowStations",
})

PLUGIN_WHITELIST_LINUX = frozenset({
    # Placeholder. Will be populated when a Linux acquisition lands.
    "linux.pslist.PsList",
    "linux.psaux.PsAux",
    "linux.lsmod.Lsmod",
    "linux.bash.Bash",
    "linux.malfind.Malfind",
    "linux.check_modules.Check_modules",
    "linux.check_syscall.Check_syscall",
    "linux.check_idt.Check_idt",
    "linux.ip.Link",
    "linux.boottime.Boottime",
})

# Per-plugin timeout overrides (seconds). Plugins not listed here use
# the caller's per_plugin_timeout argument (default 300). The values
# are observed upper bounds + margin from running each plugin on a
# 4 GiB Windows Server 2022 dump, with safety factor 3-5x.
#
# Rationale:
#   - Fast metadata plugins: 30s (info, statistics, version queries)
#   - Process-list family: 60s (linear walk of EPROCESS / handle table)
#   - Network plugins: 90s (deep scan with corruption-tolerance)
#   - Memory scanners (malfind, mutantscan, filescan): 300s
#     (linear scan of all RAM with pattern matching)
#   - Registry plugins: 60s (hive parsing is fast once mapped)
#   - Kernel/driver scanners: 180s (heuristic detection)

PLUGIN_TIMEOUTS = {
    # Fast metadata
    "windows.info.Info":                  30,
    "windows.statistics.Statistics":       30,
    "windows.verinfo.VerInfo":             30,
    "windows.kpcrs.KPCRs":                 30,
    "windows.sessions.Sessions":           30,
    "windows.envars.Envars":               60,
    # Process-list family
    "windows.pslist.PsList":               60,
    "windows.pstree.PsTree":               60,
    "windows.cmdline.CmdLine":             60,
    "windows.handles.Handles":            120,
    "windows.dlllist.DllList":            120,
    "windows.getsids.GetSIDs":             60,
    "windows.privileges.Privs":            60,
    # Network
    "windows.netscan.NetScan":             90,
    "windows.netstat.NetStat":             90,
    # Memory-wide scanners
    "windows.psscan.PsScan":               180,
    "windows.modscan.ModScan":              180,
    "windows.filescan.FileScan":            300,
    "windows.mutantscan.MutantScan":        180,
    "windows.thrdscan.ThrdScan":            180,
    "windows.driverscan.DriverScan":        180,
    "windows.poolscanner.PoolScanner":      300,
    "windows.symlinkscan.SymlinkScan":      120,
    # Code injection / malware namespace
    "windows.malware.malfind.Malfind":            300,
    "windows.malfind.Malfind":                    300,
    "windows.malware.ldrmodules.LdrModules":      180,
    "windows.ldrmodules.LdrModules":              180,
    "windows.malware.hollowprocesses.HollowProcesses": 240,
    "windows.hollowprocesses.HollowProcesses":         240,
    "windows.malware.processghosting.ProcessGhosting": 180,
    "windows.processghosting.ProcessGhosting":         180,
    "windows.malware.suspicious_threads.SuspiciousThreads": 180,
    "windows.suspicious_threads.SuspiciousThreads":         180,
    # Kernel / rootkit
    "windows.modules.Modules":              60,
    "windows.ssdt.SSDT":                    60,
    "windows.callbacks.Callbacks":          90,
    "windows.driverirp.DriverIrp":          120,
    # Registry
    "windows.registry.hivelist.HiveList":   60,
    "windows.registry.printkey.PrintKey":   90,
    "windows.amcache.Amcache":              90,
}


def _preset_plugin_list(
    preset: str,
    os_hint: str,
    custom_plugins: Optional[list[str]] = None,
) -> list[str]:
    """Resolve a (preset, os_hint) pair into the Vol3 plugin FQN list.

    For preset="custom" the caller supplies the explicit list via
    `custom_plugins`. Every plugin is validated against the OS-specific
    whitelist (PLUGIN_WHITELIST_WINDOWS / PLUGIN_WHITELIST_LINUX) to
    refuse output-binary plugins (file dumps) and prevent typos from
    silently invoking nothing.

    :raises ValueError: if the combination is not supported, or if
        a custom plugin is missing/empty/not whitelisted.
    """
    if preset == "fast":
        return list(PRESET_FAST_LINUX if os_hint == "linux"
                    else PRESET_FAST_WINDOWS)

    if preset == "full":
        return list(PRESET_FULL_LINUX if os_hint == "linux"
                    else PRESET_FULL_WINDOWS)

    if preset == "custom":
        if not custom_plugins:
            raise ValueError(
                "preset='custom' requires a non-empty 'plugins' list"
            )
        whitelist = (PLUGIN_WHITELIST_LINUX if os_hint == "linux"
                     else PLUGIN_WHITELIST_WINDOWS)
        rejected = [p for p in custom_plugins if p not in whitelist]
        if rejected:
            raise ValueError(
                f"custom plugin(s) not in whitelist for os={os_hint}: "
                f"{rejected}. Plugins producing binary file output "
                f"(dumpfiles, pedump, strings) are excluded by design."
            )
        # Preserve caller-supplied order (analyst may want a specific
        # sequence, e.g. info first then everything else).
        return list(custom_plugins)

    raise ValueError(
        f"preset {preset!r} not supported; supported: 'fast', 'full', 'custom'"
    )


def _resolve_os(summary: dict) -> str:
    """Normalise the OS hint from acquisition summary fields.

    Reads glance_os_type / glance_os_distro from the acquisition
    summary (single point of truth — see swift.summarize_acquisition).
    Returns one of {"windows", "linux"}; defaults to "windows" when
    the metadata is missing or ambiguous (consistent with our demo
    target Windows Server 2022).

    Note: Vol3 has its own automagic that detects the dump's actual
    OS by scanning kernel structures. So a wrong hint here causes at
    worst a useless plugin run that fails fast — it does not corrupt
    results.
    """
    raw_type = (summary.get("glance_os_type") or "").lower().strip()
    raw_distro = (summary.get("glance_os_distro") or "").lower().strip()

    if raw_type == "linux":
        return "linux"
    if raw_distro.startswith(("ubuntu", "debian", "centos", "rhel",
                              "fedora", "rocky", "alma", "suse",
                              "arch", "alpine")):
        return "linux"
    if raw_type == "windows":
        return "windows"
    if raw_distro.startswith("win"):
        return "windows"

    log.info(
        "OS hint not determinable (os_type=%r os_distro=%r), defaulting to windows",
        raw_type, raw_distro,
    )
    return "windows"


class VolatilityAnalyzer:
    """Run a preset (fast/full/custom) of Volatility 3 plugins on a dump.

    Stateful only across one `run()` call; reusable across jobs but
    the runner creates one instance per job.

    Pipeline inside run():
      1. Triple-witness hashing (streaming read, MD5+SHA1). If the
         result does not match the report, hashes_match_report becomes
         False — the runner translates that into fail_job. Vol3 plugins
         are NOT invoked if hashing fails the comparison (fail-fast).
      2. OS resolution (from acquisition metadata).
      3. Preset plugin list selection.
      4. Serial run_plugin() loop. Per-plugin failures (timeout,
         non-zero returncode, JSON parse errors) are recorded in the
         result dict with a status field but do NOT abort the loop.
      5. Aggregate counts (ok / failed / timeout / parse_error).

    Output schema (returned by run()):
      analyzer              "volatility"
      analyzer_version      "0.1.0"
      vol3_version          (from package constants, e.g. "2.28.0")
      preset                "fast" | "full" | "custom"
      os_hint               "windows" | "linux"
      dump_path             absolute path read
      dump_size_bytes       bytes streamed
      dump_md5              hex MD5 computed during step 1
      dump_sha1             hex SHA1 computed during step 1
      hashes_match_report   bool
      mismatch              dict or None
      duration_seconds      total wall-clock (steps 1-5)
      hash_phase_seconds    just step 1 (useful to measure overhead)
      plugin_phase_seconds  just step 4 (useful to compare presets)
      throughput_mib_per_s  derived from step 1
      plugins               dict[plugin_fqn -> run_plugin result dict]
      summary_counts        dict with ok/failed/timeout/parse_error counts

    Failure policy:
      Same as NoOpAnalyzer — does NOT raise on hash mismatch. The
      runner inspects hashes_match_report and decides. Plugin-level
      failures are degradation, not failure: they appear in the
      result with status != "ok" and the job is still considered
      completed (so the operator can see which plugins succeeded).
    """

    name = "volatility"
    version = "0.2.0"

    SUPPORTED_PRESETS = frozenset({"fast", "full", "custom"})

    def __init__(self, vol_cache_dir: Path) -> None:
        """:param vol_cache_dir: XDG_CACHE_HOME for Vol3 subprocesses
        (PDB symbol cache). The runner passes
        <cfg.work_dir>/vol3-cache so the directory is isolated from
        the operator's ~/.cache and reusable across jobs.
        """
        self.vol_cache_dir = Path(vol_cache_dir)

    def run(
        self,
        dump_path: Path,
        expected_md5: str,
        expected_sha1: str,
        summary: dict,
        preset: str = "fast",
        plugins: Optional[list[str]] = None,
        per_plugin_timeout: int = DEFAULT_PLUGIN_TIMEOUT,
    ) -> dict:
        """Execute the requested preset and return an aggregated result.

        :param dump_path:          local path to the dump file
        :param expected_md5:       MD5 from acquisition report (triple-witness)
        :param expected_sha1:      SHA1 from acquisition report (triple-witness)
        :param summary:            full summary from swift.summarize_acquisition,
                                   used for OS resolution
        :param preset:             "fast" (E3), "full"/"custom" (E4)
        :param plugins:            explicit plugin FQN list — only honoured
                                   when preset=="custom" (E4); ignored otherwise
        :param per_plugin_timeout: passed to each run_plugin() call

        :returns: dict per the schema in the class docstring.
        :raises ValueError: if preset is not in SUPPORTED_PRESETS.
        :raises FileNotFoundError: if dump_path does not exist.
        """
        if preset not in self.SUPPORTED_PRESETS:
            raise ValueError(
                f"preset {preset!r} not supported in this revision; "
                f"supported: {sorted(self.SUPPORTED_PRESETS)}"
            )

        dump_path = Path(dump_path)
        if not dump_path.is_file():
            raise FileNotFoundError(f"dump file not found: {dump_path}")

        log.info(
            "[volatility] starting: preset=%s dump=%s",
            preset, dump_path,
        )

        t_total_start = time.monotonic()

        # ----- STEP 1: triple-witness hashing -----
        t_hash_start = time.monotonic()
        md5_h = hashlib.md5()
        sha1_h = hashlib.sha1()
        size_bytes = 0
        with dump_path.open("rb") as fh:
            while True:
                chunk = fh.read(_HASH_CHUNK_SIZE)
                if not chunk:
                    break
                md5_h.update(chunk)
                sha1_h.update(chunk)
                size_bytes += len(chunk)
        hash_phase_seconds = time.monotonic() - t_hash_start

        computed_md5 = md5_h.hexdigest()
        computed_sha1 = sha1_h.hexdigest()
        em = (expected_md5 or "").lower()
        es = (expected_sha1 or "").lower()
        md5_ok = computed_md5 == em
        sha1_ok = computed_sha1 == es
        hashes_match = bool(em and es and md5_ok and sha1_ok)

        throughput_mib_s = (
            (size_bytes / (1024 * 1024)) / hash_phase_seconds
            if hash_phase_seconds > 0 else 0.0
        )

        log.info(
            "[volatility] hash phase done: %.2fs, %.1f MiB/s, match=%s",
            hash_phase_seconds, throughput_mib_s, hashes_match,
        )

        # If hashes don't match, return early WITHOUT running plugins.
        # The runner will see hashes_match_report=False and fail the
        # job. Running plugins on a tampered dump would waste compute
        # and produce misleading results.
        if not hashes_match:
            return {
                "analyzer":             self.name,
                "analyzer_version":     self.version,
                "vol3_version":         get_volatility_version(),
                "preset":               preset,
                "os_hint":              None,  # not resolved when hashes fail
                "dump_path":            str(dump_path),
                "dump_size_bytes":      size_bytes,
                "dump_md5":             computed_md5,
                "dump_sha1":             computed_sha1,
                "hashes_match_report":  False,
                "mismatch": {
                    "expected_md5":  em,
                    "computed_md5":  computed_md5,
                    "md5_match":     md5_ok,
                    "expected_sha1": es,
                    "computed_sha1": computed_sha1,
                    "sha1_match":    sha1_ok,
                },
                "duration_seconds":     round(time.monotonic() - t_total_start, 3),
                "hash_phase_seconds":   round(hash_phase_seconds, 3),
                "plugin_phase_seconds": 0.0,
                "throughput_mib_per_s": round(throughput_mib_s, 2),
                "plugins":              {},
                "summary_counts":       {"ok": 0, "failed": 0, "timeout": 0,
                                         "parse_error": 0, "skipped_hash_fail": 0},
            }

        # ----- STEP 2: OS resolution -----
        os_hint = _resolve_os(summary)
        log.info("[volatility] OS hint resolved: %s", os_hint)

        # ----- STEP 3: preset plugin list -----
        plugin_list = _preset_plugin_list(
            preset, os_hint, custom_plugins=plugins,
        )
        log.info(
            "[volatility] preset=%s os=%s -> %d plugins: %s",
            preset, os_hint, len(plugin_list), plugin_list,
        )

        # ----- STEP 4: serial plugin execution -----
        # Each plugin gets its tailored timeout from PLUGIN_TIMEOUTS,
        # falling back to per_plugin_timeout (the caller-supplied
        # default). Memory-wide scanners (malfind, filescan) get 300s;
        # metadata plugins get 30s. Differentiated timeouts prevent a
        # slow plugin from blocking the loop while letting a hung
        # plugin fail fast.
        t_plug_start = time.monotonic()
        plugin_results: dict[str, dict] = {}
        counts = {"ok": 0, "failed": 0, "timeout": 0, "parse_error": 0}

        for plugin_name in plugin_list:
            this_timeout = PLUGIN_TIMEOUTS.get(plugin_name, per_plugin_timeout)
            log.info(
                "[volatility] running plugin: %s (timeout=%ds)",
                plugin_name, this_timeout,
            )
            result = run_plugin(
                dump_path=dump_path,
                plugin_name=plugin_name,
                cache_dir=self.vol_cache_dir,
                timeout=this_timeout,
            )
            plugin_results[plugin_name] = result
            status = result.get("status", "failed")
            counts[status] = counts.get(status, 0) + 1

        plugin_phase_seconds = time.monotonic() - t_plug_start

        # ----- STEP 5: aggregate and return -----
        total_duration = time.monotonic() - t_total_start

        log.info(
            "[volatility] DONE preset=%s total=%.1fs (hash=%.1fs plugins=%.1fs) counts=%s",
            preset, total_duration, hash_phase_seconds, plugin_phase_seconds,
            counts,
        )

        return {
            "analyzer":             self.name,
            "analyzer_version":     self.version,
            "vol3_version":         get_volatility_version(),
            "preset":               preset,
            "os_hint":              os_hint,
            "dump_path":            str(dump_path),
            "dump_size_bytes":      size_bytes,
            "dump_md5":             computed_md5,
            "dump_sha1":             computed_sha1,
            "hashes_match_report":  True,
            "mismatch":             None,
            "duration_seconds":     round(total_duration, 3),
            "hash_phase_seconds":   round(hash_phase_seconds, 3),
            "plugin_phase_seconds": round(plugin_phase_seconds, 3),
            "throughput_mib_per_s": round(throughput_mib_s, 2),
            "plugins":              plugin_results,
            "summary_counts":       counts,
        }
