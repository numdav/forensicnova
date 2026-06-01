"""MISP enrichment analyzer for ForensicNova (Stage F.2).

The MispEnricher is the second-pass "intelligence" layer of the
analyzer backend. It does NOT touch the RAM dump. Instead it reads an
existing ``analysis-volatility-*.json`` (already produced by the
VolatilityAnalyzer), extracts indicators of compromise (IOCs) from the
Vol3 plugin output, queries a MISP instance for each IOC, and produces
an ``analysis-misp-*.json`` structured per schema v1.0.

Pipeline (implemented in MispEnricher.run):
    1. Validate source analysis (hash coherence + os_hint == windows)
    2. Extract IOCs by plugin (see _ioc_extractors)         [Step B]
    3. Filter IOCs (RFC1918 / loopback / multicast / MS CDN /
       Windows-native processes / system DLL paths)         [this file]
    4. Extract injection signals (malfind / psxview)         [Step B]
    5. For each surviving IOC: query MISP via pymisp          [Step C]
    6. Aggregate enrichment results
    7. Compute deterministic threat_score (green/yellow/red,
       MISP matches + injection signals)                     [Step D]
    8. Return analysis-misp-*.json per schema v1.0           [Step E]

Design references:
    - schema-analysis-v1.md  section 4 (Analysis MISP schema)
    - stage_F_design.md      section 4 (MispEnricher architecture)

Filtering rationale (see _is_private_ip, _is_ms_cdn, etc.): we drop
IOCs that are certainly not interesting BEFORE querying MISP, to avoid
(a) flooding MISP with useless lookups and (b) false positives on
legitimate Windows traffic / native processes. Crucially, the
process-name filter is a NOISE-REDUCTION heuristic, not a malware
escape hatch: C2 IPs come from netscan (not name-filtered) and code
injection is flagged by malfind independently of the host process name.
"""
from __future__ import annotations

import ipaddress
import logging
import re
import uuid
from datetime import datetime, timezone
from typing import Iterable

# pymisp is imported lazily/guarded so that this module can be imported
# (and its module-level filtering helpers unit-tested) even in an
# environment where pymisp is not installed.
try:
    from pymisp import PyMISP
except ImportError:  # pragma: no cover
    PyMISP = None  # type: ignore

log = logging.getLogger(__name__)

ANALYZER_VERSION = "0.1.0"


# =====================================================================
# Filtering constants
# =====================================================================

# Microsoft Update / CDN / corp IP ranges that represent LEGITIMATE
# Windows system traffic (Windows Update, Defender signatures, Bing,
# activation, telemetry). These are public IPs, so RFC1918 filtering
# does not catch them; we whitelist a minimal core set here.
#
# NOTE (thesis future work): Microsoft publishes hundreds of ranges,
# updated regularly, in machine-readable form (endpoints.office.com,
# Azure IP ranges JSON). This hardcoded list is intentionally minimal:
# it filters the most common Windows Update / Microsoft endpoints. A
# production system would fetch and refresh the full list dynamically.
MS_UPDATE_CDN_RANGES = [
    ipaddress.ip_network("13.107.4.0/22"),     # Windows Update / MS CDN
    ipaddress.ip_network("13.107.6.0/24"),     # MS CDN
    ipaddress.ip_network("13.107.9.0/24"),     # MS CDN
    ipaddress.ip_network("204.79.197.0/24"),   # Bing / MSN
    ipaddress.ip_network("131.107.0.0/16"),    # Microsoft Corp
    ipaddress.ip_network("23.218.0.0/16"),     # Akamai-hosted MS content
]

# Windows-native process image names (lowercased). Processes whose
# ImageFileName matches this set are NOT emitted as filename IOCs:
# sending "svchost.exe" to MISP yields only noise (thousands of benign
# events mention it). The malware's REAL indicators (C2 IP from
# netscan, file hashes) are captured by other, non-name-filtered
# vectors, and code injection into a native process is flagged by
# malfind regardless of the host name.
#
# NOTE: Vol3 EPROCESS ImageFileName is truncated to 15 chars by the
# Windows kernel, so long names appear cut. Matching is case-insensitive
# on the (possibly truncated) name as reported by pslist.
WINDOWS_NATIVE_PROCESSES = frozenset({
    "system", "registry", "memcompression", "smss.exe", "csrss.exe",
    "wininit.exe", "winlogon.exe", "services.exe", "lsass.exe",
    "lsaiso.exe", "svchost.exe", "fontdrvhost.exe", "dwm.exe",
    "explorer.exe", "taskhostw.exe", "sihost.exe", "ctfmon.exe",
    "runtimebroker.e", "runtimebroker.exe", "searchapp.exe",
    "searchui.exe", "searchindexer.", "searchindexer.exe",
    "startmenuexperi", "shellexperienc", "applicationfram",
    "spoolsv.exe", "dllhost.exe", "conhost.exe", "wmiprvse.exe",
    "msmpeng.exe", "nissrv.exe", "securityhealth", "mpdefendercore",
    "smartscreen.ex", "smartscreen.exe", "audiodg.exe",
    "wininit.exe", "lsm.exe", "taskeng.exe", "taskmgr.exe",
    "mmc.exe", "wuauclt.exe", "trustedinstall", "tiworker.exe",
    "msiexec.exe", "vmtoolsd.exe", "vm3dservice.ex", "vmacthlp.exe",
    "servermanager.", "vds.exe", "dfsrs.exe", "dns.exe",
    # Additional Server 2022 natives observed on a clean dump. Vol3
    # truncates ImageFileName to 15 chars, so several appear cut; we
    # store the TRUNCATED forms because that is what pslist reports.
    "fontdrvhost.ex", "sppsvc.exe", "wlms.exe", "aggregatorhost",
    "sppextcomobj.e", "msdtc.exe", "userinit.exe", "startmenuexper",
    "runtimebroker.", "textinputhost.", "win32calc.exe",
    "shellexperienc", "applicationfra", "dwm.exe", "lsaiso.exe",
    "secdrv.exe", "wlms.exe", "spaceman.exe", "wermgr.exe",
    "werfault.exe", "consent.exe", "dashost.exe", "sgrmbroker.exe",
    "sgrmbroker.exe", "backgroundtask", "systemsettings",
})

# System DLL path prefixes (lowercased). DLL paths under these
# directories are not emitted as IOCs (legitimate system libraries).
SYSTEM_DLL_PREFIXES = (
    "c:\\windows\\system32\\",
    "c:\\windows\\syswow64\\",
    "c:\\windows\\winsxs\\",
)

# RFC 5737 documentation ranges (TEST-NET-1/2/3). Python's ipaddress
# marks these as is_private==True (they are non-routable), but our
# demo deliberately uses 203.0.113.42 (TEST-NET-3) as the Meterpreter
# C2 address precisely BECAUSE it is non-routable yet looks public.
# We must therefore NOT filter these out — they have to reach MISP so
# the demo C2 IOC matches. We treat TEST-NET as "public for our
# purposes" by exempting it from the private-IP filter below.
DOC_TEST_NET_RANGES = [
    ipaddress.ip_network("192.0.2.0/24"),     # TEST-NET-1
    ipaddress.ip_network("198.51.100.0/24"),  # TEST-NET-2
    ipaddress.ip_network("203.0.113.0/24"),   # TEST-NET-3 (demo C2)
]


# =====================================================================
# Threat-score constants
# =====================================================================

# Galaxy "name:value" prefixes that, if matched by ANY enriched event,
# push the threat score to red. Any threat actor (APT), high-impact
# malware classes, and notorious offensive tooling.
HIGH_RISK_GALAXY_PREFIXES = (
    "Threat Actor:",          # any APT / named actor
    "Intrusion Set:",         # ATT&CK group naming variant
    "Malware:Ransomware",
    "Malware:Wiper",
    "Tool:Mimikatz",
    "Tool:Cobalt Strike",
    "Tool:Empire",
    "Tool:Meterpreter",
)

# Best-effort actor-hint dictionary used by _parse_attribution as a
# TEXTUAL fallback when an event lacks structured threat-actor
# galaxies/tags. CIRCL OSINT events frequently mention actor names
# only in the 'info' field (e.g. "Sofacy", "APT28") without a
# corresponding galaxy. We surface this as actor_hint (not actor) in
# the analysis JSON to distinguish heuristic from structured data.
# Keys are case-insensitive substrings to search for in event.info.
KNOWN_ACTOR_HINTS = {
    "apt28": "APT28", "sofacy": "APT28", "fancy bear": "APT28",
    "tsar team": "APT28",
    "apt29": "APT29", "cozy bear": "APT29", "the dukes": "APT29",
    "lazarus": "Lazarus", "hidden cobra": "Lazarus",
    "apt1": "APT1", "comment crew": "APT1",
    "apt41": "APT41", "winnti": "APT41", "barium": "APT41",
    "fin7": "FIN7", "carbanak": "FIN7",
    "muddywater": "MuddyWater", "static kitten": "MuddyWater",
    "turla": "Turla", "snake": "Turla",
    "equation group": "Equation",
    "darkhotel": "DarkHotel",
    "kimsuky": "Kimsuky", "thallium": "Kimsuky",
    "conti": "Conti", "lockbit": "LockBit", "blackcat": "BlackCat",
    "alphv": "BlackCat", "revil": "REvil", "sodinokibi": "REvil",
}


# =====================================================================
# Filtering helper functions (module-level, unit-testable)
# =====================================================================

def _is_private_ip(ip_str: str) -> bool:
    """True if IP is RFC1918 private, loopback, or multicast.

    EXCEPTION: RFC 5737 documentation ranges (TEST-NET) are treated as
    NOT private, because the demo uses 203.0.113.42 as the Meterpreter
    C2 and it must reach MISP. See DOC_TEST_NET_RANGES.

    Returns False for anything that is not a parseable IP address
    (so malformed values are treated as "not private" and would be
    caught/skipped elsewhere rather than silently dropped here).
    """
    try:
        ip = ipaddress.ip_address(ip_str)
    except ValueError:
        return False
    # Exempt documentation/TEST-NET ranges: they look public to us.
    if any(ip in net for net in DOC_TEST_NET_RANGES):
        return False
    return ip.is_private or ip.is_loopback or ip.is_multicast or ip.is_link_local


def _is_valid_ip(ip_str: str) -> bool:
    """True only if ip_str parses as a real IPv4/IPv6 address.

    Guards against malformed values that Vol3 sometimes emits from
    partially-overwritten memory (e.g. '86.0.622.38', octet > 255).
    Such junk must never be sent to MISP as an IOC.
    """
    try:
        ipaddress.ip_address(ip_str)
        return True
    except ValueError:
        return False


def _is_ms_cdn(ip_str: str) -> bool:
    """True if IP falls in a known Microsoft Update/CDN/corp range."""
    try:
        ip = ipaddress.ip_address(ip_str)
    except ValueError:
        return False
    return any(ip in net for net in MS_UPDATE_CDN_RANGES)


def _is_windows_native_process(image_name: str) -> bool:
    """True if a process image name is a known Windows-native process."""
    if not image_name:
        return False
    return image_name.strip().lower() in WINDOWS_NATIVE_PROCESSES


def _is_system_dll_path(path: str) -> bool:
    """True if a DLL path is under a known system directory."""
    if not path:
        return False
    return path.strip().lower().startswith(SYSTEM_DLL_PREFIXES)


# =====================================================================
# IOC extractors and injection-signal counters (Step B)
# =====================================================================
#
# Vol3's JSON renderer emits ABSENT values as the literal string
# 'None' (not Python None), and empty/listening sockets show
# '0.0.0.0' / '::' / '*'. _nullish() treats all of these as "no value".

_NULLISH = frozenset({"", "none", "0.0.0.0", "::", "*", "*:*"})


def _nullish(value) -> bool:
    """True if a Vol3 cell carries no real value (incl. literal 'None')."""
    return value is None or str(value).strip().lower() in _NULLISH


# Regexes for pulling IOCs out of free-text command lines.
_IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_URL_RE = re.compile(r"https?://[^\s\"'<>]+", re.IGNORECASE)
_SHA256_RE = re.compile(r"\b[A-Fa-f0-9]{64}\b")
_SHA1_RE = re.compile(r"\b[A-Fa-f0-9]{40}\b")
_MD5_RE = re.compile(r"\b[A-Fa-f0-9]{32}\b")


def _extract_iocs_from_netscan(rows: list) -> Iterable[tuple]:
    """Yield ForeignAddr as ip-dst, skipping null/private/CDN addresses.

    netscan columns (Vol3 2.28.0): ForeignAddr, ForeignPort, LocalAddr,
    LocalPort, Owner, PID, Proto, State, Created, Offset.
    """
    for row in rows:
        addr = row.get("ForeignAddr")
        if _nullish(addr) or not _is_valid_ip(addr):
            continue
        if _is_private_ip(addr) or _is_ms_cdn(addr):
            continue
        ctx = (f"ForeignAddr:{row.get('ForeignPort')} from PID "
               f"{row.get('PID')} ({row.get('Owner')}) "
               f"{row.get('Proto')} {row.get('State')}")
        yield ("ip-dst", addr, ctx)


def _extract_iocs_from_pslist(rows: list) -> Iterable[tuple]:
    """Yield non-native process ImageFileName as filename IOC.

    pslist columns: ImageFileName, PID, PPID, Threads, Handles,
    SessionId, Wow64, CreateTime, ExitTime, Offset(V).
    """
    for row in rows:
        name = row.get("ImageFileName")
        if _nullish(name) or _is_windows_native_process(name):
            continue
        ctx = f"PID {row.get('PID')}, PPID {row.get('PPID')}"
        yield ("filename", name, ctx)


def _extract_iocs_from_cmdline(rows: list) -> Iterable[tuple]:
    """Regex URLs / public IPs / hashes out of command-line Args.

    cmdline columns: Args, Process, PID.
    """
    for row in rows:
        args = row.get("Args")
        if _nullish(args):
            continue
        proc, pid = row.get("Process"), row.get("PID")
        for url in set(_URL_RE.findall(args)):
            yield ("url", url, f"cmdline of {proc} (PID {pid})")
        for ip in set(_IP_RE.findall(args)):
            if not _is_valid_ip(ip) or _is_private_ip(ip) or _is_ms_cdn(ip):
                continue
            yield ("ip-dst", ip, f"cmdline IP of {proc} (PID {pid})")
        for h in set(_SHA256_RE.findall(args)):
            yield ("sha256", h.lower(), f"cmdline hash of {proc} (PID {pid})")


def _tally_netscan_filtered(rows: list) -> dict:
    """Count netscan ForeignAddr entries dropped, by reason (for audit)."""
    private = ms_cdn = localhost = 0
    for row in rows:
        addr = row.get("ForeignAddr")
        if _nullish(addr):
            continue  # listening/closed sockets: not "filtered IOCs"
        try:
            ip = ipaddress.ip_address(addr)
        except ValueError:
            continue
        if _is_ms_cdn(addr):
            ms_cdn += 1
        elif ip.is_loopback:
            localhost += 1
        elif _is_private_ip(addr):
            private += 1
    return {"private_ips": private, "ms_update_ips": ms_cdn,
            "localhost_ips": localhost}


def _tally_pslist_native(rows: list) -> int:
    """Count Windows-native processes excluded from filename IOCs."""
    return sum(1 for r in rows
               if not _nullish(r.get("ImageFileName"))
               and _is_windows_native_process(r.get("ImageFileName")))


# =====================================================================
# MispEnricher
# =====================================================================

class MispEnricher:
    """Reads a Vol3 analysis JSON, queries MISP, emits a MISP analysis.

    Usage:
        enricher = MispEnricher(misp_url, auth_key, verify_cert, timeout)
        result_dict = enricher.run(input_analysis_json, operator)

    The instance holds one PyMISP connection reused across all IOC
    queries (connection pooling).
    """

    name = "misp"
    version = ANALYZER_VERSION

    # MISP has no "preset" concept (unlike the Volatility analyzer).
    SUPPORTED_PRESETS = frozenset()

    # Plugin-FQN -> extractor function. Plugins not present here
    # contribute no IOCs (e.g. registry.hashdump is intentionally
    # excluded: credentials are not IOCs to share).
    _ioc_extractors = {
        "windows.netscan.NetScan": staticmethod(_extract_iocs_from_netscan),
        "windows.netstat.NetStat": staticmethod(_extract_iocs_from_netscan),
        "windows.pslist.PsList":   staticmethod(_extract_iocs_from_pslist),
        "windows.cmdline.CmdLine": staticmethod(_extract_iocs_from_cmdline),
    }

    def __init__(self, misp_url: str, auth_key: str,
                 verify_cert: bool = False, timeout: int = 30):
        if PyMISP is None:  # pragma: no cover
            raise RuntimeError(
                "pymisp is not installed in this environment; "
                "cannot instantiate MispEnricher"
            )
        self._misp_url = misp_url
        self._timeout = timeout
        # ssl=verify_cert: False accepts the self-signed cert MISP
        # generates at boot (see misp.conf verify_cert=false).
        self._misp = PyMISP(misp_url, auth_key, ssl=verify_cert,
                            timeout=timeout)

    # ----- public entrypoint ----------------------------------------

    def run(self, input_analysis_json: dict, operator: str) -> dict:
        """Run the full enrichment pipeline. Returns analysis-misp dict.

        Pipeline:
            1. Validate coherence (hashes_match_report=True) and
               os_hint == "windows". Raise ValueError otherwise so the
               caller (jobs_runner dispatcher) can fail the job
               cleanly instead of producing a bogus enrichment.
            2. Extract+filter IOCs (Step B extractors).
            3. Extract injection signals (precise + informative).
            4. For each unique IOC: query MISP, parse galaxies / tags /
               attribution (Step C).
            5. Compute deterministic threat_score (Step D).
            6. Aggregate summary (unique actors, galaxies, ATT&CK).
            7. Return JSON dict shaped per schema-analysis-v1 §4
               (analysis-misp). The CALLER serialises to JSON and
               uploads to Swift with the analysis_id as object name.

        Args:
            input_analysis_json: parsed analysis-volatility-*.json dict
                (loaded from Swift by the dispatcher).
            operator: keystone username forwarded by jobs_runner.

        Returns:
            dict ready to be json.dumps()'d.
        """
        started_at = datetime.now(timezone.utc)

        # ---- 1. Validation ------------------------------------------
        result = input_analysis_json.get("result") or {}
        coherence = input_analysis_json.get("coherence_check") or {}
        if not coherence.get("hashes_match_report", False):
            raise ValueError(
                "source analysis failed hash coherence check; "
                "refusing to enrich a dump whose integrity is in doubt"
            )
        os_hint = result.get("os_hint")
        if os_hint != "windows":
            raise ValueError(
                f"MISP enrichment supports only Windows dumps "
                f"(got os_hint={os_hint!r}); Linux is out of scope"
            )
        plugins = result.get("plugins") or {}

        # ---- 2. IOC extraction + filtering --------------------------
        ioc_data = self._extract_all_iocs(plugins)

        # ---- 3. Injection signals -----------------------------------
        injection_signals = self._extract_injection_signals(plugins)

        # ---- 4. MISP enrichment per IOC -----------------------------
        enrichment = []
        for ioc_type, ioc_value, context in ioc_data["flat"]:
            events_raw = self._query_misp(ioc_type, ioc_value)
            parsed_events = []
            for ev in events_raw:
                galaxies_struct = self._parse_galaxies(ev)
                galaxies_tags = self._parse_tags_as_galaxy(ev)
                # Tag list excluding the misp-galaxy:* ones (those
                # already surface inside 'galaxies'). Keeps tlp:*,
                # osint:*, type:* and similar metadata visible.
                other_tags = [
                    t.get("name") for t in (ev.get("Tag") or [])
                    if not (t.get("name") or "").startswith("misp-galaxy:")
                ]
                parsed_events.append({
                    "event_id": ev.get("id"),
                    "event_uuid": ev.get("uuid"),
                    "info": ev.get("info"),
                    "date": ev.get("date"),
                    "threat_level_id": ev.get("threat_level_id"),
                    "org": (ev.get("Orgc") or {}).get("name"),
                    "tags": other_tags,
                    "galaxies": galaxies_struct + galaxies_tags,
                    "attribution": self._parse_attribution(ev),
                })
            enrichment.append({
                "ioc_type": ioc_type,
                "ioc_value": ioc_value,
                "context": context,
                "misp_match": len(parsed_events),
                "events": parsed_events,
            })

        # ---- 5. Threat score (Step D) -------------------------------
        score, reason = self._compute_threat_score(
            enrichment, injection_signals)

        # ---- 6. Aggregate summary -----------------------------------
        # unique_actors: structured threat-actor only (NOT actor_hint,
        # which is heuristic and would dilute the aggregate).
        actors = set()
        galaxies = set()
        attcks = set()
        for entry in enrichment:
            for ev in entry["events"]:
                a = (ev.get("attribution") or {}).get("actor")
                if a:
                    actors.add(a)
                for g in ev.get("galaxies", []):
                    t = g.get("type") or g.get("name")
                    v = g.get("value")
                    if t and v:
                        galaxies.add(f"{t}:{v}")
                    if g.get("attck_id"):
                        attcks.add(g["attck_id"])

        iocs_with_match = sum(1 for e in enrichment if e["misp_match"] > 0)
        iocs_without_match = sum(1 for e in enrichment if e["misp_match"] == 0)
        total_checked = len(ioc_data["flat"])
        total_filtered = ioc_data["filtered_out"]["total_filtered"]

        # ---- MISP server info (best-effort) -------------------------
        misp_server_info = {"url": self._misp_url}
        try:
            all_evs = self._misp.search(controller="events", limit=20000,
                                        metadata=True, pythonify=False)
            if isinstance(all_evs, list):
                misp_server_info["events_count_at_query"] = len(all_evs)
        except Exception as exc:
            log.warning("could not fetch MISP server event count: %s", exc)

        # Threat-intel provenance: which feeds populate this MISP instance.
        # Captured at query time so the JSON/PDF can state the intelligence
        # source(s) the IOCs were correlated against (e.g. "CIRCL OSINT
        # Feed") rather than just the local server URL. Best-effort: a
        # failure here must never abort the enrichment.
        try:
            feeds_raw = self._misp.feeds(pythonify=False)
            feeds = []
            if isinstance(feeds_raw, list):
                for f in feeds_raw:
                    fd = f.get("Feed", f) if isinstance(f, dict) else {}
                    if not fd:
                        continue
                    feeds.append({
                        "name":            fd.get("name"),
                        "provider":        fd.get("provider"),
                        "url":             fd.get("url"),
                        "enabled":         fd.get("enabled"),
                        "caching_enabled": fd.get("caching_enabled"),
                    })
            misp_server_info["feeds"] = feeds
        except Exception as exc:  # noqa: BLE001
            log.warning("could not fetch MISP feeds: %s", exc)

        completed_at = datetime.now(timezone.utc)
        duration = (completed_at - started_at).total_seconds()

        # ---- 7. Build analysis-misp dict (schema v1.0) --------------
        acq_id = input_analysis_json.get("acquisition_id") or "unknown"
        utc_stamp = started_at.strftime("%Y%m%dT%H%M%SZ")
        job8 = uuid.uuid4().hex[:8]
        analysis_id = f"analysis-misp-{acq_id}-{utc_stamp}-{job8}"

        return {
            "schema_version": "1.0",
            "analysis_id": analysis_id,
            "acquisition_id": acq_id,
            "operator": operator,
            "started_at": started_at.isoformat(),
            "completed_at": completed_at.isoformat(),
            "duration_seconds": duration,
            "analyzer": self.name,
            "analyzer_version": self.version,
            "misp_server": misp_server_info,
            "source": {
                "input_analysis_id": input_analysis_json.get("analysis_id"),
                "input_hashes": coherence.get("dump_hashes")
                                or coherence.get("input_hashes"),
                "hashes_match_report": coherence.get("hashes_match_report"),
                "os_hint": os_hint,
            },
            "iocs_extracted": {
                **ioc_data["grouped"],
                "filtered_out": ioc_data["filtered_out"],
            },
            "enrichment": enrichment,
            "injection_signals": injection_signals,
            "summary": {
                "total_iocs_extracted": total_checked + total_filtered,
                "total_iocs_filtered": total_filtered,
                "total_iocs_checked": total_checked,
                "iocs_with_misp_match": iocs_with_match,
                "iocs_without_match": iocs_without_match,
                "unique_actors": sorted(actors),
                "unique_galaxies": sorted(galaxies),
                "unique_attck": sorted(attcks),
                "threat_score": score,
                "threat_score_reason": reason,
            },
        }

    # ----- internal helpers (implemented in later steps) ------------

    def _extract_all_iocs(self, plugins: dict) -> dict:
        """Run every known extractor, dedup, group, and tally filtered.

        Returns:
            {
              "grouped": {ip_addresses, domains, file_hashes{md5,sha1,
                          sha256}, process_names, registry_paths},
              "flat":    [(ioc_type, ioc_value, context), ...]  # dedup,
              "filtered_out": {private_ips, ms_update_ips,
                          localhost_ips, native_processes,
                          total_filtered, reason},
            }
        """
        grouped = {
            "ip_addresses": [], "domains": [],
            "file_hashes": {"md5": [], "sha1": [], "sha256": []},
            "process_names": [], "registry_paths": [],
        }
        flat = []
        seen = set()  # (ioc_type, ioc_value) dedup

        for fqn, extractor in self._ioc_extractors.items():
            p = plugins.get(fqn)
            if not p:
                continue
            rows = p.get("rows") or []
            for ioc_type, ioc_value, ctx in extractor(rows):
                key = (ioc_type, ioc_value)
                if key in seen:
                    continue
                seen.add(key)
                flat.append((ioc_type, ioc_value, ctx))
                entry = {"value": ioc_value, "source_plugin": fqn,
                         "context": ctx}
                if ioc_type == "ip-dst":
                    grouped["ip_addresses"].append(entry)
                elif ioc_type == "domain":
                    grouped["domains"].append(entry)
                elif ioc_type == "filename":
                    grouped["process_names"].append(entry)
                elif ioc_type == "url":
                    grouped["domains"].append(entry)  # urls grouped w/ domains
                elif ioc_type in ("md5", "sha1", "sha256"):
                    grouped["file_hashes"][ioc_type].append(entry)
                elif ioc_type == "regkey":
                    grouped["registry_paths"].append(entry)

        # Tally filtered (audit/transparency)
        ns = plugins.get("windows.netscan.NetScan")
        filt = _tally_netscan_filtered(ns.get("rows") or []) if ns else \
            {"private_ips": 0, "ms_update_ips": 0, "localhost_ips": 0}
        pl = plugins.get("windows.pslist.PsList")
        native = _tally_pslist_native(pl.get("rows") or []) if pl else 0
        filt["native_processes"] = native
        filt["total_filtered"] = (filt["private_ips"] + filt["ms_update_ips"]
                                  + filt["localhost_ips"] + native)
        filt["reason"] = ("RFC1918 private ranges, loopback, Microsoft "
                          "Update/CDN endpoints, Windows-native processes")

        return {"grouped": grouped, "flat": flat, "filtered_out": filt}

    def _extract_injection_signals(self, plugins: dict) -> dict:
        """Adaptive injection signals.

        Uses precise detectors when present (full preset):
        hollowprocesses, processghosting, suspicious_threads, svcdiff.
        malfind is reported as an INFORMATIVE count only (it is noisy:
        ~14 benign hits on a clean Windows host), never a verdict on
        its own. psxview "hidden" = present in psscan but not pslist.
        """
        sig = {}

        def n_rows(fqn):
            p = plugins.get(fqn)
            return len(p.get("rows") or []) if p else None

        for key, fqn in (
            ("hollow_processes",
             "windows.malware.hollowprocesses.HollowProcesses"),
            ("process_ghosting",
             "windows.malware.processghosting.ProcessGhosting"),
            ("suspicious_threads",
             "windows.malware.suspicious_threads.SuspiciousThreads"),
            ("service_diff", "windows.malware.svcdiff.SvcDiff"),
        ):
            c = n_rows(fqn)
            if c is not None:
                sig[key] = c

        mf = n_rows("windows.malware.malfind.Malfind")
        if mf is not None:
            sig["malfind_regions"] = mf  # informative only

        # psxview: INFORMATIVE ONLY, does NOT feed the threat score.
        # Empirically psxview is far too noisy on modern Windows to be
        # an automatic signal: on a clean Server 2022 dump it flags ~21
        # processes as "only visible to psscan" — but inspection shows
        # they are either (a) TERMINATED processes (Exit Time set: the
        # raw-memory scan still finds the structure while the live-
        # process lists do not) or (b) legitimate live processes that a
        # cross-view race during acquisition / known psxview false
        # positives on hardened/protected processes left visible only to
        # psscan. Neither is real hiding. We therefore report a
        # conservative count (excluding clearly-terminated processes)
        # purely as analyst context, and rely on the precise detectors
        # above (hollowprocesses / processghosting / svcdiff /
        # suspicious_threads) for the actual injection score. malfind is
        # treated the same way (noisy → informative only).
        px = plugins.get("windows.malware.psxview.PsXView")
        if px:
            only_psscan = 0
            for r in (px.get("rows") or []):
                def _f(col):
                    return str(r.get(col, "")).strip().lower() == "true"
                if not _f("psscan"):
                    continue
                # skip clearly terminated procs (Exit Time populated):
                # found by raw scan only because they are dead, not hidden
                if str(r.get("Exit Time", "")).strip():
                    continue
                other = [c for c in ("pslist", "csrss", "thrdscan",
                                     "thrdproc", "session", "deskthrd")
                         if c in r]
                if other and not any(_f(c) for c in other):
                    only_psscan += 1
            # NOTE: even this residual count is NOT used by the score;
            # it is analyst context only (see _compute_threat_score).
            sig["psxview_only_psscan"] = only_psscan

        return sig

    def _query_misp(self, ioc_type: str, ioc_value: str) -> list:
        """Query MISP events containing this IOC.

        Uses pymisp.search() with pythonify=False to get raw dicts —
        simpler than MISPEvent objects for the deeply-nested defensive
        traversal of Galaxy/Tag/Attribute we do in the parsers.

        Returns a list of Event dicts (each dict is the value of the
        outer 'Event' key, already unwrapped). Returns [] on any error
        or no match — never raises, so a single bad IOC cannot abort
        the whole enrichment run.
        """
        try:
            raw = self._misp.search(
                controller="events",
                value=ioc_value,
                type_attribute=ioc_type,
                limit=50,
                pythonify=False,
            )
        except Exception as exc:
            log.warning("MISP query failed for %s=%r: %s",
                        ioc_type, ioc_value, exc)
            return []
        if not isinstance(raw, list):
            return []
        # Each entry is {'Event': {...}}; unwrap defensively
        return [e.get("Event", e) if isinstance(e, dict) else e
                for e in raw]

    def _parse_galaxies(self, event: dict) -> list:
        """Extract structured Galaxy clusters from a MISP event dict.

        Returns a list of dicts:
            [{name, value, uuid, type, attck_id}]

        where:
          - name      = galaxy.name      (e.g. "Attack Pattern")
          - value     = cluster.value    (e.g. "Code Signing - T1553.002")
          - uuid      = cluster.uuid
          - type      = galaxy.type      (e.g. "mitre-attack-pattern")
          - attck_id  = cluster.meta.external_id[0] if mitre-attack-*,
                        else None (so reports can show "T1553.002" cleanly)

        Defensive against all missing keys — empty list if event has
        no Galaxy section. Real CIRCL OSINT events frequently have
        Galaxy = [] (attribution lives in tags or info text instead);
        we additionally pull misp-galaxy:* tags in _parse_tags_as_galaxy.
        """
        out = []
        for g in (event.get("Galaxy") or []):
            g_type = g.get("type") or ""
            g_name = g.get("name") or g_type
            for c in (g.get("GalaxyCluster") or []):
                meta = c.get("meta") or c.get("Meta") or {}
                attck_id = None
                if "mitre-attack" in g_type:
                    ext = meta.get("external_id")
                    if isinstance(ext, list) and ext:
                        attck_id = ext[0]
                    elif isinstance(ext, str):
                        attck_id = ext
                out.append({
                    "name": g_name,
                    "value": c.get("value"),
                    "uuid": c.get("uuid"),
                    "type": g_type,
                    "attck_id": attck_id,
                })
        return out

    def _parse_tags_as_galaxy(self, event: dict) -> list:
        """Extract misp-galaxy:* tags as pseudo-galaxy entries.

        Many CIRCL OSINT events do NOT promote galaxy clusters to
        structured Galaxy objects: instead they tag the event with
        strings like 'misp-galaxy:threat-actor="Sofacy"'. We parse
        these tags into the same shape as _parse_galaxies output so
        the rest of the pipeline (scoring, report) treats them
        uniformly. attck_id is None for tag-form (no meta available).

        Tag format: <namespace>:<predicate>="<value>"
        We accept misp-galaxy:<type>="<value>".
        """
        out = []
        for t in (event.get("Tag") or []):
            name = (t.get("name") or "").strip()
            if not name.startswith("misp-galaxy:"):
                continue
            # strip "misp-galaxy:" and split predicate="value"
            body = name[len("misp-galaxy:"):]
            if "=" not in body:
                continue
            predicate, _, raw_val = body.partition("=")
            value = raw_val.strip().strip('"').strip("'")
            out.append({
                "name": predicate.strip(),
                "value": value,
                "uuid": None,
                "type": predicate.strip(),
                "attck_id": None,
                "source": "tag",
            })
        return out

    def _parse_attribution(self, event: dict) -> dict:
        """Best-effort actor / country / campaign extraction.

        Three layers, tried in order; first non-empty wins per field:
          1. Structured Galaxy cluster of type 'threat-actor' /
             'intrusion-set' / 'campaign' (Event.Galaxy)
          2. misp-galaxy:* tags with predicate threat-actor / campaign
          3. Textual fallback: scan event.info for known actor
             nicknames (Sofacy -> APT28, etc.). The result is exposed
             as actor_hint (not actor) so the JSON consumer / report
             can distinguish structured intel from heuristic guess.

        Returns dict with optional keys (None when unknown):
            {actor, country, campaign, actor_hint}
        """
        out = {"actor": None, "country": None,
               "campaign": None, "actor_hint": None}

        # Layer 1: structured Galaxy
        for g in (event.get("Galaxy") or []):
            g_type = (g.get("type") or "").lower()
            for c in (g.get("GalaxyCluster") or []):
                meta = c.get("meta") or c.get("Meta") or {}
                val = c.get("value")
                if g_type in ("threat-actor", "intrusion-set") and val:
                    if not out["actor"]:
                        out["actor"] = val
                    country = (meta.get("country")
                               or meta.get("cfr-suspected-state-sponsor"))
                    if country and not out["country"]:
                        out["country"] = country if isinstance(country, str) \
                                         else country[0] if isinstance(country, list) and country else None
                elif g_type == "campaign" and val and not out["campaign"]:
                    out["campaign"] = val

        # Layer 2: misp-galaxy:* tags
        if not out["actor"] or not out["campaign"]:
            for pseudo in self._parse_tags_as_galaxy(event):
                t = (pseudo.get("type") or "").lower()
                v = pseudo.get("value")
                if t in ("threat-actor", "intrusion-set") and v and not out["actor"]:
                    out["actor"] = v
                elif t == "campaign" and v and not out["campaign"]:
                    out["campaign"] = v

        # Layer 3: textual hint from event.info — ALWAYS computed,
        # even when actor is set, because info may mention a more
        # specific alias. Recorded as actor_hint, never as actor.
        info = (event.get("info") or "").lower()
        for needle, canonical in KNOWN_ACTOR_HINTS.items():
            if needle in info:
                out["actor_hint"] = canonical
                break

        return out

    @staticmethod
    def _canonical_galaxy_kind(g: dict) -> str:
        """Canonical high-risk KIND label for a galaxy entry.

        MISP exposes a galaxy under a machine type (e.g. 'mitre-tool',
        'threat-actor') AND a human name (e.g. 'Tool', 'Threat Actor').
        HIGH_RISK_GALAXY_PREFIXES are written against the human names, so
        we normalise EITHER identifier to the canonical label here. This
        lets R1 fire on real MISP galaxies (structured clusters OR
        misp-galaxy:* tags, whose predicate is the machine type), instead
        of only on strings that already happen to be in 'Name:value'
        form. Returns '' for kinds we do not treat as high-risk.
        """
        ident = f"{g.get('type') or ''}|{g.get('name') or ''}".lower()
        if "threat-actor" in ident or "threat actor" in ident:
            return "Threat Actor"
        if "intrusion-set" in ident or "intrusion set" in ident:
            return "Intrusion Set"
        if "malware" in ident:
            return "Malware"
        if "tool" in ident:
            return "Tool"
        return ""

    def _compute_threat_score(self, enrichment: list,
                              injection_signals: dict) -> tuple:
        """Deterministic threat score: returns (score, reason).

        score is one of "green" / "yellow" / "red". reason is a short
        human-readable string explaining the verdict, suitable for the
        analysis JSON and the PDF report ("why red?").

        Rules (evaluated in order; first match wins):
          R1. RED   if any enriched event carries a galaxy/tag whose
                    "<type>:<value>" starts with one of
                    HIGH_RISK_GALAXY_PREFIXES (APT actor, ransomware,
                    Mimikatz, Cobalt Strike, ...).
          R2. RED   if any precise injection detector fires:
                    hollow_processes / process_ghosting /
                    suspicious_threads / service_diff > 0.
                    malfind_regions and psxview_only_psscan are
                    intentionally NOT used here (too noisy: ~14 / ~8
                    false positives on a clean Windows dump).
          R3. RED   if total MISP matches > 5 (broad exposure even
                    without high-risk attribution).
          R4. YELLOW if 1..5 MISP matches and no R1/R2/R3 trigger.
          R5. GREEN  otherwise (no matches AND no precise injection).

        enrichment is the list built in run() (Step E): each item is
        a dict {ioc_type, ioc_value, misp_match (int), events: [...]}
        where each event has galaxies and an attribution.
        """
        # --- Pre-compute aggregates we need across rules ---
        total_matches = sum(e.get("misp_match", 0) for e in enrichment)

        # Build "<kind>:<value>" strings for the high-risk test. MISP
        # galaxies arrive with a machine type ('mitre-tool') and a human
        # name ('Tool'); HIGH_RISK_GALAXY_PREFIXES are written against the
        # human names, so we normalise via _canonical_galaxy_kind. Only
        # galaxies of a high-risk KIND yield a string here (others could
        # never match a prefix anyway). NOTE: the galaxy strings DISPLAYED
        # elsewhere (summary unique_galaxies, dashboard, PDF) are built
        # separately and intentionally LEFT UNCHANGED — this normalisation
        # is local to the R1 comparison only.
        galaxy_strs = []
        for e in enrichment:
            for evt in e.get("events", []):
                for g in evt.get("galaxies", []):
                    v = g.get("value") or ""
                    kind = self._canonical_galaxy_kind(g)
                    if kind and v:
                        galaxy_strs.append(f"{kind}:{v}")

        # --- R1: high-risk galaxy match ---
        for gs in galaxy_strs:
            for prefix in HIGH_RISK_GALAXY_PREFIXES:
                if gs.startswith(prefix):
                    return ("red",
                            f"high-risk galaxy match: {gs}")

        # --- R2: precise injection detector ---
        precise = {
            "hollow_processes": injection_signals.get("hollow_processes", 0),
            "process_ghosting": injection_signals.get("process_ghosting", 0),
            "suspicious_threads": injection_signals.get("suspicious_threads", 0),
            "service_diff": injection_signals.get("service_diff", 0),
        }
        fired = [k for k, n in precise.items() if n and n > 0]
        if fired:
            details = ", ".join(f"{k}={precise[k]}" for k in fired)
            return ("red",
                    f"precise injection detector(s) fired: {details}")

        # --- R3: broad MISP exposure ---
        if total_matches > 5:
            return ("red",
                    f"broad MISP exposure: {total_matches} total matches")

        # --- R4: moderate matches ---
        if total_matches >= 1:
            return ("yellow",
                    f"{total_matches} MISP match(es), no high-risk attribution")

        # --- R5: clean ---
        return ("green",
                "no MISP matches and no precise injection signals")
