"""Form for the New analysis workflow.

Three coupled fields:
    - analyzer  (volatility — the only analyzer exposed in this release)
    - preset    (fast | full | custom)
    - plugins   (multi-select) — only used when preset=custom

The plugin multi-select is grouped by SANS macro-area of memory
forensics so the analyst can pick a meaningful subset without
scrolling through 88 plugins alphabetically:

    - Identify Rogue Processes       pslist / psscan / pstree / psxview
    - Analyze Process Objects        cmdline / handles / dlllist / ...
    - Review Network Artifacts       netscan / netstat
    - Code Injection / Malware       malfind / ldrmodules / ...
    - Drivers / Rootkit / Services   modules / ssdt / drivermodule / ...
    - File / Memory Scanners         filescan / mutantscan / ...
    - Registry                       registry.* / amcache / scheduled_tasks
    - Metadata / Misc                info / statistics / verinfo / ...

Choices are populated from GET /api/v1/plugins on the analyzer
backend (single source of truth) so this form auto-tracks any new
plugin added to the whitelist without code changes here.
"""
from __future__ import annotations

import logging

from django import forms
from django.utils.translation import gettext_lazy as _

from forensicnova_dashboard.api import client as fn_api

LOG = logging.getLogger(__name__)


# Mapping of plugin-name fragments to SANS macro-areas. The matching
# order matters: more specific category-level rules (windows.malware.*,
# windows.registry.*) are checked first; submodule-level rules apply
# afterward. A plugin that matches no rule falls into "Metadata / Misc".
def _sans_group_for(plugin_fqn: str) -> str:
    parts = plugin_fqn.split(".")
    cat = ""
    sub = ""
    if len(parts) >= 4:        # e.g. windows.malware.malfind.Malfind
        cat = parts[1].lower()
        sub = parts[2].lower()
    elif len(parts) >= 3:      # e.g. windows.pslist.PsList
        sub = parts[1].lower()

    if cat == "malware":
        return "Code Injection / Malware"
    if cat == "registry":
        return "Registry / Credentials"

    if sub in {"pslist", "psscan", "pstree", "psxview"}:
        return "Identify Rogue Processes"
    if sub in {"cmdline", "handles", "dlllist", "getsids",
               "getservicesids", "privileges", "envars", "sessions",
               "vadinfo", "vadwalk", "vadregexscan", "joblinks",
               "iat", "pe_symbols", "deskscan", "desktops", "windows",
               "windowstations", "consoles", "cmdscan"}:
        return "Analyze Process Objects"
    if sub in {"netscan", "netstat"}:
        return "Review Network Artifacts"
    if sub in {"malfind", "ldrmodules", "hollowprocesses",
               "processghosting", "suspicious_threads", "pebmasquerade",
               "skeleton_key_check", "svcdiff", "unhooked_system_calls",
               "etwpatch", "debugregisters", "suspended_threads",
               # YARA scanners — pattern-based code/data detection
               "vadyarascan", "vmayarascan", "yarascan",
               # EDR-bypass detectors — modern injection techniques
               "direct_system_calls", "indirect_system_calls"}:
        return "Code Injection / Malware"
    if sub in {"modules", "modscan", "ssdt", "callbacks", "driverirp",
               "drivermodule", "driverscan", "unloadedmodules",
               "threads", "orphan_kernel_threads", "kpcrs", "devicetree",
               "svcscan", "svclist", "timers"}:
        return "Drivers / Rootkit / Services"
    if sub in {"filescan", "mutantscan", "thrdscan", "symlinkscan",
               "mbrscan", "poolscanner", "memmap", "virtmap",
               "bigpools", "shimcachemem", "truecrypt",
               # MFT / NTFS forensics — recovers filesystem metadata
               # from RAM (file timestamps, ADS, resident small files)
               "mftscan"}:
        return "File / Memory Scanners"
    if sub in {"amcache", "scheduled_tasks"}:
        return "Registry / Credentials"
    # Credential dumpers (deprecated aliases that still appear in
    # vol --help; the official paths are under windows.registry.* and
    # are handled by the cat == "registry" branch above).
    if sub in {"hashdump", "cachedump", "lsadump"}:
        return "Registry / Credentials"

    return "Metadata / Misc"


# Display order for the optgroups in the multi-select. Putting
# "Identify Rogue Processes" first matches the SANS triage flow
# (start with what's running, then drill into objects/network/code).
_SANS_GROUP_ORDER = [
    "Identify Rogue Processes",
    "Analyze Process Objects",
    "Review Network Artifacts",
    "Code Injection / Malware",
    "Drivers / Rootkit / Services",
    "File / Memory Scanners",
    "Registry / Credentials",
    "Metadata / Misc",
]


class NewAnalysisForm(forms.Form):
    """Pick analyzer, preset, optional custom plugins for one acquisition."""

    ANALYZER_CHOICES = (
        ("volatility", _("Volatility 3 (memory forensics)")),
    )

    PRESET_CHOICES = (
        ("",       _("— pick a preset —")),
        ("fast",   _("fast — 11 plugins, ~2-3 min on 4 GiB (triage)")),
        ("full",   _("full — 34 plugins, ~10-13 min on 4 GiB (deep dive)")),
        ("custom", _("custom — pick specific plugins below")),
    )

    analyzer = forms.ChoiceField(
        label=_("Analyzer"),
        choices=ANALYZER_CHOICES,
        initial="volatility",
        help_text=_(
            "Pick which analyzer to run on the dump. Volatility 3 is the "
            "memory forensics engine driving every plugin in this system."
        ),
    )

    preset = forms.ChoiceField(
        label=_("Preset"),
        choices=PRESET_CHOICES,
        required=False,
        initial="fast",
        help_text=_(
            "'fast' is the default first-response triage: covers "
            "the highest-signal plugins in each SANS FOR508 stage "
            "(rogue processes, PowerShell history, services, code "
            "injection); "
            "'full' adds 23 deep-dive plugins for complete SANS "
            "FOR508 six-stage coverage including rootkit detection, "
            "anti-EDR syscall analysis, and persistence artifacts; "
            "'custom' lets you pick exactly which plugins to run."
        ),
    )

    plugins = forms.MultipleChoiceField(
        label=_("Custom plugins"),
        required=False,
        help_text=_(
            "Only used when preset='custom'. Hold Ctrl/Cmd to select "
            "multiple. Plugins are grouped by SANS macro-area of "
            "memory forensics."
        ),
    )

    def __init__(self, *args, request=None, acquisition_id=None, **kwargs):
        super().__init__(*args, **kwargs)
        self._request = request
        self._acquisition_id = acquisition_id
        # Populate plugin choices from the analyzer backend so we
        # auto-track any change to the whitelist.
        self.fields["plugins"].choices = self._build_plugin_choices()

    def _build_plugin_choices(self):
        """Return choices as a list of (group_label, [(value, label)])."""
        if self._request is None:
            return []
        try:
            catalog = fn_api.list_plugins(self._request)
        except fn_api.ForensicNovaApiError as exc:
            LOG.warning("could not load plugin catalog: %s", exc)
            return [(_("(could not load plugin list)"), [])]

        # We grab the Windows whitelist since our demo target is
        # Windows Server 2022; a future improvement is to switch
        # whitelist based on the selected acquisition's os_hint.
        plugin_list = (
            (catalog.get("volatility") or {})
            .get("plugin_whitelist", {})
            .get("windows", [])
        )

        # Bucket the plugins under their SANS group label.
        buckets: dict[str, list[tuple[str, str]]] = {
            g: [] for g in _SANS_GROUP_ORDER
        }
        for fqn in plugin_list:
            group = _sans_group_for(fqn)
            buckets.setdefault(group, []).append((fqn, fqn))

        # Build the (group_label, choices_in_group) list in the
        # declared display order, dropping empty groups.
        out: list[tuple[str, list[tuple[str, str]]]] = []
        for group in _SANS_GROUP_ORDER:
            entries = sorted(buckets.get(group, []), key=lambda t: t[0])
            if entries:
                out.append((group, entries))
        return out

    # ---- cross-field validation ----

    def clean(self):
        cleaned = super().clean()
        analyzer = cleaned.get("analyzer")
        preset = cleaned.get("preset") or None
        plugins = cleaned.get("plugins") or []

        # volatility: require a preset; custom requires plugins;
        # non-custom presets ignore any supplied plugin list.
        if analyzer == "volatility":
            if not preset:
                self.add_error(
                    "preset",
                    _("Pick a preset (fast / full / custom)."),
                )
                return cleaned
            if preset == "custom" and not plugins:
                self.add_error(
                    "plugins",
                    _("Custom preset requires at least one plugin."),
                )
            if preset != "custom" and plugins:
                # Soft: clear the plugins field — they would have been
                # ignored by the backend anyway.
                cleaned["plugins"] = []

        return cleaned
