"""ForensicNova - PDF report generator (single acquisition).

Renders a forensic-grade printable verbal from a v1.1 JSON acquisition
report dict. The PDF is intended for legal hand-off and operator
countersignature; printing happens on demand from the same JSON, so the
JSON remains the canonical source of truth.

Architecture
------------
- Module-level constants for styles (built once at import).
- Module-level ``render_*()`` helpers returning ``list[Flowable]``,
  reusable as-is by a future ``CasePdfReport`` orchestrator without
  modification (case report on the thesis roadmap).
- ``_HeaderFooter`` callback drawn on every page via ReportLab canvas
  (page number + acquisition_id + generation timestamp).
- ``ForensicPdfReport(report).render() -> bytes`` for in-memory PDF.

Forensic stance
---------------
The PDF is an *act of printing*, NOT primary evidence. Primary evidence
lives in the JSON (immutable hashes) and the RAW dump (Swift object).
Therefore:

* No ``invariant=True``: each print is a distinct document with its own
  ``CreationDate``, byte-different from previous prints. This is a
  feature, not a bug --- every print is traceable as a separate
  generation event.
* ``generated_at`` is the UTC moment the PDF is built, shown on the
  cover and in the footer of every page.
* The same operator who performed the acquisition is the one who prints
  and signs the report. ``operator`` on cover and footer is read from
  ``report['operator']`` (immutable, set at acquisition time).

Defensive rendering
-------------------
- Every ``dict.get(key, default)`` has a fallback ('-' for strings,
  empty for tables). Schema drift in single fields does not crash render.
- ``target_system`` renders ``nova / flavor / glance / hypervisor /
  libvirt`` blocks individually but always tolerant of missing keys.
"""

from datetime import datetime, timezone
from io import BytesIO
import json

from reportlab.lib.pagesizes import A4
from reportlab.lib.units import mm
from reportlab.lib.styles import ParagraphStyle
from reportlab.lib.colors import HexColor
from reportlab.lib.enums import TA_CENTER
from reportlab.platypus import (
    SimpleDocTemplate,
    Paragraph,
    Spacer,
    Table,
    TableStyle,
    PageBreak,
    KeepTogether,
    HRFlowable,
)


# ---------------------------------------------------------------------------
# Color tokens
# ---------------------------------------------------------------------------

COLOR_INK    = HexColor('#1a1a1a')
COLOR_MUTED  = HexColor('#6b6b6b')
COLOR_RULE   = HexColor('#cccccc')
COLOR_BAND   = HexColor('#f5f5f5')
COLOR_OK     = HexColor('#2e7d32')   # integrity verified
COLOR_FAIL   = HexColor('#c62828')   # integrity failed
COLOR_WARN   = HexColor('#ef6c00')   # not-yet-performed / placeholder
COLOR_OK_BG    = HexColor('#e8f5e9')
COLOR_FAIL_BG  = HexColor('#ffebee')
COLOR_WARN_BG  = HexColor('#fff3e0')


# ---------------------------------------------------------------------------
# ParagraphStyle catalog
# ---------------------------------------------------------------------------

STYLE_TITLE = ParagraphStyle(
    name='fn_title', fontName='Helvetica-Bold',
    fontSize=22, leading=26, textColor=COLOR_INK, spaceAfter=4 * mm,
)
STYLE_SUBTITLE = ParagraphStyle(
    name='fn_subtitle', fontName='Helvetica',
    fontSize=11, leading=14, textColor=COLOR_MUTED, spaceAfter=8 * mm,
)
STYLE_H1 = ParagraphStyle(
    name='fn_h1', fontName='Helvetica-Bold',
    fontSize=14, leading=18, textColor=COLOR_INK,
    spaceBefore=6 * mm, spaceAfter=3 * mm,
)
STYLE_H2 = ParagraphStyle(
    name='fn_h2', fontName='Helvetica-Bold',
    fontSize=10.5, leading=13, textColor=COLOR_INK,
    spaceBefore=3 * mm, spaceAfter=2 * mm,
)
STYLE_BODY = ParagraphStyle(
    name='fn_body', fontName='Helvetica',
    fontSize=9.5, leading=12, textColor=COLOR_INK,
)
STYLE_MUTED = ParagraphStyle(
    name='fn_muted', fontName='Helvetica',
    fontSize=9, leading=11, textColor=COLOR_MUTED,
)
STYLE_MONO = ParagraphStyle(
    name='fn_mono', fontName='Courier',
    fontSize=8.5, leading=11, textColor=COLOR_INK,
)
STYLE_LABEL = ParagraphStyle(
    name='fn_label', fontName='Helvetica-Bold',
    fontSize=9, leading=11, textColor=COLOR_MUTED,
)
STYLE_BADGE_OK = ParagraphStyle(
    name='fn_badge_ok', fontName='Helvetica-Bold',
    fontSize=14, leading=16, textColor=COLOR_OK, alignment=TA_CENTER,
)
STYLE_BADGE_FAIL = ParagraphStyle(
    name='fn_badge_fail', fontName='Helvetica-Bold',
    fontSize=14, leading=16, textColor=COLOR_FAIL, alignment=TA_CENTER,
)
STYLE_BADGE_WARN = ParagraphStyle(
    name='fn_badge_warn', fontName='Helvetica-Bold',
    fontSize=12, leading=14, textColor=COLOR_WARN, alignment=TA_CENTER,
)
STYLE_DISCLAIMER = ParagraphStyle(
    name='fn_disclaimer', fontName='Helvetica',
    fontSize=8.5, leading=11, textColor=COLOR_MUTED,
    spaceAfter=2 * mm,
)


# ---------------------------------------------------------------------------
# Reusable TableStyles
# ---------------------------------------------------------------------------

def _kv_table_style():
    """Two-column key:value table style (evidence, target_system, etc.)."""
    return TableStyle([
        ('FONT',         (0, 0), (-1, -1), 'Helvetica', 9),
        ('TEXTCOLOR',    (0, 0), (0, -1),  COLOR_MUTED),
        ('TEXTCOLOR',    (1, 0), (1, -1),  COLOR_INK),
        ('VALIGN',       (0, 0), (-1, -1), 'TOP'),
        ('LEFTPADDING',  (0, 0), (-1, -1), 4),
        ('RIGHTPADDING', (0, 0), (-1, -1), 4),
        ('TOPPADDING',   (0, 0), (-1, -1), 3),
        ('BOTTOMPADDING',(0, 0), (-1, -1), 3),
        ('LINEBELOW',    (0, 0), (-1, -2), 0.25, COLOR_RULE),
    ])


def _coc_table_style():
    """Chain of custody: numbered events with timestamp + description."""
    return TableStyle([
        ('FONT',         (0, 0), (-1, 0),  'Helvetica-Bold', 9),
        ('TEXTCOLOR',    (0, 0), (-1, 0),  COLOR_INK),
        ('BACKGROUND',   (0, 0), (-1, 0),  COLOR_BAND),
        ('FONT',         (0, 1), (-1, -1), 'Helvetica', 8.5),
        ('VALIGN',       (0, 0), (-1, -1), 'TOP'),
        ('ALIGN',        (0, 0), (0, -1),  'CENTER'),
        ('LEFTPADDING',  (0, 0), (-1, -1), 4),
        ('RIGHTPADDING', (0, 0), (-1, -1), 4),
        ('TOPPADDING',   (0, 0), (-1, -1), 3),
        ('BOTTOMPADDING',(0, 0), (-1, -1), 3),
        ('LINEBELOW',    (0, 0), (-1, -1), 0.25, COLOR_RULE),
    ])


# ---------------------------------------------------------------------------
# Format helpers
# ---------------------------------------------------------------------------

def _fmt_size(n):
    """Bytes -> '2.00 GiB (2,147,483,648 bytes)' style human format."""
    if n is None:
        return '—'
    try:
        n = int(n)
    except (TypeError, ValueError):
        return str(n)
    units = [('TiB', 1 << 40), ('GiB', 1 << 30), ('MiB', 1 << 20), ('KiB', 1 << 10)]
    for unit, mult in units:
        if n >= mult:
            return f'{n / mult:.2f} {unit} ({n:,} bytes)'
    return f'{n:,} bytes'


def _now_utc_iso():
    """UTC now in ISO-8601 with seconds precision and 'Z' suffix."""
    return datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')


def _short_uuid(s):
    """First 8 chars for compact display."""
    if not s:
        return '—'
    return str(s)[:8]


def _safe(v, default='—'):
    if v is None or v == '':
        return default
    return str(v)


def _p(text, style=STYLE_BODY):
    return Paragraph(_safe(text), style)


def _p_mono(text):
    return Paragraph(_safe(text), STYLE_MONO)


def _strip_container(swift_path):
    """'forensics/dump-vm-ts.raw' -> 'dump-vm-ts.raw'. Returns container name too."""
    if not swift_path:
        return '—', '—'
    if '/' in swift_path:
        container, _, obj = swift_path.partition('/')
        return container, obj
    return '—', swift_path


# ---------------------------------------------------------------------------
# Block: cover
# ---------------------------------------------------------------------------

def render_cover(report, generated_at):
    """Cover page.

    Operator + acquisition timeline + integrity badge are the three
    most prominent visual signals on this page.
    """
    flow = []

    flow.append(Paragraph('ForensicNova', STYLE_TITLE))
    flow.append(Paragraph('Volatile memory acquisition report', STYLE_SUBTITLE))
    flow.append(HRFlowable(width='100%', thickness=0.6, color=COLOR_RULE,
                           spaceBefore=0, spaceAfter=4 * mm))

    # Pull dump-side data once: hashes and integrity flag are reported
    # inline within the Acquisition identity table below.
    dump = report.get('dump') or {}
    etag_verified = dump.get('etag_verified')
    integrity_str = (
        'yes' if etag_verified is True
        else ('no' if etag_verified is False else 'unknown')
    )

    # ---- Acquisition identity ----
    flow.append(Paragraph('Acquisition identity', STYLE_H1))

    instance   = report.get('instance')   or {}
    timestamps = report.get('timestamps') or {}
    tool       = report.get('tool')       or {}
    tool_label = f"{_safe(tool.get('name'))} v{_safe(tool.get('version'))}"

    # Timeline of the technical operations is the central evidence on
    # WHEN acquisition was performed. Kept visually grouped so it's
    # immediately readable.
    started   = timestamps.get('started_at')
    completed = timestamps.get('completed_at')
    duration  = timestamps.get('duration_seconds')
    duration_str = (
        f"{duration} s" if isinstance(duration, (int, float)) else '—'
    )

    rows = [
        [_p('Acquisition ID',  STYLE_LABEL),  _p_mono(report.get('acquisition_id'))],
        [_p('Operator',        STYLE_LABEL),  _p(report.get('operator'))],
        [_p('Target VM',       STYLE_LABEL),  _p(instance.get('name'))],
        [_p('VM UUID',         STYLE_LABEL),  _p_mono(instance.get('id'))],
        [_p('Libvirt domain',  STYLE_LABEL),  _p_mono(instance.get('domain'))],
        [_p('Acquisition started',   STYLE_LABEL), _p_mono(started)],
        [_p('Acquisition completed', STYLE_LABEL), _p_mono(completed)],
        [_p('Duration',        STYLE_LABEL),  _p_mono(duration_str)],
        # Hashes and integrity check, inline (the green INTEGRITY VERIFIED
        # banner that used to live above this table has been removed --
        # the data itself, in monospace, IS the forensic statement).
        [_p('MD5',                  STYLE_LABEL), _p_mono(dump.get('md5'))],
        [_p('SHA-1',                STYLE_LABEL), _p_mono(dump.get('sha1'))],
        [_p('Integrity verified',   STYLE_LABEL), _p_mono(integrity_str)],
        [_p('Tool',            STYLE_LABEL),  _p(tool_label)],
        [_p('Report schema',   STYLE_LABEL),  _p(report.get('schema_version'))],
    ]
    t = Table(rows, colWidths=[55 * mm, 125 * mm])
    t.setStyle(_kv_table_style())
    flow.append(t)
    flow.append(Spacer(1, 8 * mm))

    # ---- Document generation metadata ----
    # Distinct from acquisition timeline: this is the "act of printing"
    # timestamp, useful when the PDF is filed as part of legal hand-off.
    flow.append(Paragraph('Document generation', STYLE_H1))
    gen_rows = [
        [_p('PDF generated at (UTC)', STYLE_LABEL), _p_mono(generated_at)],
        [_p('Generated by',       STYLE_LABEL), _p(report.get('operator'))],
        [_p('Document type',      STYLE_LABEL),
         _p('Single-acquisition forensic report')],
    ]
    t2 = Table(gen_rows, colWidths=[55 * mm, 125 * mm])
    t2.setStyle(_kv_table_style())
    flow.append(t2)

    flow.append(Spacer(1, 14 * mm))

    # ---- Operator signature block (printable, ink countersignature) ----
    #
    # Layout, top to bottom:
    #   "Operator signature"
    #
    #   Full name (block capitals): _________________________________
    #                                (authenticated as Keystone user: <op>)
    #
    #   Date and place: ________     Signature: ________
    #
    # Rationale: the JSON report carries only the Keystone username
    # (``operator`` field, e.g. "dfir-tester"), which is the technical
    # identity of the session. The operator's physical/legal identity
    # (e.g. "Mario Rossi") is a separate fact that the analyst declares
    # by signing the printed PDF. Tying the two together explicitly --
    # "the person whose handwritten name appears here was authenticated
    # as Keystone user X" -- is the legally meaningful binding.
    flow.append(Paragraph('Operator signature', STYLE_H1))
    flow.append(Spacer(1, 8 * mm))

    operator_keystone = _safe(report.get('operator'))

    # Row 1: full name in block capitals (handwritten)
    name_rows = [[
        _p('Full name (block capitals)', STYLE_LABEL),
        _p('', STYLE_BODY),
    ]]
    name_table = Table(
        name_rows,
        colWidths=[55 * mm, 125 * mm],
        rowHeights=[14 * mm],
    )
    name_table.setStyle(TableStyle([
        ('FONT',          (0, 0), (-1, -1), 'Helvetica', 9),
        ('VALIGN',        (0, 0), (-1, -1), 'BOTTOM'),
        ('TEXTCOLOR',     (0, 0), (-1, -1), COLOR_MUTED),
        ('LINEBELOW',     (1, 0), (1, 0), 0.5, COLOR_INK),
        ('LEFTPADDING',   (0, 0), (-1, -1), 2),
        ('RIGHTPADDING',  (0, 0), (-1, -1), 2),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 2),
    ]))
    flow.append(name_table)

    # Hint below the line: ties the handwritten name to the Keystone
    # session identity already recorded in the JSON report.
    flow.append(Paragraph(
        f'authenticated as Keystone user: '
        f'<font face="Courier">{operator_keystone}</font>',
        STYLE_MUTED,
    ))
    flow.append(Spacer(1, 8 * mm))

    # Row 2: date/place + signature (handwritten)
    sig_rows = [[
        _p('Date and place', STYLE_LABEL),
        _p('', STYLE_BODY),
        _p('Signature', STYLE_LABEL),
        _p('', STYLE_BODY),
    ]]
    sig = Table(
        sig_rows,
        colWidths=[35 * mm, 55 * mm, 25 * mm, 65 * mm],
        rowHeights=[14 * mm],
    )
    sig.setStyle(TableStyle([
        ('FONT',          (0, 0), (-1, -1), 'Helvetica', 9),
        ('VALIGN',        (0, 0), (-1, -1), 'BOTTOM'),
        ('TEXTCOLOR',     (0, 0), (-1, -1), COLOR_MUTED),
        ('LINEBELOW',     (1, 0), (1, 0), 0.5, COLOR_INK),
        ('LINEBELOW',     (3, 0), (3, 0), 0.5, COLOR_INK),
        ('LEFTPADDING',   (0, 0), (-1, -1), 2),
        ('RIGHTPADDING',  (0, 0), (-1, -1), 2),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 2),
    ]))
    flow.append(sig)

    return flow


# ---------------------------------------------------------------------------
# Block: evidence
# ---------------------------------------------------------------------------

def render_evidence(report):
    """Evidence integrity: hashes, size, Swift coordinates, etag."""
    flow = []
    flow.append(Paragraph('Evidence', STYLE_H1))

    dump = report.get('dump') or {}
    container, obj_name = _strip_container(dump.get('swift_object'))

    rows = [
        [_p('Object name',        STYLE_LABEL), _p_mono(obj_name)],
        [_p('Swift container',    STYLE_LABEL), _p_mono(container)],
        [_p('Size',               STYLE_LABEL), _p_mono(_fmt_size(dump.get('size_bytes')))],
        [_p('Format',             STYLE_LABEL), _p_mono(dump.get('format'))],
        [_p('Acquisition method', STYLE_LABEL), _p_mono(dump.get('acquisition_method'))],
        [_p('MD5',                STYLE_LABEL), _p_mono(dump.get('md5'))],
        [_p('SHA-1',              STYLE_LABEL), _p_mono(dump.get('sha1'))],
        [_p('Swift ETag',         STYLE_LABEL), _p_mono(dump.get('swift_etag'))],
        [_p('ETag verified',      STYLE_LABEL),
         _p_mono('yes' if dump.get('etag_verified') is True
                 else ('no' if dump.get('etag_verified') is False
                       else 'unknown'))],
    ]

    # SLO upload metadata: if the dump used upload_method == "slo",
    # show segment composition. Older v1.1 reports do not carry these
    # fields and the block is silently skipped.
    upload_method = dump.get('upload_method')
    if upload_method:
        rows.append([_p('Upload method', STYLE_LABEL), _p_mono(upload_method)])

    t = Table(rows, colWidths=[55 * mm, 125 * mm])
    t.setStyle(_kv_table_style())
    flow.append(t)

    # ---- SLO segments table (if present) ----
    segments = dump.get('slo_segments') or []
    if segments:
        flow.append(Spacer(1, 4 * mm))
        flow.append(Paragraph('SLO segments', STYLE_H2))
        seg_rows = [[
            _p('#',     STYLE_LABEL),
            _p('Name',  STYLE_LABEL),
            _p('Size',  STYLE_LABEL),
            _p('MD5',   STYLE_LABEL),
            _p('ETag',  STYLE_LABEL),
        ]]
        for i, seg in enumerate(segments, start=1):
            seg_rows.append([
                _p_mono(str(i)),
                _p_mono(seg.get('name')),
                _p_mono(_fmt_size(seg.get('size'))),
                _p_mono(seg.get('md5')),
                _p_mono(seg.get('etag')),
            ])
        seg_table = Table(seg_rows,
                          colWidths=[10 * mm, 50 * mm, 30 * mm, 45 * mm, 45 * mm])
        seg_table.setStyle(_coc_table_style())
        flow.append(seg_table)

    return flow


# ---------------------------------------------------------------------------
# Block: target system
# ---------------------------------------------------------------------------

def render_target_system(report):
    """Nova / Flavor / Glance / Hypervisor / Libvirt metadata.

    These fields are the OpenStack-side hint to a downstream analyst
    (Volatility 3 profile selection). Each sub-block renders with a
    fixed key set; missing values appear as '-'.
    """
    flow = []
    flow.append(Paragraph('Target system', STYLE_H1))
    flow.append(Paragraph(
        'Hypervisor-side metadata. Useful for Volatility 3 profile / ISF '
        'selection. No data is ever read from inside the guest.',
        STYLE_MUTED,
    ))
    flow.append(Spacer(1, 2 * mm))

    ts = report.get('target_system') or {}

    flow.extend(_kv_block('Nova', [
        ('ID',                ts.get('nova', {}).get('id')),
        ('Name',              ts.get('nova', {}).get('name')),
        ('Status',            ts.get('nova', {}).get('status')),
        ('Created',           ts.get('nova', {}).get('created')),
        ('Compute host',      ts.get('nova', {}).get('host')),
        ('Hypervisor host',   ts.get('nova', {}).get('hypervisor_hostname')),
    ]))

    flow.extend(_kv_block('Flavor', [
        ('ID',     ts.get('flavor', {}).get('id')),
        ('Name',   ts.get('flavor', {}).get('name')),
        ('vCPUs',  ts.get('flavor', {}).get('vcpus')),
        ('RAM',    _fmt_mb(ts.get('flavor', {}).get('ram_mb'))),
        ('Disk',   _fmt_gb(ts.get('flavor', {}).get('disk_gb'))),
    ]))

    flow.extend(_kv_block('Glance image', [
        ('ID',                ts.get('glance', {}).get('id')),
        ('Name',              ts.get('glance', {}).get('name')),
        ('Disk format',       ts.get('glance', {}).get('disk_format')),
        ('Container format',  ts.get('glance', {}).get('container_format')),
        ('OS type',           ts.get('glance', {}).get('os_type')),
        ('OS distro',         ts.get('glance', {}).get('os_distro')),
        ('OS version',        ts.get('glance', {}).get('os_version')),
        ('Architecture',      ts.get('glance', {}).get('architecture')),
        ('HW machine type',   ts.get('glance', {}).get('hw_machine_type')),
    ]))

    flow.extend(_kv_block('Hypervisor & libvirt', [
        ('Hypervisor type',  ts.get('hypervisor', {}).get('type')),
        ('Domain name',      ts.get('libvirt', {}).get('domain_name')),
        ('Architecture',     ts.get('libvirt', {}).get('architecture')),
        ('Machine type',     ts.get('libvirt', {}).get('machine_type')),
        ('CPU mode',         ts.get('libvirt', {}).get('cpu_mode')),
        ('Memory',           _fmt_mb(ts.get('libvirt', {}).get('memory_mb'))),
        ('vCPUs',            ts.get('libvirt', {}).get('vcpus')),
    ]))

    return flow


def _kv_block(title, pairs):
    """Render an H2 + 2-column key:value table, used per target_system subsystem."""
    out = [Paragraph(title, STYLE_H2)]
    rows = [[_p(k, STYLE_LABEL), _p_mono(v)] for k, v in pairs]
    t = Table(rows, colWidths=[55 * mm, 125 * mm])
    t.setStyle(_kv_table_style())
    out.append(t)
    out.append(Spacer(1, 3 * mm))
    return [KeepTogether(out)]


def _fmt_mb(n):
    if n is None:
        return None
    try:
        return f'{int(n)} MB'
    except (TypeError, ValueError):
        return str(n)


def _fmt_gb(n):
    if n is None:
        return None
    try:
        return f'{int(n)} GB'
    except (TypeError, ValueError):
        return str(n)


# ---------------------------------------------------------------------------
# Block: chain of custody
# ---------------------------------------------------------------------------

def render_chain_of_custody(report):
    """Numbered, timestamped event timeline.

    Long event payloads ('data') would not fit cleanly inside cells, so
    the table shows seq/timestamp/event/description and a separate small
    paragraph below the row dumps the JSON payload pretty-printed in
    monospace. Failed events are flagged in red.
    """
    flow = []
    flow.append(Paragraph('Chain of custody', STYLE_H1))

    coc        = report.get('chain_of_custody') or {}
    events     = coc.get('events') or []
    total      = coc.get('total_events') if 'total_events' in coc else len(events)

    flow.append(Paragraph(
        f"{total} event{'s' if total != 1 else ''} recorded by the acquisition "
        f"pipeline. Persisted append-only on the hypervisor at "
        f"<font face='Courier'>/var/log/forensicnova/chain-of-custody.jsonl</font>.",
        STYLE_MUTED,
    ))
    flow.append(Spacer(1, 3 * mm))

    if not events:
        flow.append(Paragraph('(no events recorded)', STYLE_MUTED))
        return flow

    header = [
        _p('#',           STYLE_LABEL),
        _p('Timestamp',   STYLE_LABEL),
        _p('Event',       STYLE_LABEL),
        _p('Description', STYLE_LABEL),
    ]
    rows = [header]

    failure_rows = []  # (table_row_index, payload_json_str) for red coloring
    detail_blocks = []  # collected after the table — 'data' payloads pretty-printed

    for i, ev in enumerate(events, start=1):
        seq        = ev.get('seq') or i
        ts         = ev.get('timestamp') or '—'
        ev_type    = ev.get('event_type') or '—'
        desc       = ev.get('description') or '—'
        # Trim the date for compactness — 'YYYY-MM-DDTHH:MM:SS.ffffffZ'
        ts_compact = str(ts)[11:23] if isinstance(ts, str) and len(ts) >= 23 else ts

        rows.append([
            _p_mono(f'{seq:02d}'),
            _p_mono(ts_compact),
            _p_mono(ev_type),
            _p(desc, STYLE_BODY),
        ])

        if 'failed' in ev_type or 'integrity_failure' in ev_type:
            failure_rows.append(i)  # row index in the table (1-based, since header is row 0)

        # Keep a compact data dump for events that have a payload —
        # only show those whose data is non-trivial to avoid noise.
        data = ev.get('data')
        if data:
            detail_blocks.append((seq, ev_type, data))

    coc_table = Table(rows, colWidths=[10 * mm, 25 * mm, 55 * mm, 90 * mm])
    style = _coc_table_style()
    for r in failure_rows:
        style.add('TEXTCOLOR', (0, r), (-1, r), COLOR_FAIL)
        style.add('FONT',      (0, r), (-1, r), 'Helvetica-Bold', 8.5)
    coc_table.setStyle(style)
    flow.append(coc_table)

    # ---- Per-event payloads ----
    if detail_blocks:
        flow.append(Spacer(1, 6 * mm))
        flow.append(Paragraph('Event payloads', STYLE_H2))
        for seq, ev_type, data in detail_blocks:
            try:
                payload = json.dumps(data, indent=2, ensure_ascii=False)
            except (TypeError, ValueError):
                payload = repr(data)
            payload_html = (
                payload.replace('&', '&amp;')
                       .replace('<', '&lt;').replace('>', '&gt;')
                       .replace('\n', '<br/>')
                       .replace(' ', '&nbsp;')
            )
            flow.append(Paragraph(
                f"<b>#{seq:02d}</b> &mdash; <font face='Courier'>{ev_type}</font>",
                STYLE_BODY,
            ))
            flow.append(Paragraph(payload_html, STYLE_MONO))
            flow.append(Spacer(1, 2 * mm))

    return flow


# ---------------------------------------------------------------------------
# Block: analysis (placeholder for thesis)
# ---------------------------------------------------------------------------

def render_analysis(report):
    """Analysis section.

    Empty for the exam prototype. The thesis adds Volatility 3, YARA and
    threat-intelligence findings under ``report['analysis']``. When that
    key is present, this method renders it; otherwise it shows a neutral
    'not yet performed' placeholder so the section structure is
    consistent across reports.
    """
    flow = []
    flow.append(Paragraph('Analysis', STYLE_H1))

    analysis = report.get('analysis')
    if not analysis:
        # Coloured banner identical in style to the integrity badge —
        # but in WARN palette. Communicates: this is a known gap, not
        # a missing field.
        banner = Table(
            [[Paragraph('Analysis: not yet performed', STYLE_BADGE_WARN)]],
            colWidths=[180 * mm], rowHeights=[12 * mm],
        )
        banner.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, -1), COLOR_WARN_BG),
            ('BOX',        (0, 0), (-1, -1), 0.5, COLOR_WARN),
            ('VALIGN',     (0, 0), (-1, -1), 'MIDDLE'),
            ('ALIGN',      (0, 0), (-1, -1), 'CENTER'),
        ]))
        flow.append(banner)
        flow.append(Spacer(1, 3 * mm))
        flow.append(Paragraph(
            'The acquisition pipeline collected and verified the volatile '
            'memory image. Forensic analysis (Volatility 3 IOC extraction, '
            'YARA scanning, threat-intelligence correlation) is part of '
            'the thesis roadmap and will be appended to the JSON report '
            'under <font face="Courier">analysis</font>. When that section '
            'becomes available, the timestamps below will be populated:',
            STYLE_BODY,
        ))
        flow.append(Spacer(1, 2 * mm))
        rows = [
            [_p('Analysis started',   STYLE_LABEL), _p_mono('—')],
            [_p('Analysis completed', STYLE_LABEL), _p_mono('—')],
            [_p('Analyst',            STYLE_LABEL), _p_mono('—')],
            [_p('Tools / versions',   STYLE_LABEL), _p_mono('—')],
        ]
        t = Table(rows, colWidths=[55 * mm, 125 * mm])
        t.setStyle(_kv_table_style())
        flow.append(t)
        return flow

    # Real analysis section (reserved for thesis): defensive renderer that
    # accepts whatever shape ``analysis`` has and displays its top-level
    # keys + sub-tables. Will be specialised once the thesis schema lands.
    rows = [
        [_p('Analysis started',   STYLE_LABEL), _p_mono(analysis.get('started_at'))],
        [_p('Analysis completed', STYLE_LABEL), _p_mono(analysis.get('completed_at'))],
        [_p('Analyst',            STYLE_LABEL), _p_mono(analysis.get('analyst'))],
        [_p('Tools / versions',   STYLE_LABEL),
         _p_mono(', '.join(analysis.get('tools', [])) if analysis.get('tools') else None)],
    ]
    t = Table(rows, colWidths=[55 * mm, 125 * mm])
    t.setStyle(_kv_table_style())
    flow.append(t)
    flow.append(Spacer(1, 3 * mm))

    # Generic key-dump for everything else under 'analysis'.
    for k, v in analysis.items():
        if k in ('started_at', 'completed_at', 'analyst', 'tools'):
            continue
        flow.append(Paragraph(str(k), STYLE_H2))
        try:
            payload = json.dumps(v, indent=2, ensure_ascii=False)
        except (TypeError, ValueError):
            payload = repr(v)
        payload_html = (
            payload.replace('&', '&amp;')
                   .replace('<', '&lt;').replace('>', '&gt;')
                   .replace('\n', '<br/>')
                   .replace(' ', '&nbsp;')
        )
        flow.append(Paragraph(payload_html, STYLE_MONO))
        flow.append(Spacer(1, 2 * mm))

    return flow


# ---------------------------------------------------------------------------
# Block: disclaimer
# ---------------------------------------------------------------------------

def render_disclaimer():
    """Legal / forensic disclaimer."""
    flow = []
    flow.append(Paragraph('Notice', STYLE_H1))
    paragraphs = [
        "This report is generated automatically by the ForensicNova plugin "
        "from the canonical JSON acquisition record. The JSON record, the raw "
        "memory image, and the chain-of-custody journal are the primary "
        "evidentiary artifacts; this PDF is a printable presentation of those "
        "artifacts intended for legal hand-off and operator countersignature.",

        "Cryptographic integrity of the memory image is established at the "
        "hypervisor before any transfer (MD5 + SHA-1, streaming) and "
        "verified end-to-end against Swift via ETag comparison. The chain of "
        "custody is appended to a journal on the hypervisor and embedded in "
        "the JSON report. Any tampering with stored evidence breaks the hash "
        "match; tampering with the PDF does not affect the underlying evidence.",

        "Each generation of this PDF is a distinct act and carries the UTC "
        "timestamp of generation. The operator named on the cover is the "
        "analyst who performed the acquisition and who countersigns this "
        "document. Reproducing this PDF at a later time will produce a new, "
        "byte-different document with a new generation timestamp; the "
        "underlying evidence remains the same.",

        "ForensicNova is an academic prototype developed at Università degli "
        "Studi di Salerno (ISISLab) for the M.Sc. course Piattaforme di "
        "Cloud Computing and as baseline for the related M.Sc. thesis. "
        "Use in production forensic workflows is the responsibility of the "
        "deploying organisation.",
    ]
    for p in paragraphs:
        flow.append(Paragraph(p, STYLE_DISCLAIMER))
    return flow


# ---------------------------------------------------------------------------
# NumberedCanvas - two-pass rendering for "page X of Y"
# ---------------------------------------------------------------------------
#
# ReportLab's normal flow renders pages incrementally: each page is finalised
# the moment ``showPage()`` is called, and at that instant the total number
# of pages of the document is unknown. A standard ``onFirstPage`` /
# ``onLaterPages`` callback can therefore print "page X" but not "page X of Y".
#
# For documents with legal effects we want X of Y. The official ReportLab
# pattern for this is the so-called *NumberedCanvas* (two-pass build):
#
#   1. First pass (during ``doc.build()``): every call to ``showPage()`` is
#      intercepted, the canvas state is snapshotted into a list, and a fresh
#      page is started without writing the previous one to the PDF stream.
#   2. Second pass (during ``save()``): we now know ``len(states)`` -- the
#      total page count. We iterate the snapshots, restore each state in
#      turn, draw the header/footer with the known total, and only then call
#      the real ``showPage()`` to commit the page to the PDF.
#
# Cost: the in-memory snapshots roughly double peak memory of the build.
# For the size of our reports (tens of KB to ~1 MB), entirely negligible.

from reportlab.pdfgen.canvas import Canvas


class _NumberedCanvas(Canvas):
    """Canvas subclass that defers page commit until total count is known.

    Subclasses set two class attributes (ACQ_ID, OPERATOR) via the
    ``_make_canvas_class`` factory below; the factory is what gets
    passed to ``doc.build(canvasmaker=...)``.
    """

    # Set by _make_canvas_class()
    ACQ_ID   = ''
    OPERATOR = ''

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._saved_page_states = []

    def showPage(self):
        # Snapshot the page state instead of committing the page now.
        # _startPage() prepares a new blank page surface for the next
        # flowables, so the build loop sees a normal canvas progression.
        self._saved_page_states.append(dict(self.__dict__))
        self._startPage()

    def save(self):
        # Now we know how many pages we have. Walk the snapshots in order,
        # paint header+footer with the total, and commit each page.
        total_pages = len(self._saved_page_states)
        for state in self._saved_page_states:
            self.__dict__.update(state)
            self._draw_page_decoration(total_pages)
            super().showPage()
        super().save()

    def _draw_page_decoration(self, total_pages):
        """Draw header band and footer band on the current page.

        Layout summary (top to bottom):
          - top thin rule + brand left + 'operator: <name>' right
          - ... flowables (drawn earlier by the build loop) ...
          - bottom thin rule
          - acq id (left) | PDF generated <ts> (center) | page X of Y (right)
        """
        self.saveState()

        page_w = self._pagesize[0]
        page_h = self._pagesize[1]
        margin_x = 15 * mm
        baseline = 10 * mm

        # ---- Top band -------------------------------------------------
        self.setStrokeColor(COLOR_RULE)
        self.setLineWidth(0.4)
        self.line(margin_x, page_h - 12 * mm,
                  page_w - margin_x, page_h - 12 * mm)

        # Top-left: brand
        self.setFont('Helvetica-Bold', 8)
        self.setFillColor(COLOR_INK)
        self.drawString(margin_x, page_h - 9 * mm, 'ForensicNova')
        self.setFont('Helvetica', 8)
        self.setFillColor(COLOR_MUTED)
        self.drawString(margin_x + 30 * mm, page_h - 9 * mm,
                        'volatile memory acquisition report')

        # Top-right: operator
        self.setFont('Helvetica', 8)
        self.setFillColor(COLOR_MUTED)
        self.drawRightString(page_w - margin_x, page_h - 9 * mm,
                             f'operator: {self.OPERATOR}')

        # ---- Bottom band ----------------------------------------------
        self.setStrokeColor(COLOR_RULE)
        self.setLineWidth(0.4)
        self.line(margin_x, baseline + 4 * mm,
                  page_w - margin_x, baseline + 4 * mm)

        # Bottom-left: acquisition_id (full, monospace, small)
        self.setFont('Courier', 7.5)
        self.setFillColor(COLOR_MUTED)
        self.drawString(margin_x, baseline,
                        f'acq: {self.ACQ_ID}')

        # Bottom-right: page X of Y. Total is now known.
        self.setFont('Helvetica', 7.5)
        self.drawRightString(page_w - margin_x, baseline,
                             f'page {self._pageNumber} of {total_pages}')

        self.restoreState()


def _make_canvas_class(acquisition_id, operator):
    """Factory: bind the two header/footer fields onto a fresh subclass.

    ``doc.build(canvasmaker=...)`` instantiates the canvas itself, so we
    cannot pass arguments to ``__init__``. Closing the data onto class
    attributes of a fresh per-render subclass is the cleanest workaround.
    """
    return type('_NumberedCanvasBound', (_NumberedCanvas,), {
        'ACQ_ID':   acquisition_id,
        'OPERATOR': operator,
    })


# ---------------------------------------------------------------------------
# Main class
# ---------------------------------------------------------------------------

class ForensicPdfReport:
    """Renders a single-acquisition forensic PDF report.

    Usage::

        pdf_bytes = ForensicPdfReport(report_dict).render()
    """

    def __init__(self, report: dict):
        if not isinstance(report, dict):
            raise TypeError("report must be a dict (the v1.1 JSON report)")
        self.report = report

    def render(self) -> bytes:
        report = self.report
        generated_at   = _now_utc_iso()
        acquisition_id = report.get('acquisition_id') or 'unknown'
        operator       = report.get('operator')        or 'unknown'

        buffer = BytesIO()
        doc = SimpleDocTemplate(
            buffer,
            pagesize=A4,
            topMargin=22 * mm,
            bottomMargin=18 * mm,
            leftMargin=15 * mm,
            rightMargin=15 * mm,
            title=f'ForensicNova report - {acquisition_id}',
            author=operator,
            subject='Volatile memory acquisition - forensic report',
            creator='ForensicNova',
        )

        story = []
        story.extend(render_cover(report, generated_at))
        story.append(PageBreak())
        story.extend(render_evidence(report))
        story.append(Spacer(1, 4 * mm))
        story.extend(render_target_system(report))
        story.append(Spacer(1, 4 * mm))
        story.extend(render_chain_of_custody(report))
        story.append(Spacer(1, 4 * mm))
        story.extend(render_analysis(report))
        story.append(PageBreak())
        story.extend(render_disclaimer())

        # Build with a NumberedCanvas subclass so the footer can show
        # 'page X of Y' (the total is unknown until the canvas save phase).
        canvas_class = _make_canvas_class(acquisition_id, operator)
        doc.build(story, canvasmaker=canvas_class)

        return buffer.getvalue()
