"""Host posture panels: YARA, file scan, persistence, system integrity."""

from __future__ import annotations

import json
from typing import NamedTuple

from sqlalchemy import (
    desc,
    select,
)
from sqlalchemy.orm import Session

from avai.host_monitor import (
    SystemIntegrityRow,
    YaraCoverageRow,
    YaraStatusRow,
)

from .common import (
    Page,
    RowFilter,
    VerdictTable,
    _existing_tables,
    _tally,
)


def yara_status(session: Session) -> "dict | None":
    """The file scanner's compiled-ruleset summary (single row, written by
    the monitor). ``None`` when the scanner has never compiled — e.g. a DB
    from before the monitor ran the file_scan collector."""
    if YaraStatusRow.__tablename__ not in _existing_tables(session):
        return None
    row = session.get(YaraStatusRow, 1)
    if row is None:
        return None
    by_category = json.loads(row.by_category_json or "{}")
    return {
        "compiled_at": row.compiled_at,
        "rules_loaded": row.rules_loaded,
        "files_loaded": row.files_loaded,
        "files_skipped": row.files_skipped,
        "rules_dir": row.rules_dir,
        "sources": json.loads(row.sources_json or "{}"),
        "skip_reasons": json.loads(row.skip_reasons_json or "{}"),
        # Top categories descending — the long tail isn't worth the pixels.
        "top_categories": sorted(
            by_category.items(), key=lambda kv: kv[1], reverse=True
        )[:12],
        "category_count": len(by_category),
    }


_FILE_SCAN_TABLE = VerdictTable(
    "file_scan",
    ("rule", "path", "sha256", "scan_source", "tags_json", "meta_json"),
    search=("rule", "path", "author"),
)


def file_scan(session: Session, run_id: str, filters: RowFilter = RowFilter()) -> dict:
    """The File Scan panel: the compiled-ruleset summary plus this run's
    YARA matches (file_scan rows annotated with their LLM verdict), each
    carrying the matched rule's author parsed from its meta for attribution.
    """
    matches = _FILE_SCAN_TABLE.rows(session, run_id)
    for m in matches:
        meta = json.loads(m.get("meta_json") or "{}")
        m["author"] = meta.get("author") or ""
    return {
        "status": yara_status(session),
        "coverage": yara_coverage(session),
        "matches": filters.keep(matches, _FILE_SCAN_TABLE.search),
        **filters.fields(),
    }


def yara_coverage(session: Session) -> "dict | None":
    """The most recent LLM assessment of how well the loaded ruleset covers
    this host (posture / headline / summary / gaps / recommendations). None
    when the assessor has never run or its table predates this DB."""
    if YaraCoverageRow.__tablename__ not in _existing_tables(session):
        return None
    row = session.execute(
        select(YaraCoverageRow).order_by(desc(YaraCoverageRow.created_at)).limit(1)
    ).scalar_one_or_none()
    if row is None:
        return None
    return {
        "posture": row.posture,
        "headline": row.headline,
        "summary": row.summary,
        "gaps": json.loads(row.gaps_json or "[]"),
        "recommendations": json.loads(row.recommendations_json or "[]"),
        "created_at": row.created_at,
        "model": row.model,
    }


class PersistencePages(NamedTuple):
    """The page each persistence table is on; they page independently."""

    ssh: Page = Page()
    hosts: Page = Page()
    priv: Page = Page()


_SSH_KEYS_TABLE = VerdictTable(
    "ssh_authorized_keys",
    ("owner", "key_type", "fingerprint", "comment", "options", "path"),
    search=("owner", "key_type", "fingerprint", "comment"),
)
_HOSTS_TABLE = VerdictTable(
    "hosts_file", ("ip", "hostnames", "source_path"), search=("ip", "hostnames")
)
_PRIVILEGE_TABLE = VerdictTable(
    "privilege_config",
    ("kind", "subject", "detail", "source_path"),
    search=("kind", "subject", "detail"),
)


def persistence_tampering(
    session: Session,
    run_id: str,
    filters: RowFilter = RowFilter(),
    pages: PersistencePages = PersistencePages(),
):
    """The persistence & tampering posture for ``run_id``: SSH authorized
    keys, /etc/hosts mappings, and privilege config, each list annotated
    with LLM verdicts, plus per-table counts for the section header."""
    ssh, hosts, priv = (
        filters.keep(table.rows(session, run_id), table.search)
        for table in (_SSH_KEYS_TABLE, _HOSTS_TABLE, _PRIVILEGE_TABLE)
    )
    ssh_rows, ssh_paging = pages.ssh.slice(ssh)
    hosts_rows, hosts_paging = pages.hosts.slice(hosts)
    priv_rows, priv_paging = pages.priv.slice(priv)

    return {
        "ssh_keys": ssh_rows,
        "hosts": hosts_rows,
        "privilege": priv_rows,
        "counts": {
            "ssh_keys": _tally(ssh),
            "hosts": _tally(hosts),
            "privilege": _tally(priv),
        },
        "pagination": {"ssh": ssh_paging, "hosts": hosts_paging, "priv": priv_paging},
        # The route sizes all three tables alike.
        "per_page": pages.ssh.size,
        **filters.fields(),
        "any": bool(ssh or hosts or priv),
    }


def system_integrity(session: Session, run_id: str):
    """Return the latest system-integrity posture as a platform-tagged
    dict the template can render directly.

    macOS and Linux write to the same table but different places:
    the macOS collector fills the named columns (filevault_active, …);
    the Linux collector puts everything in ``raw_json`` (selinux,
    apparmor, ufw, …). We detect which one produced the row and emit
    the matching labels — otherwise a Linux row (or vice-versa) renders
    under the wrong OS's labels and an unset column reads as a scary,
    false "OFF" (e.g. "FileVault OFF" for data collected in a Linux VM).
    """
    row = session.execute(
        select(SystemIntegrityRow).where(SystemIntegrityRow.run_id == run_id).limit(1)
    ).scalar_one_or_none()
    if row is None:
        return None

    try:
        raw = json.loads(row.raw_json) if row.raw_json else {}
    except (json.JSONDecodeError, TypeError):
        raw = {}

    linux_keys = {
        "selinux",
        "apparmor",
        "ufw_active",
        "firewalld_active",
        "sshd_active",
        "vnc_active",
        "luks_mappings",
    }
    # Behaviour ("active now") signals, written by the network-service
    # controls alongside the posture columns. Each row is
    # ``(label, enabled, active)``; active is None for topics that have no
    # live-session concept (FileVault, Gatekeeper, …).
    svc = raw.get("services") or {}

    def _active(topic: str):
        entry = svc.get(topic)
        return entry.get("active") if isinstance(entry, dict) else None

    if linux_keys & set(raw):
        apparmor = raw.get("apparmor")
        apparmor_on = (
            apparmor.get("enabled") if isinstance(apparmor, dict) else apparmor
        )
        return {
            "platform": "Linux",
            "rows": [
                ("SELinux", raw.get("selinux"), None),
                ("AppArmor", apparmor_on, None),
                ("Firewall (ufw)", raw.get("ufw_active"), None),
                ("Firewall (firewalld)", raw.get("firewalld_active"), None),
                ("SSH (sshd)", raw.get("sshd_active"), _active("remote_login")),
                ("VNC", raw.get("vnc_active"), _active("screen_sharing")),
                ("Disk encryption (LUKS)", bool(raw.get("luks_mappings")), None),
            ],
        }
    return {
        "platform": "macOS",
        "rows": [
            ("FileVault", row.filevault_active, None),
            ("Firewall", row.firewall_global_state, None),
            ("Firewall stealth", row.firewall_stealth, None),
            ("Gatekeeper", row.gatekeeper_assessments_enabled, None),
            ("SSH (sshd)", row.remote_login_enabled, _active("remote_login")),
            ("Screen Sharing", row.screen_sharing_enabled, _active("screen_sharing")),
            (
                "Remote Mgmt (ARD)",
                row.remote_management_enabled,
                _active("remote_management"),
            ),
        ],
    }
