"""Host posture panels: YARA, file scan, persistence, system integrity."""

from __future__ import annotations

import json

from sqlalchemy import (
    desc,
    select,
)
from sqlalchemy.orm import Session

from avai.host_monitor import (
    FileScanRow,
    HostsFileRow,
    PrivilegeConfigRow,
    SshAuthorizedKeyRow,
    SystemIntegrityRow,
    YaraCoverageRow,
    YaraStatusRow,
)

from .common import (
    DEFAULT_PER_PAGE,
    _collector_rows_with_verdict,
    _existing_tables,
    _paginate,
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


def file_scan(
    session: Session,
    run_id: str,
    verdict: str = "",
    q: str = "",
    limit: int = 500,
) -> dict:
    """The File Scan panel: the compiled-ruleset summary plus this run's
    YARA matches (file_scan rows annotated with their LLM verdict), each
    carrying the matched rule's author parsed from its meta for attribution.
    """
    matches = _collector_rows_with_verdict(
        session,
        run_id,
        FileScanRow,
        "file_scan",
        ("rule", "path", "sha256", "scan_source", "tags_json", "meta_json"),
        limit,
    )
    for m in matches:
        meta = json.loads(m.get("meta_json") or "{}")
        m["author"] = meta.get("author") or ""
    if verdict:
        matches = [m for m in matches if m.get("verdict") == verdict]
    if q:
        ql = q.lower()
        matches = [
            m
            for m in matches
            if any(
                ql in str(m.get(f) or "").lower() for f in ("rule", "path", "author")
            )
        ]
    return {
        "status": yara_status(session),
        "coverage": yara_coverage(session),
        "matches": matches,
        "verdict": verdict,
        "q": q,
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


def persistence_tampering(
    session: Session,
    run_id: str,
    limit: int = 500,
    verdict: str = "",
    q: str = "",
    ssh_page: int = 1,
    hosts_page: int = 1,
    priv_page: int = 1,
    per_page: int = DEFAULT_PER_PAGE,
):
    """The persistence & tampering posture for ``run_id``: SSH authorized
    keys, /etc/hosts mappings, and privilege config — each list annotated
    with LLM verdicts, plus per-table counts for the section header."""
    ssh = _collector_rows_with_verdict(
        session,
        run_id,
        SshAuthorizedKeyRow,
        "ssh_authorized_keys",
        ("owner", "key_type", "fingerprint", "comment", "options", "path"),
        limit,
    )
    hosts = _collector_rows_with_verdict(
        session,
        run_id,
        HostsFileRow,
        "hosts_file",
        ("ip", "hostnames", "source_path"),
        limit,
    )
    priv = _collector_rows_with_verdict(
        session,
        run_id,
        PrivilegeConfigRow,
        "privilege_config",
        ("kind", "subject", "detail", "source_path"),
        limit,
    )

    def _counts(rs: list[dict]) -> dict:
        return {
            "total": len(rs),
            "malicious": sum(1 for r in rs if r["verdict"] == "malicious"),
            "suspicious": sum(1 for r in rs if r["verdict"] == "suspicious"),
        }

    def _filter_rows(rs, fields):
        if verdict:
            rs = [r for r in rs if r.get("verdict") == verdict]
        if q:
            ql = q.lower()
            rs = [
                r for r in rs if any(ql in str(r.get(f) or "").lower() for f in fields)
            ]
        return rs

    ssh = _filter_rows(ssh, ("owner", "key_type", "fingerprint", "comment"))
    hosts = _filter_rows(hosts, ("ip", "hostnames"))
    priv = _filter_rows(priv, ("kind", "subject", "detail"))

    ssh_rows, ssh_total, ssh_pages = _paginate(ssh, ssh_page, per_page)
    hosts_rows, hosts_total, hosts_pages = _paginate(hosts, hosts_page, per_page)
    priv_rows, priv_total, priv_pages = _paginate(priv, priv_page, per_page)

    return {
        "ssh_keys": ssh_rows,
        "hosts": hosts_rows,
        "privilege": priv_rows,
        "counts": {
            "ssh_keys": _counts(ssh),
            "hosts": _counts(hosts),
            "privilege": _counts(priv),
        },
        "pagination": {
            "ssh": {"page": ssh_page, "total": ssh_total, "total_pages": ssh_pages},
            "hosts": {
                "page": hosts_page,
                "total": hosts_total,
                "total_pages": hosts_pages,
            },
            "priv": {"page": priv_page, "total": priv_total, "total_pages": priv_pages},
        },
        "per_page": per_page,
        "verdict": verdict,
        "q": q,
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
