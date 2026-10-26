"""Host posture panels: YARA, file scan, persistence, system integrity."""

from __future__ import annotations

from operator import itemgetter
from typing import Any, NamedTuple

from sqlalchemy import desc, select
from sqlalchemy.orm import Session

from avai.host_monitor import SystemIntegrityRow, YaraCoverageRow, YaraStatusRow

from .panel_reads import (
    Page,
    RowFilter,
    SchemaProbe,
    StoredJson,
    VerdictTable,
    VerdictTally,
)

# The yara_status table holds one row with this id.
YARA_STATUS_ID = 1

# Keys only the Linux collector writes into raw_json.
LINUX_KEYS = frozenset(
    {
        "selinux",
        "apparmor",
        "ufw_active",
        "firewalld_active",
        "sshd_active",
        "vnc_active",
        "luks_mappings",
    }
)


class YaraPanels:
    """The file scanner's ruleset summary and the LLM's coverage assessment.
    Each is None when it never ran or its table predates this DB."""

    TOP_CATEGORIES = 12
    FILE_SCAN_TABLE = VerdictTable(
        "file_scan",
        ("rule", "path", "sha256", "scan_source", "tags_json", "meta_json"),
        search=("rule", "path", "author"),
    )

    def __init__(self, session: Session) -> None:
        self._session = session

    def status(self) -> dict[str, Any] | None:
        if YaraStatusRow.__tablename__ not in SchemaProbe(self._session).tables():
            return None
        row = self._session.get(YaraStatusRow, YARA_STATUS_ID)
        if row is None:
            return None
        by_category = StoredJson().as_dict(row.by_category_json)
        ranked = sorted(by_category.items(), key=itemgetter(1), reverse=True)
        return {
            "compiled_at": row.compiled_at,
            "rules_loaded": row.rules_loaded,
            "files_loaded": row.files_loaded,
            "files_skipped": row.files_skipped,
            "rules_dir": row.rules_dir,
            "sources": StoredJson().as_dict(row.sources_json),
            "skip_reasons": StoredJson().as_dict(row.skip_reasons_json),
            # Top categories descending: the long tail isn't worth the pixels.
            "top_categories": ranked[: self.TOP_CATEGORIES],
            "category_count": len(by_category),
        }

    def coverage(self) -> dict[str, Any] | None:
        if YaraCoverageRow.__tablename__ not in SchemaProbe(self._session).tables():
            return None
        statement = (
            select(YaraCoverageRow).order_by(desc(YaraCoverageRow.created_at)).limit(1)
        )
        row = self._session.execute(statement).scalar_one_or_none()
        if row is None:
            return None
        return {
            "posture": row.posture,
            "headline": row.headline,
            "summary": row.summary,
            "gaps": StoredJson().as_list(row.gaps_json),
            "recommendations": StoredJson().as_list(row.recommendations_json),
            "created_at": row.created_at,
            "model": row.model,
        }

    def file_scan(self, run_id: str, filters: RowFilter) -> dict[str, Any]:
        """The ruleset summary plus this run's YARA matches, each carrying the
        matched rule's author (from its meta) for attribution."""
        matches = self.FILE_SCAN_TABLE.rows(self._session, run_id)
        for match in matches:
            match["author"] = (
                StoredJson().as_dict(match.get("meta_json")).get("author") or ""
            )
        return {
            "status": self.status(),
            "coverage": self.coverage(),
            "matches": filters.keep(matches, self.FILE_SCAN_TABLE.search),
            **filters.fields(),
        }


class PersistencePages(NamedTuple):
    """The page each persistence table is on; they page independently."""

    ssh: Page = Page()
    hosts: Page = Page()
    priv: Page = Page()


class PersistencePanel:
    """SSH authorized keys, /etc/hosts mappings and privilege config for a
    run, each annotated with LLM verdicts, plus per-table counts."""

    SSH_KEYS_TABLE = VerdictTable(
        "ssh_authorized_keys",
        ("owner", "key_type", "fingerprint", "comment", "options", "path"),
        search=("owner", "key_type", "fingerprint", "comment"),
    )
    HOSTS_TABLE = VerdictTable(
        "hosts_file", ("ip", "hostnames", "source_path"), search=("ip", "hostnames")
    )
    PRIVILEGE_TABLE = VerdictTable(
        "privilege_config",
        ("kind", "subject", "detail", "source_path"),
        search=("kind", "subject", "detail"),
    )

    def __init__(self, session: Session, run_id: str) -> None:
        self._session = session
        self._run_id = run_id

    def tampering(self, filters: RowFilter, pages: PersistencePages) -> dict[str, Any]:
        ssh, hosts, priv = self._rows(filters)
        sliced = {
            "ssh": pages.ssh.slice(ssh),
            "hosts": pages.hosts.slice(hosts),
            "priv": pages.priv.slice(priv),
        }
        return {
            "ssh_keys": sliced["ssh"][0],
            "hosts": sliced["hosts"][0],
            "privilege": sliced["priv"][0],
            "counts": self._counts((ssh, hosts, priv)),
            "pagination": {name: paging for name, (_rows, paging) in sliced.items()},
            # The route sizes all three tables alike.
            "per_page": pages.ssh.size,
            **filters.fields(),
            "any": bool(ssh or hosts or priv),
        }

    def _rows(self, filters: RowFilter) -> list[list[dict[str, Any]]]:
        tables = (self.SSH_KEYS_TABLE, self.HOSTS_TABLE, self.PRIVILEGE_TABLE)
        return [
            filters.keep(table.rows(self._session, self._run_id), table.search)
            for table in tables
        ]

    def _counts(self, tables: tuple[list[Any], list[Any], list[Any]]) -> dict[str, Any]:
        tally = VerdictTally()
        ssh, hosts, priv = tables
        return {
            "ssh_keys": tally.of(ssh),
            "hosts": tally.of(hosts),
            "privilege": tally.of(priv),
        }


class ServiceActivity:
    """``topic -> active now`` from the network-service controls, or None for
    topics with no live-session concept (FileVault, Gatekeeper, ...)."""

    def __init__(self, raw: dict[str, Any]) -> None:
        self._raw = raw

    def active(self, topic: str) -> Any:
        services = self._raw.get("services") or {}
        entry = services.get(topic)
        return entry.get("active") if isinstance(entry, dict) else None


class LinuxPosture:
    def __init__(self, raw: dict[str, Any]) -> None:
        self._raw = raw

    def describe(self) -> dict[str, Any]:
        raw, activity = self._raw, ServiceActivity(self._raw)
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
                ("SSH (sshd)", raw.get("sshd_active"), activity.active("remote_login")),
                ("VNC", raw.get("vnc_active"), activity.active("screen_sharing")),
                ("Disk encryption (LUKS)", bool(raw.get("luks_mappings")), None),
            ],
        }


class MacosPosture:
    def __init__(self, row: SystemIntegrityRow, raw: dict[str, Any]) -> None:
        self._row = row
        self._raw = raw

    def describe(self) -> dict[str, Any]:
        row = self._row
        local = [
            ("FileVault", row.filevault_active, None),
            ("Firewall", row.firewall_global_state, None),
            ("Firewall stealth", row.firewall_stealth, None),
            ("Gatekeeper", row.gatekeeper_assessments_enabled, None),
        ]
        return {"platform": "macOS", "rows": local + self._remote()}

    def _remote(self) -> list[tuple[str, Any, Any]]:
        row, activity = self._row, ServiceActivity(self._raw)
        return [
            ("SSH (sshd)", row.remote_login_enabled, activity.active("remote_login")),
            (
                "Screen Sharing",
                row.screen_sharing_enabled,
                activity.active("screen_sharing"),
            ),
            (
                "Remote Mgmt (ARD)",
                row.remote_management_enabled,
                activity.active("remote_management"),
            ),
        ]


class IntegrityPosture:
    """The latest system-integrity posture as a platform-tagged dict the
    template renders directly. macOS fills the named columns; Linux puts
    everything in ``raw_json``. Detecting which one wrote the row keeps a
    Linux row from rendering under macOS labels, where an unset column
    would read as a scary, false "OFF". Each row is ``(label, enabled,
    active)``."""

    def __init__(self, session: Session) -> None:
        self._session = session

    def for_run(self, run_id: str) -> dict[str, Any] | None:
        statement = (
            select(SystemIntegrityRow)
            .where(SystemIntegrityRow.run_id == run_id)
            .limit(1)
        )
        row = self._session.execute(statement).scalar_one_or_none()
        if row is None:
            return None
        raw = StoredJson().as_dict(row.raw_json)
        if LINUX_KEYS & set(raw):
            return LinuxPosture(raw).describe()
        return MacosPosture(row, raw).describe()
