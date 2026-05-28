"""Tests for the read-only Flask dashboard.

The dashboard has two surfaces we lock down:

  1. ``_ensure_db_exists`` — the bug that earlier 500'd every panel on
     a fresh mount. This file pins the regression.
  2. The HTTP endpoints — Flask test client hits each route against
     an empty schema and asserts a 200, empty-shape response.
"""
from __future__ import annotations

import os
from pathlib import Path

import pytest
from sqlalchemy import create_engine

from avai.dashboard import _ensure_db_exists, app
from avai.host_monitor import Base


# ---------------------------------------------------------------------------
# _ensure_db_exists — regression for the read-only 500 bug
# ---------------------------------------------------------------------------

class TestEnsureDbExists:
    def test_creates_file_when_missing(self, tmp_path):
        db = tmp_path / "new.db"
        assert not db.exists()
        _ensure_db_exists(str(db))
        assert db.exists()
        assert db.stat().st_size > 0  # schema bytes written

    def test_creates_parent_directory(self, tmp_path):
        db = tmp_path / "nested" / "deeper" / "avai.db"
        _ensure_db_exists(str(db))
        assert db.exists()

    def test_is_no_op_when_file_already_populated(self, tmp_path):
        db = tmp_path / "preexisting.db"
        # Touch a non-trivial file so _ensure thinks it's real.
        db.write_bytes(b"x" * 100)
        mtime_before = db.stat().st_mtime_ns
        _ensure_db_exists(str(db))
        # No rewrite.
        assert db.stat().st_mtime_ns == mtime_before

    def test_schema_is_queryable_after_create(self, tmp_path):
        """The bug it regresses against: dashboard opens the file with
        ``mode=ro&immutable=1`` — that mode requires the schema to
        already exist. Verify every collector table is present."""
        db = tmp_path / "fresh.db"
        _ensure_db_exists(str(db))

        # Open the file the same way the dashboard does.
        engine = create_engine(
            f"sqlite:///file:{db}?mode=ro&immutable=1&uri=true",
        )
        with engine.connect() as conn:
            from sqlalchemy import text
            names = [r[0] for r in conn.execute(text(
                "select name from sqlite_master where type='table'"
            ))]
        # The fix's contract — every model table must exist on the
        # fresh DB, so the dashboard's queries don't 500.
        for required in (
            "collection_runs", "processes", "launch_items", "judgements",
            "enrichment_evidence",
        ):
            assert required in names


# ---------------------------------------------------------------------------
# Flask test client — every endpoint must answer 200 on an empty DB
# ---------------------------------------------------------------------------

@pytest.fixture
def client(tmp_path, monkeypatch):
    """Bind the Flask app to a fresh empty DB and return its test
    client. Avoids the real app.run() loop entirely."""
    db = tmp_path / "test.db"
    _ensure_db_exists(str(db))
    app.config.update(TESTING=True, DB_PATH=str(db))
    with app.test_client() as c:
        yield c


class TestDashboardEndpoints:
    def test_root_returns_html_page(self, client):
        r = client.get("/")
        assert r.status_code == 200
        assert b"<html" in r.data or b"<!doctype html" in r.data.lower()

    def test_notifications_endpoint_returns_empty_items(self, client):
        # This is what the Docker HEALTHCHECK hits.
        r = client.get("/api/notifications/new?since=2099-01-01")
        assert r.status_code == 200
        body = r.get_json()
        assert body == {"items": [],
                        "now": body["now"],   # presence — value is a timestamp
                        "since": "2099-01-01"}

    def test_chart_verdicts_endpoint(self, client):
        r = client.get("/api/chart/verdicts")
        assert r.status_code == 200
        body = r.get_json()
        assert isinstance(body, dict)
        # Empty DB → every verdict bucket is zero or missing — either
        # is acceptable as long as the endpoint doesn't 500.

    @pytest.mark.parametrize("path", [
        "/fragments/header-meta",
        "/fragments/overview",
        "/fragments/sysint",
        "/fragments/errors",
        "/fragments/row-counts",
        "/fragments/runs",
    ])
    def test_each_htmx_fragment_returns_200_on_empty_db(self, client, path):
        r = client.get(path)
        assert r.status_code == 200, f"{path} → {r.status_code}"

    def test_findings_fragment_supports_pagination_param(self, client):
        # Empty DB but the param-parsing must not crash.
        r = client.get("/fragments/findings?page=1")
        assert r.status_code == 200

    def test_unknown_endpoint_is_404_not_500(self, client):
        r = client.get("/this-route-does-not-exist")
        assert r.status_code == 404
