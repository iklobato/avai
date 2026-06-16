"""Tests for the AutoSEO article webhook and the public /blog routes.

Covers auth (Bearer + optional HMAC), the test event, insert/update idempotency
keyed on the AutoSEO id, the published-URL response, error paths (bad JSON,
missing fields) and the SSRF guard on image downloads.
"""

from __future__ import annotations

import hashlib
import hmac
import json

import pytest
from sqlalchemy import create_engine, select
from sqlalchemy.orm import Session

from avai.dashboard import _ensure_db_exists, app
from avai.dashboard.autoseo import (
    TOKEN_ENV,
    BlogPostRow,
    _check_signature,
    _download_image,
    _url_is_safe,
)

TOKEN = "aseo_wh_b4f9779f67f1f5297587c26ea9342a4f"


@pytest.fixture
def client(tmp_path, monkeypatch):
    db = tmp_path / "test.db"
    _ensure_db_exists(str(db))
    app.config.update(TESTING=True, DB_PATH=str(db))
    # Steer image storage into the tmp dir so tests never write into the package.
    monkeypatch.setenv(TOKEN_ENV, TOKEN)
    monkeypatch.setenv("AUTOSEO_SITE_URL", "https://mysite.com")
    with app.test_client() as c:
        yield c


def _rw(db_path):
    return create_engine(
        f"sqlite:///{db_path}", connect_args={"check_same_thread": False}
    )


def _post(client, body, *, token=TOKEN, sign=False, headers=None):
    raw = json.dumps(body).encode("utf-8")
    hdrs = {"Content-Type": "application/json"}
    if token is not None:
        hdrs["Authorization"] = f"Bearer {token}"
    if sign:
        hdrs["X-AutoSEO-Signature"] = hmac.new(
            TOKEN.encode(), raw, hashlib.sha256
        ).hexdigest()
    if headers:
        hdrs.update(headers)
    return client.post("/webhooks/autoseo", data=raw, headers=hdrs)


def _article(**over):
    body = {
        "event": "article.published",
        "id": 42,
        "title": "Ten SEO Strategies",
        "slug": "ten-seo-strategies",
        "published_url": None,
        "metaDescription": "A guide.",
        "content_html": "<p>Hello <strong>world</strong></p>",
        "content_markdown": "Hello **world**",
        "heroImageUrl": None,
        "heroImageAlt": "hero",
        "infographicImageUrl": None,
        "keywords": ["seo strategies"],
        "metaKeywords": "seo, strategies",
        "faqSchema": [{"question": "Q?", "answer": "A."}],
        "languageCode": "en",
        "status": "published",
        "publishedAt": "2026-06-16T10:00:00Z",
        "updatedAt": "2026-06-16T10:00:00Z",
        "createdAt": "2026-06-16T09:00:00Z",
    }
    body.update(over)
    return body


# --------------------------------------------------------------------------- auth


class TestAuth:
    def test_missing_server_token_fails_closed_503(self, client, monkeypatch):
        monkeypatch.delenv(TOKEN_ENV, raising=False)
        assert _post(client, _article()).status_code == 503

    def test_missing_bearer_is_401(self, client):
        assert _post(client, _article(), token=None).status_code == 401

    def test_wrong_bearer_is_401(self, client):
        assert _post(client, _article(), token="wrong").status_code == 401

    def test_valid_signature_accepted(self, client):
        assert _post(client, _article(), sign=True).status_code == 200

    def test_bad_signature_rejected_401(self, client):
        r = _post(client, _article(), headers={"X-AutoSEO-Signature": "deadbeef"})
        assert r.status_code == 401

    def test_absent_signature_still_ok(self, client):
        assert _post(client, _article()).status_code == 200

    def test_check_signature_helper(self):
        raw = b'{"a":1}'
        good = hmac.new(TOKEN.encode(), raw, hashlib.sha256).hexdigest()
        assert _check_signature(raw, good, TOKEN)
        assert _check_signature(raw, f"sha256={good}", TOKEN)
        assert not _check_signature(raw, "nope", TOKEN)


# --------------------------------------------------------------------------- events


class TestEvents:
    def test_test_event_returns_url_without_creating_post(self, client):
        r = _post(client, {"event": "test"})
        assert r.status_code == 200
        assert r.get_json()["url"] == "https://mysite.com/test"
        with Session(_rw(app.config["DB_PATH"])) as s:
            assert s.scalars(select(BlogPostRow)).first() is None

    def test_publish_inserts_and_returns_public_url(self, client):
        r = _post(client, _article())
        assert r.status_code == 200
        assert r.get_json()["url"] == "https://mysite.com/blog/ten-seo-strategies"
        with Session(_rw(app.config["DB_PATH"])) as s:
            row = s.scalar(select(BlogPostRow).where(BlogPostRow.autoseo_id == 42))
            assert row is not None
            assert row.title == "Ten SEO Strategies"
            assert json.loads(row.keywords_json) == ["seo strategies"]

    def test_duplicate_delivery_updates_in_place(self, client):
        _post(client, _article())
        # Same id, new content arrives as article.updated.
        _post(
            client,
            _article(event="article.updated", title="Updated Title"),
        )
        with Session(_rw(app.config["DB_PATH"])) as s:
            rows = s.scalars(
                select(BlogPostRow).where(BlogPostRow.autoseo_id == 42)
            ).all()
            assert len(rows) == 1
            assert rows[0].title == "Updated Title"


# --------------------------------------------------------------------------- errors


class TestErrors:
    def test_invalid_json_is_400(self, client):
        r = client.post(
            "/webhooks/autoseo",
            data=b"{not json",
            headers={"Authorization": f"Bearer {TOKEN}"},
        )
        assert r.status_code == 400

    def test_missing_id_is_400(self, client):
        body = _article()
        del body["id"]
        assert _post(client, body).status_code == 400

    def test_missing_slug_is_400(self, client):
        assert _post(client, _article(slug="")).status_code == 400

    def test_store_failure_returns_500(self, client, monkeypatch):
        def boom(*a, **k):
            raise RuntimeError("db down")

        monkeypatch.setattr("avai.dashboard.autoseo._store_post", boom)
        assert _post(client, _article()).status_code == 500


# --------------------------------------------------------------------------- images / SSRF


class TestImageSafety:
    @pytest.mark.parametrize(
        "url",
        [
            "http://127.0.0.1/x.png",
            "http://localhost/x.png",
            "http://169.254.169.254/latest/meta-data/",  # cloud metadata
            "http://10.0.0.5/x.png",
            "http://192.168.1.1/x.png",
            "ftp://example.com/x.png",
            "file:///etc/passwd",
            "not-a-url",
        ],
    )
    def test_unsafe_urls_rejected(self, url):
        assert _url_is_safe(url) is False

    def test_download_skips_unsafe_url_without_network(self, tmp_path):
        # Loopback URL is rejected before any socket is opened.
        assert _download_image("http://127.0.0.1/hero.png", tmp_path, "hero") is None

    def test_publish_with_private_image_url_still_succeeds(self, client):
        r = _post(client, _article(heroImageUrl="http://127.0.0.1/hero.png"))
        assert r.status_code == 200
        with Session(_rw(app.config["DB_PATH"])) as s:
            row = s.scalar(select(BlogPostRow).where(BlogPostRow.autoseo_id == 42))
            # Original URL is kept; nothing was hot-linked or fetched.
            assert row.hero_image_url == "http://127.0.0.1/hero.png"
            assert row.hero_image_local is None

    def test_local_image_url_wired_when_download_succeeds(self, client, monkeypatch):
        import avai.dashboard.autoseo as mod

        def fake_store(url, article_id, name):
            return f"/static/blog/{article_id}/{name}.png" if url else None

        monkeypatch.setattr(mod, "_store_image", fake_store)
        _post(client, _article(heroImageUrl="https://cdn.example.com/h.png"))
        with Session(_rw(app.config["DB_PATH"])) as s:
            row = s.scalar(select(BlogPostRow).where(BlogPostRow.autoseo_id == 42))
            assert row.hero_image_local == "/static/blog/42/hero.png"


# --------------------------------------------------------------------------- blog routes


class TestBlogRoutes:
    def test_blog_post_renders_after_publish(self, client):
        _post(client, _article())
        r = client.get("/blog/ten-seo-strategies")
        assert r.status_code == 200
        assert b"Ten SEO Strategies" in r.data
        assert b"Hello <strong>world</strong>" in r.data

    def test_unknown_slug_is_404(self, client):
        assert client.get("/blog/nope").status_code == 404

    def test_blog_index_lists_posts(self, client):
        _post(client, _article())
        r = client.get("/blog")
        assert r.status_code == 200
        assert b"ten-seo-strategies" in r.data
