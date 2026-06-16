"""AutoSEO (https://getautoseo.com) article webhook + public blog rendering.

A single POST endpoint receives published/updated articles from AutoSEO,
stores them in a new ``autoseo_blog_posts`` table (idempotent upsert keyed on
the AutoSEO article ``id`` so duplicate deliveries update in place), downloads
the hero/infographic images locally instead of hot-linking, and serves the
posts at ``/blog/<slug>``.

This module only ever CREATEs its own table — it never alters or drops any
existing schema. The table is registered on the shared ``Base`` and provisioned
with ``CREATE TABLE IF NOT EXISTS`` semantics (``checkfirst=True``), so it is
added next to the monitor's existing tables without touching their data.

Configuration (environment):
  AUTOSEO_WEBHOOK_TOKEN  Shared Bearer/HMAC secret. REQUIRED — the endpoint
                         fails closed (HTTP 503) when unset, mirroring the
                         dashboard's existing AVAI_CONTROL_TOKEN gate. Keep it
                         in your (gitignored) .env, never in source.
  AUTOSEO_SITE_URL       Public base URL of the site, used to build the
                         returned post URL. Defaults to http://127.0.0.1:8765.
"""

from __future__ import annotations

import hashlib
import hmac
import ipaddress
import json
import logging
import os
import socket
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional
from urllib.parse import urljoin, urlparse

import requests
from flask import abort, current_app, jsonify, render_template, request
from markupsafe import Markup
from sqlalchemy import create_engine, desc, select
from sqlalchemy.orm import Mapped, Session, mapped_column

from avai.host_monitor import Base

from .app import _PKG_DIR, app

LOG = logging.getLogger("avai.autoseo")

TOKEN_ENV = "AUTOSEO_WEBHOOK_TOKEN"
SITE_URL_ENV = "AUTOSEO_SITE_URL"
_DEFAULT_SITE_URL = "http://127.0.0.1:8765"

# Image download guards. AutoSEO sends fully-qualified CDN URLs; we fetch them
# server-side, so they get the same SSRF treatment as any user-supplied URL.
_MAX_IMAGE_BYTES = 10 * 1024 * 1024
_IMAGE_TIMEOUT_S = 10
_MAX_REDIRECTS = 5
_CONTENT_TYPE_EXT = {
    "image/jpeg": ".jpg",
    "image/jpg": ".jpg",
    "image/png": ".png",
    "image/gif": ".gif",
    "image/webp": ".webp",
    "image/svg+xml": ".svg",
    "image/avif": ".avif",
}


class BlogPostRow(Base):
    """One AutoSEO article. ``autoseo_id`` is the upstream article id and the
    upsert key, so a re-delivered ``article.published`` or a later
    ``article.updated`` for the same id overwrites this row instead of
    inserting a duplicate."""

    __tablename__ = "autoseo_blog_posts"

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    autoseo_id: Mapped[int] = mapped_column(unique=True, index=True)
    event: Mapped[Optional[str]]
    title: Mapped[str]
    slug: Mapped[str] = mapped_column(index=True)
    published_url: Mapped[Optional[str]]
    meta_description: Mapped[Optional[str]]
    content_html: Mapped[Optional[str]]
    content_markdown: Mapped[Optional[str]]
    hero_image_url: Mapped[Optional[str]]
    hero_image_local: Mapped[Optional[str]]
    hero_image_alt: Mapped[Optional[str]]
    infographic_image_url: Mapped[Optional[str]]
    infographic_image_local: Mapped[Optional[str]]
    keywords_json: Mapped[Optional[str]]
    meta_keywords: Mapped[Optional[str]]
    faq_schema_json: Mapped[Optional[str]]
    language_code: Mapped[Optional[str]]
    status: Mapped[Optional[str]]
    published_at: Mapped[Optional[str]]
    updated_at: Mapped[Optional[str]]
    created_at: Mapped[Optional[str]]
    received_at: Mapped[str]


# ---------------------------------------------------------------------------
# DB — a writable engine (the dashboard's own engine is read-only) that
# provisions ONLY this table, leaving every existing table untouched.
# ---------------------------------------------------------------------------

_rw_cache: dict[str, object] = {}
_rw_lock = threading.Lock()


def _rw_engine():
    """Process-wide read-write engine for the configured DB, created once per
    path. On first build it ensures ``autoseo_blog_posts`` exists via
    ``checkfirst=True`` (``CREATE TABLE IF NOT EXISTS``) — no other table is
    created or altered."""
    db_path = current_app.config["DB_PATH"]
    eng = _rw_cache.get(db_path)
    if eng is None:
        with _rw_lock:
            eng = _rw_cache.get(db_path)
            if eng is None:
                eng = create_engine(
                    f"sqlite:///{db_path}",
                    connect_args={"check_same_thread": False},
                )
                BlogPostRow.__table__.create(bind=eng, checkfirst=True)
                _rw_cache[db_path] = eng
    return eng


# ---------------------------------------------------------------------------
# Auth — Bearer token (required) + optional HMAC-SHA256 body signature.
# ---------------------------------------------------------------------------


def _check_bearer(auth_header: str, token: str) -> bool:
    prefix = "Bearer "
    if not auth_header.startswith(prefix):
        return False
    return hmac.compare_digest(auth_header[len(prefix) :].strip(), token)


def _check_signature(raw_body: bytes, signature: str, secret: str) -> bool:
    """HMAC-SHA256 of the *raw* request bytes, keyed by the shared token.
    Accepts a bare hex digest or a ``sha256=<hex>`` form."""
    expected = hmac.new(secret.encode("utf-8"), raw_body, hashlib.sha256).hexdigest()
    provided = (
        signature.split("=", 1)[1] if signature.startswith("sha256=") else signature
    )
    return hmac.compare_digest(expected, provided.strip())


# ---------------------------------------------------------------------------
# Image download with SSRF protection.
# ---------------------------------------------------------------------------


def _host_is_public(host: str) -> bool:
    """True only if every address ``host`` resolves to is a routable public
    IP. Blocks loopback/private/link-local/reserved/multicast targets so a
    crafted image URL can't make us fetch internal services or cloud
    metadata endpoints."""
    try:
        infos = socket.getaddrinfo(host, None)
    except socket.gaierror:
        return False
    for info in infos:
        ip = ipaddress.ip_address(info[4][0])
        if (
            ip.is_private
            or ip.is_loopback
            or ip.is_link_local
            or ip.is_reserved
            or ip.is_multicast
            or ip.is_unspecified
        ):
            return False
    return True


def _url_is_safe(url: str) -> bool:
    parsed = urlparse(url)
    if parsed.scheme not in ("http", "https") or not parsed.hostname:
        return False
    return _host_is_public(parsed.hostname)


def _ext_for(content_type: str, url: str) -> str:
    ext = _CONTENT_TYPE_EXT.get(content_type)
    if ext:
        return ext
    suffix = Path(urlparse(url).path).suffix.lower()
    return suffix if suffix in _CONTENT_TYPE_EXT.values() else ".img"


def _download_image(
    url: Optional[str], dest_dir: Path, basename: str
) -> Optional[Path]:
    """Fetch ``url`` to ``dest_dir/basename.<ext>`` and return the path, or
    ``None`` if the URL is unsafe/unreachable/too big/not an image. Redirects
    are followed manually so each hop is SSRF-checked (``requests``' automatic
    redirects would bypass the per-hop guard)."""
    if not url or not _url_is_safe(url):
        return None
    session = requests.Session()
    current = url
    try:
        for _ in range(_MAX_REDIRECTS):
            if not _url_is_safe(current):
                return None
            resp = session.get(
                current, stream=True, timeout=_IMAGE_TIMEOUT_S, allow_redirects=False
            )
            try:
                if resp.status_code in (301, 302, 303, 307, 308):
                    location = resp.headers.get("Location")
                    if not location:
                        return None
                    current = urljoin(resp.url, location)
                    continue
                if resp.status_code != 200:
                    return None
                content_type = (
                    resp.headers.get("Content-Type", "").split(";")[0].strip().lower()
                )
                if not content_type.startswith("image/"):
                    return None
                dest_dir.mkdir(parents=True, exist_ok=True)
                path = dest_dir / f"{basename}{_ext_for(content_type, current)}"
                size = 0
                with open(path, "wb") as fh:
                    for chunk in resp.iter_content(8192):
                        size += len(chunk)
                        if size > _MAX_IMAGE_BYTES:
                            fh.close()
                            path.unlink(missing_ok=True)
                            return None
                        fh.write(chunk)
                return path
            finally:
                resp.close()
        return None
    except requests.RequestException as exc:
        LOG.warning("autoseo image download failed for %s: %s", url, exc)
        return None


def _media_root() -> Path:
    return _PKG_DIR / "static" / "blog"


def _store_image(url: Optional[str], article_id: int, name: str) -> Optional[str]:
    """Download ``url`` for article ``article_id`` and return the local
    ``/static/...`` URL path, or ``None`` to fall back to the original URL."""
    path = _download_image(url, _media_root() / str(article_id), name)
    if path is None:
        return None
    return f"/static/blog/{article_id}/{path.name}"


# ---------------------------------------------------------------------------
# Persistence.
# ---------------------------------------------------------------------------


def _store_post(payload: dict, article_id: int, slug: str) -> None:
    hero_local = _store_image(payload.get("heroImageUrl"), article_id, "hero")
    info_local = _store_image(
        payload.get("infographicImageUrl"), article_id, "infographic"
    )

    faq = payload.get("faqSchema")
    with Session(_rw_engine()) as session:
        row = session.scalar(
            select(BlogPostRow).where(BlogPostRow.autoseo_id == article_id)
        )
        if row is None:
            row = BlogPostRow(autoseo_id=article_id)
            session.add(row)
        row.event = payload.get("event")
        row.title = payload.get("title") or ""
        row.slug = slug
        row.published_url = payload.get("published_url")
        row.meta_description = payload.get("metaDescription")
        row.content_html = payload.get("content_html")
        row.content_markdown = payload.get("content_markdown")
        row.hero_image_url = payload.get("heroImageUrl")
        # Keep the prior local copy if a re-fetch failed this delivery.
        if hero_local:
            row.hero_image_local = hero_local
        row.hero_image_alt = payload.get("heroImageAlt")
        row.infographic_image_url = payload.get("infographicImageUrl")
        if info_local:
            row.infographic_image_local = info_local
        row.keywords_json = json.dumps(payload.get("keywords") or [])
        row.meta_keywords = payload.get("metaKeywords")
        row.faq_schema_json = json.dumps(faq) if faq is not None else None
        row.language_code = payload.get("languageCode")
        row.status = payload.get("status")
        row.published_at = payload.get("publishedAt")
        row.updated_at = payload.get("updatedAt")
        row.created_at = payload.get("createdAt")
        row.received_at = datetime.now(timezone.utc).isoformat(timespec="seconds")
        session.commit()


def _site_url() -> str:
    return os.environ.get(SITE_URL_ENV, _DEFAULT_SITE_URL).rstrip("/")


# ---------------------------------------------------------------------------
# Routes.
# ---------------------------------------------------------------------------


@app.route("/webhooks/autoseo", methods=["POST"])
def autoseo_webhook():
    """Receive an AutoSEO article delivery. Verifies the Bearer token (and the
    HMAC signature when present), then upserts the post keyed on the AutoSEO
    ``id``. Returns ``{"url": ...}`` with the public post URL on success, or a
    5xx so AutoSEO retries."""
    token = os.environ.get(TOKEN_ENV)
    if not token:
        LOG.error("%s is not set; refusing AutoSEO webhook (fail closed)", TOKEN_ENV)
        return jsonify({"error": "webhook not configured"}), 503

    if not _check_bearer(request.headers.get("Authorization", ""), token):
        return jsonify({"error": "unauthorized"}), 401

    raw_body = request.get_data()
    signature = request.headers.get("X-AutoSEO-Signature")
    if signature and not _check_signature(raw_body, signature, token):
        return jsonify({"error": "invalid signature"}), 401

    try:
        payload = json.loads(raw_body.decode("utf-8"))
    except (ValueError, UnicodeDecodeError):
        return jsonify({"error": "invalid JSON body"}), 400
    if not isinstance(payload, dict):
        return jsonify({"error": "invalid JSON body"}), 400

    site = _site_url()
    event = payload.get("event") or request.headers.get("X-AutoSEO-Event", "")
    if event == "test":
        return jsonify({"url": f"{site}/test"}), 200

    try:
        article_id = int(payload["id"])
    except (KeyError, TypeError, ValueError):
        return jsonify({"error": "missing or invalid 'id'"}), 400
    slug = (payload.get("slug") or "").strip()
    if not slug:
        return jsonify({"error": "missing 'slug'"}), 400

    # Edge boundary: convert any unexpected failure (image I/O, DB) into a 500
    # so AutoSEO retries the delivery rather than dropping the article.
    try:
        _store_post(payload, article_id, slug)
    except Exception:
        LOG.exception("autoseo webhook failed to store article id=%s", article_id)
        return jsonify({"error": "internal error"}), 500

    return jsonify({"url": f"{site}/blog/{slug}"}), 200


# Tags allowed in rendered article HTML. AutoSEO's content_html is third-party,
# so it's sanitised before rendering to prevent stored XSS.
_ARTICLE_TAGS = [
    "p",
    "br",
    "hr",
    "strong",
    "em",
    "b",
    "i",
    "u",
    "s",
    "code",
    "pre",
    "blockquote",
    "ul",
    "ol",
    "li",
    "a",
    "img",
    "figure",
    "figcaption",
    "h1",
    "h2",
    "h3",
    "h4",
    "h5",
    "h6",
    "table",
    "thead",
    "tbody",
    "tr",
    "th",
    "td",
    "span",
    "div",
]
_ARTICLE_ATTRS = {
    "a": ["href", "title", "rel"],
    "img": ["src", "alt", "title", "width", "height"],
    "*": ["id"],
}


def _safe_html(html: str) -> Markup:
    """Sanitise article HTML to a safe subset. Falls back to escaped text if
    bleach isn't installed (same optional-dep posture as render_markdown)."""
    from markupsafe import escape

    if not html:
        return Markup("")
    try:
        import bleach
    except ImportError:  # pragma: no cover - depends on optional extras
        return Markup(f'<div class="whitespace-pre-line">{escape(html)}</div>')
    clean = bleach.clean(
        html,
        tags=_ARTICLE_TAGS,
        attributes=_ARTICLE_ATTRS,
        protocols=["http", "https", "mailto", "data"],
        strip=True,
    )
    return Markup(clean)


def _faq_jsonld(faq_schema_json: Optional[str]) -> Optional[Markup]:
    """Build a schema.org FAQPage JSON-LD blob from stored FAQ pairs."""
    if not faq_schema_json:
        return None
    try:
        pairs = json.loads(faq_schema_json)
    except ValueError:
        return None
    if not isinstance(pairs, list) or not pairs:
        return None
    doc = {
        "@context": "https://schema.org",
        "@type": "FAQPage",
        "mainEntity": [
            {
                "@type": "Question",
                "name": p.get("question", ""),
                "acceptedAnswer": {"@type": "Answer", "text": p.get("answer", "")},
            }
            for p in pairs
            if isinstance(p, dict)
        ],
    }
    return Markup(json.dumps(doc))


@app.route("/blog")
def autoseo_blog_index():
    with Session(_rw_engine()) as session:
        posts = session.scalars(
            select(BlogPostRow).order_by(desc(BlogPostRow.published_at))
        ).all()
    return render_template("blog_index.html", posts=posts)


@app.route("/blog/<slug>")
def autoseo_blog_post(slug):
    with Session(_rw_engine()) as session:
        post = session.scalar(
            select(BlogPostRow)
            .where(BlogPostRow.slug == slug)
            .order_by(desc(BlogPostRow.received_at))
            .limit(1)
        )
    if post is None:
        abort(404)
    return render_template(
        "blog_post.html",
        post=post,
        content=_safe_html(post.content_html or ""),
        hero=post.hero_image_local or post.hero_image_url,
        infographic=post.infographic_image_local or post.infographic_image_url,
        faq_jsonld=_faq_jsonld(post.faq_schema_json),
    )
