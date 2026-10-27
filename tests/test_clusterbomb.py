"""Tests for clusterbomb, run against a local in-process login endpoint."""

from __future__ import annotations

import importlib.util
import pathlib
import sys
import threading
import time
import urllib.parse
from wsgiref.simple_server import make_server

import pytest

# Load clusterbomb.py (not a package) by path. Register it in sys.modules
# before executing so its @dataclass can resolve its own module.
_spec = importlib.util.spec_from_file_location(
    "clusterbomb", pathlib.Path(__file__).resolve().parent.parent / "clusterbomb.py"
)
clusterbomb = importlib.util.module_from_spec(_spec)
sys.modules["clusterbomb"] = clusterbomb
_spec.loader.exec_module(clusterbomb)

VALID = ("admin", "s3cr3t")


def login_app(environ, start_response):
    length = int(environ.get("CONTENT_LENGTH") or 0)
    body = environ["wsgi.input"].read(length).decode()
    form = urllib.parse.parse_qs(body)
    user = form.get("username", [""])[0]
    pw = form.get("password", [""])[0]
    if (user, pw) == VALID:
        start_response("302 Found", [("Location", "/dashboard"), ("Content-Length", "0")])
        return [b""]
    page = b"Invalid username or password"
    start_response("200 OK", [("Content-Type", "text/plain"), ("Content-Length", str(len(page)))])
    return [page]


@pytest.fixture(scope="module")
def login_url():
    httpd = make_server("127.0.0.1", 0, login_app)
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    yield f"http://127.0.0.1:{httpd.server_address[1]}/login"
    httpd.shutdown()


def make_bomb(url, rule, **kw):
    return clusterbomb.ClusterBomb(
        url=url, user_field="username", pass_field="password",
        extra_data={}, headers={}, rule=rule, **kw,
    )


def run(bomb, users, passwords):
    hits = []
    bomb.run(users, passwords, lambda a, e: hits.append(a) if a.success else None)
    return hits


def test_finds_valid_credentials_by_status(login_url):
    rule = clusterbomb.SuccessRule(302, None, None, None, None)
    bomb = make_bomb(login_url, rule, threads=4, stop_on_first=False)
    hits = run(bomb, ["root", "admin", "guest"], ["x", "s3cr3t", "y"])
    assert [(h.username, h.password) for h in hits] == [VALID]


def test_finds_valid_credentials_by_fail_regex(login_url):
    # Success = the "Invalid..." text is absent.
    rule = clusterbomb.SuccessRule(None, None, None, "Invalid", None)
    bomb = make_bomb(login_url, rule, threads=2, stop_on_first=False)
    hits = run(bomb, ["admin"], ["nope", "s3cr3t"])
    assert len(hits) == 1
    assert hits[0].password == "s3cr3t"


def test_no_false_positive_on_all_bad(login_url):
    rule = clusterbomb.SuccessRule(302, None, None, None, None)
    bomb = make_bomb(login_url, rule, threads=4, stop_on_first=False)
    hits = run(bomb, ["a", "b"], ["c", "d"])
    assert hits == []


def test_stop_on_first_hit(login_url):
    rule = clusterbomb.SuccessRule(302, None, None, None, None)
    bomb = make_bomb(login_url, rule, threads=1, stop_on_first=True)
    seen = []
    bomb.run(["admin"], ["s3cr3t", "more", "passwords", "here"],
             lambda a, e: seen.append(a))
    # Password list continues after the hit, but we stop early.
    assert any(a.success for a in seen)
    assert len(seen) < 4


def test_rate_limiter_spaces_attempts():
    limiter = clusterbomb.RateLimiter(rate=20)  # 50ms apart
    start = time.monotonic()
    for _ in range(5):
        limiter.wait()
    # 5 waits at 50ms should take at least ~200ms (first is free).
    assert time.monotonic() - start >= 0.18


def test_default_rule_is_redirect():
    rule = clusterbomb.SuccessRule(None, None, None, None, None)
    assert rule.success_status == 302
