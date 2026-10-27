#!/usr/bin/env python3
"""clusterbomb — a login credential tester for AUTHORIZED security testing.

A cleaned-up, general version of my original Cluster Bomb lab script. It tries
username/password combinations against a login form (the Burp Intruder
"cluster bomb" idea: every username against every password) and reports which
combinations the server accepts, using a success rule you define.

Only use this against systems you are explicitly authorized to test: your own
lab, a signed engagement, or an in-scope bug bounty program with brute-force
allowed. Unauthorized credential testing is illegal, and most production login
pages have lockout you can trip. The tool prints this reminder on every run.
"""

from __future__ import annotations

import argparse
import itertools
import re
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass

import requests

CONSENT = (
    "AUTHORIZED TESTING ONLY. Use against your own lab, a signed engagement, or "
    "an in-scope bounty program that permits brute force."
)


@dataclass
class Attempt:
    username: str
    password: str
    status: int
    length: int
    elapsed: float
    success: bool


class RateLimiter:
    """Blocks so that no more than `rate` attempts start per second."""

    def __init__(self, rate: float) -> None:
        self.min_interval = 1.0 / rate if rate > 0 else 0.0
        self._lock = threading.Lock()
        self._next = 0.0

    def wait(self) -> None:
        if self.min_interval <= 0:
            return
        with self._lock:
            now = time.monotonic()
            sleep_for = self._next - now
            self._next = max(now, self._next) + self.min_interval
        if sleep_for > 0:
            time.sleep(sleep_for)


def read_list(path: str, inline: str | None) -> list[str]:
    if inline is not None:
        return [inline]
    if path == "-":
        return [line.rstrip("\n") for line in sys.stdin if line.strip()]
    with open(path, encoding="utf-8", errors="replace") as fh:
        return [line.rstrip("\n") for line in fh if line.strip()]


class SuccessRule:
    """Decides whether a response means the login succeeded."""

    def __init__(
        self,
        success_status: int | None,
        fail_status: int | None,
        success_regex: str | None,
        fail_regex: str | None,
        max_length: int | None,
    ) -> None:
        self.success_status = success_status
        self.fail_status = fail_status
        self.success_re = re.compile(success_regex) if success_regex else None
        self.fail_re = re.compile(fail_regex) if fail_regex else None
        self.max_length = max_length
        if not any([success_status, fail_status, success_regex, fail_regex, max_length]):
            # Sensible default for many apps: a redirect after login.
            self.success_status = 302

    def matches(self, resp: requests.Response) -> bool:
        if self.success_status is not None and resp.status_code == self.success_status:
            return True
        if self.fail_status is not None and resp.status_code != self.fail_status:
            return True
        if self.success_re is not None and self.success_re.search(resp.text):
            return True
        if self.fail_re is not None and not self.fail_re.search(resp.text):
            return True
        if self.max_length is not None and len(resp.content) != self.max_length:
            return True
        return False


class ClusterBomb:
    def __init__(
        self,
        url: str,
        user_field: str,
        pass_field: str,
        extra_data: dict[str, str],
        headers: dict[str, str],
        rule: SuccessRule,
        method: str = "POST",
        threads: int = 4,
        rate: float = 0.0,
        timeout: float = 10.0,
        proxy: str | None = None,
        stop_on_first: bool = True,
    ) -> None:
        self.url = url
        self.user_field = user_field
        self.pass_field = pass_field
        self.extra_data = extra_data
        self.rule = rule
        self.method = method
        self.threads = threads
        self.timeout = timeout
        self.stop_on_first = stop_on_first
        self.limiter = RateLimiter(rate)
        self._stop = threading.Event()
        self.session_factory = lambda: _make_session(headers, proxy)

    def _try(self, username: str, password: str) -> Attempt:
        self.limiter.wait()
        session = self.session_factory()
        data = {self.user_field: username, self.pass_field: password, **self.extra_data}
        start = time.monotonic()
        resp = session.request(
            self.method, self.url, data=data,
            timeout=self.timeout, allow_redirects=False,
        )
        elapsed = time.monotonic() - start
        return Attempt(
            username, password, resp.status_code, len(resp.content),
            elapsed, self.rule.matches(resp),
        )

    def run(self, usernames: list[str], passwords: list[str], on_result):
        combos = itertools.product(usernames, passwords)
        hits: list[Attempt] = []
        with ThreadPoolExecutor(max_workers=self.threads) as pool:
            futures = {}
            for user, pw in combos:
                if self._stop.is_set():
                    break
                futures[pool.submit(self._try, user, pw)] = (user, pw)
            for fut in as_completed(futures):
                user, pw = futures[fut]
                try:
                    attempt = fut.result()
                except Exception as exc:  # noqa: BLE001 - report and keep going
                    on_result(Attempt(user, pw, -1, 0, 0.0, False), str(exc))
                    continue
                on_result(attempt, None)
                if attempt.success:
                    hits.append(attempt)
                    if self.stop_on_first:
                        self._stop.set()
                        break
        return hits


def _make_session(headers: dict[str, str], proxy: str | None) -> requests.Session:
    session = requests.Session()
    session.headers.update({"User-Agent": "clusterbomb/1.0 (authorized testing)"})
    session.headers.update(headers)
    if proxy:
        session.proxies = {"http": proxy, "https": proxy}
        session.verify = False
    return session


def parse_kv(raw: list[str], sep: str) -> dict[str, str]:
    out = {}
    for item in raw:
        if sep not in item:
            raise SystemExit(f"expected 'name{sep}value', got {item!r}")
        name, _, value = item.partition(sep)
        out[name.strip()] = value.strip()
    return out


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="clusterbomb",
        description="Test username/password combinations against an authorized login.",
        epilog=CONSENT,
    )
    p.add_argument("-u", "--url", required=True, help="login endpoint")
    p.add_argument("-X", "--method", default="POST")
    p.add_argument("--user-field", default="username", help="form field for the username")
    p.add_argument("--pass-field", default="password", help="form field for the password")

    p.add_argument("-U", "--users", help="username wordlist file ('-' for stdin)")
    p.add_argument("--user", help="a single username (instead of -U)")
    p.add_argument("-P", "--passwords", help="password wordlist file ('-' for stdin)")
    p.add_argument("--password", help="a single password (instead of -P)")

    p.add_argument("-D", "--data", action="append", default=[], metavar="name=value",
                   help="extra form fields (e.g. a CSRF token); repeatable")
    p.add_argument("-H", "--header", action="append", default=[], metavar="'Name: value'")
    p.add_argument("--proxy", help="proxy, e.g. http://127.0.0.1:8080")
    p.add_argument("--timeout", type=float, default=10.0)

    sr = p.add_argument_group("success rule (how a valid login is recognised)")
    sr.add_argument("--success-status", type=int, help="status code that means success (e.g. 302)")
    sr.add_argument("--fail-status", type=int, help="status code for a FAILED login; anything else is success")
    sr.add_argument("--success-regex", help="regex present in a successful response")
    sr.add_argument("--fail-regex", help="regex present only on failure (e.g. 'Invalid'); absence means success")
    sr.add_argument("--length", type=int, dest="max_length", help="failed-response content length; a different length means success")

    p.add_argument("-t", "--threads", type=int, default=4)
    p.add_argument("--rate", type=float, default=0.0, help="max attempts/sec (0 = unlimited). Be gentle.")
    p.add_argument("--continue", dest="keep_going", action="store_true",
                   help="try all combinations instead of stopping at the first hit")
    p.add_argument("-v", "--verbose", action="store_true", help="print every attempt")
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    print(f"[!] {CONSENT}\n", file=sys.stderr)

    if not (args.users or args.user) or not (args.passwords or args.password):
        raise SystemExit("[-] need a username source (-U/--user) and a password source (-P/--password)")

    usernames = read_list(args.users, args.user) if (args.users or args.user) else []
    passwords = read_list(args.passwords, args.password) if (args.passwords or args.password) else []

    rule = SuccessRule(
        args.success_status, args.fail_status,
        args.success_regex, args.fail_regex, args.max_length,
    )
    bomb = ClusterBomb(
        url=args.url, user_field=args.user_field, pass_field=args.pass_field,
        extra_data=parse_kv(args.data, "="), headers=parse_kv(args.header, ":"),
        rule=rule, method=args.method.upper(), threads=args.threads,
        rate=args.rate, timeout=args.timeout, proxy=args.proxy,
        stop_on_first=not args.keep_going,
    )

    total = len(usernames) * len(passwords)
    print(f"[*] {len(usernames)} users x {len(passwords)} passwords = {total} attempts", file=sys.stderr)
    done = [0]

    def on_result(attempt: Attempt, error: str | None) -> None:
        done[0] += 1
        if error:
            if args.verbose:
                print(f"    [err] {attempt.username}:{attempt.password} -> {error}", file=sys.stderr)
            return
        if attempt.success:
            print(f"[+] HIT  {attempt.username}:{attempt.password}  "
                  f"(status {attempt.status}, len {attempt.length})")
        elif args.verbose:
            print(f"    {attempt.username}:{attempt.password} -> {attempt.status} ({attempt.length}b)",
                  file=sys.stderr)

    start = time.monotonic()
    try:
        hits = bomb.run(usernames, passwords, on_result)
    except KeyboardInterrupt:
        print("\n[-] interrupted", file=sys.stderr)
        return 130

    elapsed = time.monotonic() - start
    print(f"\n[*] {done[0]} attempts in {elapsed:.1f}s, {len(hits)} hit(s)", file=sys.stderr)
    return 0 if hits else 1


if __name__ == "__main__":
    raise SystemExit(main())
