# Tools

A small collection of offensive-security tools I use for bug bounty and
penetration testing.

> ⚠️ **Authorized use only.** Everything here is for systems you own or are
> explicitly authorized to test. Each tool prints this reminder when it runs.

## Contents

### `clusterbomb.py` — login credential tester

A general version of the Burp Intruder "cluster bomb" attack for login forms:
it tries every username against every password and reports which combinations
the server accepts. Grew out of a one-off script I wrote for a web-security lab.

Features: username/password wordlists (or single values), configurable form
fields and extra data (CSRF tokens), custom headers, a proxy switch for Burp,
threading, a rate limiter so you don't hammer the target, and flexible success
detection (status code, response length, or a regex that appears on
success/failure).

```bash
pip install -r requirements.txt

# Success = HTTP 302 redirect after login
python3 clusterbomb.py -u https://lab.local/login \
  -U users.txt -P rockyou-top100.txt \
  --success-status 302 --rate 5 -t 4

# Success = the "Invalid" error is NOT present
python3 clusterbomb.py -u https://lab.local/login \
  --user admin -P passwords.txt \
  --fail-regex "Invalid username or password" \
  -D "csrf=TOKEN" --proxy http://127.0.0.1:8080
```

Run `python3 clusterbomb.py -h` for all options.

### `github_sensitiveLeaks.sh` — multi-repo secret scanner

Takes an authorized GitHub search scope (e.g. an org or user), discovers the
repositories in it via the GitHub API, and runs TruffleHog across all of them in
one pass — useful for recon on large targets. Counts findings without printing
secret values, and writes results to a locked-down local directory.

```bash
export GITHUB_TOKEN="your_token"
./github_sensitiveLeaks.sh 'org:YOUR_ORG'
```

Requires `curl`, `python3` and `trufflehog`.

## Testing

```bash
pip install -r requirements.txt -r requirements-dev.txt
pytest -q
```

`clusterbomb.py` is tested against an in-process login endpoint — no real target
is contacted.

## License

MIT. See [LICENSE](LICENSE).
