# Regression tester

Run webres6's test suite and integration smoke-tests to confirm the current branch introduces no functional regressions. Scaled to the diff — trivial changes are skipped, not rubber-stamped.

## The deal

webres6 has unit tests for the API only (`api/test_*.py`), all using mocked Selenium/Valkey/S3/DNSProbe. They're fast but miss real integration paths. There are **no tests at all** for `viewer/`, `cli/`, `mcp/`, or the storage backends against real Valkey/S3. Close that gap with integration testing when the diff touches anything not under `api/`, or anything that the mocked tests can't cover (real browser behavior, real DNS, real storage).

**Integration uses a locally-running API server, not docker-compose.** Docker Desktop on macOS does not provide real IPv6 connectivity to containers, which makes docker-based integration runs unreliable for an IPv6-readiness checker. Run the API on the host directly — the host has real IPv6, a real Chrome, and a real network stack.

## Step 1 — scope and plan

```bash
git status
git diff main...HEAD --stat
```

**Branch base.** `main` is the default base and almost always correct. If working on a stacked branch, a fork point that isn't `main`, or the user has explicitly named a different base, ask before running `git diff` against the wrong reference — a wrong base produces a misleading scope and the rest of the run is wasted.

**Branch diff vs. working tree.** `git diff main...HEAD` shows committed changes on the branch. `git status` may also list uncommitted changes and untracked files. Default stance:
- **In scope:** committed branch changes (`git diff main...HEAD`) — this is what's being merged.
- **Out of scope:** uncommitted modifications and untracked files — they aren't part of the regression being verified.
- **But mention them:** if `git status` shows uncommitted/untracked work in test-relevant directories (`api/`, `viewer/`, `mcp/`, `cli/`, `helm/`, Dockerfiles), list those files in the **Coverage gaps** section. If they look substantive, ask whether they should be included before starting.

**Categorize the diff.** Decide once, up front, which class this diff falls into:

| Class | Diff touches… | Unit tests | Docker build | Integration |
|---|---|---|---|---|
| **trivial** | only `*.md`, `analysis/`, `.claude/`, memory files, `doc/`, unrelated `.github/workflows/`, screenshots, sample data | **skip** | skip | skip |
| **api-internal** | only `api/test_*.py`, `api/pytest.ini`, or comments/docstrings under `api/` | run | skip | skip |
| **api-runtime** | `api/webres6_*.py` (non-test), `serverconfig/` | run | run (api only) | run |
| **build/infra** | `**/Dockerfile`, `docker-compose*.yml`, `**/pyproject.toml`, `**/uv.lock`, `helm/**`, `.github/workflows/docker-build.yml` | run | run (relevant images) | run if any runtime touched |
| **viewer/cli/mcp** | `viewer/`, `cli/`, `mcp/` | run as baseline | run (relevant image) | run + note coverage gap |
| **mixed** | spans multiple categories | union of the above | union | union |

For **trivial**: state that explicitly and exit after Step 1 with verdict PASS (no runtime regression possible). Don't run unit tests as ceremony.

For everything else, report the plan (which steps will run, which will skip, why) before running long things.

## Step 2 — unit tests

```bash
cd api && source .venv/bin/activate && ./run_tests.sh
```

Capture pass/fail. If failures, read the relevant source and test files and explain what broke in plain language — don't just paste the traceback.

## Step 3 — docker image build check

The CI workflow `docker-build.yml` builds and pushes images for `webres6-api`, `webres6-viewer`, and `webres6-mcp` on every push to `main`. A broken Dockerfile or build context breaks deploy.

**Build only — do not start the stack.** Integration testing happens in Step 4 against the local API server.

**Build only the images affected by the diff:**

| Image | Affected by changes to |
|---|---|
| `webres6-api` | `api/**` (incl. `api/Dockerfile`, `api/pyproject.toml`, `api/uv.lock`, `api/serverconfig/`) |
| `webres6-viewer` | `viewer/**` (incl. its Dockerfile) |
| `webres6-mcp` | `mcp/**` (incl. `mcp/Dockerfile`, `mcp/pyproject.toml`) |

Cross-cutting changes that affect all images — build all three.

```bash
# Example: api-only diff
docker-compose -f docker-compose.dev.yml build webres6-api

# Example: cross-cutting / unsure
docker-compose -f docker-compose.dev.yml build webres6-api webres6-viewer webres6-mcp
```

On failure: identify which image broke, read the relevant `Dockerfile`, cross-reference with the diff, and report the root cause in plain language.

If docker is missing on this host, mark this step SKIPPED with reason and continue.

## Step 4 — integration smoke-test (local API server)

**Do not use docker-compose.** Run the API directly against the host network.

### IPv6 connectivity pre-flight

```bash
# Check for a global (non-link-local, non-loopback) IPv6 address
ifconfig | awk '/inet6/{print $2}' | grep -v '^fe80' | grep -v '^::1'

# Probe an IPv6-only endpoint (5-second timeout)
curl -6 -sf --max-time 5 -o /dev/null https://ipv6.google.com 2>&1 && echo "IPv6 reachable" || echo "IPv6 unreachable"
```

If either check fails: tell the user what failed and why it matters (libunbound resolves DNS over IPv6-only, so every DNS probe will return SERVFAIL and every site will show `ipv6_only_score: 0.0`). Ask:

> "IPv6 is not reachable. Do you want to (a) fix it and re-run, or (b) continue anyway (results will show 0% IPv6 scores and are not meaningful)?"

If the user chooses to fix it first, stop and wait. If they choose to continue, mark the result **PARTIAL — IPv6 not available** and note that all IPv6 scores are expected to be 0%.

### Port check

```bash
lsof -iTCP:6400 -sTCP:LISTEN
```

If something is already listening on port 6400, ask the user before proceeding — don't kill an unknown process.

### Start the server

```bash
cd api && source .venv/bin/activate
./webres6_api.py --debug --port 6400 > /tmp/webres6-api.log 2>&1 &
echo $! > /tmp/webres6-api.pid
```

Use `run_in_background: true` for this. Poll for readiness:

```bash
for i in $(seq 1 30); do
  curl -sf -o /dev/null http://localhost:6400/ && echo "ready" && break
  sleep 1
done
```

If it doesn't come up in 30s, `cat /tmp/webres6-api.log`, report the failure, and stop.

### Smoke tests

```bash
# Basic crawl — must succeed and return a report
curl -sf "http://localhost:6400/res6/url(https://example.com)" | python3 -m json.tool | head -80

# IPv6-only target — should classify as IPv6-ready
curl -sf "http://localhost:6400/res6/url(https://ipv6.he.net)" | python3 -m json.tool | head -80
```

If the diff touches something specific (NAT64 handling, screenshots, DNS probe, MCP tools, a particular host classification rule), add at least one test case that exercises that path.

### Tear down (always, even on failure)

```bash
kill "$(cat /tmp/webres6-api.pid)" 2>/dev/null
rm -f /tmp/webres6-api.pid
```

The viewer is static HTML/JS — no point spinning it up for a regression check. If the diff touches `viewer/`, call it out as a coverage gap (Step 5).

## Step 5 — coverage gap report

Always tell the user what was **not** covered. Examples:
- "Diff modifies `viewer/main.js` — no automated tests for viewer; manual browser check recommended."
- "Diff modifies `cli/webres6_cli.py` — no tests for CLI; ran `./webres6_cli.py https://example.com` as smoke check."
- "Diff modifies `mcp/server.py` — no tests; verified `webres6-mcp --transport http` starts without crashing."
- "Storage backend logic changed but unit tests use a mock — real Valkey/S3 paths not exercised here."

If there's a non-API change with zero realistic way to test, say so. Don't invent tests.

## Output format

Return a markdown report:

```
## Regression test: <branch or scope>

**Verdict:** <PASS | FAIL | PARTIAL — see notes>

### Unit tests
- Result: <PASS / FAIL with N failures>
- Suite: api/run_tests.sh
- Notes: <only if failures or skips>

### Docker image build
- Result: <PASS / FAIL / SKIPPED — reason>
- Images: <which ones were built>
- Notes: <only if failures or skipped>

### Integration tests
- Result: <PASS / FAIL / SKIPPED — reason>
- Mode: local API server (no docker — Docker Desktop on macOS lacks real IPv6)
- Cases run:
  - `curl /res6/url(https://example.com)` → <ok / failed: …>
  - `curl /res6/url(https://ipv6.he.net)` → <ok / failed: …>
  - <any diff-specific cases added>

### Coverage gaps
<list of paths/behaviors changed by the diff that were NOT exercised, and why>

### Failures
<for each failure: what broke, where in the source it traces to, plain-language explanation>
```

If everything passes and gaps are minor, the report can be short. If something failed, the **failure analysis is the most important part**.

## Safety rules

- **Don't claim a test passed if it didn't run.** If a step was skipped (port busy, venv missing, ChromeDriver missing), say so in the verdict.
- **Don't run destructive commands.** No `docker system prune`, no deleting `data/`, no `git reset`. Don't kill processes you didn't start.
- **`./local_cache/` is fair game** — it's the local persistence dir and gets recreated on demand.
- **Always tear down the API server you started**, even if tests fail.
