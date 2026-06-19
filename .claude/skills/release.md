# Release skill

Bump the version across all five version-tracked files, commit, and tag — after a security review and regression test pass.

## Files that must all match

1. `VERSION`
2. `api/webres6_api.py` — `webres6_version = "X.Y.Z"`
3. `api/pyproject.toml` — `version = "X.Y.Z"`
4. `mcp/pyproject.toml` — `version = "X.Y.Z"`
5. `helm/Chart.yaml` — both `version: X.Y.Z` and `appVersion: "X.Y.Z"`

The pre-commit hook enforces that all five match before any commit goes through.

## Workflow

### Step 1 — determine the new version

Read the current version from `VERSION`. If the user provided a target version (e.g. `/release 1.8.0`), use that. Otherwise ask: "Current version is X.Y.Z — what should the new version be?"

Validate that the new version:
- Is a valid semver string (`MAJOR.MINOR.PATCH`)
- Is strictly greater than the current version (compare numerically per semver)
- Does not already exist as a git tag (`git tag --list "vX.Y.Z"`)

If any check fails, stop and report why.

### Step 2 — pre-release gate: security review + regression tests

Before touching any files, run both checks in parallel:

```
Launch security-reviewer agent: full codebase security review (same prompt as /security-review)
Launch regression-tester agent: full working tree regression test
```

Wait for both to complete. Then:

- If the security review found any **HIGH** severity findings: stop and present them to the user. Do not proceed until the user explicitly acknowledges each finding and either confirms it is acceptable or asks you to fix it first.
- If the regression test verdict is **FAIL**: stop and present the failures. Do not proceed until they are resolved.
- If both pass (or only LOW/MEDIUM findings the user accepts): continue to Step 3.

Present a brief summary to the user and ask for confirmation before continuing.

### Step 3 — confirm the release plan

Show a summary:
```
Security review: PASS (or: N findings — user accepted)
Regression tests: PASS

Bumping version: X.Y.Z → A.B.C

Files to update:
  VERSION
  api/webres6_api.py      webres6_version = "A.B.C"
  api/pyproject.toml      version = "A.B.C"
  mcp/pyproject.toml      version = "A.B.C"
  helm/Chart.yaml         version: A.B.C  +  appVersion: "A.B.C"

Will create:
  git commit  "Bump version to A.B.C"
  git tag     vA.B.C

Proceed? (yes / no)
```

Wait for explicit confirmation before making any changes.

### Step 4 — update all five files

Use the Edit tool (not sed/awk) to update each file precisely:

- `VERSION`: replace the entire content with `A.B.C\n`
- `api/webres6_api.py`: replace `webres6_version   = "X.Y.Z"` with `webres6_version   = "A.B.C"` (preserve whitespace)
- `api/pyproject.toml`: replace `version = "X.Y.Z"` with `version = "A.B.C"` — match only the top-level `version` line (not dependency version pins)
- `mcp/pyproject.toml`: same as above
- `helm/Chart.yaml`: replace `version: X.Y.Z` and `appVersion: "X.Y.Z"` separately

After all edits, verify consistency:
```bash
grep -h 'webres6_version\|^version\|^appVersion' \
  VERSION api/webres6_api.py api/pyproject.toml mcp/pyproject.toml helm/Chart.yaml \
  | grep -v '#' | grep -v 'selenium\|valkey'
```
All values shown must equal A.B.C. If any mismatch is found, stop and report — do not commit.

### Step 5 — commit and tag

Check for uncommitted changes in the five version files before staging:
```bash
git status --short VERSION api/webres6_api.py api/pyproject.toml mcp/pyproject.toml helm/Chart.yaml
```
Only the five version files should appear as modified. If any other unexpected changes are staged, warn the user.

Stage only the five version files:
```bash
git add VERSION api/webres6_api.py api/pyproject.toml mcp/pyproject.toml helm/Chart.yaml
```

Commit (the pre-commit hook will re-verify consistency — if it fails, something is wrong):
```bash
git commit -m "Bump version to A.B.C"
```

If the commit fails (hook rejection or other error), stop and report. Do not tag.

Tag:
```bash
git tag vA.B.C
```

### Step 6 — report

```
Release A.B.C complete.

  Commit: <short hash> "Bump version to A.B.C"
  Tag:    vA.B.C (local only)

To publish:
  git push && git push origin vA.B.C

Pushing the tag triggers the docker-build.yml CI workflow, which builds
and pushes Docker images for webres6-api, webres6-viewer, and webres6-mcp.
```

## Safety rules

- **Never push automatically.** Always leave push to the user.
- **Do not bump if there are uncommitted changes** in any of the five version files before Step 4 begins — check with `git status` and warn if any are modified.
- **Do not proceed past Step 3 without explicit user confirmation.**
- **Do not skip the security review and regression test gate** in Step 2, even if the user asks to go fast. If the user wants to bypass it, ask them to confirm explicitly that they accept the risk.
