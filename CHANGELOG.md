# Changelog

## Unreleased (2026-10-27)

### Added
- `--fixable-only` hides confirmed findings that have no fixed version yet. Findings flagged as known
  exploited (KEV) or as malicious packages are always kept. Priorities are renumbered, and the exit code
  follows the findings that are shown, so the flag works as a CI gate.
- The report summary has two new fields, `with_fix_available` and `hidden_without_fix`, and the text
  report prints both.
  On a real Debian 13 container (`--dpkg /var/lib/dpkg/status --online`), 1 of 1,474 findings had a fix.
- Tests in `test/cli.test.js`. `docs/core.js` was rebuilt.
