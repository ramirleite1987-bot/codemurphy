# CodeMurphy v0.1 design

CodeMurphy reviews changes locally or on GitHub and helps a team choose reviewers
with evidence from its own repositories. Its target is better useful-issue
recall, precision, and cost than incumbent review tools on the team's held-out
PRs. A passing smoke test establishes functionality, not superiority.

A hosted GitHub App would simplify organization-wide installation and central
feedback, but would require a service, data retention decisions, and app
credentials. A CLI alone would be easy to self-host but require every team to
write their own PR automation. The first release combines a Python CLI with a
composite GitHub Action: each repository owns its config and secrets, and CI can
run without a CodeMurphy server.

- Python 3.11+, Git for local reviews, no runtime Python dependencies.
- Immutable Git refs and an explicit file allowlist for linked context. Select
  relevant references per diff batch; include provenance with verified citations.
  Bound the number of files, input characters, requests, and response bytes.
- A shared rubric covers correctness, security, scalability, clarity, tests,
  and edge cases. The project can configure paths, categories, and instructions.
- An OpenAI-compatible adapter and a native Anthropic Messages adapter allow
  independent, parallel model runs on the same input. A deterministic scanner
  detects recognizable credential patterns. A finding must cite a changed line
  and quote the redacted diff before it can be reported.
- GitHub reviews use base-branch config and the PR Files API. The Action does
  not check out or execute PR code. Forks are off by default. Review comments
  target the verified head, never approve or merge, and strip model-generated
  links, mentions, and markup. Private linked context disables publication and
  stays out of the Actions summary.
- JSON reports carry per-model latency, token counts, configured cost estimates,
  coverage, and individual findings. SQLite is optional; it stores aggregate
  stats and finding IDs for human feedback. The labeled benchmark reports
  precision, recall, severity-weighted recall, cost, and latency, with support
  for normalized third-party findings and a common completed-case comparison.
- v0.1 does not promise complete secret detection, execute scanners on arbitrary
  code, train on feedback, or claim a win without a head-to-head evaluation.
